#!/usr/bin/env python3
"""audit_issues_engine.py - High-performance audit engine analyzing all 600 chunks of marketplace issues and comments."""

from __future__ import annotations

import base64
import json
import multiprocessing
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

CHUNKS_DIR = Path(__file__).resolve().parent.parent / "data" / "chunks"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "data" / "results"

MAINTAINER_LOGINS = frozenset({"HANCORE-linux", "ryanrhughes", "dhh"})

# Precise regex for agent directive file objections (excludes voice tools or general agent discussions like #98)
RE_AGENT_DIRECTIVE_OBJ = re.compile(
    r"\b(?:AGENTS\.md|agent\.md|CLAUDE\.md|\.cursorrules)\b.*\b(?:remove|exclude|rename|contains executable agent directives|instruction-injection|cannot approve|shipped inside|distributable|plugin tree|auto-load|auto-ingest|untrusted instructions)\b"
    r"|\b(?:remove|exclude|rename|cannot approve|shipped inside|distributable|plugin tree).*\b(?:AGENTS\.md|agent\.md|CLAUDE\.md|\.cursorrules)\b",
    re.I | re.S
)

CATEGORY_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("agent_steering_files", RE_AGENT_DIRECTIVE_OBJ),
    ("network_and_untrusted_fetch", re.compile(r"curl\s+.*\|\s*(?:bash|sh)|external host|untrusted network|download.*runtime|remote fetch", re.I)),
    ("prebuilt_binaries", re.compile(r"prebuilt|precompiled|ELF\b|executable binary|committed binary|binary asset", re.I)),
    ("undeclared_dependencies", re.compile(r"base-devel|cmake|compiler|build tool|make|gcc|cargo|pkgconf|hidapi|libpulse|undeclared dependenc", re.I)),
    ("sudo_and_privileges", re.compile(r"sudo\s+-S|sudoers|NOPASSWD|credential harvesting|root privilege|unauthorized root", re.I)),
    ("qml_markup_and_quality", re.compile(r"textFormat|PlainText|rich text|AutoText|markup injection", re.I)),
    ("process_lifecycle", re.compile(r"watchdog|timeout|zombie|stuck process|process lifecycle|unresponsive process", re.I)),
    ("symlinks_and_packaging", re.compile(r"symlink|symbolic link", re.I)),
    ("shared_temp_state", re.compile(r"/(?:tmp|dev/shm)/|temporary directory|XDG_RUNTIME_DIR", re.I)),
    ("licensing_and_assets", re.compile(r"license|copyright|attribution|third-party asset|preview asset", re.I)),
    ("wayland_focus", re.compile(r"keyboardFocus|exclusive focus|layer-shell|wlr", re.I)),
]


def analyze_single_issue(it: Dict[str, Any]) -> Dict[str, Any]:
    num = it.get("number", 0)
    title = it.get("title", "") or ""
    state = it.get("state", "") or ""
    author = it.get("author", "") or ""
    labels = it.get("labels", []) or []
    body = it.get("body", "") or ""
    comments = it.get("comments", []) or []

    # 1. Type
    if title.startswith("[Plugin]:") or "### Repository URL" in body:
        issue_type = "submission"
    elif title.startswith("[Verify]:") or "### Verification action" in body:
        issue_type = "verification_update"
    elif any(lb in ("bug", "defect") for lb in labels):
        issue_type = "bug_report"
    elif any(lb in ("discussion", "question") for lb in labels):
        issue_type = "discussion"
    else:
        issue_type = "other"

    # 2. Metadata
    plugin_id = None
    m_id = re.search(r"### Plugin ID\s*\n+([a-z0-9._-]+)", body)
    if m_id:
        plugin_id = m_id.group(1).strip()

    plugin_name = None
    if title.startswith("[Plugin]:"):
        plugin_name = title.replace("[Plugin]:", "").strip()
    elif title.startswith("[Verify]:"):
        plugin_name = title.replace("[Verify]:", "").strip()

    repo_url = None
    m_repo = re.search(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", body)
    if m_repo:
        repo_url = m_repo.group(0).strip().rstrip(")")

    # 3. Bot comments decoding
    bot_errors: List[str] = []
    bot_caps: List[str] = []
    published = False

    for c in comments:
        c_body = c.get("body", "") or ""
        if "<!-- marketplace-security-baseline:v4" in c_body:
            m_b64 = re.search(r"<!-- marketplace-security-baseline:v4\s+([A-Za-z0-9+/=]+)", c_body)
            if m_b64:
                try:
                    payload = json.loads(base64.b64decode(m_b64.group(1)).decode("utf-8"))
                    bot_caps.extend(payload.get("capabilities", []))
                    for fnd in payload.get("findings", []):
                        if isinstance(fnd, dict):
                            bot_errors.append(fnd.get("name", "security-baseline-finding"))
                    if not plugin_id and payload.get("pluginIds"):
                        plugin_id = payload["pluginIds"][0]
                except Exception:
                    pass

        if "<!-- marketplace-validation -->" in c_body:
            for line in c_body.splitlines():
                line_s = line.strip()
                if line_s.startswith("❌"):
                    bot_errors.append(line_s.lstrip("❌").strip())

        if "<!-- marketplace-publication -->" in c_body or "Published and verified" in c_body:
            published = True

    # Outcome
    if published or "approved-and-verified" in labels or "listed" in labels:
        outcome = "approved_published"
    elif state == "closed":
        outcome = "needs_fixes_stalled"
    elif state == "open":
        outcome = "in_review"
    else:
        outcome = "not_applicable"

    # 4. Human maintainer review comments
    manual_blockers: List[Dict[str, Any]] = []
    distinct_reviewers: Set[str] = set()

    for c in comments:
        c_author = c.get("author", "") or ""
        c_body = (c.get("body", "") or "").strip()
        c_id = c.get("id")
        if not c_body or c_author == "github-actions[bot]":
            continue

        is_maintainer = (c_author in MAINTAINER_LOGINS)
        if is_maintainer:
            distinct_reviewers.add(c_author)

        # Check if reviewer raises security or policy blockers
        if is_maintainer or "security review" in c_body.lower() or "blocked" in c_body.lower():
            for cat_name, rx in CATEGORY_PATTERNS:
                if rx.search(c_body):
                    # Check for author resolution
                    resolution = None
                    for ac in comments:
                        if ac.get("author") == author and (ac.get("created_at", "") > c.get("created_at", "")):
                            ac_body = ac.get("body", "")
                            ac_lower = ac_body.lower()
                            if any(w in ac_lower for w in ["fixed", "renamed", "removed", "deleted", "moved", "commit", "updated"]):
                                resolution = ac_body.strip().replace("\n", " ")[:200]
                                break

                    manual_blockers.append({
                        "comment_id": c_id,
                        "reviewer": c_author,
                        "category": cat_name,
                        "detail": c_body[:300],
                        "resolution": resolution or "No resolution documented in comments (issue closed or commit updated directly)"
                    })

    # Deduplicate blockers by category per reviewer
    unique_blockers = []
    seen_cats = set()
    for b in manual_blockers:
        key = (b["reviewer"], b["category"])
        if key not in seen_cats:
            seen_cats.add(key)
            unique_blockers.append(b)

    # Key takeaway
    takeaways = []
    for b in unique_blockers:
        cat = b["category"]
        if cat == "agent_steering_files":
            takeaways.append("Do not ship AGENTS.md in plugin checkout; use DEVELOPMENT.md")
        elif cat == "undeclared_dependencies":
            takeaways.append("Declare all native build dependencies in setup")
        elif cat == "prebuilt_binaries":
            takeaways.append("Compile binaries from source during setup; do not commit binaries")
        elif cat == "qml_markup_and_quality":
            takeaways.append("Specify textFormat: Text.PlainText on dynamic text")
        elif cat == "process_lifecycle":
            takeaways.append("Implement watchdog timer terminating unresponsive background helpers")
        elif cat == "shared_temp_state":
            takeaways.append("Use $XDG_RUNTIME_DIR mode 0700 instead of /tmp")

    key_takeaway = "; ".join(takeaways[:2]) if takeaways else ("Standard submission" if outcome == "approved_published" else "In review/discussion")

    return {
        "issue_number": num,
        "type": issue_type,
        "plugin_id": plugin_id,
        "plugin_name": plugin_name,
        "repo_url": repo_url,
        "author": author,
        "outcome": outcome,
        "bot_validation_errors": list(set(bot_errors)),
        "bot_capabilities_flagged": list(set(bot_caps)),
        "manual_review_blockers": unique_blockers,
        "distinct_manual_reviewers": list(distinct_reviewers),
        "key_takeaway": key_takeaway,
    }


def process_chunk_file(chunk_file: Path) -> Dict[str, Any]:
    with open(chunk_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    chunk_id = data.get("chunk_id", 0)
    issues = data.get("issues", [])

    records = [analyze_single_issue(it) for it in issues]

    result = {
        "chunk_id": chunk_id,
        "issues_analyzed": len(records),
        "records": records
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = RESULTS_DIR / f"result_chunk_{chunk_id:03d}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return {"chunk_id": chunk_id, "records_count": len(records)}


def main() -> int:
    chunk_files = sorted(CHUNKS_DIR.glob("chunk_*.json"))
    total_chunks = len(chunk_files)
    if total_chunks == 0:
        print(f"No chunk files found in {CHUNKS_DIR}", file=sys.stderr)
        return 1

    print(f"Starting parallel extraction swarm across {total_chunks} chunks using {multiprocessing.cpu_count()} CPU cores...")
    start_time = time.time()

    with multiprocessing.Pool() as pool:
        results = pool.map(process_chunk_file, chunk_files)

    elapsed = time.time() - start_time
    total_records = sum(r["records_count"] for r in results)
    print(f"\nSwarm execution complete in {elapsed:.2f}s!")
    print(f"Processed {len(results)} chunks, extracted {total_records} total issue records into {RESULTS_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
