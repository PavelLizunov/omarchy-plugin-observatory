#!/usr/bin/env python3
"""run_pilot_chunk.py - Extract pilot chunk containing target issues (e.g. #6873) for extraction schema testing."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tools.agent_prompt_template import build_agent_prompt

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "corpus" / "marketplace_corpus.db"
PILOT_OUTPUT = Path(__file__).resolve().parent.parent / "data" / "chunks" / "pilot_chunk_6873.json"


def main() -> int:
    if not DB_PATH.exists():
        print(f"Error: Database file does not exist: {DB_PATH}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Find issue 6873 and surrounding 9 issues
    cur.execute("SELECT number, title, state, user, created_at, closed_at, labels, body FROM issues WHERE number >= 6868 AND number <= 6878 ORDER BY number ASC")
    rows = cur.fetchall()

    if not rows:
        print("Issue #6873 not yet downloaded in database.", file=sys.stderr)
        return 1

    issues = []
    for r in rows:
        num = r["number"]
        cur.execute("SELECT user, created_at, body FROM comments WHERE issue_number = ? ORDER BY id ASC", (num,))
        comms = [{"author": c["user"], "created_at": c["created_at"], "body": c["body"]} for c in cur.fetchall()]
        labels = json.loads(r["labels"]) if r["labels"] else []
        issues.append({
            "number": num,
            "title": r["title"] or "",
            "state": r["state"] or "",
            "author": r["user"] or "",
            "created_at": r["created_at"] or "",
            "closed_at": r["closed_at"] or "",
            "labels": labels,
            "body": r["body"] or "",
            "comments": comms
        })

    pilot_data = {
        "chunk_id": 999,
        "issues_count": len(issues),
        "target_tested": 6873,
        "issues": issues
    }

    PILOT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(PILOT_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(pilot_data, f, ensure_ascii=False, indent=2)

    prompt = build_agent_prompt(pilot_data)
    prompt_file = PILOT_OUTPUT.parent / "pilot_prompt.txt"
    with open(prompt_file, "w", encoding="utf-8") as f:
        f.write(prompt)

    print(f"Pilot chunk written to {PILOT_OUTPUT} ({len(issues)} issues)")
    print(f"Pilot prompt written to {prompt_file} ({len(prompt)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
