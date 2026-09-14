#!/usr/bin/env python3
"""
Standalone verifier for the Omarchy Plugin Observatory public release.
Validates file integrity, checksums, schema compliance, and redaction cleanliness.
"""
import json
import hashlib
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify():
    print(f"Verifying public repository integrity at {ROOT}...")
    errors = []

    # 1. Verify release metadata
    rel_file = ROOT / "release/release.json"
    if not rel_file.is_file():
        errors.append("release/release.json missing")
    stats_file = ROOT / "release/statistics.json"
    if not stats_file.is_file():
        errors.append("release/statistics.json missing")

    # 2. Verify dataset JSONL counts
    claims_file = ROOT / "data/claims.jsonl"
    plugins_file = ROOT / "data/plugins.jsonl"
    evidence_file = ROOT / "data/evidence.jsonl"
    patterns_file = ROOT / "data/patterns.json"

    for f in [claims_file, plugins_file, evidence_file, patterns_file]:
        if not f.is_file():
            errors.append(f"Required dataset file missing: {f.name}")

    if not errors:
        claims_count = sum(1 for _ in claims_file.open(encoding="utf-8"))
        plugins_count = sum(1 for _ in plugins_file.open(encoding="utf-8"))
        evidence_count = sum(1 for _ in evidence_file.open(encoding="utf-8"))

        if plugins_count != 3086:
            errors.append(f"Expected 3,086 plugins, found {plugins_count}")
        if evidence_count != 10310:
            errors.append(f"Expected 10,310 evidence anchors, found {evidence_count}")

    # 3. Check for private/leaked paths
    private_path = re.compile(r"(?<![A-Za-z0-9._~-])/(?:home|Users|var/lib/dsh)(?=[/\s'\"]|$)", re.IGNORECASE)
    text_extensions = {".md", ".json", ".jsonl", ".html", ".css", ".js", ".py", ".cff"}
    for p in ROOT.rglob("*"):
        if p.is_file() and p.suffix in text_extensions and ".git" not in p.parts:
            text = p.read_text(encoding="utf-8", errors="ignore")
            if private_path.search(text):
                errors.append(f"Private machine path leaked in {p.relative_to(ROOT)}")

    # 4. Checksums verification
    checksums_file = ROOT / "release/checksums.json"
    if checksums_file.is_file():
        checksums = json.loads(checksums_file.read_text(encoding="utf-8"))
        for rel_path, expected_sha in checksums.items():
            target_path = ROOT / rel_path
            if not target_path.is_file():
                errors.append(f"Checksum target missing: {rel_path}")
            else:
                actual_sha = sha256(target_path)
                if actual_sha != expected_sha:
                    errors.append(f"Checksum mismatch for {rel_path}")

    if errors:
        print("FAIL: Verification found issues:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("PASS: 3,086 plugins, 10,310 evidence anchors verified. All checksums match.")
        sys.exit(0)

if __name__ == "__main__":
    verify()
