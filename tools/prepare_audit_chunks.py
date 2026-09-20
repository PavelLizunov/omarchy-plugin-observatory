#!/usr/bin/env python3
"""prepare_audit_chunks.py - Shard the marketplace SQLite corpus into 600 balanced JSON chunks for parallel agent analysis.

Reads issues and comments from data/corpus/marketplace_corpus.db, groups comments by issue,
and splits the issues into 600 JSON files:
data/chunks/chunk_001.json ... data/chunks/chunk_600.json
"""

from __future__ import annotations

import json
import math
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "corpus" / "marketplace_corpus.db"
CHUNKS_DIR = Path(__file__).resolve().parent.parent / "data" / "chunks"
NUM_CHUNKS = 600


def main() -> int:
    if not DB_PATH.exists():
        print(f"Error: Database file does not exist: {DB_PATH}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    print("Loading comments from database...", flush=True)
    comments_by_issue: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    cur = conn.cursor()
    cur.execute("SELECT issue_number, user, created_at, body FROM comments ORDER BY id ASC")
    for r in cur:
        comments_by_issue[r["issue_number"]].append({
            "author": r["user"],
            "created_at": r["created_at"],
            "body": r["body"] or "",
        })

    print(f"Loaded comments for {len(comments_by_issue)} distinct issues.", flush=True)

    print("Loading issues from database...", flush=True)
    cur.execute("SELECT number, title, state, user, created_at, closed_at, labels, body FROM issues ORDER BY number ASC")
    issues: List[Dict[str, Any]] = []
    for r in cur:
        try:
            labels = json.loads(r["labels"]) if r["labels"] else []
        except Exception:
            labels = []
        num = r["number"]
        issues.append({
            "number": num,
            "title": r["title"] or "",
            "state": r["state"] or "",
            "author": r["user"] or "",
            "created_at": r["created_at"] or "",
            "closed_at": r["closed_at"] or "",
            "labels": labels,
            "body": r["body"] or "",
            "comments": comments_by_issue.get(num, []),
        })

    total_issues = len(issues)
    print(f"Total issues loaded: {total_issues}", flush=True)
    if total_issues == 0:
        print("No issues found in database.", file=sys.stderr)
        return 1

    CHUNKS_DIR.mkdir(parents=True, exist_ok=True)
    chunk_size = math.ceil(total_issues / NUM_CHUNKS)
    print(f"Partitioning into {NUM_CHUNKS} chunks (~{chunk_size} issues per chunk)...", flush=True)

    chunks_manifest = []
    for chunk_id in range(1, NUM_CHUNKS + 1):
        start_idx = (chunk_id - 1) * chunk_size
        end_idx = min(start_idx + chunk_size, total_issues)
        chunk_items = issues[start_idx:end_idx] if start_idx < total_issues else []

        chunk_filename = f"chunk_{chunk_id:03d}.json"
        chunk_filepath = CHUNKS_DIR / chunk_filename

        chunk_data = {
            "chunk_id": chunk_id,
            "total_chunks": NUM_CHUNKS,
            "issues_count": len(chunk_items),
            "start_issue_number": chunk_items[0]["number"] if chunk_items else None,
            "end_issue_number": chunk_items[-1]["number"] if chunk_items else None,
            "issues": chunk_items,
        }

        with open(chunk_filepath, "w", encoding="utf-8") as f:
            json.dump(chunk_data, f, ensure_ascii=False, indent=2)

        chunks_manifest.append({
            "chunk_id": chunk_id,
            "filename": chunk_filename,
            "issues_count": len(chunk_items),
            "start_issue": chunk_items[0]["number"] if chunk_items else None,
            "end_issue": chunk_items[-1]["number"] if chunk_items else None,
        })

    index_path = CHUNKS_DIR / "chunks_index.json"
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_issues": total_issues,
            "total_chunks": NUM_CHUNKS,
            "chunk_size": chunk_size,
            "chunks": chunks_manifest,
        }, f, indent=2)

    print(f"Successfully generated {NUM_CHUNKS} chunks in {CHUNKS_DIR}!")
    print(f"Index written to {index_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
