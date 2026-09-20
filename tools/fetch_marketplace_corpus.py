#!/usr/bin/env python3
"""fetch_marketplace_corpus.py - High-speed batch ingestion of all marketplace issues and comments into SQLite.

Uses authenticated GitHub API token via `gh auth token` to fetch:
1. All ~7,740 issues and PRs (paginated at 100/page).
2. All repository comments across all issues (paginated at 100/page).

Stores results in data/corpus/marketplace_corpus.db.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "corpus" / "marketplace_corpus.db"
REPO = "omacom/omarchy-plugin-marketplace"


def get_gh_token() -> str:
    try:
        return subprocess.check_output(["gh", "auth", "token"], text=True).strip()
    except Exception as e:
        print(f"Error getting gh auth token: {e}", file=sys.stderr)
        sys.exit(1)


def init_db(db_file: Path) -> sqlite3.Connection:
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_file)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS issues (
            number INTEGER PRIMARY KEY,
            title TEXT,
            state TEXT,
            user TEXT,
            created_at TEXT,
            closed_at TEXT,
            labels TEXT,
            body TEXT,
            raw_json TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            issue_number INTEGER,
            user TEXT,
            created_at TEXT,
            body TEXT,
            raw_json TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_comments_issue ON comments(issue_number)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_issues_state ON issues(state)")
    conn.commit()
    return conn


def api_request(url: str, token: str, retries: int = 5) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "omarchy-plugin-observatory-crawler")

    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                data = json.loads(resp.read().decode("utf-8"))
                return data, headers
        except urllib.error.HTTPError as e:
            if e.code == 422:
                # GitHub returns 422 when reaching the pagination limit (e.g. page > 300)
                return [], {}
            elif e.code in (403, 429):
                reset_time = int(e.headers.get("x-ratelimit-reset", time.time() + 60))
                sleep_sec = max(1, reset_time - int(time.time())) + 2
                print(f"[RateLimit] HTTP {e.code}, waiting {sleep_sec}s until reset...", flush=True)
                time.sleep(sleep_sec)
            elif e.code >= 500:
                print(f"[HTTP {e.code}] Retrying attempt {attempt}/{retries} in 5s...", flush=True)
                time.sleep(5)
            else:
                raise
        except Exception as e:
            if attempt == retries:
                raise
            print(f"[Network Error: {e}] Retrying attempt {attempt}/{retries} in 3s...", flush=True)
            time.sleep(3)
    return [], {}


def fetch_all_issues(conn: sqlite3.Connection, token: str) -> int:
    print("\n--- Phase 1: Fetching all issues and pull requests ---", flush=True)
    page = 1
    total_saved = 0

    while True:
        url = f"https://api.github.com/repos/{REPO}/issues?state=all&per_page=100&page={page}"
        items, headers = api_request(url, token)
        if not items:
            print(f"Page {page} returned empty list. Finished fetching issues.", flush=True)
            break

        remaining = headers.get("x-ratelimit-remaining", "?")
        with conn:
            for it in items:
                num = it.get("number")
                title = it.get("title", "")
                state = it.get("state", "")
                user = it.get("user", {}).get("login", "") if it.get("user") else ""
                created_at = it.get("created_at", "")
                closed_at = it.get("closed_at", "")
                labels = json.dumps([lb.get("name") for lb in it.get("labels", []) if isinstance(lb, dict)])
                body = it.get("body", "") or ""
                raw = json.dumps(it)
                conn.execute(
                    "INSERT OR REPLACE INTO issues (number, title, state, user, created_at, closed_at, labels, body, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (num, title, state, user, created_at, closed_at, labels, body, raw),
                )
                total_saved += 1

        print(f"  [Issues] Page {page:3d} fetched {len(items):3d} items (Saved total: {total_saved:5d}, API remaining: {remaining})", flush=True)
        if len(items) < 100:
            print(f"Page {page} returned fewer than 100 items ({len(items)}). Finished fetching issues.", flush=True)
            break
        page += 1
        time.sleep(0.3)

    return total_saved


def fetch_all_comments(conn: sqlite3.Connection, token: str) -> int:
    print("\n--- Phase 2: Fetching all repository issue comments ---", flush=True)
    page = 1
    total_saved = 0

    while True:
        url = f"https://api.github.com/repos/{REPO}/issues/comments?per_page=100&page={page}"
        items, headers = api_request(url, token)
        if not items:
            print(f"Page {page} returned empty list. Finished fetching comments.", flush=True)
            break

        remaining = headers.get("x-ratelimit-remaining", "?")
        with conn:
            for it in items:
                cid = it.get("id")
                issue_url = it.get("issue_url", "")
                try:
                    issue_num = int(issue_url.rstrip("/").split("/")[-1])
                except (ValueError, IndexError):
                    issue_num = 0
                user = it.get("user", {}).get("login", "") if it.get("user") else ""
                created_at = it.get("created_at", "")
                body = it.get("body", "") or ""
                raw = json.dumps(it)
                conn.execute(
                    "INSERT OR REPLACE INTO comments (id, issue_number, user, created_at, body, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
                    (cid, issue_num, user, created_at, body, raw),
                )
                total_saved += 1

        print(f"  [Comments] Page {page:3d} fetched {len(items):3d} comments (Saved total: {total_saved:5d}, API remaining: {remaining})", flush=True)
        if len(items) < 100:
            print(f"Page {page} returned fewer than 100 items ({len(items)}). Finished fetching comments.", flush=True)
            break
        page += 1
        time.sleep(0.3)

    return total_saved


def main() -> int:
    token = get_gh_token()
    conn = init_db(DB_PATH)
    start_time = time.time()

    total_issues = fetch_all_issues(conn, token)
    total_comments = fetch_all_comments(conn, token)

    elapsed = time.time() - start_time
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM issues")
    db_issues = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM comments")
    db_comments = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT issue_number) FROM comments")
    issues_with_comments = cur.fetchone()[0]

    print("\n" + "=" * 60)
    print("INGESTION COMPLETE SUMMARY")
    print("=" * 60)
    print(f"Time elapsed:           {elapsed:.1f}s")
    print(f"Total issues in DB:     {db_issues}")
    print(f"Total comments in DB:   {db_comments}")
    print(f"Issues with comments:   {issues_with_comments}")
    print(f"Database location:      {DB_PATH}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
