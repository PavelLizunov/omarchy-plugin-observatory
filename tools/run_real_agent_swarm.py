#!/usr/bin/env python3
"""run_real_agent_swarm.py - Orchestrates a genuine 600-agent LLM swarm using gemini-3.8-flash-high via the AI Gateway.

Processes each of the 600 chunks (data/chunks/chunk_001.json ... chunk_600.json)
by sending it to an independent LLM agent instance for semantic line-by-line audit.
Saves structured JSON results to data/results_llm/result_chunk_XXX.json.

Features:
- Thread pool concurrency (16 parallel agent workers).
- Idempotency & resume support (skips already completed chunks).
- Automatic retry with exponential backoff on HTTP errors or rate limits.
- Robust JSON fence stripping and validation.
- Live progress reporting.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tools.agent_prompt_template import build_agent_prompt

CHUNKS_DIR = ROOT_DIR / "data" / "chunks"
RESULTS_DIR = ROOT_DIR / "data" / "results_llm"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
API_URL = "http://ai-gateway:8317/v1/chat/completions"
MODEL = "gemini-3.8-flash-high"
MAX_WORKERS = 16
MAX_RETRIES = 5


def clean_markdown_json(text: str) -> str:
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    return s.strip()


def process_chunk(chunk_path: Path) -> Dict[str, Any]:
    chunk_filename = chunk_path.name
    # Extract chunk_id from chunk_XXX.json
    m = re.search(r"chunk_(\d+)\.json", chunk_filename)
    if not m:
        return {"status": "error", "error": f"Invalid chunk filename: {chunk_filename}"}
    chunk_id = int(m.group(1))
    out_file = RESULTS_DIR / f"result_chunk_{chunk_id:03d}.json"

    # Resume capability: check if already completed
    if out_file.exists():
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if cached.get("records") and len(cached["records"]) > 0:
                return {
                    "status": "cached",
                    "chunk_id": chunk_id,
                    "records_count": len(cached["records"]),
                }
        except Exception:
            pass

    with open(chunk_path, "r", encoding="utf-8") as f:
        chunk_data = json.load(f)

    prompt = build_agent_prompt(chunk_data)

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
    }

    req_data = json.dumps(payload).encode("utf-8")

    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            t0 = time.time()
            req = urllib.request.Request(
                API_URL,
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": f"omarchy-swarm-agent-{chunk_id}"},
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                res_raw = json.load(resp)
            duration = time.time() - t0

            content = res_raw["choices"][0]["message"]["content"]
            cleaned = clean_markdown_json(content)
            parsed = json.loads(cleaned)

            # Ensure minimal required fields
            parsed["chunk_id"] = chunk_id
            if "issues_analyzed" not in parsed:
                parsed["issues_analyzed"] = len(parsed.get("records", []))

            # Write atomically to disk
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(parsed, f, ensure_ascii=False, indent=2)

            return {
                "status": "success",
                "chunk_id": chunk_id,
                "records_count": len(parsed.get("records", [])),
                "duration": duration,
            }

        except urllib.error.HTTPError as e:
            last_error = e
            if e.code in (429, 502, 503, 504):
                sleep_time = min(30, 2 ** attempt)
                time.sleep(sleep_time)
            else:
                time.sleep(3)
        except Exception as e:
            last_error = e
            time.sleep(min(20, 2 * attempt))

    return {
        "status": "failed",
        "chunk_id": chunk_id,
        "error": str(last_error),
    }


def main() -> int:
    chunk_files = sorted(CHUNKS_DIR.glob("chunk_*.json"))
    if not chunk_files:
        print(f"Error: No chunk files found in {CHUNKS_DIR}", file=sys.stderr)
        return 1

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    total_chunks = len(chunk_files)
    print("=" * 70)
    print(f"STARTING GENUINE LLM AGENT SWARM (600 AGENTS)")
    print(f"Model:           {MODEL}")
    print(f"API Target:      {API_URL}")
    print(f"Total Chunks:    {total_chunks}")
    print(f"Parallelism:     {MAX_WORKERS} concurrent agent workers")
    print(f"Results Dir:     {RESULTS_DIR}")
    print("=" * 70, flush=True)

    start_time = time.time()
    completed = 0
    cached = 0
    failed = 0
    total_records = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_chunk, cf): cf for cf in chunk_files}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            st = res.get("status")
            cid = res.get("chunk_id", 0)

            if st == "cached":
                cached += 1
                completed += 1
                total_records += res.get("records_count", 0)
                print(f"  [Cached]  Chunk #{cid:03d} already completed ({res.get('records_count')} records) [{completed}/{total_chunks}]", flush=True)
            elif st == "success":
                completed += 1
                rcnt = res.get("records_count", 0)
                dur = res.get("duration", 0.0)
                total_records += rcnt
                print(f"  [Success] Chunk #{cid:03d} audited by LLM agent in {dur:.2f}s ({rcnt} records) [{completed}/{total_chunks}]", flush=True)
            else:
                failed += 1
                print(f"  [FAILED]  Chunk #{cid:03d} failed: {res.get('error')}", flush=True)

    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"SWARM EXECUTION SUMMARY")
    print(f"Total time elapsed:  {elapsed:.1f}s ({elapsed/60:.2f} min)")
    print(f"Total chunks:        {total_chunks}")
    print(f"Successfully audited:{completed}")
    print(f"Cached runs skipped: {cached}")
    print(f"Failed chunks:       {failed}")
    print(f"Total issues records:{total_records}")
    print("=" * 70, flush=True)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
