#!/usr/bin/env python3
"""
Deterministic rebuilder for release/statistics.json and release/checksums.json.

Assumptions & Invariants:
  - Root directory is an explicit, trusted root directory.
  - Quiescent filesystem tree assumption: no concurrent modifications during execution.
  - Fail-closed bounded loaders: validates all mandatory inputs and outputs.
    Missing datasets, malformed JSON, symlinks, or non-regular files cause immediate abort.
  - Derives metadata provenance explicitly: release ID is derived from release/release.json,
    not blindly preserved from stale draft strings.
  - Complete statistics computation: computes records, anchors, chunks, joins, verdicts,
    file references, revision-verified records, corrections, sources, and privilege distribution.
  - Exact checksum manifest with hash substitution: derives the new statistics bytes and
    substitutes the hash for release/statistics.json before write or check.
    Subsequent runs produce byte-for-byte identical output.
  - Strictly offline: never accesses the network.
  - Preserves historical records (data/*): never mutates input datasets.

Usage:
  python3 tools/rebuild_release.py [--root PATH] [--check] [--verbose]
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Import safe loaders and validators from verify_public_export
try:
    from tools.verify_public_export import (
        EXCLUDED_DIRS,
        REQUIRED_DATA_FILES,
        REQUIRED_SCHEMA_FILES,
        get_public_inventory_files,
        is_strict_bool,
        is_strict_dict,
        is_strict_int,
        is_strict_list,
        is_strict_nonempty_str,
        is_strict_str,
        preflight_required_file,
        read_strict_jsonl,
        sha256_file,
        strict_json_loads,
        validate_safe_rel_path,
    )
except ImportError:
    from verify_public_export import (
        EXCLUDED_DIRS,
        REQUIRED_DATA_FILES,
        REQUIRED_SCHEMA_FILES,
        get_public_inventory_files,
        is_strict_bool,
        is_strict_dict,
        is_strict_int,
        is_strict_list,
        is_strict_nonempty_str,
        is_strict_str,
        preflight_required_file,
        read_strict_jsonl,
        sha256_file,
        strict_json_loads,
        validate_safe_rel_path,
    )


def preflight_rebuild_environment(root: Path):
    """
    Preflights mandatory inputs and output targets before performing any computation.
    Fails closed if inputs are missing, malformed, or if any input/output is a symlink.
    """
    # 1. release/release.json is mandatory
    preflight_required_file("release/release.json", root)

    # 2. All 6 schemas are mandatory
    for rel_schema in REQUIRED_SCHEMA_FILES:
        preflight_required_file(rel_schema, root)

    # 3. All 6 data files are mandatory
    for rel_data in REQUIRED_DATA_FILES:
        preflight_required_file(rel_data, root)

    # 4. Output paths check
    release_dir = root / "release"
    if os.path.islink(release_dir):
        raise ValueError(f"Output directory cannot be a symlink: {release_dir}")

    for out_name in ["release/statistics.json", "release/checksums.json"]:
        out_path = root / out_name
        if os.path.lexists(out_path):
            if os.path.islink(out_path):
                raise ValueError(f"Output target cannot be a symlink: {out_name}")
            st = os.lstat(out_path)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"Output target must be a regular file: {out_name}")


def compute_statistics(root: Path) -> Dict[str, Any]:
    """
    Computes exact, reproducible statistics from verified local datasets.
    Derives release version from release/release.json and claim IDs from data/claims.jsonl.
    """
    # 0. Preflight mandatory inputs
    preflight_rebuild_environment(root)

    # Syntax-check every input, including patterns and schemas that do not affect counts.
    for name in ["data/patterns.json", *REQUIRED_SCHEMA_FILES]:
        strict_json_loads((root / name).read_text(encoding="utf-8"), context=name)
    get_public_inventory_files(root)  # reject special files/symlinks before hashing or writing

    # 1. Read release metadata
    rel_path = root / "release/release.json"
    rel_data = strict_json_loads(rel_path.read_text(encoding="utf-8"), context="release/release.json")
    if not is_strict_dict(rel_data) or not is_strict_nonempty_str(rel_data.get("release_id")):
        raise ValueError("release/release.json missing valid 'release_id'")
    release_id = rel_data["release_id"]

    # 2. Process data/plugins.jsonl
    plugins_count = 0
    file_refs_count = 0
    rev_verified_count = 0
    chunk_prefixes: Set[str] = set()
    verdicts = {"broken": 0, "pass": 0, "suspicious": 0, "warning": 0}
    joins = {"directory_candidate": 0, "exact": 0, "unmatched": 0}
    privilege_counts = {"false": 0, "null": 0, "true": 0}

    plugins_file = root / "data/plugins.jsonl"
    plugins_records = read_strict_jsonl(plugins_file)
    for line_no, p in plugins_records:
        plugins_count += 1

        f_count = p.get("files_inspected_count", 0)
        if not is_strict_int(f_count) or f_count < 0:
            raise ValueError(f"plugins.jsonl:{line_no} invalid files_inspected_count: {f_count!r}")
        file_refs_count += f_count

        rev_ver = p.get("revision_verified")
        if not is_strict_bool(rev_ver):
            raise ValueError(f"plugins.jsonl:{line_no} invalid revision_verified: {rev_ver!r}")
        if rev_ver is True:
            rev_verified_count += 1

        rk = p.get("record_key", "")
        if not is_strict_nonempty_str(rk) or ":" not in rk:
            raise ValueError(f"plugins.jsonl:{line_no} missing valid record_key")
        chunk_prefixes.add(rk.split(":")[0])

        norm_v = p.get("verdict", {}).get("normalized")
        if norm_v in verdicts:
            verdicts[norm_v] += 1
        else:
            raise ValueError(f"plugins.jsonl:{line_no} unknown normalized verdict: {norm_v!r}")

        j = p.get("join")
        if j in joins:
            joins[j] += 1
        else:
            raise ValueError(f"plugins.jsonl:{line_no} unknown join enum: {j!r}")

        # Privilege tri-state
        priv = p.get("features", {}).get("privilege")
        if priv is True:
            privilege_counts["true"] += 1
        elif priv is False:
            privilege_counts["false"] += 1
        elif priv is None:
            privilege_counts["null"] += 1
        else:
            raise ValueError(f"plugins.jsonl:{line_no} invalid privilege value: {priv!r}")

    # 3. Process data/evidence.jsonl
    evidence_file = root / "data/evidence.jsonl"
    evidence_records = read_strict_jsonl(evidence_file)
    evidence_count = len(evidence_records)

    # 4. Process data/corrections.jsonl
    corrections_file = root / "data/corrections.jsonl"
    corrections_records = read_strict_jsonl(corrections_file)
    corrections_count = len(corrections_records)

    # 5. Process data/sources.jsonl
    sources_file = root / "data/sources.jsonl"
    sources_records = read_strict_jsonl(sources_file)
    sources_count = len(sources_records)

    # 6. Process data/claims.jsonl to map statistics pointers
    claims_file = root / "data/claims.jsonl"
    claims_records = read_strict_jsonl(claims_file)
    claim_ids: Dict[str, str] = {}
    for line_no, c in claims_records:
        cid = c.get("claim_id")
        src = c.get("source", {})
        if is_strict_dict(src) and src.get("file") == "release/statistics.json":
            json_path = src.get("json_path_or_section", "")
            if json_path.startswith("$."):
                stat_key = json_path[2:]
                claim_ids[stat_key] = cid

    # Historical provenance comes from explicit release metadata, never stale output.
    source_commit = rel_data.get("historical_source_commit")
    if source_commit is not None and (type(source_commit) is not str or not re.fullmatch(r"[0-9a-f]{40}", source_commit)):
        raise ValueError("release metadata historical_source_commit must be null or a full commit")

    stats: Dict[str, Any] = {
        "anchors": evidence_count,
        "chunks": len(chunk_prefixes),
        "claim_ids": dict(sorted(claim_ids.items())),
        "corrections": corrections_count,
        "files_inspected_references": file_refs_count,
        "joins": dict(sorted(joins.items())),
        "normalized_verdicts": dict(sorted(verdicts.items())),
        "privilege_distribution": dict(sorted(privilege_counts.items())),
        "records": plugins_count,
        "release": release_id,
        "revision_verified_records": rev_verified_count,
        "source_commit": source_commit,
        "sources": sources_count,
        "units_note": "Report records and explicit typed metadata; not verified source behavior.",
    }

    return dict(sorted(stats.items()))


def compute_checksums(root: Path, stats_bytes_override: Optional[bytes] = None) -> Dict[str, str]:
    """
    Computes SHA-256 checksums for all public inventory deliverable files.
    If stats_bytes_override is provided, its digest is used for release/statistics.json
    so that checksums reflect newly generated stats before writing to disk.
    """
    errors: List[str] = []
    public_files = get_public_inventory_files(root, errors=errors)
    if errors:
        raise ValueError(f"Path safety error during inventory walk: {errors[0]}")

    checksums: Dict[str, str] = {}
    stats_sha = hashlib.sha256(stats_bytes_override).hexdigest() if stats_bytes_override is not None else None

    for rel_file in sorted(public_files):
        if rel_file == "release/statistics.json" and stats_sha is not None:
            checksums[rel_file] = stats_sha
        else:
            full_path = root / rel_file
            checksums[rel_file] = sha256_file(full_path)

    # Ensure release/statistics.json is included even if not yet on disk
    if "release/statistics.json" not in checksums and stats_sha is not None:
        checksums["release/statistics.json"] = stats_sha

    return dict(sorted(checksums.items()))


def main():
    parser = argparse.ArgumentParser(
        description="Deterministically rebuild release/statistics.json and release/checksums.json."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Path to repository root (defaults to parent of tools/ directory).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check whether statistics.json and checksums.json match regenerated values without modifying files.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output.",
    )

    args = parser.parse_args()
    root = (args.root if args.root else Path(__file__).resolve().parents[1]).resolve()

    if args.verbose:
        print(f"[rebuild] Target root: {root}")

    # 1. Preflight environment (fails fast if inputs missing, bad, or symlinked)
    preflight_rebuild_environment(root)

    # 2. Compute statistics and serialize to exact canonical JSON bytes
    new_stats = compute_statistics(root)
    new_stats_str = json.dumps(new_stats, indent=2, sort_keys=True) + "\n"
    new_stats_bytes = new_stats_str.encode("utf-8")

    # 3. Compute checksums with the newly derived statistics hash substituted
    new_checksums = compute_checksums(root, stats_bytes_override=new_stats_bytes)
    new_checksums_str = json.dumps(new_checksums, indent=2, sort_keys=True) + "\n"
    new_checksums_bytes = new_checksums_str.encode("utf-8")

    stats_path = root / "release/statistics.json"
    checksums_path = root / "release/checksums.json"

    if args.check:
        mismatches = []
        if not stats_path.is_file():
            mismatches.append(f"Missing {stats_path}")
        else:
            current_stats_bytes = stats_path.read_bytes()
            if current_stats_bytes != new_stats_bytes:
                mismatches.append("release/statistics.json does not match rebuilt state")

        if not checksums_path.is_file():
            mismatches.append(f"Missing {checksums_path}")
        else:
            current_checksums_bytes = checksums_path.read_bytes()
            if current_checksums_bytes != new_checksums_bytes:
                mismatches.append("release/checksums.json does not match rebuilt state")

        if mismatches:
            print("FAIL: Check mode found mismatches:")
            for m in mismatches:
                print(f"  - {m}")
            raise SystemExit(1)
        else:
            print("OK: release/statistics.json and release/checksums.json are up to date.")
            raise SystemExit(0)

    # Normal write mode
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path.write_bytes(new_stats_bytes)
    checksums_path.write_bytes(new_checksums_bytes)

    print(
        f"SUCCESS: Deterministically rebuilt release/statistics.json and release/checksums.json ({len(new_checksums)} files hashed)."
    )


if __name__ == "__main__":
    main()
