#!/usr/bin/env python3
"""
tools/migrate_review_records.py

Deterministic, idempotent, historical-preserving migration of Omarchy Plugin Observatory datasets.
Preserves all 3,086 plugin records and 10,310 evidence anchors field-for-field.
Reads data/sources.jsonl and data/corrections.jsonl as canonical sources-of-truth.
Attaches additive review and correction fields without altering historical verdicts or booleans.
Refuses inconsistent existing review fields or foreign unknown references instead of clobbering.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

try:
    from tools.verify_public_export import preflight_required_file, strict_json_loads
except ModuleNotFoundError:
    from verify_public_export import preflight_required_file, strict_json_loads

CLAIM_SOURCE_MAP = {
    "CLM-CORPUS-RECORDS": {"file": "release/statistics.json", "json_path_or_section": "$.records"},
    "CLM-CORPUS-CHUNKS": {"file": "release/statistics.json", "json_path_or_section": "$.chunks"},
    "CLM-CORPUS-ANCHORS": {"file": "release/statistics.json", "json_path_or_section": "$.anchors"},
    "CLM-CORPUS-FILE-REFERENCES": {"file": "release/statistics.json", "json_path_or_section": "$.files_inspected_references"},
    "CLM-VERDICT-PASS": {"file": "release/statistics.json", "json_path_or_section": "$.normalized_verdicts.pass"},
    "CLM-VERDICT-WARNING": {"file": "release/statistics.json", "json_path_or_section": "$.normalized_verdicts.warning"},
    "CLM-VERDICT-BROKEN": {"file": "release/statistics.json", "json_path_or_section": "$.normalized_verdicts.broken"},
    "CLM-VERDICT-SUSPICIOUS": {"file": "release/statistics.json", "json_path_or_section": "$.normalized_verdicts.suspicious"},
    "CLM-JOIN-EXACT": {"file": "release/statistics.json", "json_path_or_section": "$.joins.exact"},
    "CLM-JOIN-DIRECTORY-CANDIDATE": {"file": "release/statistics.json", "json_path_or_section": "$.joins.directory_candidate"},
    "CLM-JOIN-UNMATCHED": {"file": "release/statistics.json", "json_path_or_section": "$.joins.unmatched"},
    "CLM-SOURCE-REVISIONS": {"file": "release/statistics.json", "json_path_or_section": "$.revision_verified_records"},
    "CLM-METHOD-RUNTIME": {"file": "METHODOLOGY.md", "json_path_or_section": "METHODOLOGY.md#scope-and-limitations"}
}


def load_canonical_ledgers(data_dir: Path):
    """Load sources and corrections from canonical JSONL files and build lookup maps."""
    sources_file = data_dir / "sources.jsonl"
    corrections_file = data_dir / "corrections.jsonl"

    if not sources_file.is_file():
        raise FileNotFoundError(f"Canonical source ledger missing: {sources_file}")
    if not corrections_file.is_file():
        raise FileNotFoundError(f"Canonical correction ledger missing: {corrections_file}")

    sources_map = {}
    plugin_to_sources = {}
    for line_idx, line in enumerate(sources_file.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        src = strict_json_loads(line)
        sid = src.get("source_id")
        if not sid:
            raise ValueError(f"Source row {line_idx} missing source_id")
        if sid in sources_map:
            raise ValueError(f"Duplicate source_id in sources.jsonl: {sid}")
        sources_map[sid] = src
        for rid in src.get("record_ids", []):
            plugin_to_sources.setdefault(rid, set()).add(sid)

    corrections_map = {}
    plugin_to_corrections = {}
    evidence_to_corrections = {}
    for line_idx, line in enumerate(corrections_file.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        corr = strict_json_loads(line)
        cid = corr.get("correction_id")
        if not cid:
            raise ValueError(f"Correction row {line_idx} missing correction_id")
        if cid in corrections_map:
            raise ValueError(f"Duplicate correction_id in corrections.jsonl: {cid}")
        corrections_map[cid] = corr

        # Validate that referenced sources exist
        for sid in corr.get("source_ids", []):
            if sid not in sources_map:
                raise ValueError(f"Correction {cid} references unknown source_id: {sid}")

        rid = corr.get("record_id")
        if rid:
            plugin_to_corrections.setdefault(rid, set()).add(cid)

        for eid in corr.get("evidence_ids", []):
            evidence_to_corrections.setdefault(eid, set()).add(cid)

    return sources_map, corrections_map, plugin_to_sources, plugin_to_corrections, evidence_to_corrections


def migrate_plugins(data_dir: Path, plugin_to_sources, plugin_to_corrections, dry_run: bool = False):
    plugins_file = data_dir / "plugins.jsonl"
    if not plugins_file.is_file():
        raise FileNotFoundError(f"Missing {plugins_file}")

    lines = plugins_file.read_text(encoding="utf-8").splitlines()
    if len(lines) != 3086:
        raise ValueError(f"Expected exactly 3086 plugin records, got {len(lines)}")

    # First pass: collect all record_ids to validate ledger references
    existing_rids = set()
    records = []
    for line in lines:
        rec = strict_json_loads(line)
        if rec["record_id"] in existing_rids:
            raise ValueError(f"Duplicate record_id: {rec['record_id']}")
        existing_rids.add(rec["record_id"])
        records.append(rec)

    for rid in plugin_to_corrections:
        if rid not in existing_rids:
            raise ValueError(f"Correction references unknown plugin record_id: {rid}")
    for rid in plugin_to_sources:
        if rid not in existing_rids:
            raise ValueError(f"Source references unknown plugin record_id: {rid}")

    migrated_records = []
    required_baseline_keys = {
        "record_id", "record_key", "directory", "plugin_id", "manifest_author",
        "features", "category", "join", "verdict", "evidence_ids", "source_report",
        "limitations", "redactions", "files_inspected_count", "release",
        "revision_verified", "registry_commit"
    }

    for idx, rec in enumerate(records):
        for k in required_baseline_keys:
            if k not in rec:
                raise ValueError(f"Plugin {rec.get('record_id', idx)} missing required baseline key '{k}'")

        # Immutability invariant: historical flags must be false for ALL 3,086 records
        if rec["revision_verified"] is not False:
            raise ValueError(f"Plugin {rec['record_id']} historical revision_verified must remain False, got {rec['revision_verified']}")
        if rec["verdict"].get("runtime_verified") is not False:
            raise ValueError(f"Plugin {rec['record_id']} historical verdict.runtime_verified must remain False")

        rid = rec["record_id"]
        corr_ids = sorted(plugin_to_corrections.get(rid, []))
        src_ids = sorted(plugin_to_sources.get(rid, []))
        expected_status = "corrected-static-interpretation" if corr_ids else "historical-unverified"
        expected_review = {
            "status": expected_status,
            "correction_ids": corr_ids,
            "source_ids": src_ids,
            "runtime_verified": False
        }

        if "review" in rec:
            existing_review = rec["review"]
            if (existing_review.get("status") != expected_status or
                sorted(existing_review.get("correction_ids", [])) != corr_ids or
                sorted(existing_review.get("source_ids", [])) != src_ids or
                existing_review.get("runtime_verified") is not False):
                raise ValueError(
                    f"Foreign or inconsistent existing review on {rid}: "
                    f"found {existing_review}, expected {expected_review}"
                )
            migrated_records.append(rec)
        else:
            new_rec = copy.deepcopy(rec)
            new_rec["review"] = expected_review
            migrated_records.append(new_rec)

    if not dry_run:
        with plugins_file.open("w", encoding="utf-8") as f:
            for rec in migrated_records:
                f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    return len(migrated_records)


def migrate_evidence(data_dir: Path, evidence_to_corrections, dry_run: bool = False):
    evidence_file = data_dir / "evidence.jsonl"
    if not evidence_file.is_file():
        raise FileNotFoundError(f"Missing {evidence_file}")

    lines = evidence_file.read_text(encoding="utf-8").splitlines()
    if len(lines) != 10310:
        raise ValueError(f"Expected exactly 10310 evidence anchors, got {len(lines)}")

    existing_eids = set()
    records = []
    for line in lines:
        rec = strict_json_loads(line)
        if rec["evidence_id"] in existing_eids:
            raise ValueError(f"Duplicate evidence_id: {rec['evidence_id']}")
        existing_eids.add(rec["evidence_id"])
        records.append(rec)

    for eid in evidence_to_corrections:
        if eid not in existing_eids:
            raise ValueError(f"Correction references unknown evidence_id: {eid}")

    migrated_records = []
    required_baseline_keys = {
        "evidence_id", "record_id", "record_key", "file", "line",
        "snippet", "type", "proof", "proof_grade",
        "runtime_measurement_required", "source_revision_verified",
        "limitations", "source_report", "release"
    }

    for idx, rec in enumerate(records):
        for k in required_baseline_keys:
            if k not in rec:
                raise ValueError(f"Evidence {rec.get('evidence_id', idx)} missing required baseline key '{k}'")

        # Immutability invariant: historical flag must remain false for ALL 10,310 records
        if rec["source_revision_verified"] is not False:
            raise ValueError(f"Evidence {rec['evidence_id']} historical source_revision_verified must remain False")

        eid = rec["evidence_id"]
        corr_ids = sorted(evidence_to_corrections.get(eid, []))
        expected_status = "historical-unverified"

        has_interp = "interpretation_status" in rec
        has_corrs = "correction_ids" in rec

        if has_interp or has_corrs:
            existing_interp = rec.get("interpretation_status")
            existing_corrs = sorted(rec.get("correction_ids", []))
            if existing_interp != expected_status or existing_corrs != corr_ids:
                raise ValueError(
                    f"Foreign or inconsistent existing review fields on evidence {eid}: "
                    f"status={existing_interp}, corrections={existing_corrs}"
                )
            migrated_records.append(rec)
        else:
            new_rec = copy.deepcopy(rec)
            new_rec["interpretation_status"] = expected_status
            new_rec["correction_ids"] = corr_ids
            migrated_records.append(new_rec)

    if not dry_run:
        with evidence_file.open("w", encoding="utf-8") as f:
            for rec in migrated_records:
                f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    return len(migrated_records)


def migrate_claims(data_dir: Path, dry_run: bool = False):
    claims_file = data_dir / "claims.jsonl"
    if not claims_file.is_file():
        raise FileNotFoundError(f"Missing {claims_file}")

    lines = claims_file.read_text(encoding="utf-8").splitlines()
    if len(lines) != 13:
        raise ValueError(f"Expected exactly 13 claim records, got {len(lines)}")

    migrated_claims = []
    for line in lines:
        claim = strict_json_loads(line)
        cid = claim["claim_id"]
        if cid not in CLAIM_SOURCE_MAP:
            raise ValueError(f"Unknown claim_id: {cid}")
        expected_source = CLAIM_SOURCE_MAP[cid]
        if claim.get("source") != expected_source:
            new_claim = copy.deepcopy(claim)
            new_claim["source"] = expected_source
            migrated_claims.append(new_claim)
        else:
            migrated_claims.append(claim)

    if not dry_run:
        with claims_file.open("w", encoding="utf-8") as f:
            for c in migrated_claims:
                f.write(json.dumps(c, ensure_ascii=False, sort_keys=True) + "\n")

    return len(migrated_claims)


def run_migration(root: Path, dry_run: bool = False):
    root = root.resolve()
    data_dir = root / "data"
    for name in ["plugins", "evidence", "claims", "sources", "corrections"]:
        preflight_required_file(f"data/{name}.jsonl", root)
    sources_map, corrections_map, plugin_to_sources, plugin_to_corrections, evidence_to_corrections = (
        load_canonical_ledgers(data_dir)
    )

    # Validate every transformation first: bad evidence must not partially migrate plugins.
    n_plugins = migrate_plugins(data_dir, plugin_to_sources, plugin_to_corrections, dry_run=True)
    n_evidence = migrate_evidence(data_dir, evidence_to_corrections, dry_run=True)
    n_claims = migrate_claims(data_dir, dry_run=True)
    if not dry_run:
        # Quiescent tree required; use version control for recovery from an interrupted write.
        migrate_plugins(data_dir, plugin_to_sources, plugin_to_corrections, dry_run=False)
        migrate_evidence(data_dir, evidence_to_corrections, dry_run=False)
        migrate_claims(data_dir, dry_run=False)

    return {
        "sources": len(sources_map),
        "corrections": len(corrections_map),
        "plugins": n_plugins,
        "evidence": n_evidence,
        "claims": n_claims,
        "dry_run": dry_run
    }


def main():
    parser = argparse.ArgumentParser(description="Deterministic review records migration")
    parser.add_argument("--root", type=str, default=str(Path(__file__).resolve().parents[1]),
                        help="Project root directory")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate and simulate migration without writing changes to disk")
    parser.add_argument("--validate", action="store_true",
                        help="Validate consistency of existing ledgers without modifying files")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    dry_run = args.dry_run or args.validate

    try:
        results = run_migration(root, dry_run=dry_run)
        mode_str = "Validation (no-write)" if dry_run else "Migration"
        print(f"{mode_str} SUCCESS: {results['plugins']} plugins, {results['evidence']} evidence, "
              f"{results['claims']} claims, {results['sources']} sources, {results['corrections']} corrections.")
        return 0
    except Exception as exc:
        print(f"Migration FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
