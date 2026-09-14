#!/usr/bin/env python3
"""
tests/test_migration.py

Test suite for tools/migrate_review_records.py.
Verifies:
1. No-write validate/dry-run guarantees.
2. Idempotent migration execution.
3. Refusal of unknown references in source/correction ledgers.
4. Refusal of foreign/inconsistent existing review additions.
5. Historical immutability across all 3,086 plugins and 10,310 evidence records.
"""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.migrate_review_records import (
    load_canonical_ledgers,
    migrate_plugins,
    migrate_evidence,
    migrate_claims,
    run_migration,
)


def compute_file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestMigrationDryRun(unittest.TestCase):
    """Ensure dry-run and validate flags never write changes to disk."""

    def test_dry_run_leaves_files_unchanged(self):
        data_dir = ROOT / "data"
        targets = ["plugins.jsonl", "evidence.jsonl", "claims.jsonl", "sources.jsonl", "corrections.jsonl"]
        before_hashes = {t: compute_file_sha256(data_dir / t) for t in targets}

        result = run_migration(ROOT, dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["plugins"], 3086)
        self.assertEqual(result["evidence"], 10310)
        self.assertEqual(result["claims"], 13)

        after_hashes = {t: compute_file_sha256(data_dir / t) for t in targets}
        self.assertEqual(before_hashes, after_hashes, "dry_run=True modified files on disk!")

    def test_cli_dry_run_and_validate(self):
        cmd_dry = [sys.executable, str(ROOT / "tools" / "migrate_review_records.py"), "--dry-run"]
        proc_dry = subprocess.run(cmd_dry, capture_output=True, text=True)
        self.assertEqual(proc_dry.returncode, 0, f"CLI --dry-run failed: {proc_dry.stderr}")
        self.assertIn("Validation (no-write) SUCCESS", proc_dry.stdout)

        cmd_val = [sys.executable, str(ROOT / "tools" / "migrate_review_records.py"), "--validate"]
        proc_val = subprocess.run(cmd_val, capture_output=True, text=True)
        self.assertEqual(proc_val.returncode, 0, f"CLI --validate failed: {proc_val.stderr}")
        self.assertIn("Validation (no-write) SUCCESS", proc_val.stdout)


class TestMigrationIdempotency(unittest.TestCase):
    """Ensure repeatedly running migration produces identical results without clobbering."""

    def test_idempotent_execution(self):
        targets = ["plugins.jsonl", "evidence.jsonl", "claims.jsonl"]
        with tempfile.TemporaryDirectory(prefix="observatory-migration-idempotent-") as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "data", root / "data")
            run_migration(root, dry_run=False)
            first_hashes = {t: compute_file_sha256(root / "data" / t) for t in targets}
            run_migration(root, dry_run=False)
            second_hashes = {t: compute_file_sha256(root / "data" / t) for t in targets}
            self.assertEqual(first_hashes, second_hashes, "Migration is not idempotent!")


class TestUnknownRefsRefusal(unittest.TestCase):
    """Ensure migration refuses unknown references across ledgers."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="observatory-test-unknown-")
        self.test_root = Path(self.temp_dir.name)
        self.test_data = self.test_root / "data"
        self.test_data.mkdir(parents=True)

        # Copy original files
        for fname in ["sources.jsonl", "corrections.jsonl", "plugins.jsonl", "evidence.jsonl", "claims.jsonl"]:
            shutil.copy(ROOT / "data" / fname, self.test_data / fname)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_unknown_plugin_record_id_in_corrections(self):
        corr_file = self.test_data / "corrections.jsonl"
        corrs = [json.loads(line) for line in corr_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        corrs[0]["record_id"] = "plugin:chunk_9999-9@draft-nonexistent"
        corr_file.write_text("\n".join(json.dumps(c) for c in corrs) + "\n", encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            run_migration(self.test_root, dry_run=True)
        self.assertIn("unknown plugin record_id", str(ctx.exception))

    def test_unknown_evidence_id_in_corrections(self):
        corr_file = self.test_data / "corrections.jsonl"
        corrs = [json.loads(line) for line in corr_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        corrs[2]["evidence_ids"].append("EVD-CHUNK_9999-9-999")
        corr_file.write_text("\n".join(json.dumps(c) for c in corrs) + "\n", encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            run_migration(self.test_root, dry_run=True)
        self.assertIn("unknown evidence_id", str(ctx.exception))

    def test_unknown_source_id_in_corrections(self):
        corr_file = self.test_data / "corrections.jsonl"
        corrs = [json.loads(line) for line in corr_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        corrs[0]["source_ids"].append("SRC-NONEXISTENT-SOURCE-ID")
        corr_file.write_text("\n".join(json.dumps(c) for c in corrs) + "\n", encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            run_migration(self.test_root, dry_run=True)
        self.assertIn("unknown source_id", str(ctx.exception))

    def test_unknown_plugin_record_id_in_sources(self):
        src_file = self.test_data / "sources.jsonl"
        sources = [json.loads(line) for line in src_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        sources[0]["record_ids"].append("plugin:chunk_9999-9@draft-nonexistent")
        src_file.write_text("\n".join(json.dumps(s) for c in sources for s in [c]) + "\n", encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            run_migration(self.test_root, dry_run=True)
        self.assertIn("unknown plugin record_id", str(ctx.exception))


class TestForeignExistingReviewRefusal(unittest.TestCase):
    """Ensure migration refuses foreign or conflicting review fields instead of clobbering."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="observatory-test-foreign-")
        self.test_root = Path(self.temp_dir.name)
        self.test_data = self.test_root / "data"
        self.test_data.mkdir(parents=True)

        for fname in ["sources.jsonl", "corrections.jsonl", "plugins.jsonl", "evidence.jsonl", "claims.jsonl"]:
            shutil.copy(ROOT / "data" / fname, self.test_data / fname)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_foreign_plugin_review_status(self):
        plugins_file = self.test_data / "plugins.jsonl"
        lines = plugins_file.read_text(encoding="utf-8").splitlines()
        first_rec = json.loads(lines[0])
        first_rec["review"]["status"] = "unauthorized-foreign-pass"
        lines[0] = json.dumps(first_rec)
        plugins_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            run_migration(self.test_root, dry_run=True)
        self.assertIn("Foreign or inconsistent existing review", str(ctx.exception))

    def test_foreign_plugin_runtime_verified_flipped(self):
        plugins_file = self.test_data / "plugins.jsonl"
        lines = plugins_file.read_text(encoding="utf-8").splitlines()
        first_rec = json.loads(lines[0])
        first_rec["review"]["runtime_verified"] = True
        lines[0] = json.dumps(first_rec)
        plugins_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            run_migration(self.test_root, dry_run=True)
        self.assertIn("Foreign or inconsistent existing review", str(ctx.exception))

    def test_foreign_evidence_interpretation_status(self):
        ev_file = self.test_data / "evidence.jsonl"
        lines = ev_file.read_text(encoding="utf-8").splitlines()
        first_rec = json.loads(lines[0])
        first_rec["interpretation_status"] = "foreign-verified"
        lines[0] = json.dumps(first_rec)
        ev_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            run_migration(self.test_root, dry_run=True)
        self.assertIn("Foreign or inconsistent existing review fields", str(ctx.exception))


class TestHistoryImmutability(unittest.TestCase):
    """Ensure all historical values and booleans remain strictly preserved."""

    def test_historical_booleans_all_records(self):
        with open(ROOT / "data" / "plugins.jsonl", "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                rec = json.loads(line)
                self.assertIs(
                    rec.get("revision_verified"), False,
                    f"Plugin row {idx} ({rec.get('record_id')}) revision_verified must be False"
                )
                self.assertIs(
                    rec["verdict"].get("runtime_verified"), False,
                    f"Plugin row {idx} verdict.runtime_verified must be False"
                )
                self.assertIs(
                    rec["review"].get("runtime_verified"), False,
                    f"Plugin row {idx} review.runtime_verified must be False"
                )

        with open(ROOT / "data" / "evidence.jsonl", "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                rec = json.loads(line)
                self.assertIs(
                    rec.get("source_revision_verified"), False,
                    f"Evidence row {idx} ({rec.get('evidence_id')}) source_revision_verified must be False"
                )
                self.assertEqual(
                    rec.get("interpretation_status"), "historical-unverified",
                    f"Evidence row {idx} interpretation_status must be 'historical-unverified'"
                )

    def test_field_by_field_against_frozen_baseline(self):
        baseline = "a430cfa38ca8e8b32727cbfc661d6ff7b3f2a434"
        for name, additions in [("plugins", {"review"}),
                                ("evidence", {"interpretation_status", "correction_ids"})]:
            proc = subprocess.run(["git", "show", f"{baseline}:data/{name}.jsonl"],
                                  cwd=ROOT, capture_output=True, text=True)
            if proc.returncode != 0:
                self.skipTest("Frozen Git baseline unavailable (e.g. source archive); history comparison not verified")
            historical = [json.loads(line) for line in proc.stdout.splitlines()]
            current = [json.loads(line) for line in (ROOT / "data" / f"{name}.jsonl").read_text().splitlines()]
            self.assertEqual(len(historical), len(current))
            for idx, (old, new) in enumerate(zip(historical, current)):
                self.assertEqual(set(new) - set(old), additions)
                self.assertEqual({k: v for k, v in new.items() if k not in additions}, old,
                                 f"{name} row {idx}: historical fields changed")


if __name__ == "__main__":
    unittest.main()
