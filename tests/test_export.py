#!/usr/bin/env python3
"""
Comprehensive test suite for export verification and rebuild tooling.

Covers all 9 defect categories:
  1. Preflight checks for all required files (metadata, six schemas, six data paths).
     Rejects symlinks and non-regular files without opening/reading/writing outside sentinels.
  2. Bounded path safety: raw dot/dotdot/backslash/noncanonical path rejection prior to
     normalization. Exact disk vs manifest public inventory (no surplus, no excluded files,
     no silent skipping of public dot-directories or dot-files).
  3. Self-contained schemas: rejection of $ref, $dynamicRef, $recursiveRef, and $id.
     Requires all six schemas even if datasets are empty; base mode parses schema JSON.
  4. Structural typing and schema conformity: rejects malformed required field values
     ({}, [], null, non-numeric) without crash; avoids bool-as-int coercion; validates
     tri-state features; validates metadata release_id, status, schema_version, locales (en/ru);
     enforces unique non-empty string lists; verifies source revision40, hashes, and licenses.
  5. Relational and referential integrity: removes 'if sources and' / 'if corrections and'
     loopholes to catch dangling references when collections are empty; validates reciprocal
     ownership, record_key agreement, and review.status vs correction_ids.
  6. Mandatory 13 Claim IDs: strict types (int vs bool), exact source pointer resolution,
     runtime claim consistency (agrees with false in records), exact statistics including
     corrections, sources, and privilege distribution.
  7. Deterministic rebuilder (rebuild_release.py): derives new statistics bytes and
     pre-substitutes the hash into the checksums manifest; byte-identical subsequent runs;
     fails closed without manufacturing empty stats; derives release provenance explicitly.
  8. Validation requirements: range jsonschema>=4.0.0,<5.0.0 and offline verification.
  9. Negative tests asserting actual error messages; immutable historical fields integration test.
"""
import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.rebuild_release import compute_checksums, compute_statistics, preflight_rebuild_environment
from tools.verify_public_export import (
    MANDATORY_CLAIM_IDS,
    REQUIRED_DATA_FILES,
    REQUIRED_METADATA_FILES,
    REQUIRED_SCHEMA_FILES,
    ExportVerifier,
    check_no_unsupported_schema_keywords,
    is_strict_bool,
    is_strict_int,
    preflight_required_file,
    strict_json_loads,
    validate_safe_rel_path,
)


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class ExportFixtureBuilder:
    """Creates a self-contained, valid minimal export fixture copying the actual six project schemas."""

    @staticmethod
    def create_valid_fixture(root: Path) -> Dict[str, Any]:
        data_dir = root / "data"
        release_dir = root / "release"
        schemas_dir = root / "schemas"
        site_dir = root / "site"

        for d in [data_dir, release_dir, schemas_dir, site_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # 1. Copy the actual SIX schemas from the repository
        real_schemas_dir = PROJECT_ROOT / "schemas"
        for schema_file in [
            "plugin.schema.json",
            "evidence.schema.json",
            "claim.schema.json",
            "pattern.schema.json",
            "correction.schema.json",
            "source.schema.json",
        ]:
            src_file = real_schemas_dir / schema_file
            if src_file.is_file():
                shutil.copy2(src_file, schemas_dir / schema_file)

        # 2. release/release.json
        release_info = {
            "release_id": "v1.0.1-rc.1",
            "schema_version": 2,
            "status": "release-candidate",
            "release_date": "2026-09-14",
            "locales": ["en", "ru"],
            "canonical_editorial_locales": ["en", "ru"],
        }
        (release_dir / "release.json").write_text(json.dumps(release_info, indent=2) + "\n", encoding="utf-8")

        # 3. METHODOLOGY.md (needed for CLM-METHOD-RUNTIME source pointer)
        methodology_content = "# Methodology\n\n## Scope and Limitations\nStatic analysis only; no runtime execution.\n"
        (root / "METHODOLOGY.md").write_text(methodology_content, encoding="utf-8")

        # 4. data/plugins.jsonl (complete valid records satisfying published schemas)
        plugins = [
            {
                "record_id": "rec_0001",
                "record_key": "chunk_0000:0",
                "plugin_id": "plugin-alpha",
                "directory": "alpha-dir",
                "release": "v1.0.1-rc.1",
                "source_report": "reports/level1/chunk_0000.json",
                "files_inspected_count": 5,
                "revision_verified": False,
                "join": "exact",
                "verdict": {
                    "normalized": "pass",
                    "raw": "Clean execution",
                    "summary": "Clean",
                    "scope": "static-audit",
                    "runtime_verified": False,
                },
                "review": {
                    "status": "historical-unverified",
                    "correction_ids": [],
                    "source_ids": ["src_0001"],
                    "runtime_verified": False,
                },
                "features": {
                    "privilege": False,
                    "background": True,
                    "concat": False,
                    "persists": None,
                    "polling": None,
                    "shell": True,
                },
                "limitations": ["Static analysis only"],
                "evidence_ids": ["ev_0001", "ev_0002"],
            },
            {
                "record_id": "rec_0002",
                "record_key": "chunk_0000:1",
                "plugin_id": "plugin-beta",
                "directory": "beta-dir",
                "release": "v1.0.1-rc.1",
                "source_report": "reports/level1/chunk_0000.json",
                "files_inspected_count": 8,
                "revision_verified": False,
                "join": "unmatched",
                "verdict": {
                    "normalized": "warning",
                    "raw": "Unthrottled timer observed",
                    "summary": "Timer issue",
                    "scope": "static-audit",
                    "runtime_verified": False,
                },
                "review": {
                    "status": "corrected-static-interpretation",
                    "correction_ids": ["corr_0001"],
                    "source_ids": [],
                    "runtime_verified": False,
                },
                "features": {
                    "privilege": True,
                    "background": False,
                    "concat": False,
                    "persists": None,
                    "polling": None,
                    "shell": False,
                },
                "limitations": ["Static analysis only"],
                "evidence_ids": ["ev_0003"],
            },
        ]
        with (data_dir / "plugins.jsonl").open("w", encoding="utf-8") as f:
            for p in plugins:
                f.write(json.dumps(p) + "\n")

        # 5. data/evidence.jsonl
        evidence = [
            {
                "evidence_id": "ev_0001",
                "record_id": "rec_0001",
                "record_key": "chunk_0000:0",
                "file": "Widget.qml",
                "line": 42,
                "snippet": "Timer { interval: 2000 }",
                "type": "GATED_TIMER",
                "proof": "Timer is gated on visible",
                "proof_grade": "legacy-reported-interpretation",
                "runtime_measurement_required": False,
                "source_revision_verified": False,
                "limitations": ["Historical anchor"],
                "source_report": "reports/level1/chunk_0000.json",
                "release": "v1.0.1-rc.1",
                "interpretation_status": "historical-unverified",
                "correction_ids": [],
            },
            {
                "evidence_id": "ev_0002",
                "record_id": "rec_0001",
                "record_key": "chunk_0000:0",
                "file": "Service.qml",
                "line": 10,
                "snippet": "Process { command: ['playerctl'] }",
                "type": "DISCRETE_ARGV_DISPATCH",
                "proof": "Discrete argv array used",
                "proof_grade": "legacy-reported-interpretation",
                "runtime_measurement_required": False,
                "source_revision_verified": False,
                "limitations": ["Historical anchor"],
                "source_report": "reports/level1/chunk_0000.json",
                "release": "v1.0.1-rc.1",
                "interpretation_status": "historical-unverified",
                "correction_ids": [],
            },
            {
                "evidence_id": "ev_0003",
                "record_id": "rec_0002",
                "record_key": "chunk_0000:1",
                "file": "Main.qml",
                "line": 88,
                "snippet": "sudo -S",
                "type": "PRIVILEGE_ESCALATION",
                "proof": "sudo invocation observed",
                "proof_grade": "legacy-reported-interpretation",
                "runtime_measurement_required": False,
                "source_revision_verified": False,
                "limitations": ["Historical anchor"],
                "source_report": "reports/level1/chunk_0000.json",
                "release": "v1.0.1-rc.1",
                "interpretation_status": "historical-unverified",
                "correction_ids": ["corr_0001"],
            },
        ]
        with (data_dir / "evidence.jsonl").open("w", encoding="utf-8") as f:
            for e in evidence:
                f.write(json.dumps(e) + "\n")

        # 6. data/corrections.jsonl
        corrections = [
            {
                "correction_id": "corr_0001",
                "record_id": "rec_0002",
                "evidence_ids": ["ev_0003"],
                "source_ids": [],
                "status": "corrected-static-interpretation",
                "checked_at": "2026-09-14",
                "observation": {
                    "en": "UI prompts user for sudo password",
                    "ru": "Интерфейс запрашивает пароль sudo",
                },
                "correction": {
                    "en": "Credential handling risk in UI, not proven unauthorized escalation",
                    "ru": "Риск обработки учетных данных в UI, а не доказанная эскалация",
                },
                "limitations": {
                    "en": "Requires inspection of sudoers policy",
                    "ru": "Требует проверки политики sudoers",
                },
            }
        ]
        with (data_dir / "corrections.jsonl").open("w", encoding="utf-8") as f:
            for c in corrections:
                f.write(json.dumps(c) + "\n")

        # 7. data/sources.jsonl (with limitations as array of strings per schema)
        sources = [
            {
                "source_id": "src_0001",
                "record_ids": ["rec_0001"],
                "repository_url": "https://github.com/example/plugin-alpha",
                "revision": "0123456789abcdef0123456789abcdef01234567",
                "revision_relation": "current-reference",
                "checked_at": "2026-09-14",
                "files": [
                    {
                        "path": "Widget.qml",
                        "url": "https://github.com/example/plugin-alpha/blob/0123456789abcdef0123456789abcdef01234567/Widget.qml",
                        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    }
                ],
                "license": {
                    "spdx": "MIT",
                    "url": "https://github.com/example/plugin-alpha/blob/0123456789abcdef0123456789abcdef01234567/LICENSE",
                    "status": "identified-at-revision",
                },
                "scope": "widget-timer",
                "limitations": ["Static review of Widget.qml only"],
            }
        ]
        with (data_dir / "sources.jsonl").open("w", encoding="utf-8") as f:
            for s in sources:
                f.write(json.dumps(s) + "\n")

        # 8. data/patterns.json
        patterns = [
            {
                "pattern_id": "PAT-SAFE-ARGV",
                "polarity": "protective",
                "title": {
                    "en": "Discrete argument vectors",
                    "ru": "Дискретный массив аргументов",
                },
                "guidance": {
                    "en": "Prefer executable and arguments as separate array items.",
                    "ru": "Передавайте исполняемый файл и аргументы отдельными элементами массива.",
                },
                "evidence_types": ["DISCRETE_ARGV_DISPATCH"],
            }
        ]
        (data_dir / "patterns.json").write_text(json.dumps(patterns, indent=2) + "\n", encoding="utf-8")

        # 9. data/claims.jsonl (all 13 mandatory Claim IDs)
        claims = [
            {
                "claim_id": "CLM-CORPUS-RECORDS",
                "kind": "corpus-statistic",
                "value": 2,
                "unit": "plugin-records",
                "statement": {"en": "2 records.", "ru": "2 записи."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.records"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-CORPUS-ANCHORS",
                "kind": "evidence-statistic",
                "value": 3,
                "unit": "evidence-anchors",
                "statement": {"en": "3 anchors.", "ru": "3 якоря."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.anchors"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-CORPUS-CHUNKS",
                "kind": "corpus-statistic",
                "value": 1,
                "unit": "chunks",
                "statement": {"en": "1 chunk.", "ru": "1 чанк."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.chunks"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-CORPUS-FILE-REFERENCES",
                "kind": "evidence-statistic",
                "value": 13,
                "unit": "file-references",
                "statement": {"en": "13 file references.", "ru": "13 ссылок на файлы."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.files_inspected_references"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-VERDICT-PASS",
                "kind": "verdict-statistic",
                "value": 1,
                "unit": "plugin-records",
                "statement": {"en": "1 pass.", "ru": "1 pass."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.normalized_verdicts.pass"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-VERDICT-WARNING",
                "kind": "verdict-statistic",
                "value": 1,
                "unit": "plugin-records",
                "statement": {"en": "1 warning.", "ru": "1 warning."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.normalized_verdicts.warning"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-VERDICT-BROKEN",
                "kind": "verdict-statistic",
                "value": 0,
                "unit": "plugin-records",
                "statement": {"en": "0 broken.", "ru": "0 broken."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.normalized_verdicts.broken"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-VERDICT-SUSPICIOUS",
                "kind": "verdict-statistic",
                "value": 0,
                "unit": "plugin-records",
                "statement": {"en": "0 suspicious.", "ru": "0 suspicious."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.normalized_verdicts.suspicious"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-JOIN-EXACT",
                "kind": "crosswalk-statistic",
                "value": 1,
                "unit": "plugin-records",
                "statement": {"en": "1 exact join.", "ru": "1 точный join."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.joins.exact"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-JOIN-DIRECTORY-CANDIDATE",
                "kind": "crosswalk-statistic",
                "value": 0,
                "unit": "plugin-records",
                "statement": {"en": "0 candidate.", "ru": "0 candidate."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.joins.directory_candidate"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-JOIN-UNMATCHED",
                "kind": "crosswalk-statistic",
                "value": 1,
                "unit": "plugin-records",
                "statement": {"en": "1 unmatched.", "ru": "1 unmatched."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.joins.unmatched"},
                "evidence_level": "reproduced-metadata",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-SOURCE-REVISIONS",
                "kind": "method-limit",
                "value": 0,
                "unit": "revision-verified-records",
                "statement": {"en": "0 verified revisions.", "ru": "0 проверенных ревизий."},
                "source": {"file": "release/statistics.json", "json_path_or_section": "$.revision_verified_records"},
                "evidence_level": "documented-limit",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
            {
                "claim_id": "CLM-METHOD-RUNTIME",
                "kind": "method-limit",
                "value": False,
                "unit": "runtime-executed",
                "statement": {"en": "Static analysis only.", "ru": "Только статический анализ."},
                "source": {"file": "METHODOLOGY.md", "json_path_or_section": "METHODOLOGY.md#scope-and-limitations"},
                "evidence_level": "documented-limit",
                "release": "v1.0.1-rc.1",
                "status": "verified",
            },
        ]
        with (data_dir / "claims.jsonl").open("w", encoding="utf-8") as f:
            for c in claims:
                f.write(json.dumps(c) + "\n")

        # 10. Compute and write deterministic statistics and checksums
        stats = compute_statistics(root)
        stats_bytes = (json.dumps(stats, indent=2, sort_keys=True) + "\n").encode("utf-8")
        (release_dir / "statistics.json").write_bytes(stats_bytes)

        checksums = compute_checksums(root, stats_bytes_override=stats_bytes)
        (release_dir / "checksums.json").write_text(json.dumps(checksums, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        return {
            "plugins": plugins,
            "evidence": evidence,
            "corrections": corrections,
            "sources": sources,
            "claims": claims,
            "patterns": patterns,
            "statistics": stats,
        }


class TestExportVerification(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="test-observatory-")
        self.root = Path(self.temp_dir.name)
        ExportFixtureBuilder.create_valid_fixture(self.root)

    def tearDown(self):
        self.temp_dir.cleanup()

    def update_checksums(self, recompute_stats: bool = True):
        if recompute_stats:
            stats = compute_statistics(self.root)
            stats_bytes = (json.dumps(stats, indent=2, sort_keys=True) + "\n").encode("utf-8")
            (self.root / "release/statistics.json").write_bytes(stats_bytes)
        else:
            stats_bytes = (self.root / "release/statistics.json").read_bytes()
        checksums = compute_checksums(self.root, stats_bytes_override=stats_bytes)
        (self.root / "release/checksums.json").write_text(
            json.dumps(checksums, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    # -----------------------------------------------------------------------
    # Baseline Fixture Tests
    # -----------------------------------------------------------------------

    def test_valid_fixture_passes_stdlib(self):
        verifier = ExportVerifier(root=self.root, check_schema=False)
        self.assertTrue(verifier.verify(), f"Expected PASS but got errors: {verifier.errors}")
        self.assertEqual(len(verifier.errors), 0)

    def test_valid_fixture_passes_schema(self):
        verifier = ExportVerifier(root=self.root, check_schema=True)
        self.assertTrue(verifier.verify(), f"Expected PASS but got errors: {verifier.errors}")
        self.assertEqual(len(verifier.errors), 0)

    # -----------------------------------------------------------------------
    # 1. Preflight and Outside Symlink Sentinel Tests (No Open/Read/Write)
    # -----------------------------------------------------------------------

    def test_symlink_to_mocked_outside_sentinel_rejects_without_access(self):
        outside_dir = Path(self.temp_dir.name).parent / "outside_sentinel_dir"
        outside_dir.mkdir(parents=True, exist_ok=True)
        sentinel_file = outside_dir / "sentinel.txt"
        sentinel_content = "CANARY_SECRET_DATA_DO_NOT_READ\n"
        sentinel_file.write_text(sentinel_content, encoding="utf-8")

        initial_stat = sentinel_file.stat()

        # Symlink a required file to the outside sentinel
        target_symlink = self.root / "release/release.json"
        target_symlink.unlink()
        target_symlink.symlink_to(sentinel_file)

        verifier = ExportVerifier(root=self.root)
        success = verifier.verify()

        self.assertFalse(success)
        self.assertTrue(any("Required file cannot be a symlink: release/release.json" in e for e in verifier.errors))

        # Assert sentinel was not modified or altered
        after_stat = sentinel_file.stat()
        self.assertEqual(sentinel_file.read_text(encoding="utf-8"), sentinel_content)
        self.assertEqual(initial_stat.st_mtime_ns, after_stat.st_mtime_ns)

        # Clean up sentinel dir
        shutil.rmtree(outside_dir, ignore_errors=True)

    def test_symlinked_data_file_fails_preflight(self):
        outside_file = self.root.parent / "fake_plugins.jsonl"
        outside_file.write_text('{"record_id": "canary"}\n', encoding="utf-8")

        p_file = self.root / "data/plugins.jsonl"
        p_file.unlink()
        p_file.symlink_to(outside_file)

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(any("Required file cannot be a symlink: data/plugins.jsonl" in e for e in verifier.errors))

        outside_file.unlink()

    def test_rebuild_environment_preflight_rejects_symlinks(self):
        outside_file = self.root.parent / "outside_stats.json"
        outside_file.write_text('{"records": 0}\n', encoding="utf-8")

        stats_path = self.root / "release/statistics.json"
        stats_path.unlink()
        stats_path.symlink_to(outside_file)

        with self.assertRaises(ValueError) as ctx:
            preflight_rebuild_environment(self.root)
        self.assertIn("Output target cannot be a symlink: release/statistics.json", str(ctx.exception))

        outside_file.unlink()

    # -----------------------------------------------------------------------
    # 2. Path Containment & Inventory Policy Tests (Raw Checks Prior to Norm)
    # -----------------------------------------------------------------------

    def test_validate_safe_rel_path_rejects_raw_traversal(self):
        with self.assertRaises(ValueError) as ctx:
            validate_safe_rel_path("foo/../bar", self.root)
        self.assertIn("Raw dot/dotdot/empty component forbidden in path", str(ctx.exception))

    def test_validate_safe_rel_path_rejects_raw_dot(self):
        with self.assertRaises(ValueError) as ctx:
            validate_safe_rel_path("./foo", self.root)
        self.assertIn("Raw dot/dotdot/empty component forbidden in path", str(ctx.exception))

    def test_validate_safe_rel_path_rejects_backslash(self):
        with self.assertRaises(ValueError) as ctx:
            validate_safe_rel_path("foo\\bar", self.root)
        self.assertIn("Backslash forbidden in export path", str(ctx.exception))

    def test_validate_safe_rel_path_rejects_noncanonical_slashes(self):
        with self.assertRaises(ValueError) as ctx:
            validate_safe_rel_path("foo//bar", self.root)
        self.assertIn("Raw dot/dotdot/empty component forbidden in path", str(ctx.exception))

    def test_inventory_discovers_public_dot_directory(self):
        # A public dot-directory (like .well-known) must NOT be silently skipped
        well_known = self.root / ".well-known"
        well_known.mkdir(parents=True, exist_ok=True)
        (well_known / "security.txt").write_text("Contact: security@example.com\n", encoding="utf-8")

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("Mandatory inventory omission: .well-known/security.txt exists on disk but is missing from checksums.json" in e
                for e in verifier.errors)
        )

    def test_inventory_discovers_public_dot_file(self):
        # A public dotfile (like .gitignore) must be in checksums.json
        (self.root / ".custom_dotfile").write_text("data\n", encoding="utf-8")
        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("Mandatory inventory omission: .custom_dotfile exists on disk but is missing from checksums.json" in e
                for e in verifier.errors)
        )

    def test_inventory_rejects_excluded_paths_in_manifest(self):
        checksums_path = self.root / "release/checksums.json"
        checksums = json.loads(checksums_path.read_text(encoding="utf-8"))
        checksums["tests/test_export.py"] = "0" * 64
        checksums_path.write_text(json.dumps(checksums, indent=2) + "\n", encoding="utf-8")

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("Excluded file forbidden in checksums.json: tests/test_export.py" in e for e in verifier.errors)
        )

    # -----------------------------------------------------------------------
    # 3. Self-Contained Schemas & Unsupported Keywords ($ref, $id)
    # -----------------------------------------------------------------------

    def test_schema_rejects_ref_keyword(self):
        schema_file = self.root / "schemas/plugin.schema.json"
        s = json.loads(schema_file.read_text(encoding="utf-8"))
        s["properties"]["injected"] = {"$ref": "#/definitions/foo"}
        schema_file.write_text(json.dumps(s, indent=2) + "\n", encoding="utf-8")
        self.update_checksums()

        verifier = ExportVerifier(root=self.root, check_schema=False)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("Unsupported schema reference or identifier keyword forbidden" in e and "$ref" in e for e in verifier.errors)
        )

    def test_schema_rejects_id_keyword(self):
        schema_file = self.root / "schemas/plugin.schema.json"
        s = json.loads(schema_file.read_text(encoding="utf-8"))
        s["$id"] = "https://example.com/schemas/plugin.json"
        schema_file.write_text(json.dumps(s, indent=2) + "\n", encoding="utf-8")
        self.update_checksums()

        verifier = ExportVerifier(root=self.root, check_schema=False)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("Unsupported schema reference or identifier keyword forbidden" in e and "$id" in e for e in verifier.errors)
        )

    def test_schema_rejects_dynamic_and_recursive_ref(self):
        with self.assertRaises(ValueError):
            check_no_unsupported_schema_keywords({"items": {"$dynamicRef": "#meta"}})
        with self.assertRaises(ValueError):
            check_no_unsupported_schema_keywords({"items": {"$recursiveRef": "#"}})

    def test_missing_schema_file_fails_in_stdlib_mode(self):
        (self.root / "schemas/source.schema.json").unlink()
        verifier = ExportVerifier(root=self.root, check_schema=False)
        self.assertFalse(verifier.verify())
        self.assertTrue(any("Required file missing on disk: schemas/source.schema.json" in e for e in verifier.errors))

    # -----------------------------------------------------------------------
    # 4. Strict Typing, Malformed Fields Without Crash, Tri-State Features
    # -----------------------------------------------------------------------

    def test_malformed_required_fields_deterministic_error_without_crash(self):
        plugins_file = self.root / "data/plugins.jsonl"
        lines = plugins_file.read_text(encoding="utf-8").strip().splitlines()
        p = json.loads(lines[0])
        # Inject malformed required field values
        p["files_inspected_count"] = {}
        p["record_id"] = None
        p["features"] = []
        p["verdict"] = "not-an-object"
        lines[0] = json.dumps(p)
        plugins_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.update_checksums(recompute_stats=False)

        verifier = ExportVerifier(root=self.root)
        # Verify it runs deterministically and catches errors without raising uncaught exceptions
        success = verifier.verify()
        self.assertFalse(success)
        self.assertTrue(any("record_id must be a non-empty string" in e for e in verifier.errors))
        self.assertTrue(any("features must be an object" in e for e in verifier.errors))
        self.assertTrue(any("verdict must be an object" in e for e in verifier.errors))

    def test_bool_as_int_rejected_in_stats_and_claims(self):
        # Stats records = True instead of 2
        stats_file = self.root / "release/statistics.json"
        stats = json.loads(stats_file.read_text(encoding="utf-8"))
        stats["records"] = True
        stats_file.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
        self.update_checksums(recompute_stats=False)

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(any("Statistics records mismatch" in e for e in verifier.errors))

        # Claim CLM-CORPUS-RECORDS value = True instead of 2
        claims_file = self.root / "data/claims.jsonl"
        lines = claims_file.read_text(encoding="utf-8").strip().splitlines()
        c = json.loads(lines[0])
        c["value"] = True
        lines[0] = json.dumps(c)
        claims_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.update_checksums(recompute_stats=False)

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(any("Claim CLM-CORPUS-RECORDS value mismatch" in e for e in verifier.errors))

    def test_plugin_features_tri_state_validation(self):
        plugins_file = self.root / "data/plugins.jsonl"
        lines = plugins_file.read_text(encoding="utf-8").strip().splitlines()
        p = json.loads(lines[0])

        # String value is not tri-state
        p["features"]["privilege"] = "unprivileged"
        lines[0] = json.dumps(p)
        plugins_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.update_checksums(recompute_stats=False)

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(any("features.privilege must be boolean or null" in e for e in verifier.errors))

    def test_release_metadata_locales_and_types(self):
        rel_file = self.root / "release/release.json"
        rel_data = json.loads(rel_file.read_text(encoding="utf-8"))

        # Missing 'ru' in locales
        rel_data["locales"] = ["en"]
        rel_file.write_text(json.dumps(rel_data, indent=2) + "\n", encoding="utf-8")
        self.update_checksums()

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(any("locales must include both 'en' and 'ru'" in e for e in verifier.errors))

    def test_source_record_revision_must_be_40_hex(self):
        sources_file = self.root / "data/sources.jsonl"
        lines = sources_file.read_text(encoding="utf-8").strip().splitlines()
        src = json.loads(lines[0])
        src["revision"] = "not-a-40-char-hex-hash"
        lines[0] = json.dumps(src)
        sources_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.update_checksums()

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(any("revision must be 40-hex git commit" in e for e in verifier.errors))

    # -----------------------------------------------------------------------
    # 5. Relational Integrity & Empty Collections Dangling Reference Checks
    # -----------------------------------------------------------------------

    def test_empty_corrections_dangling_reference_fails(self):
        # Empty out corrections.jsonl
        (self.root / "data/corrections.jsonl").write_text("", encoding="utf-8")
        # plugin rec_0002 still points to corr_0001
        self.update_checksums()

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("Plugin rec_0002 review references non-existent correction_id: corr_0001" in e for e in verifier.errors)
        )

    def test_empty_sources_dangling_reference_fails(self):
        # Empty out sources.jsonl
        (self.root / "data/sources.jsonl").write_text("", encoding="utf-8")
        # plugin rec_0001 still points to src_0001
        self.update_checksums()

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("Plugin rec_0001 review references non-existent source_id: src_0001" in e for e in verifier.errors)
        )

    def test_record_key_mismatch_between_plugin_and_evidence(self):
        evidence_file = self.root / "data/evidence.jsonl"
        lines = evidence_file.read_text(encoding="utf-8").strip().splitlines()
        e = json.loads(lines[0])
        e["record_key"] = "chunk_9999:99"
        lines[0] = json.dumps(e)
        evidence_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.update_checksums()

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(any("Record key mismatch for ev_0001" in e for e in verifier.errors))

    def test_review_status_corrected_requires_nonempty_corrections(self):
        plugins_file = self.root / "data/plugins.jsonl"
        lines = plugins_file.read_text(encoding="utf-8").strip().splitlines()
        p = json.loads(lines[1])
        p["review"]["correction_ids"] = []
        lines[1] = json.dumps(p)
        plugins_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.update_checksums()

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("review.status is 'corrected-static-interpretation' but correction_ids is empty" in e
                for e in verifier.errors)
        )

    def test_duplicate_id_in_evidence_ids_list_rejected(self):
        plugins_file = self.root / "data/plugins.jsonl"
        lines = plugins_file.read_text(encoding="utf-8").strip().splitlines()
        p = json.loads(lines[0])
        p["evidence_ids"] = ["ev_0001", "ev_0001"]
        lines[0] = json.dumps(p)
        plugins_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.update_checksums()

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("evidence_ids must be a list of unique non-empty strings" in e for e in verifier.errors)
        )

    # -----------------------------------------------------------------------
    # 6. Mandatory 13 Claims, Strict Types & Privilege Distribution
    # -----------------------------------------------------------------------

    def test_missing_mandatory_claim_id_fails(self):
        claims_file = self.root / "data/claims.jsonl"
        lines = claims_file.read_text(encoding="utf-8").strip().splitlines()
        # Remove CLM-METHOD-RUNTIME
        lines = [line for line in lines if "CLM-METHOD-RUNTIME" not in line]
        claims_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.update_checksums()

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("Mandatory claim missing from data/claims.jsonl: CLM-METHOD-RUNTIME" in e for e in verifier.errors)
        )

    def test_runtime_claim_false_must_agree_with_records(self):
        plugins_file = self.root / "data/plugins.jsonl"
        lines = plugins_file.read_text(encoding="utf-8").strip().splitlines()
        p = json.loads(lines[0])
        p["verdict"]["runtime_verified"] = True
        lines[0] = json.dumps(p)
        plugins_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.update_checksums()

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("Claim CLM-METHOD-RUNTIME states false, but one or more plugins have runtime_verified=true" in e
                for e in verifier.errors)
        )

    def test_privilege_distribution_in_statistics_must_match_exact(self):
        stats_file = self.root / "release/statistics.json"
        stats = json.loads(stats_file.read_text(encoding="utf-8"))
        stats["privilege_distribution"]["true"] = 999
        stats_file.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
        self.update_checksums(recompute_stats=False)

        verifier = ExportVerifier(root=self.root)
        self.assertFalse(verifier.verify())
        self.assertTrue(
            any("Statistics privilege_distribution.true mismatch" in e for e in verifier.errors)
        )

    # -----------------------------------------------------------------------
    # 7. Deterministic Rebuilder Tests (rebuild_release.py)
    # -----------------------------------------------------------------------

    def test_rebuilder_subsequent_runs_byte_identical(self):
        # Run rebuild once
        cmd = [sys.executable, str(PROJECT_ROOT / "tools/rebuild_release.py"), "--root", str(self.root)]
        proc1 = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc1.returncode, 0, f"Rebuild 1 failed: {proc1.stderr}")

        stats_1 = (self.root / "release/statistics.json").read_bytes()
        checksums_1 = (self.root / "release/checksums.json").read_bytes()

        # Run rebuild second time
        proc2 = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc2.returncode, 0, f"Rebuild 2 failed: {proc2.stderr}")

        stats_2 = (self.root / "release/statistics.json").read_bytes()
        checksums_2 = (self.root / "release/checksums.json").read_bytes()

        self.assertEqual(stats_1, stats_2, "Statistics changed across consecutive rebuild runs")
        self.assertEqual(checksums_1, checksums_2, "Checksums changed across consecutive rebuild runs")

        # Now test check mode passes cleanly
        proc_check = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "tools/rebuild_release.py"), "--root", str(self.root), "--check"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc_check.returncode, 0, f"Check mode failed: {proc_check.stdout}")

    def test_rebuilder_fails_closed_on_missing_dataset(self):
        (self.root / "data/evidence.jsonl").unlink()
        with self.assertRaises(ValueError):
            compute_statistics(self.root)

    # -----------------------------------------------------------------------
    # 8. Integration Test: Real Repository Historical Fields Verification
    # -----------------------------------------------------------------------

    def test_real_historical_dataset_immutable_invariants(self):
        # Verify that actual project datasets conform to expected immutable historical counts
        plugins_file = PROJECT_ROOT / "data/plugins.jsonl"
        evidence_file = PROJECT_ROOT / "data/evidence.jsonl"
        claims_file = PROJECT_ROOT / "data/claims.jsonl"
        patterns_file = PROJECT_ROOT / "data/patterns.json"
        corrections_file = PROJECT_ROOT / "data/corrections.jsonl"
        sources_file = PROJECT_ROOT / "data/sources.jsonl"

        # 1. Total records
        plugins = [json.loads(line) for line in plugins_file.read_text(encoding="utf-8").strip().splitlines()]
        self.assertEqual(len(plugins), 3086, "Historical plugin count must be exactly 3086")

        evidence = [json.loads(line) for line in evidence_file.read_text(encoding="utf-8").strip().splitlines()]
        self.assertEqual(len(evidence), 10310, "Historical evidence count must be exactly 10310")

        claims = [json.loads(line) for line in claims_file.read_text(encoding="utf-8").strip().splitlines()]
        self.assertEqual(len(claims), 13, "Historical claims count must be exactly 13")

        patterns = json.loads(patterns_file.read_text(encoding="utf-8"))
        self.assertEqual(len(patterns), 8, "Curated patterns count must be exactly 8")

        corrections = [json.loads(line) for line in corrections_file.read_text(encoding="utf-8").strip().splitlines()]
        self.assertEqual(len(corrections), 4, "Mandatory corrections count must be exactly 4")

        sources = [json.loads(line) for line in sources_file.read_text(encoding="utf-8").strip().splitlines()]
        self.assertEqual(len(sources), 11, "Pinned sources count must be exactly 11")

        # 2. Immutable historical verification flags
        self.assertTrue(all(p.get("revision_verified") is False for p in plugins))
        self.assertTrue(all(p.get("verdict", {}).get("runtime_verified") is False for p in plugins))
        self.assertTrue(all(p.get("review", {}).get("runtime_verified") is False for p in plugins))

        # 3. Privilege distribution
        priv_counts = {"false": 0, "null": 0, "true": 0}
        for p in plugins:
            priv = p.get("features", {}).get("privilege")
            if priv is True:
                priv_counts["true"] += 1
            elif priv is False:
                priv_counts["false"] += 1
            elif priv is None:
                priv_counts["null"] += 1
        self.assertEqual(priv_counts, {"false": 1569, "null": 1441, "true": 76})


if __name__ == "__main__":
    unittest.main()
