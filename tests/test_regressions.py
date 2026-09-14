"""Coordinator regressions for concrete failures found during release repair."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from test_export import ExportFixtureBuilder, PROJECT_ROOT
from tools.verify_public_export import ExportVerifier, strict_json_loads
from tools.rebuild_release import compute_checksums, compute_statistics
from tools.migrate_review_records import run_migration


class ReleaseRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        ExportFixtureBuilder.create_valid_fixture(self.root)

    def verify(self):
        manifest = compute_checksums(self.root)
        (self.root / 'release/checksums.json').write_text(json.dumps(manifest))
        verifier = ExportVerifier(self.root)
        result = verifier.verify()
        return result, '\n'.join(verifier.errors)

    def test_overflow_number_is_not_silently_infinity(self):
        for value in ['1e9999', '-1e9999', '{"x":1e9999}']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                strict_json_loads(value)

    def test_blank_jsonl_line_fails(self):
        path = self.root / 'data/evidence.jsonl'
        path.write_text(path.read_text() + '\n')
        ok, errors = self.verify()
        self.assertFalse(ok)
        self.assertIn('Blank JSONL line', errors)

    def test_nonrequired_special_file_never_opened(self):
        if not hasattr(os, 'mkfifo'):
            self.skipTest('FIFO test requires POSIX')
        fifo = self.root / 'site/unexpected.txt'
        os.mkfifo(fifo)
        with patch.object(Path, 'read_text', side_effect=AssertionError('No content read before preflight')):
            verifier = ExportVerifier(self.root)
            self.assertFalse(verifier.verify())
        self.assertIn('Non-regular', '\n'.join(verifier.errors))

    def test_runtime_claim_cannot_point_to_arbitrary_file(self):
        path = self.root / 'data/claims.jsonl'
        claims = [json.loads(line) for line in path.read_text().splitlines()]
        for claim in claims:
            if claim['claim_id'] == 'CLM-METHOD-RUNTIME':
                claim['source'] = {'file': 'site/index.html', 'json_path_or_section': 'anything'}
        path.write_text(''.join(json.dumps(row) + '\n' for row in claims))
        ok, errors = self.verify()
        self.assertFalse(ok)
        self.assertIn('source pointer must be exactly', errors)

    def test_runtime_heading_not_fuzzy_word_match(self):
        (self.root / 'METHODOLOGY.md').write_text('# Scope\n# unrelated limitations\n')
        ok, errors = self.verify()
        self.assertFalse(ok)
        self.assertIn('target heading is missing', errors)

    def test_source_permalink_must_pin_full_revision(self):
        path = self.root / 'data/sources.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0]['files'][0]['url'] = rows[0]['files'][0]['url'].replace(rows[0]['revision'], 'main')
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        ok, errors = self.verify()
        self.assertFalse(ok)
        self.assertIn('file URL must match', errors)

    def test_unlinked_source_requires_explicit_external_context(self):
        path = self.root / 'data/sources.jsonl'
        row = json.loads(path.read_text().splitlines()[0])
        row['source_id'] = 'SRC-UNLINKED'
        row['record_ids'] = []
        with path.open('a') as output:
            output.write(json.dumps(row) + '\n')
        ok, errors = self.verify()
        self.assertFalse(ok)
        self.assertIn('empty record_ids require explicit external context', errors)

    def test_rebuild_rejects_malformed_noncounted_input(self):
        (self.root / 'data/patterns.json').write_text('not json')
        with self.assertRaises(ValueError):
            compute_statistics(self.root)

    def test_stale_output_does_not_control_provenance(self):
        meta = self.root / 'release/release.json'
        value = json.loads(meta.read_text())
        value['historical_source_commit'] = 'a' * 40
        meta.write_text(json.dumps(value))
        old = self.root / 'release/statistics.json'
        value = json.loads(old.read_text())
        value['source_commit'] = 'b' * 40
        old.write_text(json.dumps(value))
        self.assertEqual(compute_statistics(self.root)['source_commit'], 'a' * 40)

    def test_migration_late_validation_failure_writes_nothing(self):
        shutil.rmtree(self.root / 'data')
        shutil.copytree(PROJECT_ROOT / 'data', self.root / 'data')
        evidence = self.root / 'data/evidence.jsonl'
        evidence.write_text('not json\n')
        before = {p.name: p.read_bytes() for p in (self.root / 'data').iterdir()}
        with self.assertRaises(ValueError):
            run_migration(self.root)
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / 'data').iterdir()})

    def test_migration_rejects_symlink_inputs(self):
        shutil.rmtree(self.root / 'data')
        shutil.copytree(PROJECT_ROOT / 'data', self.root / 'data')
        target = self.root / 'data/plugins.jsonl'
        target.unlink()
        target.symlink_to(PROJECT_ROOT / 'data/plugins.jsonl')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            run_migration(self.root)


if __name__ == '__main__':
    unittest.main()
