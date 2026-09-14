# Export and release tools

Run from the repository root. Python **3.9+** is required; base checks and migration use only the standard library. Schema verification is an explicit optional dependency. None of these Python tools fetches sources, executes snippets or installs packages automatically.

## Verify an export

```bash
python3 tools/verify_public_export.py
python3 tools/verify_public_export.py --schema
python3 tools/verify_public_export.py --root /path/to/export --schema
```

Exit 0 means the selected checks passed; exit 1 reports validation failures. CLI usage errors use argparse's exit 2. A checksum does not authenticate an author or establish the truth of a finding.

**Base mode:** strict JSON (duplicate keys, blank JSONL lines and nonfinite/out-of-range numbers rejected), required field/type checks, stable IDs and reciprocal ownership links, explicit null handling, typed metadata counts, exact claim pointers, required inventory and hashes. All six schemas must exist, parse and contain no reference-resolution keywords. This is **not a full JSON Schema implementation**.

**`--schema`:** all base checks plus Draft 2020-12 validation against all six schemas with `jsonschema`. An unavailable dependency is an error, not a skipped PASS. The schemas are intentionally self-contained: `$ref`, `$dynamicRef`, `$recursiveRef` and `$id` are unsupported, including local fragments. This prevents implicit resolver file/network access. Changing that contract requires review.

Optional isolated setup (requires package-network access only for installation):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r tools/requirements-validation.txt
.venv/bin/python tools/verify_public_export.py --schema
```

`jsonschema` 4.10.3 was available in the release-repair environment; the requirements file specifies the compatible 4.x range. No dependency installation is needed if your environment already provides it.

## Filesystem and trust boundary

Use a **trusted explicit root and a quiescent tree**: no concurrent modifications by an untrusted process. These tools are not a sandbox for an attacker who can race the filesystem or alter the verifier itself.

- Mandatory inputs and public file inventory are checked for symlinks/nonregular files before reading their contents. Symlink components, raw dot/dotdot, absolute and noncanonical manifest paths are rejected.
- The manifest must exactly cover the included public files. It excludes its own checksum, `.git`, `.dsh`, tests, `.venv`, `node_modules`, Python/tool caches and temporary editor artifacts. Public dotfiles are otherwise included. Run verification in a clean release checkout, not a directory containing unrelated private files.
- A limited pattern detects common private-machine path prefixes in included text. It is **not** a complete secret scanner or a guarantee that every sensitive value is removed.
- Source permalinks/hashes are structurally checked, not retrieved. Historical `source_report` labels are intentionally unavailable; they are not followed as local file references. Reported source behavior and quotation rights remain outside automatic verification.

## Rebuild derived artifacts

```bash
python3 tools/rebuild_release.py
python3 tools/rebuild_release.py --check
python3 tools/verify_public_export.py --schema
```

The builder derives `release/statistics.json` from data and explicit release metadata, then computes `release/checksums.json` using the new statistics bytes. Repeated runs on an unchanged tree are byte-identical. `--check` does not write and exits 1 for differences.

It rejects missing/malformed inputs and unsafe input/output paths. Unlike verification, missing statistics/checksums are allowed as **outputs to create**. It does not change historical records or make them accurate by recomputing hashes. Run the full verifier after rebuilding. Commit both derived files with their inputs; any later included-file edit requires rebuilding again.

## Historical repair migration

```bash
python3 tools/migrate_review_records.py --dry-run
python3 tools/migrate_review_records.py --validate
python3 tools/migrate_review_records.py
```

This is a guarded migration for the original 3,086/10,310 snapshot, not a general importer. `sources.jsonl` and `corrections.jsonl` are canonical ledgers. All transformations are validated before writes; existing inconsistent review additions are refused rather than overwritten. `--dry-run` and `--validate` perform no writes. There is no multi-file crash-atomic transaction: use version control and a quiescent tree to recover from an interrupted write. Later editorial additions should update reciprocal links explicitly, then use the verifier.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py' -v
node --test tests/site.test.cjs
```

Python tests use isolated writable fixtures. The historical comparison uses frozen commit `a430cfa38ca8e8b32727cbfc661d6ff7b3f2a434`, not current HEAD; a source archive lacking that commit reports the comparison skipped. Full schema tests require the optional dependency above.

Browser tests use Node **20+**, Playwright and Chromium as **development-only** tools. To install them in a disposable directory without changing runtime dependencies:

```bash
test_tools=$(mktemp -d)
npm install --prefix "$test_tools" playwright@1.62.1
PLAYWRIGHT_BROWSERS_PATH="$test_tools/browsers" "$test_tools/node_modules/.bin/playwright" install chromium
PLAYWRIGHT_BROWSERS_PATH="$test_tools/browsers" \
PLAYWRIGHT_MODULE="$test_tools/node_modules/playwright" \
node --test tests/browser.test.cjs
```

Installation needs network access and the browser's platform libraries. If already installed, set `PLAYWRIGHT_MODULE` to that installation and use its matching browser cache. Tests serve allowlisted local files through an ephemeral loopback server, exercise the actual page and close browser/server on completion. Screenshots go to ignored `.dsh/viewer-work/`. They do not start or replace a production server. Remove the disposable test-tools directory when no longer needed.

Browser coverage includes loading, empty/malformed statistics, language changes, request ordering, error recovery, text injection, local links, keyboard controls, 320px layout in EN/RU/DE/JA and declared palette contrast. This is not a complete accessibility audit, all-language linguistic review, or plugin runtime test.
