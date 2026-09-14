#!/usr/bin/env python3
"""
Strict standalone verifier for the Omarchy Plugin Observatory public export.

Assumptions & Invariants:
  - Root directory is an explicit, trusted root directory.
  - Quiescent filesystem tree assumption: no concurrent racing modifications
    by untrusted processes during verification.
  - Fail-fast preflight: all mandatory metadata files, all six schemas, and
    all six data files are preflighted before ANY reads or joins. Symlinks
    and non-regular files are rejected completely without target reads.
  - Strict bounded path containment: rejects absolute paths, directory
    traversals (..), raw dot components, backslashes, non-canonical representations,
    and symlink escapes BEFORE normalization.
  - Mandatory public inventory: exact disk vs manifest matching with zero
    omissions and zero excluded files in the manifest. Public dot-directories
    and dot-files are not silently skipped unless explicitly excluded.
  - Strict RFC 8259 JSON compliance: rejects non-finite constants and duplicate keys.
  - Self-contained schemas: rejects $ref, $dynamicRef, $recursiveRef, and $id
    completely with clear unsupported-reference errors. Zero remote resolver retrieval.
  - Strict stdlib typing: never coerces bool to int (in datasets, stats, or claims).
    Enforces tri-state features (bool or null) and preserves null for nullable fields.
  - Complete relational & referential integrity: bidirectional links, matching record_key,
    review.status vs correction_ids agreement, and zero tolerance for dangling
    references even when collections are empty.
  - Claims & Statistics: all 13 mandatory Claim IDs verified with exact source pointer
    resolution, strict types, runtime claim consistency, and exact stats including
    corrections, sources, and privilege distribution.

Usage:
  python3 tools/verify_public_export.py [--root PATH] [--schema] [--verbose]
"""
import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from datetime import date
from urllib.parse import quote
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

EXCLUDED_DIRS: Set[str] = {
    ".git",
    ".dsh",
    "__pycache__",
    "node_modules",
    ".venv",
    "tests",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

TEXT_EXTENSIONS: Set[str] = {
    ".md",
    ".json",
    ".jsonl",
    ".html",
    ".css",
    ".js",
    ".py",
    ".cff",
    ".txt",
    ".jsonld",
}

PRIVATE_PATH_REGEX = re.compile(
    r"(?<![A-Za-z0-9._~-])/(?:home|Users|var/lib/dsh)(?=[/\s'\"\\\\]|$)",
    re.IGNORECASE,
)

HEX_SHA256_REGEX = re.compile(r"^[0-9a-f]{64}$")
HEX_REVISION40_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")
URL_REGEX = re.compile(r"^https?://[^\s]+$")
DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")

FORBIDDEN_SCHEMA_KEYWORDS = {"$ref", "$dynamicRef", "$recursiveRef", "$id"}

REQUIRED_METADATA_FILES = [
    "release/release.json",
    "release/statistics.json",
    "release/checksums.json",
]

REQUIRED_SCHEMA_FILES = [
    "schemas/plugin.schema.json",
    "schemas/evidence.schema.json",
    "schemas/claim.schema.json",
    "schemas/pattern.schema.json",
    "schemas/correction.schema.json",
    "schemas/source.schema.json",
]

REQUIRED_DATA_FILES = [
    "data/plugins.jsonl",
    "data/evidence.jsonl",
    "data/claims.jsonl",
    "data/patterns.json",
    "data/corrections.jsonl",
    "data/sources.jsonl",
]

MANDATORY_CLAIM_IDS = [
    "CLM-CORPUS-RECORDS",
    "CLM-CORPUS-CHUNKS",
    "CLM-CORPUS-ANCHORS",
    "CLM-CORPUS-FILE-REFERENCES",
    "CLM-VERDICT-PASS",
    "CLM-VERDICT-WARNING",
    "CLM-VERDICT-BROKEN",
    "CLM-VERDICT-SUSPICIOUS",
    "CLM-JOIN-EXACT",
    "CLM-JOIN-DIRECTORY-CANDIDATE",
    "CLM-JOIN-UNMATCHED",
    "CLM-SOURCE-REVISIONS",
    "CLM-METHOD-RUNTIME",
]


STAT_CLAIM_PATHS = {
    "CLM-CORPUS-RECORDS": "records",
    "CLM-CORPUS-CHUNKS": "chunks",
    "CLM-CORPUS-ANCHORS": "anchors",
    "CLM-CORPUS-FILE-REFERENCES": "files_inspected_references",
    "CLM-VERDICT-PASS": "normalized_verdicts.pass",
    "CLM-VERDICT-WARNING": "normalized_verdicts.warning",
    "CLM-VERDICT-BROKEN": "normalized_verdicts.broken",
    "CLM-VERDICT-SUSPICIOUS": "normalized_verdicts.suspicious",
    "CLM-JOIN-EXACT": "joins.exact",
    "CLM-JOIN-DIRECTORY-CANDIDATE": "joins.directory_candidate",
    "CLM-JOIN-UNMATCHED": "joins.unmatched",
    "CLM-SOURCE-REVISIONS": "revision_verified_records",
}


# Strict JSON parser: reject duplicate keys and nonfinite/out-of-range numbers.

def _reject_constant(constant: str):
    raise ValueError(f"Non-finite JSON number constant not permitted in RFC 8259 export: {constant!r}")


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    d: Dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"Duplicate JSON object key: {k!r}")
        d[k] = v
    return d


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"JSON number exceeds finite floating-point range: {value}")
    return number


def strict_json_loads(s: str, context: str = "") -> Any:
    try:
        return json.loads(
            s,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except Exception as e:
        ctx = f" in {context}" if context else ""
        raise ValueError(f"Malformed or non-compliant JSON{ctx}: {e}") from e


def read_strict_jsonl(path: Path) -> List[Tuple[int, Dict[str, Any]]]:
    records: List[Tuple[int, Dict[str, Any]]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str:
                raise ValueError(f"Blank JSONL line at {path.name}:{line_no}")
            data = strict_json_loads(line_str, context=f"{path.name}:{line_no}")
            if not isinstance(data, dict):
                raise ValueError(f"Expected JSON object at {path.name}:{line_no}, got {type(data).__name__}")
            records.append((line_no, data))
    return records


# ---------------------------------------------------------------------------
# Strict Type Checking Helpers (preventing bool-as-int and type confusion)
# ---------------------------------------------------------------------------

def is_strict_int(val: Any) -> bool:
    return type(val) is int


def is_strict_bool(val: Any) -> bool:
    return type(val) is bool


def is_strict_str(val: Any) -> bool:
    return type(val) is str


def is_strict_nonempty_str(val: Any) -> bool:
    return type(val) is str and len(val.strip()) > 0


def is_strict_list(val: Any) -> bool:
    return type(val) is list


def is_strict_dict(val: Any) -> bool:
    return type(val) is dict


def is_unique_nonempty_str_list(val: Any) -> bool:
    if not is_strict_list(val):
        return False
    seen = set()
    for item in val:
        if not is_strict_nonempty_str(item) or item in seen:
            return False
        seen.add(item)
    return True


# ---------------------------------------------------------------------------
# Path Containment & Bounded Root Safety
# ---------------------------------------------------------------------------

def validate_safe_rel_path(rel_path_str: str, root: Path) -> Path:
    """
    Validates that rel_path_str is a safe, strictly relative path contained within root.
    Rejects raw dot (.), dotdot (..), backslash (\\), and noncanonical paths BEFORE normalization.
    Rejects absolute paths, null bytes, and symlink components.
    Never reads through a symlink.
    """
    if not is_strict_str(rel_path_str) or not rel_path_str or "\0" in rel_path_str:
        raise ValueError(f"Invalid path string: {rel_path_str!r}")

    if "\\" in rel_path_str:
        raise ValueError(f"Backslash forbidden in export path: {rel_path_str!r}")

    if (
        os.path.isabs(rel_path_str)
        or rel_path_str.startswith("/")
        or re.match(r"^[a-zA-Z]:", rel_path_str)
    ):
        raise ValueError(f"Absolute path forbidden in export manifest: {rel_path_str!r}")

    parts = rel_path_str.split("/")
    for part in parts:
        if part == "" or part == "." or part == "..":
            raise ValueError(f"Raw dot/dotdot/empty component forbidden in path: {rel_path_str!r}")

    norm = os.path.normpath(rel_path_str).replace("\\", "/")
    if norm != rel_path_str:
        raise ValueError(f"Non-canonical path forbidden: {rel_path_str!r} (canonical is {norm!r})")

    root_resolved = root.resolve()
    curr = root
    for idx, part in enumerate(parts):
        curr = curr / part
        if os.path.islink(curr):
            if idx == len(parts) - 1:
                raise ValueError(f"Required file cannot be a symlink: {rel_path_str}")
            raise ValueError(f"Symlink forbidden in path component: {rel_path_str!r} at {curr}")

    try:
        curr.resolve().relative_to(root_resolved)
    except ValueError:
        raise ValueError(f"Target path escapes root boundary: {rel_path_str!r}")

    return curr


def preflight_required_file(rel_path_str: str, root: Path) -> Path:
    """
    Preflights a required file:
      - Validates that rel_path_str is safe and strictly relative to root
      - Verifies no path component is a symlink
      - Verifies the file itself exists and is a regular file (never a symlink, dir, socket, or fifo)
    Fails fast without opening or reading the file.
    """
    target = validate_safe_rel_path(rel_path_str, root)
    if not os.path.lexists(target):
        raise ValueError(f"Required file missing on disk: {rel_path_str}")
    if os.path.islink(target):
        raise ValueError(f"Required file cannot be a symlink: {rel_path_str}")
    st = os.lstat(target)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"Required file must be a regular file: {rel_path_str}")
    return target


def is_temporary_file(filename: str) -> bool:
    if filename.endswith("~") or filename.endswith(".swp") or filename == ".DS_Store":
        return True
    if filename.endswith(".pyc") or filename.endswith(".pyo"):
        return True
    return False


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_public_inventory_files(root: Path, errors: Optional[List[str]] = None) -> Set[str]:
    """
    Walks root and discovers all public deliverable files.
    Excludes strictly EXCLUDED_DIRS and temporary artifacts.
    Public dot-directories (e.g. .well-known) are NOT silently skipped.
    Public dot-files (e.g. .gitignore) are NOT silently skipped.
    Rejects symlinks and non-regular files during traversal.
    """
    public_files: Set[str] = set()

    def walk_error(error):
        raise ValueError(f"Cannot enumerate public inventory: {error}")

    for dirpath, dirnames, filenames in os.walk(root, onerror=walk_error):
        filtered_dirs = []
        for d in dirnames:
            if d in EXCLUDED_DIRS:
                continue
            dir_full = Path(dirpath) / d
            if os.path.islink(dir_full):
                msg = f"Symlink directory forbidden in export: {dir_full}"
                if errors is not None:
                    errors.append(msg)
                else:
                    raise ValueError(msg)
                continue
            filtered_dirs.append(d)
        dirnames[:] = filtered_dirs

        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""

        for filename in filenames:
            if is_temporary_file(filename):
                continue
            rel_file = f"{rel_dir}/{filename}" if rel_dir else filename
            if rel_file == "release/checksums.json":
                continue

            full_file = Path(dirpath) / filename
            if os.path.islink(full_file):
                msg = f"Symlink file forbidden in public inventory: {rel_file}"
                if errors is not None:
                    errors.append(msg)
                else:
                    raise ValueError(msg)
                continue

            st = os.lstat(full_file)
            if not stat.S_ISREG(st.st_mode):
                msg = f"Non-regular file forbidden in public inventory: {rel_file}"
                if errors is not None:
                    errors.append(msg)
                else:
                    raise ValueError(msg)
                continue

            public_files.add(rel_file)

    return public_files


# ---------------------------------------------------------------------------
# Self-Contained Schema Validator (Rejection of $ref, $dynamicRef, $recursiveRef, $id)
# ---------------------------------------------------------------------------

def check_no_unsupported_schema_keywords(schema_obj: Any, path: str = ""):
    if isinstance(schema_obj, dict):
        for k, v in schema_obj.items():
            if k in FORBIDDEN_SCHEMA_KEYWORDS:
                loc = path or "/"
                raise ValueError(
                    f"Unsupported schema reference or identifier keyword forbidden in self-contained schema: {k!r} at {loc}"
                )
            check_no_unsupported_schema_keywords(v, f"{path}/{k}")
    elif isinstance(schema_obj, list):
        for idx, item in enumerate(schema_obj):
            check_no_unsupported_schema_keywords(item, f"{path}[{idx}]")


# ---------------------------------------------------------------------------
# Verifier Core Logic
# ---------------------------------------------------------------------------

class ExportVerifier:
    def __init__(self, root: Path, check_schema: bool = False, verbose: bool = False):
        self.root = root.resolve()
        self.check_schema = check_schema
        self.verbose = verbose
        self.errors: List[str] = []

    def log(self, msg: str):
        if self.verbose:
            print(f"[verifier] {msg}")

    def error(self, msg: str):
        self.errors.append(msg)

    def verify(self) -> bool:
        self.log(f"Verifying public export at {self.root}...")

        # 1. Quiescent root preflight of all required files (fails fast before reads)
        if not self._preflight_all_required_files():
            return False

        # Inspect all public entries before any content reads (including hygiene scans).
        try:
            self.public_files = get_public_inventory_files(self.root, self.errors)
        except (OSError, ValueError) as exc:
            self.error(str(exc))
        if self.errors:
            return False

        # 2. Check self-contained schemas syntax and forbidden keywords in base mode
        self._check_schemas_syntax_and_keywords()
        if self.errors:
            return False

        # 3. Check release metadata (release/release.json)
        self._check_release_metadata()

        # 4. Checksums & Mandatory Inventory Coverage (exact disk vs manifest)
        self._check_checksums_and_inventory()

        # 5. Redaction / Private machine paths leak check
        self._check_private_path_leaks()

        # 6. Strict parse & structural integrity of datasets
        datasets = self._check_datasets_structure()
        plugins, evidence, claims, patterns, corrections, sources = datasets

        # Fail with deterministic errors before joins if structural errors exist
        if self.errors:
            return False

        # 7. Relational & Link Integrity (runs safely if datasets are parsed)
        if plugins is not None and evidence is not None:
            self._check_relational_integrity(
                plugins,
                evidence,
                claims or [],
                patterns or [],
                corrections or [],
                sources or [],
            )

        # 8. Statistics & Claims consistency
        if plugins is not None and evidence is not None:
            self._check_statistics_and_claims(
                plugins,
                evidence,
                claims or [],
                corrections or [],
                sources or [],
            )

        # 9. Optional JSON Schema Draft 2020-12 validation
        if self.check_schema:
            self._run_schema_validation(
                plugins or [],
                evidence or [],
                claims or [],
                patterns or [],
                corrections or [],
                sources or [],
            )

        return len(self.errors) == 0

    def _preflight_all_required_files(self) -> bool:
        all_required = REQUIRED_METADATA_FILES + REQUIRED_SCHEMA_FILES + REQUIRED_DATA_FILES
        has_error = False
        for rel_path in all_required:
            try:
                preflight_required_file(rel_path, self.root)
            except Exception as e:
                self.error(f"Preflight failure for required path {rel_path}: {e}")
                has_error = True
        return not has_error

    def _check_schemas_syntax_and_keywords(self):
        for rel_schema in REQUIRED_SCHEMA_FILES:
            schema_path = self.root / rel_schema
            try:
                content = schema_path.read_text(encoding="utf-8")
                schema_json = strict_json_loads(content, context=rel_schema)
                if not is_strict_dict(schema_json):
                    self.error(f"Schema {rel_schema} must be a JSON object, got {type(schema_json).__name__}")
                check_no_unsupported_schema_keywords(schema_json)
            except Exception as e:
                self.error(f"Schema verification failure for {rel_schema}: {e}")

    def _check_release_metadata(self):
        rel_path = self.root / "release/release.json"
        try:
            rel_data = strict_json_loads(rel_path.read_text(encoding="utf-8"), context="release/release.json")
        except Exception as e:
            self.error(f"Failed to parse release/release.json: {e}")
            return

        if not is_strict_dict(rel_data):
            self.error("release/release.json must be a JSON object")
            return

        for key in ["release_id", "schema_version", "status", "release_date", "locales"]:
            if key not in rel_data:
                self.error(f"release/release.json missing required key: {key}")

        if "release_id" in rel_data and not is_strict_nonempty_str(rel_data["release_id"]):
            self.error("release/release.json release_id must be a non-empty string")

        if type(rel_data.get("schema_version")) is not int or rel_data.get("schema_version") != 2:
            self.error("release/release.json schema_version must be integer 2")
        if not is_strict_str(rel_data.get("release_date")):
            self.error("release/release.json release_date must be a date string")
        else:
            try:
                date.fromisoformat(rel_data["release_date"])
            except ValueError:
                self.error("release/release.json release_date must be a valid ISO date")

        if "status" in rel_data and not is_strict_nonempty_str(rel_data["status"]):
            self.error("release/release.json status must be a non-empty string")

        if "locales" in rel_data:
            locs = rel_data["locales"]
            if not is_unique_nonempty_str_list(locs):
                self.error("release/release.json locales must be a list of unique non-empty strings")
            else:
                if "en" not in locs or "ru" not in locs:
                    self.error("release/release.json locales must include both 'en' and 'ru'")

    def _check_checksums_and_inventory(self):
        checksums_path = self.root / "release/checksums.json"
        try:
            checksums_data = strict_json_loads(
                checksums_path.read_text(encoding="utf-8"), context="release/checksums.json"
            )
        except Exception as e:
            self.error(f"Failed to parse release/checksums.json: {e}")
            return

        if not is_strict_dict(checksums_data):
            self.error("release/checksums.json must be a JSON object mapping relative paths to hashes")
            return

        manifest_files: Set[str] = set()
        for rel_path_str, expected_sha in checksums_data.items():
            if not is_strict_str(rel_path_str) or not is_strict_str(expected_sha):
                self.error(f"Invalid entry in release/checksums.json: {rel_path_str!r}: {expected_sha!r}")
                continue

            manifest_files.add(rel_path_str)

            if not HEX_SHA256_REGEX.match(expected_sha):
                self.error(f"Invalid SHA-256 hash format for {rel_path_str}: {expected_sha}")
                continue

            # Validate safe relative path and ensure it's not excluded
            try:
                target_path = validate_safe_rel_path(rel_path_str, self.root)
            except ValueError as e:
                self.error(f"Path safety violation in release/checksums.json: {e}")
                continue

            if rel_path_str == "release/checksums.json":
                self.error("release/checksums.json cannot include itself in the manifest")
                continue

            parts = rel_path_str.split("/")
            if any(part in EXCLUDED_DIRS for part in parts):
                self.error(f"Excluded file forbidden in checksums.json: {rel_path_str}")
                continue

            if is_temporary_file(Path(rel_path_str).name):
                self.error(f"Temporary file forbidden in checksums.json: {rel_path_str}")
                continue

            if not os.path.lexists(target_path):
                self.error(f"Checksum target missing on disk: {rel_path_str}")
                continue

            if os.path.islink(target_path):
                self.error(f"Checksum target cannot be a symlink: {rel_path_str}")
                continue

            st = os.lstat(target_path)
            if not stat.S_ISREG(st.st_mode):
                self.error(f"Checksum target must be a regular file: {rel_path_str}")
                continue

            actual_sha = sha256_file(target_path)
            if actual_sha != expected_sha:
                self.error(f"Checksum mismatch for {rel_path_str}: expected {expected_sha}, got {actual_sha}")

        disk_files = get_public_inventory_files(self.root, self.errors)
        missing_from_manifest = disk_files - manifest_files
        if missing_from_manifest:
            for f in sorted(missing_from_manifest):
                self.error(f"Mandatory inventory omission: {f} exists on disk but is missing from checksums.json")

        extra_in_manifest = manifest_files - disk_files
        if extra_in_manifest:
            for f in sorted(extra_in_manifest):
                self.error(f"Manifest entry not present on disk: {f}")

    def _check_private_path_leaks(self):
        # Use the preflighted inventory, not a second traversal that might open special files.
        for rel_path in sorted(self.public_files):
            p = self.root / rel_path
            if p.suffix.lower() not in TEXT_EXTENSIONS:
                continue
            try:
                text = p.read_text(encoding="utf-8")
                if PRIVATE_PATH_REGEX.search(text):
                    self.error(f"Private machine path leaked in {rel_path}")
            except (OSError, UnicodeError) as exc:
                self.error(f"Could not read UTF-8 text file {rel_path}: {exc}")

    def _check_datasets_structure(
        self,
    ) -> Tuple[
        Optional[List[Dict[str, Any]]],
        Optional[List[Dict[str, Any]]],
        Optional[List[Dict[str, Any]]],
        Optional[List[Dict[str, Any]]],
        Optional[List[Dict[str, Any]]],
        Optional[List[Dict[str, Any]]],
    ]:
        plugins: Optional[List[Dict[str, Any]]] = None
        evidence: Optional[List[Dict[str, Any]]] = None
        claims: Optional[List[Dict[str, Any]]] = None
        patterns: Optional[List[Dict[str, Any]]] = None
        corrections: Optional[List[Dict[str, Any]]] = None
        sources: Optional[List[Dict[str, Any]]] = None

        # 1. plugins.jsonl
        try:
            raw_plugins = read_strict_jsonl(self.root / "data/plugins.jsonl")
            plugins = []
            for line_no, p in raw_plugins:
                self._validate_plugin_record(line_no, p)
                plugins.append(p)
        except Exception as e:
            self.error(f"Error reading data/plugins.jsonl: {e}")

        # 2. evidence.jsonl
        try:
            raw_evidence = read_strict_jsonl(self.root / "data/evidence.jsonl")
            evidence = []
            for line_no, e in raw_evidence:
                self._validate_evidence_record(line_no, e)
                evidence.append(e)
        except Exception as e:
            self.error(f"Error reading data/evidence.jsonl: {e}")

        # 3. claims.jsonl
        try:
            raw_claims = read_strict_jsonl(self.root / "data/claims.jsonl")
            claims = []
            for line_no, c in raw_claims:
                self._validate_claim_record(line_no, c)
                claims.append(c)
        except Exception as e:
            self.error(f"Error reading data/claims.jsonl: {e}")

        # 4. patterns.json
        try:
            pat_content = (self.root / "data/patterns.json").read_text(encoding="utf-8")
            patterns_data = strict_json_loads(pat_content, context="data/patterns.json")
            if not is_strict_list(patterns_data):
                self.error("data/patterns.json must contain a JSON array of patterns")
            else:
                patterns = []
                for idx, pat in enumerate(patterns_data, 1):
                    self._validate_pattern_record(idx, pat)
                    patterns.append(pat)
        except Exception as e:
            self.error(f"Error reading data/patterns.json: {e}")

        # 5. corrections.jsonl
        try:
            raw_corrections = read_strict_jsonl(self.root / "data/corrections.jsonl")
            corrections = []
            for line_no, corr in raw_corrections:
                self._validate_correction_record(line_no, corr)
                corrections.append(corr)
        except Exception as e:
            self.error(f"Error reading data/corrections.jsonl: {e}")

        # 6. sources.jsonl
        try:
            raw_sources = read_strict_jsonl(self.root / "data/sources.jsonl")
            sources = []
            for line_no, src in raw_sources:
                self._validate_source_record(line_no, src)
                sources.append(src)
        except Exception as e:
            self.error(f"Error reading data/sources.jsonl: {e}")

        return plugins, evidence, claims, patterns, corrections, sources

    def _validate_plugin_record(self, line_no: int, p: Dict[str, Any]):
        required = [
            "record_id",
            "record_key",
            "plugin_id",
            "directory",
            "verdict",
            "review",
            "features",
            "evidence_ids",
            "release",
            "limitations",
            "revision_verified",
            "source_report",
        ]
        for key in required:
            if key not in p:
                self.error(f"Plugin record at line {line_no} missing required field: {key}")

        for str_key in ["record_id", "record_key", "plugin_id", "directory", "release", "source_report"]:
            if str_key in p and not is_strict_nonempty_str(p[str_key]):
                self.error(f"Plugin record at line {line_no} {str_key} must be a non-empty string")

        if "files_inspected_count" in p:
            val = p["files_inspected_count"]
            if not is_strict_int(val) or val < 0:
                self.error(
                    f"Plugin record at line {line_no} has invalid files_inspected_count (expected int >= 0, got {val!r})"
                )

        if "revision_verified" in p:
            val = p["revision_verified"]
            if not is_strict_bool(val):
                self.error(
                    f"Plugin record at line {line_no} has invalid revision_verified (expected bool, got {val!r})"
                )

        if "join" in p and p["join"] not in {"exact", "directory_candidate", "unmatched"}:
            self.error(f"Plugin record at line {line_no} has invalid join enum value: {p['join']!r}")

        if "evidence_ids" in p:
            if not is_unique_nonempty_str_list(p["evidence_ids"]):
                self.error(f"Plugin record at line {line_no} evidence_ids must be a list of unique non-empty strings")

        if "limitations" in p:
            if not is_strict_list(p["limitations"]) or not all(is_strict_str(x) for x in p["limitations"]):
                self.error(f"Plugin record at line {line_no} limitations must be a list of strings")

        # Features tri-state validation (bool or null)
        if "features" in p:
            feat = p["features"]
            if not is_strict_dict(feat):
                self.error(f"Plugin record at line {line_no} features must be an object")
            else:
                for fk, fv in feat.items():
                    if not (is_strict_bool(fv) or fv is None):
                        self.error(
                            f"Plugin record at line {line_no} features.{fk} must be boolean or null, got {fv!r}"
                        )

        # Verdict object
        if "verdict" in p:
            v = p["verdict"]
            if not is_strict_dict(v):
                self.error(f"Plugin record at line {line_no} verdict must be an object")
            else:
                for vk in ["normalized", "raw", "summary", "scope", "runtime_verified"]:
                    if vk not in v:
                        self.error(f"Plugin record at line {line_no} verdict missing required field: {vk}")
                if "normalized" in v and v["normalized"] not in {"pass", "warning", "broken", "suspicious"}:
                    self.error(f"Plugin record at line {line_no} verdict.normalized invalid: {v['normalized']!r}")
                if "raw" in v and not is_strict_str(v["raw"]):
                    self.error(f"Plugin record at line {line_no} verdict.raw must be a string")
                if "summary" in v and v["summary"] is not None and not is_strict_str(v["summary"]):
                    self.error(f"Plugin record at line {line_no} verdict.summary must be string or null")
                if "scope" in v and v["scope"] != "static-audit":
                    self.error(f"Plugin record at line {line_no} verdict.scope must be 'static-audit'")
                if "runtime_verified" in v and not is_strict_bool(v["runtime_verified"]):
                    self.error(f"Plugin record at line {line_no} verdict.runtime_verified must be bool")

        # Review object
        if "review" in p:
            rev = p["review"]
            if not is_strict_dict(rev):
                self.error(f"Plugin record at line {line_no} review must be an object")
            else:
                for rk in ["status", "correction_ids", "source_ids", "runtime_verified"]:
                    if rk not in rev:
                        self.error(f"Plugin record at line {line_no} review missing required field: {rk}")
                if "status" in rev and rev["status"] not in {"historical-unverified", "corrected-static-interpretation"}:
                    self.error(f"Plugin record at line {line_no} review.status invalid: {rev['status']!r}")
                if "correction_ids" in rev and not is_unique_nonempty_str_list(rev["correction_ids"]):
                    self.error(f"Plugin record at line {line_no} review.correction_ids must be a list of unique non-empty strings")
                if "source_ids" in rev and not is_unique_nonempty_str_list(rev["source_ids"]):
                    self.error(f"Plugin record at line {line_no} review.source_ids must be a list of unique non-empty strings")
                if "runtime_verified" in rev and not is_strict_bool(rev["runtime_verified"]):
                    self.error(f"Plugin record at line {line_no} review.runtime_verified must be bool")

    def _validate_evidence_record(self, line_no: int, e: Dict[str, Any]):
        required = [
            "evidence_id",
            "record_id",
            "record_key",
            "file",
            "line",
            "snippet",
            "type",
            "proof",
            "proof_grade",
            "runtime_measurement_required",
            "source_revision_verified",
            "limitations",
            "source_report",
            "release",
            "interpretation_status",
            "correction_ids",
        ]
        for key in required:
            if key not in e:
                self.error(f"Evidence record at line {line_no} missing required field: {key}")

        for str_key in ["evidence_id", "record_id", "record_key", "file", "type", "release"]:
            if str_key in e and not is_strict_nonempty_str(e[str_key]):
                self.error(f"Evidence record at line {line_no} {str_key} must be a non-empty string")

        if "snippet" in e and not is_strict_str(e["snippet"]):
            self.error(f"Evidence record at line {line_no} snippet must be a string")

        if "proof" in e and not is_strict_str(e["proof"]):
            self.error(f"Evidence record at line {line_no} proof must be a string")

        if "source_report" in e and not is_strict_str(e["source_report"]):
            self.error(f"Evidence record at line {line_no} source_report must be a string")

        if "line" in e:
            val = e["line"]
            if not is_strict_int(val) or val < 0:
                self.error(f"Evidence record at line {line_no} has invalid line (expected int >= 0, got {val!r})")

        if "proof_grade" in e and e["proof_grade"] != "legacy-reported-interpretation":
            self.error(f"Evidence record at line {line_no} proof_grade must be 'legacy-reported-interpretation'")

        if "runtime_measurement_required" in e and not is_strict_bool(e["runtime_measurement_required"]):
            self.error(f"Evidence record at line {line_no} runtime_measurement_required must be bool")

        if "source_revision_verified" in e and not is_strict_bool(e["source_revision_verified"]):
            self.error(f"Evidence record at line {line_no} source_revision_verified must be bool")

        if "interpretation_status" in e and e["interpretation_status"] != "historical-unverified":
            self.error(f"Evidence record at line {line_no} interpretation_status must be 'historical-unverified'")

        if "correction_ids" in e and not is_unique_nonempty_str_list(e["correction_ids"]):
            self.error(f"Evidence record at line {line_no} correction_ids must be a list of unique non-empty strings")

        if "limitations" in e:
            if not is_strict_list(e["limitations"]) or not all(is_strict_str(x) for x in e["limitations"]):
                self.error(f"Evidence record at line {line_no} limitations must be a list of strings")

    def _validate_claim_record(self, line_no: int, c: Dict[str, Any]):
        required = [
            "claim_id",
            "kind",
            "value",
            "unit",
            "statement",
            "source",
            "evidence_level",
            "release",
            "status",
        ]
        for key in required:
            if key not in c:
                self.error(f"Claim record at line {line_no} missing required field: {key}")

        for str_key in ["claim_id", "kind", "unit", "evidence_level", "release", "status"]:
            if str_key in c and not is_strict_nonempty_str(c[str_key]):
                self.error(f"Claim record at line {line_no} {str_key} must be a non-empty string")

        if "value" in c:
            val = c["value"]
            if not is_strict_int(val) and not is_strict_bool(val):
                self.error(f"Claim record at line {line_no} value must be strict int or bool, got {val!r}")

        if "statement" in c:
            st = c["statement"]
            if not is_strict_dict(st) or not is_strict_nonempty_str(st.get("en")) or not is_strict_nonempty_str(st.get("ru")):
                self.error(f"Claim record at line {line_no} statement must be dict with 'en' and 'ru' non-empty strings")

        if "source" in c:
            src = c["source"]
            if (
                not is_strict_dict(src)
                or not is_strict_nonempty_str(src.get("file"))
                or not is_strict_nonempty_str(src.get("json_path_or_section"))
            ):
                self.error(
                    f"Claim record at line {line_no} source must be dict with 'file' and 'json_path_or_section' strings"
                )

        if "status" in c:
            if c["status"] not in {"verified", "review-required", "disputed", "superseded", "retracted"}:
                self.error(f"Claim record at line {line_no} has invalid status: {c['status']!r}")

    def _validate_pattern_record(self, idx: int, pat: Dict[str, Any]):
        required = ["pattern_id", "polarity", "title", "guidance", "evidence_types"]
        for key in required:
            if key not in pat:
                self.error(f"Pattern item #{idx} missing required field: {key}")

        if "pattern_id" in pat and not is_strict_nonempty_str(pat["pattern_id"]):
            self.error(f"Pattern item #{idx} pattern_id must be a non-empty string")

        if "polarity" in pat and pat["polarity"] not in {"protective", "hazard", "neutral", "method"}:
            self.error(f"Pattern item #{idx} has invalid polarity: {pat['polarity']!r}")

        for text_field in ["title", "guidance"]:
            if text_field in pat:
                tf = pat[text_field]
                if not is_strict_dict(tf) or not is_strict_nonempty_str(tf.get("en")) or not is_strict_nonempty_str(tf.get("ru")):
                    self.error(f"Pattern item #{idx} {text_field} must be dict with 'en' and 'ru' non-empty strings")

        if "evidence_types" in pat and not is_unique_nonempty_str_list(pat["evidence_types"]):
            self.error(f"Pattern item #{idx} evidence_types must be a list of unique non-empty strings")

    def _validate_correction_record(self, line_no: int, corr: Dict[str, Any]):
        required = [
            "correction_id",
            "record_id",
            "evidence_ids",
            "source_ids",
            "status",
            "checked_at",
            "observation",
            "correction",
            "limitations",
        ]
        for key in required:
            if key not in corr:
                self.error(f"Correction record at line {line_no} missing required field: {key}")

        if "correction_id" in corr and not is_strict_nonempty_str(corr["correction_id"]):
            self.error(f"Correction record at line {line_no} correction_id must be a non-empty string")

        if "record_id" in corr and not is_strict_nonempty_str(corr["record_id"]):
            self.error(f"Correction record at line {line_no} record_id must be a non-empty string")

        if "evidence_ids" in corr and not is_unique_nonempty_str_list(corr["evidence_ids"]):
            self.error(f"Correction record at line {line_no} evidence_ids must be a list of unique non-empty strings")

        if "source_ids" in corr and not is_unique_nonempty_str_list(corr["source_ids"]):
            self.error(f"Correction record at line {line_no} source_ids must be a list of unique non-empty strings")

        if "status" in corr and corr["status"] != "corrected-static-interpretation":
            self.error(f"Correction record at line {line_no} status must be 'corrected-static-interpretation'")

        if "checked_at" in corr and (not is_strict_str(corr["checked_at"]) or not DATE_REGEX.match(corr["checked_at"])):
            self.error(f"Correction record at line {line_no} checked_at must be YYYY-MM-DD date")

        for dict_field in ["observation", "correction", "limitations"]:
            if dict_field in corr:
                val = corr[dict_field]
                if not is_strict_dict(val) or not is_strict_nonempty_str(val.get("en")) or not is_strict_nonempty_str(val.get("ru")):
                    self.error(
                        f"Correction record at line {line_no} {dict_field} must be dict with 'en' and 'ru' non-empty strings"
                    )

    def _validate_source_record(self, line_no: int, src: Dict[str, Any]):
        required = [
            "source_id",
            "record_ids",
            "repository_url",
            "revision",
            "revision_relation",
            "checked_at",
            "files",
            "license",
            "scope",
            "limitations",
        ]
        for key in required:
            if key not in src:
                self.error(f"Source record at line {line_no} missing required field: {key}")

        if "source_id" in src and not is_strict_nonempty_str(src["source_id"]):
            self.error(f"Source record at line {line_no} source_id must be a non-empty string")

        if "record_ids" in src and not is_unique_nonempty_str_list(src["record_ids"]):
            self.error(f"Source record at line {line_no} record_ids must be a list of unique non-empty strings")
        if src.get("record_ids") == []:
            if (not is_strict_str(src.get("source_id")) or not src["source_id"].startswith("SRC-EXT-")
                    or not is_strict_str(src.get("scope")) or not src["scope"].startswith("External ")):
                self.error(f"Source at line {line_no} empty record_ids require explicit external context (SRC-EXT-, External scope)")

        if "repository_url" in src:
            url = src["repository_url"]
            if not is_strict_str(url) or not URL_REGEX.match(url):
                self.error(f"Source record at line {line_no} repository_url invalid: {url!r}")

        if "revision" in src:
            rev = src["revision"]
            if not is_strict_str(rev) or not HEX_REVISION40_REGEX.match(rev):
                self.error(f"Source record at line {line_no} revision must be 40-hex git commit: {rev!r}")

        if "revision_relation" in src and src["revision_relation"] not in {
            "reported-registry-reference",
            "current-reference",
        }:
            self.error(f"Source record at line {line_no} revision_relation invalid: {src['revision_relation']!r}")

        if "checked_at" in src and (not is_strict_str(src["checked_at"]) or not DATE_REGEX.match(src["checked_at"])):
            self.error(f"Source record at line {line_no} checked_at must be YYYY-MM-DD date")

        if "files" in src:
            if not is_strict_list(src["files"]):
                self.error(f"Source record at line {line_no} files must be a list")
            else:
                if not src["files"]:
                    self.error(f"Source at line {line_no} must contain at least one inspected file")
                for f_item in src["files"]:
                    if (
                        not is_strict_dict(f_item)
                        or not is_strict_nonempty_str(f_item.get("path"))
                        or not is_strict_nonempty_str(f_item.get("url"))
                        or not is_strict_str(f_item.get("sha256"))
                    ):
                        self.error(f"Source record at line {line_no} files item invalid: {f_item!r}")
                    elif not HEX_SHA256_REGEX.fullmatch(f_item.get("sha256", "")):
                        self.error(f"Source record at line {line_no} invalid sha256 in files: {f_item.get('sha256')!r}")
                    else:
                        path = f_item["path"]
                        if path.startswith("/") or "\\" in path or any(p in ("", ".", "..") for p in path.split("/")):
                            self.error(f"Source file path must be relative canonical POSIX: {path!r}")
                        # This release's source ledger uses GitHub permalinks only; no fetching here.
                        expected_url = f"{src.get('repository_url')}/blob/{src.get('revision')}/{quote(path, safe='/')}"
                        if f_item["url"] != expected_url:
                            self.error(f"Source at line {line_no} file URL must match repository, full revision and path")

        if "license" in src:
            lic = src["license"]
            if not is_strict_dict(lic) or lic.get("status") not in ("identified-at-revision", "unknown"):
                self.error(f"Source record at line {line_no} license object invalid: {lic!r}")
            else:
                if not all(key in lic for key in ("spdx", "url", "status")):
                    self.error(f"Source at line {line_no} license missing required fields")
                if lic.get("status") == "identified-at-revision":
                    if not is_strict_nonempty_str(lic.get("spdx")) or not is_strict_nonempty_str(lic.get("url")):
                        self.error(f"Source at line {line_no} identified license needs SPDX and permalink")
                    elif not lic["url"].startswith(f"{src.get('repository_url')}/blob/{src.get('revision')}/"):
                        self.error(f"Source at line {line_no} license URL must pin the same repository revision")
                elif lic.get("spdx") is not None or lic.get("url") is not None:
                    self.error(f"Source at line {line_no} unknown license requires null SPDX and URL")
                if lic.get("sha256") is not None and (not is_strict_str(lic["sha256"]) or not HEX_SHA256_REGEX.fullmatch(lic["sha256"])):
                    self.error(f"Source at line {line_no} invalid license sha256")
                if "copyright_notices" in lic and not is_unique_nonempty_str_list(lic["copyright_notices"]):
                    self.error(f"Source at line {line_no} invalid license notices")

        if "scope" in src and not is_strict_nonempty_str(src["scope"]):
            self.error(f"Source record at line {line_no} scope must be a non-empty string")

        if "limitations" in src:
            if not is_strict_list(src["limitations"]) or not all(is_strict_str(x) for x in src["limitations"]):
                self.error(f"Source record at line {line_no} limitations must be a list of strings")

    def _check_relational_integrity(
        self,
        plugins: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        claims: List[Dict[str, Any]],
        patterns: List[Dict[str, Any]],
        corrections: List[Dict[str, Any]],
        sources: List[Dict[str, Any]],
    ):
        # 1. Uniqueness of primary IDs
        plugin_map: Dict[str, Dict[str, Any]] = {}
        for p in plugins:
            rid = p.get("record_id")
            if not is_strict_nonempty_str(rid):
                continue
            if rid in plugin_map:
                self.error(f"Duplicate plugin record_id: {rid}")
            else:
                plugin_map[rid] = p

        evidence_map: Dict[str, Dict[str, Any]] = {}
        for e in evidence:
            eid = e.get("evidence_id")
            if not is_strict_nonempty_str(eid):
                continue
            if eid in evidence_map:
                self.error(f"Duplicate evidence_id: {eid}")
            else:
                evidence_map[eid] = e

        claim_map: Dict[str, Dict[str, Any]] = {}
        for c in claims:
            cid = c.get("claim_id")
            if not is_strict_nonempty_str(cid):
                continue
            if cid in claim_map:
                self.error(f"Duplicate claim_id: {cid}")
            else:
                claim_map[cid] = c

        pattern_map: Dict[str, Dict[str, Any]] = {}
        for pat in patterns:
            pid = pat.get("pattern_id")
            if not is_strict_nonempty_str(pid):
                continue
            if pid in pattern_map:
                self.error(f"Duplicate pattern_id: {pid}")
            else:
                pattern_map[pid] = pat

        correction_map: Dict[str, Dict[str, Any]] = {}
        for corr in corrections:
            cid = corr.get("correction_id")
            if not is_strict_nonempty_str(cid):
                continue
            if cid in correction_map:
                self.error(f"Duplicate correction_id: {cid}")
            else:
                correction_map[cid] = corr

        source_map: Dict[str, Dict[str, Any]] = {}
        for src in sources:
            sid = src.get("source_id")
            if not is_strict_nonempty_str(sid):
                continue
            if sid in source_map:
                self.error(f"Duplicate source_id: {sid}")
            else:
                source_map[sid] = src

        # 2. Referential integrity & record_key agreement: Plugin <-> Evidence
        evidence_claimed_by_plugin: Dict[str, str] = {}
        for p in plugins:
            pid = p.get("record_id")
            p_rkey = p.get("record_key")
            if not pid or not p_rkey:
                continue

            eids = p.get("evidence_ids", [])
            if not is_strict_list(eids):
                continue

            for eid in eids:
                if eid not in evidence_map:
                    self.error(f"Plugin {pid} references non-existent evidence_id: {eid}")
                else:
                    if eid in evidence_claimed_by_plugin:
                        self.error(
                            f"Evidence {eid} claimed by multiple plugins: {evidence_claimed_by_plugin[eid]} and {pid}"
                        )
                    evidence_claimed_by_plugin[eid] = pid

                    e_rec = evidence_map[eid]
                    if e_rec.get("record_id") != pid:
                        self.error(
                            f"Evidence ownership mismatch: {eid} record_id is {e_rec.get('record_id')}, but claimed by {pid}"
                        )
                    if e_rec.get("record_key") != p_rkey:
                        self.error(
                            f"Record key mismatch for {eid}: evidence has {e_rec.get('record_key')!r}, owning plugin has {p_rkey!r}"
                        )

        for e in evidence:
            eid = e.get("evidence_id")
            owner_rid = e.get("record_id")
            e_rkey = e.get("record_key")
            if not eid or not owner_rid:
                continue

            if owner_rid not in plugin_map:
                self.error(f"Evidence {eid} references non-existent plugin record_id: {owner_rid}")
            else:
                owner_plugin = plugin_map[owner_rid]
                p_eids = owner_plugin.get("evidence_ids", [])
                if eid not in p_eids:
                    self.error(
                        f"Orphan/unlinked evidence: {eid} points to {owner_rid}, but {owner_rid} does not list it in evidence_ids"
                    )
                if owner_plugin.get("record_key") != e_rkey:
                    self.error(
                        f"Record key mismatch for {eid}: evidence has {e_rkey!r}, plugin {owner_rid} has {owner_plugin.get('record_key')!r}"
                    )

        # 3. Review status agreement with correction_ids
        for p in plugins:
            pid = p.get("record_id")
            rev = p.get("review")
            if not pid or not is_strict_dict(rev):
                continue

            status = rev.get("status")
            cids = rev.get("correction_ids", [])
            sids = rev.get("source_ids", [])

            if status == "corrected-static-interpretation":
                if not cids:
                    self.error(
                        f"Plugin {pid} review.status is 'corrected-static-interpretation' but correction_ids is empty"
                    )
            elif status == "historical-unverified":
                if cids:
                    self.error(
                        f"Plugin {pid} review.status is 'historical-unverified' but correction_ids is non-empty: {cids}"
                    )

            for cid in cids:
                if cid not in correction_map:
                    self.error(f"Plugin {pid} review references non-existent correction_id: {cid}")
                else:
                    corr = correction_map[cid]
                    if corr.get("record_id") != pid:
                        self.error(
                            f"Correction {cid} target record_id mismatch: points to {corr.get('record_id')}, referenced by {pid}"
                        )

            for sid in sids:
                if sid not in source_map:
                    self.error(f"Plugin {pid} review references non-existent source_id: {sid}")
                else:
                    src = source_map[sid]
                    if pid not in src.get("record_ids", []):
                        self.error(
                            f"Source {sid} record_ids missing referencing plugin: {pid}"
                        )

        # 4. Corrections reciprocal links: Plugin, Evidence, Sources
        for corr in corrections:
            cid = corr.get("correction_id")
            rid = corr.get("record_id")
            if not cid or not rid:
                continue

            if rid not in plugin_map:
                self.error(f"Correction {cid} references non-existent plugin record_id: {rid}")
            else:
                p_corr_ids = plugin_map[rid].get("review", {}).get("correction_ids", [])
                if cid not in p_corr_ids:
                    self.error(
                        f"Correction {cid} targets plugin {rid}, but plugin does not list it in review.correction_ids"
                    )

            for eid in corr.get("evidence_ids", []):
                if eid not in evidence_map:
                    self.error(f"Correction {cid} references non-existent evidence_id: {eid}")
                else:
                    e_rec = evidence_map[eid]
                    if e_rec.get("record_id") != rid:
                        self.error(
                            f"Correction {cid} for {rid} references evidence {eid} belonging to {e_rec.get('record_id')}"
                        )
                    if cid not in e_rec.get("correction_ids", []):
                        self.error(
                            f"Evidence {eid} missing reciprocal correction_id {cid}"
                        )

            for sid in corr.get("source_ids", []):
                if sid not in source_map:
                    self.error(f"Correction {cid} references non-existent source_id: {sid}")
                elif source_map[sid].get("record_ids") and rid not in source_map[sid]["record_ids"]:
                    self.error(f"Correction {cid} references source {sid} for a different plugin")

        # 5. Evidence correction_ids references
        for e in evidence:
            eid = e.get("evidence_id")
            rid = e.get("record_id")
            if not eid or not rid:
                continue

            for cid in e.get("correction_ids", []):
                if cid not in correction_map:
                    self.error(f"Evidence {eid} references non-existent correction_id: {cid}")
                else:
                    corr = correction_map[cid]
                    if corr.get("record_id") != rid:
                        self.error(
                            f"Evidence {eid} references correction {cid} which targets different record {corr.get('record_id')}"
                        )
                    if eid not in corr.get("evidence_ids", []):
                        self.error(
                            f"Correction {cid} missing reciprocal evidence_id {eid}"
                        )

        # 6. Sources references to plugins
        for src in sources:
            sid = src.get("source_id")
            if not sid:
                continue
            rids = src.get("record_ids", [])
            for rid in rids:
                if rid not in plugin_map:
                    self.error(f"Source {sid} references non-existent plugin record_id: {rid}")
                else:
                    expected_relation = ("reported-registry-reference"
                                         if plugin_map[rid].get("registry_commit") == src.get("revision")
                                         else "current-reference")
                    if src.get("revision_relation") != expected_relation:
                        self.error(f"Source {sid} revision_relation disagrees with stored registry_commit")
                    p_sids = plugin_map[rid].get("review", {}).get("source_ids", [])
                    if sid not in p_sids:
                        self.error(
                            f"Source {sid} references plugin {rid}, but plugin does not list it in review.source_ids"
                        )

    def _check_statistics_and_claims(
        self,
        plugins: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        claims: List[Dict[str, Any]],
        corrections: List[Dict[str, Any]],
        sources: List[Dict[str, Any]],
    ):
        stats_file = self.root / "release/statistics.json"
        try:
            stats = strict_json_loads(stats_file.read_text(encoding="utf-8"), context="release/statistics.json")
        except Exception as e:
            self.error(f"Failed to parse release/statistics.json: {e}")
            return

        if not is_strict_dict(stats):
            self.error("release/statistics.json must be an object")
            return

        # 1. Total records (strict int)
        actual_records = len(plugins)
        stats_records = stats.get("records")
        if not is_strict_int(stats_records) or stats_records != actual_records:
            self.error(
                f"Statistics records mismatch: release/statistics.json has {stats_records!r}, actual is {actual_records}"
            )

        # 2. Total anchors (strict int)
        actual_anchors = len(evidence)
        stats_anchors = stats.get("anchors")
        if not is_strict_int(stats_anchors) or stats_anchors != actual_anchors:
            self.error(
                f"Statistics anchors mismatch: release/statistics.json has {stats_anchors!r}, actual is {actual_anchors}"
            )

        # 3. Chunks count (strict int)
        chunk_prefixes = {p["record_key"].split(":")[0] for p in plugins if "record_key" in p and ":" in p["record_key"]}
        actual_chunks = len(chunk_prefixes)
        stats_chunks = stats.get("chunks")
        if not is_strict_int(stats_chunks) or stats_chunks != actual_chunks:
            self.error(
                f"Statistics chunks mismatch: release/statistics.json has {stats_chunks!r}, actual is {actual_chunks}"
            )

        # 4. Files inspected references (strict int)
        actual_file_refs = sum(
            p["files_inspected_count"] for p in plugins if is_strict_int(p.get("files_inspected_count"))
        )
        stats_file_refs = stats.get("files_inspected_references")
        if not is_strict_int(stats_file_refs) or stats_file_refs != actual_file_refs:
            self.error(
                f"Statistics files_inspected_references mismatch: release/statistics.json has {stats_file_refs!r}, actual is {actual_file_refs}"
            )

        # 5. Revision verified records (strict int)
        actual_rev_verified = sum(1 for p in plugins if p.get("revision_verified") is True)
        stats_rev_verified = stats.get("revision_verified_records")
        if not is_strict_int(stats_rev_verified) or stats_rev_verified != actual_rev_verified:
            self.error(
                f"Statistics revision_verified_records mismatch: release/statistics.json has {stats_rev_verified!r}, actual is {actual_rev_verified}"
            )

        # 6. Normalized verdicts breakdown (strict ints)
        verdict_counts: Dict[str, int] = {"broken": 0, "pass": 0, "suspicious": 0, "warning": 0}
        for p in plugins:
            norm_v = p.get("verdict", {}).get("normalized")
            if norm_v in verdict_counts:
                verdict_counts[norm_v] += 1
            else:
                self.error(f"Unknown normalized verdict {norm_v!r} in plugin {p.get('record_id')}")

        stats_verdicts = stats.get("normalized_verdicts")
        if not is_strict_dict(stats_verdicts):
            self.error("Statistics normalized_verdicts must be an object")
        else:
            for v_name, expected_count in verdict_counts.items():
                act_cnt = stats_verdicts.get(v_name)
                if not is_strict_int(act_cnt) or act_cnt != expected_count:
                    self.error(
                        f"Statistics normalized_verdicts.{v_name} mismatch: statistics has {act_cnt!r}, actual is {expected_count}"
                    )

        # 7. Joins breakdown (strict ints)
        join_counts: Dict[str, int] = {"directory_candidate": 0, "exact": 0, "unmatched": 0}
        for p in plugins:
            j = p.get("join")
            if j in join_counts:
                join_counts[j] += 1
            else:
                self.error(f"Unknown join type {j!r} in plugin {p.get('record_id')}")

        stats_joins = stats.get("joins")
        if not is_strict_dict(stats_joins):
            self.error("Statistics joins must be an object")
        else:
            for j_name, expected_count in join_counts.items():
                act_cnt = stats_joins.get(j_name)
                if not is_strict_int(act_cnt) or act_cnt != expected_count:
                    self.error(
                        f"Statistics joins.{j_name} mismatch: statistics has {act_cnt!r}, actual is {expected_count}"
                    )

        # 8. Corrections and sources counts (mandatory exact numbers)
        stats_corrections = stats.get("corrections")
        if not is_strict_int(stats_corrections) or stats_corrections != len(corrections):
            self.error(
                f"Statistics corrections count mismatch: statistics has {stats_corrections!r}, actual is {len(corrections)}"
            )

        stats_sources = stats.get("sources")
        if not is_strict_int(stats_sources) or stats_sources != len(sources):
            self.error(
                f"Statistics sources count mismatch: statistics has {stats_sources!r}, actual is {len(sources)}"
            )

        # 9. Privilege distribution (mandatory exact counts for false, null, true)
        privilege_counts = {"false": 0, "null": 0, "true": 0}
        for p in plugins:
            priv = p.get("features", {}).get("privilege")
            if priv is True:
                privilege_counts["true"] += 1
            elif priv is False:
                privilege_counts["false"] += 1
            elif priv is None:
                privilege_counts["null"] += 1
            else:
                self.error(f"Unknown privilege value {priv!r} in plugin {p.get('record_id')}")

        stats_priv = stats.get("privilege_distribution")
        if not is_strict_dict(stats_priv):
            self.error("Statistics privilege_distribution must be an object")
        else:
            for pk, expected_cnt in privilege_counts.items():
                act_cnt = stats_priv.get(pk)
                if not is_strict_int(act_cnt) or act_cnt != expected_cnt:
                    self.error(
                        f"Statistics privilege_distribution.{pk} mismatch: statistics has {act_cnt!r}, actual is {expected_cnt}"
                    )

        release = strict_json_loads((self.root / "release/release.json").read_text(encoding="utf-8"))
        if stats.get("release") != release.get("release_id"):
            self.error("Statistics release must match release/release.json release_id")
        if stats.get("source_commit") != release.get("historical_source_commit"):
            self.error("Statistics source_commit must match explicit historical_source_commit metadata")

        # 10. Verify claim IDs in statistics
        claim_ids_in_stats = stats.get("claim_ids", {})
        if claim_ids_in_stats != {path: cid for cid, path in STAT_CLAIM_PATHS.items()}:
            self.error("Statistics claim_ids must map each required statistic to its exact stable claim")

        claim_map = {c.get("claim_id"): c for c in claims if is_strict_nonempty_str(c.get("claim_id"))}

        # 11. Mandatory 13 Claim IDs verification
        for cid in MANDATORY_CLAIM_IDS:
            if cid not in claim_map:
                self.error(f"Mandatory claim missing from data/claims.jsonl: {cid}")

        # 12. Verify each claim's value, strict types, and source pointers
        claim_expectations: Dict[str, Tuple[Any, type]] = {
            "CLM-CORPUS-RECORDS": (actual_records, int),
            "CLM-CORPUS-CHUNKS": (actual_chunks, int),
            "CLM-CORPUS-ANCHORS": (actual_anchors, int),
            "CLM-CORPUS-FILE-REFERENCES": (actual_file_refs, int),
            "CLM-VERDICT-PASS": (verdict_counts.get("pass", 0), int),
            "CLM-VERDICT-WARNING": (verdict_counts.get("warning", 0), int),
            "CLM-VERDICT-BROKEN": (verdict_counts.get("broken", 0), int),
            "CLM-VERDICT-SUSPICIOUS": (verdict_counts.get("suspicious", 0), int),
            "CLM-JOIN-EXACT": (join_counts.get("exact", 0), int),
            "CLM-JOIN-DIRECTORY-CANDIDATE": (join_counts.get("directory_candidate", 0), int),
            "CLM-JOIN-UNMATCHED": (join_counts.get("unmatched", 0), int),
            "CLM-SOURCE-REVISIONS": (actual_rev_verified, int),
            "CLM-METHOD-RUNTIME": (False, bool),
        }

        for cid, (expected_val, expected_type) in claim_expectations.items():
            if cid not in claim_map:
                continue

            c = claim_map[cid]
            c_val = c.get("value")

            if type(c_val) is not expected_type or c_val != expected_val:
                self.error(
                    f"Claim {cid} value mismatch: claim states {c_val!r} (type {type(c_val).__name__}), "
                    f"expected {expected_val!r} (type {expected_type.__name__})"
                )

            # Check source pointer
            c_src = c.get("source", {})
            src_file = c_src.get("file", "")
            src_section = c_src.get("json_path_or_section", "")

            expected_source = (
                {"file": "release/statistics.json", "json_path_or_section": "$." + STAT_CLAIM_PATHS[cid]}
                if cid in STAT_CLAIM_PATHS else
                {"file": "METHODOLOGY.md", "json_path_or_section": "METHODOLOGY.md#scope-and-limitations"}
            )
            if c_src != expected_source:
                self.error(f"Claim {cid} source pointer must be exactly {expected_source}")
                continue
            try:
                src_path = preflight_required_file(src_file, self.root)
                if cid == "CLM-METHOD-RUNTIME":
                    content = src_path.read_text(encoding="utf-8")
                    if not re.search(r"^## Scope and [Ll]imitations\s*$", content, re.MULTILINE):
                        self.error("Claim CLM-METHOD-RUNTIME target heading is missing")
            except (OSError, ValueError) as exc:
                self.error(f"Claim {cid} source pointer verification error: {exc}")

        # 13. Runtime claim false agrees with plugin records
        any_runtime_verified = any(
            p.get("verdict", {}).get("runtime_verified") is True
            or p.get("review", {}).get("runtime_verified") is True
            for p in plugins
        )
        if any_runtime_verified:
            self.error("Claim CLM-METHOD-RUNTIME states false, but one or more plugins have runtime_verified=true")

    def _run_schema_validation(
        self,
        plugins: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        claims: List[Dict[str, Any]],
        patterns: List[Dict[str, Any]],
        corrections: List[Dict[str, Any]],
        sources: List[Dict[str, Any]],
    ):
        try:
            import jsonschema
            from jsonschema import Draft202012Validator
        except ImportError:
            self.error(
                "ERROR: jsonschema is not installed. To run schema validation, install dependencies via: "
                "pip install -r tools/requirements-validation.txt"
            )
            return

        schema_targets = [
            ("plugin", "schemas/plugin.schema.json", plugins, "data/plugins.jsonl"),
            ("evidence", "schemas/evidence.schema.json", evidence, "data/evidence.jsonl"),
            ("claim", "schemas/claim.schema.json", claims, "data/claims.jsonl"),
            ("pattern", "schemas/pattern.schema.json", patterns, "data/patterns.json"),
            ("correction", "schemas/correction.schema.json", corrections, "data/corrections.jsonl"),
            ("source", "schemas/source.schema.json", sources, "data/sources.jsonl"),
        ]

        for name, rel_schema_path, dataset, data_desc in schema_targets:
            full_schema_path = self.root / rel_schema_path
            try:
                schema_content = strict_json_loads(
                    full_schema_path.read_text(encoding="utf-8"), context=rel_schema_path
                )
            except Exception as e:
                self.error(f"Malformed schema file {rel_schema_path}: {e}")
                continue

            # Strict check: reject $ref, $dynamicRef, $recursiveRef, $id
            try:
                check_no_unsupported_schema_keywords(schema_content)
            except ValueError as e:
                self.error(f"Schema security error in {rel_schema_path}: {e}")
                continue

            # Check meta-schema
            try:
                Draft202012Validator.check_schema(schema_content)
            except Exception as e:
                self.error(f"Invalid Draft 2020-12 schema {rel_schema_path}: {e}")
                continue

            # Instantiate validator with zero resolvers (schemas are self-contained)
            validator = Draft202012Validator(schema_content)

            # Validate each item in the dataset
            error_count = 0
            for idx, item in enumerate(dataset, 1):
                for err in validator.iter_errors(item):
                    error_count += 1
                    if error_count <= 10:
                        path_str = "/".join(str(p) for p in err.path)
                        self.error(
                            f"Schema validation failure in {data_desc} item #{idx} at path '{path_str}': {err.message}"
                        )
            if error_count > 10:
                self.error(
                    f"Total {error_count} schema validation failures in {data_desc} (truncated to first 10)"
                )


def main():
    parser = argparse.ArgumentParser(
        description="Strict standalone verifier for Omarchy Plugin Observatory public export."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Path to repository root (defaults to parent of tools/ directory).",
    )
    parser.add_argument(
        "--schema",
        action="store_true",
        help="Run full Draft 2020-12 JSON Schema validation using jsonschema (requires jsonschema 4.x).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output during verification.",
    )

    args = parser.parse_args()
    root = args.root if args.root else Path(__file__).resolve().parents[1]

    verifier = ExportVerifier(root=root, check_schema=args.schema, verbose=args.verbose)
    success = verifier.verify()

    if not success:
        print(f"FAIL: Export verification failed with {len(verifier.errors)} issue(s):")
        for err in verifier.errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        status_msg = "PASS: All structural integrity, relational links, and inventory checks passed."
        if args.schema:
            status_msg += " All JSON Schema Draft 2020-12 checks passed."
        print(status_msg)
        sys.exit(0)


if __name__ == "__main__":
    main()
