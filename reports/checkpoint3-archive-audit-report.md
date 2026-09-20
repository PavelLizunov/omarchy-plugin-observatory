# Checkpoint 3: Wave 3 Archive Audit Report

**Date:** 2026-09-20  
**Evaluator:** Omarchy Plugin Observatory Linter (`tools/check_marketplace_readiness.py` v1.2.9)  
**Target Dataset:** `/var/lib/dsh/Project/sources_wave3_archive/` (242 Community Plugin Repositories)  
**Dataset Population:** 242 total plugin directories inspected; 242 valid `manifest.json` files discovered (100% manifest presence).

---

## 1. Executive Summary & Provenance Metadata

A comprehensive static audit was conducted across the Wave 3 community plugin archive (242 repositories) using the pre-flight readiness linter (`v1.2.9`).

### 1.1 Reproducibility & Provenance
- **Invocation:** `python3 tools/check_marketplace_readiness.py /var/lib/dsh/Project/sources_wave3_archive/ --recursive --json`
- **Scanner Hash (SHA-256):** `e7e632a4a36783c6ea3768bf4c74dae2aa053c8c5e7b0b324910d07c00673bf5`
- **Scan Result Hash (SHA-256):** `c641fbb067d3f7946340050deb666316d575f08c66343341482847bee6a690b8` (`reports/checkpoint3-archive-scan.json`, 749,422 bytes)
- **Test Suite Status:** `tests/test_check_marketplace_readiness.py` (23 test methods, exit code 0)

### 1.2 Summary of Findings
- **Total Plugin Directories Scanned:** 242
- **Manifest Discovery & Compatibility Checks (`[MKT-COMPAT]`):** **0 failures** (All 242 plugins satisfy manifest schema, ID formats, kinds array, relative entry-point resolution, and symlink prohibition).
- **Automated Security Baseline Pattern Matches (`[MKT-BASE]`):** **0 detections** (Zero instances of active privileged process control trusting PID files from predictable shared temporary state were detected within the scanner's supported shell grammar).
- **Observatory Advisory Pattern Matches (`[OBS-REC]`):** **1,323 rule-pattern findings** plus **1 coverage diagnostic** (1,324 total records) across 168 repositories (69.4% advisory match rate).
- **Repositories without Advisory Matches:** **74 repositories** (30.6% of archive).
- **Repositories with Advisory Matches:** **168 repositories** (69.4% of archive).

*Note on Terminology & Scope:* These metrics represent heuristic and deterministic pattern matches produced by the static linter. A zero count for `[MKT-BASE]` establishes only that no recognized baseline violations appeared in supported source files; it does not constitute an exhaustive security guarantee or formal certification by upstream marketplace maintainers. Similarly, advisory matches represent candidates for contextual review rather than verified runtime vulnerabilities.

---

## 2. Quantitative Findings Breakdown

### 2.1 Distribution by Policy Origin & Severity

| Record Category | Policy Origin | Severity | Record Count | % of Total Records |
| :--- | :--- | :--- | :--- | :--- |
| Catalog Compatibility Failure | `[MKT-COMPAT]` | HIGH | 0 | 0.0% |
| Security Baseline Violation | `[MKT-BASE]` | HIGH | 0 | 0.0% |
| Advisory Rule Pattern | `[OBS-REC]` | HIGH | 88 | 6.6% |
| Advisory Rule Pattern | `[OBS-REC]` | MEDIUM | 1,235 | 93.3% |
| Scanner Coverage Diagnostic | `[OBS-REC]` | HIGH | 1 | 0.1% |
| **Total Emitted Records** | | | **1,324** | **100.0%** |

### 2.2 Distribution by Validation Rule

*Affected Repositories:* Each plugin repository is counted at most once per rule (distinct repository population).

| Rule ID | Rule Name | Detection Mode | Severity | Record Count | Distinct Repositories | Non-Test Paths | Test / Fixture Files |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-003** | `qml-untrusted-text-markup` | Heuristic | MEDIUM | 913 | **104** | 913 | 0 |
| **SEC-008** | `ambient-path-daemon-exec` | Heuristic | MEDIUM | 102 | **48** | 69 | 33 |
| **SEC-004** | `process-unbounded-lifecycle` | Heuristic | MEDIUM | 97 | **35** | 97 | 0 |
| *Coverage* | `file-size-limit-exceeded` (SEC-004) | Deterministic | HIGH | 1 | **1** | 1 | 0 |
| **SEC-005** | `image-unvalidated-remote-uri` | Heuristic | MEDIUM | 67 | **41** | 67 | 0 |
| **SEC-001** | `pipefail-sigpipe-crash` | Heuristic | MEDIUM | 56 | **22** | 46 | 10 |
| **SEC-002** | `shared-temp-path-state` | Heuristic | HIGH | 53 | **21** | 23 | 30 |
| **SEC-007** | `layershell-exclusive-focus` | Deterministic | HIGH | 35 | **34** | 35 | 0 |
| **SEC-006** | `dynamic-qml-eval-sink` | Deterministic | HIGH | 0 | **0** | 0 | 0 |
| **Totals** | | | | **1,324** | **168\*** | **1,251** | **73** |

*\*Note:* 168 is the union of repositories having at least one record across all categories. The 1,251 non-test paths comprise 1,250 rule-pattern matches plus 1 scanner coverage diagnostic.

---

## 3. Contextual Triage & Detection Boundary Analysis

Static pattern matching flags potential risks, but real-world triage reveals important distinctions between deployable non-test paths, test fixtures, and scanner boundaries.

### 3.1 Non-Test Paths vs. Test Code Stratification
- **Test/Fixture Records (73 records):** 73 advisory records occur inside `test/` or `tests/` directories.
  - In `SEC-002` (shared temp path), **30 of the 53 records (56.6%)** reside in test suites (e.g. `14brussell_Steam-Game-Icons/tests/test_launcher_events.py` line 67 supplying a mock icon path `/tmp/icons/...` to a unit test).
  - In `SEC-008` (ambient PATH), 33 records reside in test runner scripts.
  - While test scripts should ideally reflect secure conventions, they do not expose runtime daemon services in user desktop sessions.
- **Non-Test Paths (1,251 records):** Represent 1,250 pattern matches and 1 coverage diagnostic across component QML files, scripts, and helper binaries. Contextual triage is necessary before equating these pattern matches with verified production vulnerabilities.

### 3.2 Coverage Limitation Disambiguation (Binary Executable in `bin/`)
- In repository `mbvlabs_omniscope`, the file `bin/omniscope-search` generated a `file-size-limit-exceeded` record under SEC-004.
- Inspection shows `omniscope-search` is a **2,446,760-byte compiled ELF executable**, not shell script source. The scanner heuristics inspect extensionless files in `bin/`, hitting the 1 MiB buffer ceiling.
- **Triage Result:** This is a scanner coverage diagnostic, not an unbounded process lifecycle bug. Binary analysis was not performed, and manifest presence is not proof of full executable code coverage.

### 3.3 Rule-Specific Risk Analysis & Known Scanner Boundaries

#### SEC-003: Dynamic QML Text Markup Injection (913 records, 104 repositories)
- **Symptom:** Binding `Text.text` or `Label.text` to dynamic model properties or variables without `textFormat: Text.PlainText`.
- **Nuance:** Default Qt Quick `Text.AutoText` attempts to parse HTML/rich text when strings contain tags. If dynamic data contains unescaped `<` or `&`, rendering artifacts or layout breaks occur.
- **Mitigation Pattern:** Add `textFormat: Text.PlainText` to all dynamic user-facing text elements.

#### SEC-004: Unbounded Process Lifecycle (97 records, 35 repositories)
- **Symptom:** Declaring a `Process` element without a companion watchdog `Timer` or explicit cancellation logic in the component.
- **Nuance:** Background processes running hanging network operations or long-running commands can remain alive as stuck background jobs.
- **Scanner Boundary:** The scanner's component-level heuristic checks whether `Timer` and cancellation signals exist in the file. An unrelated `Timer` in the same component can suppress the finding (false negative), while a process intentionally managed by an external controller may be flagged (false positive).
- **Mitigation Pattern:** Couple background `Process` items with a 2-stage watchdog timer (`running = false` followed by `signal(9)`).

#### SEC-002: Shared Temporary Paths (`/tmp`, `/dev/shm`) (53 records, 21 repositories; 23 non-test)
- **Symptom:** Hardcoded references to shared temporary paths.
- **Nuance & False Positives:** `3EYE3Y3_omarchy-capture-board/bin/capture-board-paste-text` uses an absolute `$MKTEMP` variable, secure random template generation, restrictive umask, and immediate unlink. Because it references `$MKTEMP` rather than the literal string `mktemp`, the static rule flagged it.
- **Mitigation Pattern:** Anchor temporary files strictly to `$XDG_RUNTIME_DIR` (mode 0700).

#### SEC-007: Layer-Shell Exclusive Focus (35 records, 34 repositories)
- **Symptom:** Setting `WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive` (or literal `1`).
- **Impact:** Grabbing exclusive keyboard focus on Wayland locks all user input to that surface; an unresponsive UI can lock the entire user session.
- **Mitigation Pattern:** Use `WlrKeyboardFocus.OnDemand` (2) or `WlrKeyboardFocus.None` (0).

#### SEC-001: Pipefail SIGPIPE Crash (56 records, 22 repositories; 46 non-test)
- **Symptom:** Combining `set -o pipefail` with early-closing consumers (`head`, `grep -q`).
- **Impact:** Downstream closing causes SIGPIPE (exit code 141), terminating the entire pipeline under `pipefail`.
- **Mitigation Pattern:** Explicitly catch exit 141 or truncate files conditionally using file size checks.

---

## 4. Top Repositories by Total Advisory Matches

The following repositories contain the largest raw counts of advisory pattern matches (primarily repetitive dynamic `Text` elements and helper scripts), derived directly from the scan dataset:

1. `layolayo_omarchy-the-eternal-moment`: **57 records** (SEC-003: 55; SEC-004: 1; SEC-005: 1)
2. `Signal-Six_Dungeons-Of-Omakon`: **43 records** (SEC-003: 42; SEC-004: 1)
3. `onelegdave_system-quikview`: **42 records** (SEC-003: 41; SEC-008: 1)
4. `jvlianodorneles_alcalc`: **40 records** (SEC-003: 38; SEC-008: 2)
5. `leonrlr4_days`: **38 records** (SEC-001: 3; SEC-002: 1; SEC-003: 27; SEC-005: 2; SEC-007: 1; SEC-008: 4)
6. `badgetobytes_omalander`: **34 records** (SEC-003: 34)
7. `ShahinMohamed_omarchy-spendwise`: **31 records** (SEC-003: 30; SEC-004: 1)
8. `dbohry_omarchy-notch`: **30 records** (SEC-003: 25; SEC-004: 3; SEC-005: 2)
9. `theothermike_omarchy-ansi-screensaver`: **29 records** (SEC-002: 1; SEC-003: 22; SEC-004: 1; SEC-005: 4; SEC-007: 1)
10. `KS7-10_omarchy-pulse`: **28 records** (SEC-001: 5; SEC-002: 10; SEC-003: 13)

---

## 5. Conclusion & Actionable Next Steps

1. **Marketplace Ingestion Readiness:** The scanner reported no `[MKT-COMPAT]` failures or `[MKT-BASE]` detections across the 242 repositories, subject to the coverage and grammar limitations described above.
2. **Hardening Priorities for Checkpoint 4 (Design Patterns):**
   - Provide standard QML snippet patterns for `Text.PlainText`.
   - Document the 2-stage `Process` watchdog pattern (`Timer` + graceful/forced termination).
   - Document safe layer-shell focus handling (`OnDemand`).
   - Standardize portable scripts to `#!/usr/bin/bash -p` and `$XDG_RUNTIME_DIR`.
