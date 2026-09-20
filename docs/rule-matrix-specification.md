# Marketplace Readiness Rule Matrix Specification (v1.2)

**Source Reference:** `omacom/omarchy-plugin-marketplace` @ `08703e0d729d45d361a919ae1d61e992e7553a84`  
**Quickshell Reference:** Quickshell v0.2.0 (`Quickshell.Wayland`, `Quickshell.Io`)  
**Status:** Approved revisions incorporated per Astra Checkpoint 1 feedback

---

## 1. Governance & Policy Taxonomy

Findings are explicitly categorized by their **Policy Origin** and **Publication Effect**:

| Policy Origin | Definition | Publication Effect |
| :--- | :--- | :--- |
| **`[MKT-COMPAT]`** | Marketplace Compatibility Validator (`scripts/build-catalog.mjs`) | **Hard Reject**: Fails CI build / catalog generation. |
| **`[MKT-BASE]`** | Automated Security Baseline Policy v3 (Selective Mode) | **Review-Required** or **Selective Block** (`needs-fixes`). |
| **`[MKT-POLICY]`** | Manual Maintainer Security Review Policy (enforced by human maintainers) | **Manual Review Blocker**: Blocks publication during human review until resolved. |
| **`[OBS-REC]`** | Observatory Systems & Runtime Hardening Recommendation | **Advisory / Heuristic**: Maintainer scrutiny or runtime stability risk. |

Detection modes are strictly separated:
- **Deterministic**: Pure syntactic or structural assertion with zero contextual ambiguity.
- **Heuristic**: Structural pattern that warrants human reviewer inspection.

---

## 2. Rule Catalog

| Rule ID | Name | Policy Origin | Default Severity | Detection Mode | Target Files |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **MKT-001** | `manifest-schema-invalid` | `[MKT-COMPAT]` | **HIGH (Compat)** | Deterministic | `manifest.json` |
| **MKT-002** | `symlink-in-plugin-tree` | `[MKT-COMPAT]` | **HIGH (Compat)** | Deterministic | Discovered plugin folder |
| **MKT-003** | `update-commit-sha-invalid` | `[MKT-COMPAT]` | **HIGH (Compat)** | Deterministic | Issue body (`[Verify]:`) |
| **SEC-001** | `pipefail-sigpipe-crash` | `[OBS-REC]` | **MEDIUM** | Heuristic | `*.sh`, `bin/*` |
| **SEC-002** | `privileged-process-control-from-shared-temp` | `[MKT-BASE]` | **HIGH (Baseline Blocker)** | Heuristic | `*.sh`, `*.qml` |
| **SEC-003** | `qml-untrusted-text-markup` | `[OBS-REC]` | **MEDIUM** | Heuristic | `*.qml` |
| **SEC-004** | `process-unbounded-lifecycle` | `[OBS-REC]` | **MEDIUM** | Heuristic | `*.qml` |
| **SEC-005** | `image-unvalidated-remote-uri` | `[OBS-REC]` | **MEDIUM** | Heuristic | `*.qml` |
| **SEC-006** | `dynamic-qml-eval-sink` | `[OBS-REC]` | **HIGH (Review)** | Deterministic / Heur | `*.qml`, `*.js` |
| **SEC-007** | `layershell-exclusive-focus` | `[OBS-REC]` | **HIGH (Review)** | Deterministic | `*.qml` |
| **SEC-008** | `ambient-path-daemon-exec` | `[OBS-REC]` | **MEDIUM** | Heuristic | `*.sh`, `bin/*` |
| **SEC-009** | `agent-steering-directive-injection` | `[MKT-POLICY]` | **HIGH (Policy Blocker)** | Deterministic | `AGENTS.md`, `agent.md`, `CLAUDE.md`, `.cursorrules` |
| **SEC-010** | `shared-temp-path-state` | `[OBS-REC]` | **HIGH** | Heuristic | `*.sh`, `*.py` |

---

## 3. Detailed Rule Specifications

### MKT-001: `manifest-schema-invalid`
- **Origin**: `[MKT-COMPAT]` (Enforced by `scripts/build-catalog.mjs:validateManifest`).
- **Hazard**: CI validation failure; plugin cannot be indexed or published.
- **Specification**:
  - `schemaVersion` must be numeric `1`.
  - Required non-empty string fields: `id`, `name`, `version`, `author`, `description`.
  - `id` syntax: lowercase alphanumeric start, matching `^[a-z0-9][a-z0-9._-]{0,127}$` (length 1–128 characters), no `..` segments, and must NOT start with reserved namespace `omarchy.`. Single-segment IDs (e.g. `clock`) are permitted by the validator.
  - No control characters (CR, LF, NUL, tabs) in `id`, `name`, `version`, `author`, or `description`.
  - `kinds`: non-empty array consisting only of supported kinds:
    ```text
    bar, bar-widget, menu, overlay, panel, service
    ```
  - `entryPoints`: object mapping every declared kind to a valid relative path:
    - Kind `"bar-widget"` maps to entry-point key `"barWidget"`.
    - All other kinds (`bar`, `menu`, `overlay`, `panel`, `service`) map to their kind name identically.
    - All entry points present in `entryPoints` (even undeclared kinds) are validated.
  - Path syntax: no leading `/`, no `..`, no backslashes (`\`), no colons (`:`), no CR/LF/NUL.
  - Every entry-point path must resolve to an existing regular file in the snapshot tree.
  - If `barWidget.defaultSection` is present, it must match one of: `"left"`, `"center"`, `"right"`.

---

### MKT-002: `symlink-in-plugin-tree`
- **Origin**: `[MKT-COMPAT]` (`validateManifestFiles` in `scripts/build-catalog.mjs`).
- **Hazard**: Rejection of plugin listing; community plugins must bundle regular files only.
- **Scope**: Evaluated specifically within each discovered **plugin folder** (from plugin root directory downward), checked against committed Git tree objects (mode `120000`) or directory traversal. Files outside the plugin folder (e.g. repository-level tool symlinks) do not trigger this compatibility failure.

---

### MKT-003: `update-commit-sha-invalid`
- **Origin**: `[MKT-COMPAT]` (`verify-plugin.yml` / `scripts/plugin-verification-request.mjs`).
- **Hazard**: Rejection of update promotion requests.
- **Specification**:
  - Issue body must contain a full 40-character hexadecimal commit SHA.
  - Input parsing accepts lowercase, uppercase, or mixed-case hexadecimal characters (`^[0-9a-fA-F]{40}$`) and normalizes to lowercase before comparison with inspected default-branch HEAD.
  - Short SHAs, branch names, tags, or commit URLs without a 40-char SHA are rejected.

---

### SEC-001: `pipefail-sigpipe-crash`
- **Origin**: `[OBS-REC]`.
- **Hazard**: In Bash scripts with `set -o pipefail` (or `set -euo pipefail`), piping output into early-closing consumers (such as `head -n`, `head -c`, `grep -q`, `grep -m`, `sed ... q`) triggers `SIGPIPE` (exit code 141) in the producer. Under `set -e`, this prematurely aborts the background helper script.
- **Clarification**: Ordinary `tail` and `wc` drain to EOF and do not cause early pipe closure.
- **Compliant Pattern**:
  ```bash
  # Write output to temporary file, then truncate only if larger than limit (avoids zero-padding):
  "$JQ" ... > "$TMP_FILE"
  CURRENT_BYTES=$(stat -c '%s' "$TMP_FILE")
  if [[ "$CURRENT_BYTES" -gt 16384 ]]; then
      truncate -s 16384 "$TMP_FILE"
  fi
  # Or handle status explicitly without masking other errors:
  output=$(some_command) || { status=$?; [[ $status -eq 141 ]] || exit "$status"; }
  ```

---

### SEC-002: `privileged-process-control-from-shared-temp`
- **Origin**: `[MKT-BASE]` (Automated Security Baseline Policy v3 / Marker Protocol v4).
- **Hazard**: Local privilege escalation. An unprivileged script reads a PID from a predictable shared path (`/tmp/*.pid` or `/dev/shm/*.pid`) and passes it to an elevated execution command (`sudo kill`, `pkexec kill`), allowing arbitrary local users to pre-create or rewrite PIDs to signal unintended processes.
- **Specification**: Evaluated across shell scripts and QML process command arrays (`Process.command`, `Quickshell.exec`). Privilege wrappers (`sudo`, `pkexec`, `timeout`, `env`) and subshells (`sh -c`, `bash -c`) are unwrapped.
- **Enforcement**: Hard baseline blocker (`needs-fixes`).

---

### SEC-003: `qml-untrusted-text-markup`
- **Origin**: `[OBS-REC]`.
- **Hazard**: Qt Quick `Text` items default to `Text.AutoText`. External or dynamic strings (process names, window titles, track names, SSIDs) containing HTML tags are rendered as Rich Text, leading to UI disruption or remote image beaconing via `<img>`.
- **Clarification**: Static string literals (`text: "Ready"`) and static ternary choices (`text: active ? "On" : "Off"`) are trusted.
- **Compliant Pattern**:
  ```qml
  Text {
      textFormat: Text.PlainText
      text: modelData.processName
      elide: Text.ElideRight
      width: parent.width
  }
  ```

---

### SEC-004: `process-unbounded-lifecycle`
- **Origin**: `[OBS-REC]`.
- **Hazard**: Unresponsive background processes hang indefinitely or exhaust memory in Quickshell's `StdioCollector`.
- **Quickshell API Contract**:
  - `proc.running = false` issues `SIGTERM`.
  - `proc.signal(9)` issues `SIGKILL`.
  - (Quickshell `Process` does NOT expose `terminate()` or `kill()` methods).
- **Compliant Two-Stage Watchdog Pattern**:
  ```qml
  property bool isBusy: false

  // Stage 2: Grace period before forceful SIGKILL
  Timer {
      id: graceTimer
      interval: 2000
      repeat: false
      onTriggered: {
          if (helperProc.running) {
              helperProc.signal(9); // SIGKILL
          }
      }
  }

  // Stage 1: Primary deadline sending SIGTERM
  Timer {
      id: watchdog
      interval: 8000
      repeat: false
      onTriggered: {
          if (helperProc.running) {
              helperProc.running = false; // SIGTERM
              graceTimer.start();
          }
      }
  }

  Process {
      id: helperProc
      command: ["/usr/bin/some-helper"]
      onStarted: watchdog.start()
      onExited: {
          watchdog.stop()
          graceTimer.stop()
          isBusy = false
      }
  }
  ```

---

### SEC-005: `image-unvalidated-remote-uri`
- **Origin**: `[OBS-REC]`.
- **Hazard**: Unsolicited remote network requests (tracking beacons or client-side SSRF against local subnets) via dynamic `Image { source: ... }` bindings.
- **Compliant Pattern**: Download remote assets via an explicit opt-in helper into a verified local runtime cache, then bind `Image.source` to `file://` or relative resource paths.

---

### SEC-006: `dynamic-qml-eval-sink`
- **Origin**: `[OBS-REC]`.
- **Hazard**: Dynamic code evaluation via `Qt.createQmlObject()` with non-literal string concatenation introduces arbitrary QML injection inside the shell process.
- **Compliant Pattern**: Use static QML components loaded via `Loader { source: "..." }` and configure parameters via property bindings.

---

### SEC-007: `layershell-exclusive-focus`
- **Origin**: `[OBS-REC]`.
- **Hazard**: Grabbing exclusive keyboard focus on layer-shell surfaces can freeze desktop interaction or act as a keylogger.
- **Quickshell API Contract**:
  - Module: `import Quickshell.Wayland`
  - Property: `WlrLayershell.keyboardFocus`
  - Enum (`WlrKeyboardFocus`): `None = 0`, `Exclusive = 1`, `OnDemand = 2`.
- **Detection Pattern**: `WlrKeyboardFocus\.Exclusive` or `WlrLayershell\.keyboardFocus:\s*1`.
- **Policy**: Exclusive focus (`1`) is flagged as `HIGH (Review)`; standard interactive widgets must use `None` (`0`) or `OnDemand` (`2`).

---

### SEC-008: `ambient-path-daemon-exec`
- **Origin**: `[OBS-REC]`.
- **Hazard**: Periodic background daemons resolving binaries through ambient `$PATH` or portable shebangs (`#!/usr/bin/env bash`) are vulnerable to shadow executable hijacking and `BASH_ENV` startup injection.
- **Compliant Pattern**:
  ```bash
  #!/usr/bin/bash -p
  export PATH="/usr/bin:/bin"
  unset BASH_ENV ENV CDPATH IFS
  readonly JQ="/usr/bin/jq"
  ```

---

### SEC-009: `agent-steering-directive-injection`
- **Origin**: `[MKT-POLICY]` (Manual Maintainer Security Review Gate, enforced by `HANCORE-linux`).
- **Hazard**: Indirect Prompt Injection and Local Agent Hijacking. When a plugin is installed via `omarchy plugin add`, its repository is cloned into the user's local Omarchy configuration (`~/.config/omarchy/plugins/`). When the user operates AI coding tools (such as Codex, Claude Code, Cursor, OpenCode, or Windsurf) in or above that directory, tools configured to discover workspace or repository instructions can ingest root or nested `AGENTS.md`, `agent.md`, `CLAUDE.md`, or `.cursorrules` files. Depending on client configuration, these directives can steer local agent execution, exfiltrate credentials, or alter system files without explicit user consent.
- **Specification**: No AI agent steering directives (`AGENTS.md`, `agent.md`, `CLAUDE.md`, `.cursorrules`) may be committed in the distributable plugin checkout.
- **Compliant Pattern**: Rename developer and contributor guidance to neutral documentation filenames that are not auto-ingested by AI agent harnesses (e.g. `DEVELOPMENT.md` or `CONTRIBUTING.md`).

---

### SEC-010: `shared-temp-path-state`
- **Origin**: `[OBS-REC]`.
- **Hazard**: General systems hardening advising that all persistent state, lockfiles, and helper IPC sockets reside under `$XDG_RUNTIME_DIR` rather than world-writable `/tmp` or `/dev/shm`.
- **Clarification**: Comparing `stat -c '%a'` against `"700"` (or `%04a` against `"0700"`) verifies that group and other permissions as well as special permission bits (setuid/setgid/sticky) are absent.
- **Compliant Pattern**:
  ```bash
  RUNTIME_BASE="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  STATE_DIR="$RUNTIME_BASE/omarchy-myplugin"
  mkdir -p -m 0700 "$STATE_DIR"
  [[ $(stat -c '%u:%04a' "$STATE_DIR") == "$(id -u):0700" ]] || exit 1
  ```

