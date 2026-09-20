# Omarchy Plugin Marketplace Acceptance & Security Hardening Guide

**Document Version:** 1.0.0  
**Target Platform:** Omarchy Quattro / Quickshell  
**Upstream Authority:** `omacom/omarchy-plugin-marketplace`  
**Reference Specification:** `docs/rule-matrix-specification.md` (v1.2)  
**Evaluator Implementation:** `tools/check_marketplace_readiness.py` (v1.3.1)  

---

## 1. Executive Overview

This guide provides community developers, plugin maintainers, and security reviewers with practical community guidance on the acceptance gates, validation criteria, common failure modes, and secure implementation patterns governing plugin submissions to the `omacom/omarchy-plugin-marketplace`, reflecting pinned upstream verification policies (Policy v3, Marker Protocol v4).

In the Omarchy Quattro architecture, plugins run within the user-privileged `omarchy-shell` session process. While this unified design avoids the overhead of separate process multiplexing, it necessitates careful pre-flight validation: a flawed or insecure plugin can destabilize user sessions, leak sensitive information, or expose local attack vectors.

*Disclaimer & Scope Limitations:* This document and the companion readiness linter (`tools/check_marketplace_readiness.py`) are advisory community tooling. A clean pre-flight scan confirms the absence of recognized compatibility blockers and static baseline markers within the scanner's supported scope; it does not guarantee upstream marketplace acceptance, replace human maintainer review, or certify complete runtime security.

Marketplace submission evaluations are stratified into four distinct policy layers:
1. **`[MKT-COMPAT]` — Catalog Compatibility:** Hard prerequisites enforced deterministically by the marketplace catalog compiler (`scripts/build-catalog.mjs`). A violation prevents catalog generation and causes immediate submission rejection.
2. **`[MKT-BASE]` — Automated Security Baseline:** High-confidence automated gates enforcing Policy v3 and Marker Protocol v4. Violations trigger an automated `needs-fixes` block in selective enforcement mode.
3. **`[MKT-POLICY]` — Marketplace Review Policy:** Security and distribution policy blockers enforced by human maintainers during manual verification (e.g. by `HANCORE-linux`), required before publication approval.
4. **`[OBS-REC]` — Observatory Hardening Recommendations:** Advisory runtime resilience, UI safety, and lifecycle best practices identified through empirical analysis across 242 Wave 3 production community plugins.

---

## 2. Rule Taxonomy & Policy Specification

The following matrix summarizes the validation rules implemented in the community readiness engine aligned with upstream marketplace gates:

| Rule ID | Rule Name | Policy Origin | Severity | Enforcement Tier | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **MKT-001** | `manifest-schema-invalid` | `[MKT-COMPAT]` | HIGH | Hard Blocker | `manifest.json` schema, field lengths (UTF-16), ID regex, entrypoint resolution. |
| **MKT-002** | `symlink-in-plugin-tree` | `[MKT-COMPAT]` | HIGH | Hard Blocker | Prohibition of symbolic links anywhere in the submitted plugin tree. |
| **MKT-003** | `update-commit-sha-invalid` | `[MKT-COMPAT]` | HIGH | Hard Blocker | Verification of 40-character hexadecimal commit SHA format; upstream verifies HEAD equality. |
| **SEC-002** | `privileged-process-control-from-shared-temp` | `[MKT-BASE]` | HIGH | Automated Baseline | Privileged commands (`sudo kill`, `pkexec kill`) consuming PIDs from `/tmp` or `/dev/shm`. |
| **SEC-001** | `pipefail-sigpipe-crash` | `[OBS-REC]` | MEDIUM | Advisory | Pipeline to early-closing consumer (`head`, `grep -q`) triggering SIGPIPE (exit 141) under `pipefail`. |
| **SEC-003** | `qml-untrusted-text-markup` | `[OBS-REC]` | MEDIUM | Advisory | QML `Text`/`Label` binding dynamic expressions without explicit `textFormat: Text.PlainText`. |
| **SEC-004** | `process-unbounded-lifecycle` | `[OBS-REC]` | MEDIUM | Advisory | Background `Process` element lacking watchdog timer, cancellation handling, or deadline budgets. |
| **SEC-005** | `image-unvalidated-remote-uri` | `[OBS-REC]` | MEDIUM | Advisory | Direct binding of untrusted remote HTTP(S) URIs into QML `Image.source`. |
| **SEC-006** | `dynamic-qml-eval-sink` | `[OBS-REC]` | HIGH | Advisory | Dynamic code evaluation via `Qt.createQmlObject()` using non-static expressions. |
| **SEC-007** | `layershell-exclusive-focus` | `[OBS-REC]` | HIGH | Advisory | Requesting exclusive keyboard focus (`WlrKeyboardFocus.Exclusive` / `1`) on layer-shell surfaces. |
| **SEC-008** | `ambient-path-daemon-exec` | `[OBS-REC]` | MEDIUM | Advisory | Shell helper scripts relying on ambient PATH resolution (`#!/usr/bin/env bash` or `sh`). |
| **SEC-009** | `agent-steering-directive-injection` | `[MKT-POLICY]` | HIGH | Policy Blocker | AI agent directive files (`AGENTS.md`, `agent.md`, `CLAUDE.md`, `.cursorrules`) in plugin tree. |
| **SEC-010** | `shared-temp-path-state` | `[OBS-REC]` | HIGH | Advisory | Unprivileged hardcoded paths in shared directories (`/tmp`, `/dev/shm`) vulnerable to TOCTOU/symlinks. |
| **OBS-001** | `file-size-limit-exceeded` | `[OBS-REC]` | HIGH | Diagnostic | File exceeds 1 MiB scan ceiling; full static analysis skipped for this file. |
| **OBS-002** | `file-read-error` | `[OBS-REC]` | HIGH | Diagnostic | Unreadable regular file encountered during scan due to I/O or permissions. |
| **OBS-003** | `directory-walk-error` | `[OBS-REC]` | HIGH | Diagnostic | Unreadable directory encountered during recursive filesystem scan. |

---

## 3. Marketplace Acceptance Criteria (`[MKT-COMPAT]`)

### 3.1 Manifest Schema Requirements (`MKT-001`)
Every plugin must declare a valid `manifest.json` in its root directory conforming to:
- **`schemaVersion`:** Must be exactly `1` (numeric integer/float `1.0`; boolean `true` is rejected).
- **`id` Canonical 3-Step Validation:**
  To ensure deterministic behavior across different regex engines without cross-language incompatibilities (e.g. negative lookaheads fail in Bash `[[ =~ ]]` with exit code 2 and are unsupported in RE2; Python `$` matches before a trailing newline), the plugin identifier is validated via three canonical rules:
  1. **Base Syntax & Length:** Must match `^[a-z0-9][a-z0-9._-]{0,127}\Z` (length 1–128 UTF-16 code units; start with lowercase alphanumeric). In Python, use `re.fullmatch()` or `\Z` to reject trailing newlines.
  2. **No Path Traversal:** Must not contain double dots (`..`).
  3. **No Reserved Namespace:** Must not start with `omarchy.`.
  *Cross-Language Note:* Do not attempt to collapse these into a single regular expression with negative lookaheads `^(?!omarchy\.)(?!.*\.\.)` in shell scripts or Go/RE2 environments.
- **String Field Length Limits:** Evaluated in ECMAScript UTF-16 code units using `String.prototype.trim()`:
  * `id`: 128 code units
  * `name`: 120 code units (required, non-empty)
  * `version`: 64 code units (required, non-empty)
  * `author`: 120 code units (required, non-empty)
  * `description`: 500 code units (required, non-empty)
  * `license`: 120 code units (optional; if present, cannot be `null` or empty)
- **Control Characters:** No string fields may contain C0 or C1 control characters (`[\x00-\x1f\x7f-\x9f]`). Note that whitespace characters U+0085 (NEL) and U+001C–U+001F are not trimmed by ECMA-262 and are rejected as control codes.
- **`kinds`:** Non-empty array containing only supported plugin kinds: `"bar"`, `"bar-widget"`, `"menu"`, `"overlay"`, `"panel"`, `"service"`.
- **`entryPoints`:** Object mapping each declared kind to its relative entrypoint path. For kind `"bar-widget"`, the object key must be `"barWidget"`.
- **`barWidget.defaultSection`:** If present, must be strictly one of: `"left"`, `"center"`, `"right"`.

### 3.2 Entrypoint Path Safety & Resolution
- Entrypoint paths must be safe relative paths without leading `/`, `./`, traversal segments (`..`), backslashes (`\`), drive colons (`:`), or control characters.
- Every entrypoint file must exist as a regular file within the plugin directory tree.

### 3.3 Strict Symlink Prohibition (`MKT-002`)
- No symbolic links may exist anywhere within the plugin tree. This applies to files, directories, nested submodules, and entrypoints.
- *Rationale:* Symlinks risk path traversal outside the repository sandbox during marketplace catalog generation, caching, and automated builds.

### 3.4 Version Updates & Commit Verification (`MKT-003`)
- **Format Requirement:** Update requests submitted to the marketplace must provide a 40-character hexadecimal Git commit SHA (`^[0-9a-fA-F]{40}$`). Short hashes or branch names are rejected.
- **Local vs. Upstream Verification:** The local pre-flight linter validates SHA length and syntax (`--check-sha`). Upstream marketplace ingestion (`scripts/plugin-update.mjs`) separately verifies that the target commit exists and matches the repository default-branch HEAD.

---

## 4. Automated Security Baseline Gates (`[MKT-BASE]`)

The Automated Security Baseline (Marker Protocol v4) prevents local privilege escalation vectors:

### 4.1 SEC-002: Privileged Process Control from Predictable Shared Temp
- **The Vulnerability:** An unprivileged shell script or QML helper reads a PID from a predictable shared path (e.g. `/tmp/*.pid` or `/dev/shm/*.pid`) and subsequently passes that PID to a privileged command:
  ```bash
  # Vulnerable Pattern (TRIGGERS HARD BASELINE BLOCK):
  PID=$(cat /tmp/daemon.pid)
  sudo kill "$PID"
  ```
- **Attack Mechanism:** In multi-user Linux environments, `/tmp` and `/dev/shm` are world-writable sticky directories. Any local unprivileged user can pre-create `/tmp/daemon.pid` as a symlink or write an arbitrary target PID (such as PID 1 or an essential system service). When the plugin helper runs with elevated privileges, it terminates or signals the attacker's chosen process.
- **Enforcement:** The baseline engine inspects shell scripts and QML execution arrays (`Quickshell.exec`, `Process.command`), unwrapping privilege escalation wrappers (`sudo`, `pkexec`, `timeout`, `env`) and subshells (`sh -c`, `bash -c`). Detecting this pattern triggers an automated baseline blocker.

---

## 5. Security & Reliability Hardening Patterns (`[OBS-REC]`)

Empirical static analysis across 242 Wave 3 community repositories identified advisory pattern matches in 168 repositories (69.4% advisory match rate across deployable components and test fixtures; see [`reports/checkpoint3-archive-audit-report.md`](../reports/checkpoint3-archive-audit-report.md)). These pattern matches represent candidates for contextual review rather than verified runtime vulnerabilities. Maintainers should apply the following hardening patterns to eliminate common resilience and UI risks:

### 5.1 Text & Markup Rendering Safety (`SEC-003`)
- **Vulnerability:** QML `Text` and `Label` components default to `Text.AutoText`. Qt Quick heuristically inspects strings: if dynamic data (e.g. track titles, window titles, system telemetry, weather data) contains HTML tags (`<font>`, `<b>`, `<img>`), Qt parses them as rich markup.
- **Impact:** Visual corruption, unexpected layout displacement, and unintended network fetches (e.g. inline `<img src="http://...">` tags triggering remote HTTP requests).
- **Remediation Pattern:** Always set `textFormat: Text.PlainText` on any UI element rendering dynamic or external text:
  ```qml
  // Component Fragment (Insert inside Item or Window component)
  // Required Context Property: string dynamicWindowTitle (e.g. bound from parent or model)
  Text {
      text: root.dynamicWindowTitle
      textFormat: Text.PlainText
  }
  ```

### 5.2 Process Watchdogs & Bounded Lifecycle (`SEC-004`)
- **Vulnerability:** Background `Process` elements executing external helpers without companion timers or cancellation handlers. If a helper hangs on I/O, network requests, or deadlocks, it remains alive indefinitely as a stuck background process.
- **Remediation Pattern:** Implement an owned, two-stage watchdog timer with strict cancellation on process exit to avoid stale signals targeting subsequent invocations:
  ```qml
  // Component Fragment (Requires Quickshell 1.0 or Quickshell.Io 1.0; place inside root Item/Object)
  Process {
      id: proc
      command: ["/usr/bin/some-tool", "arg1"]
      onRunningChanged: {
          if (proc.running) {
              // New invocation started: disarm stale escalation and arm watchdog
              escalationTimer.stop();
              watchdog.restart();
          } else {
              // Process terminated (naturally or killed): cancel both timers immediately
              watchdog.stop();
              escalationTimer.stop();
          }
      }
  }

  Timer {
      id: watchdog
      interval: 10000 // 10s execution budget for one-shot operation
      repeat: false
      onTriggered: {
          if (proc.running) {
              // Stage 1: Graceful SIGTERM via Quickshell running=false
              proc.running = false;
              escalationTimer.restart();
          }
      }
  }

  Timer {
      id: escalationTimer
      interval: 2000 // 2s grace period to allow graceful shutdown
      repeat: false
      onTriggered: {
          // Only escalate if the same process invocation is still alive
          if (proc.running) {
              // Stage 2: Forceful SIGKILL via Quickshell signal API
              proc.signal(9);
          }
      }
  }
  ```
- *Streaming Helpers:* For persistent daemon helpers, use request/heartbeat timers that reset on incoming frames rather than a fixed 10-second timer. Keep admission closed until `proc.running === false` confirms termination.

### 5.3 Shell Environment Sanitization & Explicit Interpreter (`SEC-008`)
- **Vulnerability:** Helper scripts using portable ambient shebangs (`#!/usr/bin/env bash` or `sh`) execute in user sessions where `$PATH` can be manipulated by virtual environments or local bin directories.
- **Remediation Pattern:** Standardize on explicit interpreter paths with Bash privileged mode:
  ```bash
  #!/usr/bin/bash -p
  # Runnable Helper Script Header
  set -euo pipefail
  export PATH="/usr/bin:/bin"
  export LC_ALL="C"
  unset BASH_ENV CDPATH GLOBIGNORE
  ```
  *Technical Scoping:* The `-p` option enables privileged mode, suppressing startup-file execution (`BASH_ENV`, `ENV`) and exported shell functions. Because `-p` does not clear inherited variables or reset `PATH`, explicitly set a trusted `PATH` and reset environment state at script initialization.

### 5.4 Pipefail, Early Consumers, and Bounded SIGPIPE Handling (`SEC-001`)
- **Vulnerability:** Combining `set -o pipefail` with early-closing consumers (`head`, `grep -q`, `sed '...q'`). When the consumer closes the pipe early, the upstream producer receives SIGPIPE (exit code 141). Under `set -e` (`errexit`), this non-zero status crashes the script.
- **Remediation Pattern:** Enforce a hard byte limit before accumulation, capture `${PIPESTATUS[@]}` directly in the executing shell, and ensure clean trap cleanup:
  ```bash
  #!/usr/bin/bash -p
  # Runnable Helper Script: Pipefail-safe bounded stream reader
  set -euo pipefail
  export PATH="/usr/bin:/bin"
  export LC_ALL="C"
  unset BASH_ENV CDPATH GLOBIGNORE

  # Parameters with fail-fast input validation
  INPUT="${1:?Error: INPUT string is required as \$1}"
  RAW_MAX_BYTES="${2:-65536}"

  # Validate MAX_BYTES: must be a positive non-zero integer <= 16 MiB
  if [[ ! "$RAW_MAX_BYTES" =~ ^[1-9][0-9]{0,7}$ ]] || [ "$RAW_MAX_BYTES" -gt 16777216 ]; then
      echo "Error: MAX_BYTES must be a positive integer <= 16777216 (16 MiB), got: $RAW_MAX_BYTES" >&2
      exit 1
  fi
  MAX_BYTES="$RAW_MAX_BYTES"

  tmp_out=$(mktemp) || exit 1
  trap 'rm -f -- "$tmp_out"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  # Execute pipeline byte-capped while preserving PIPESTATUS in the executing shell
  set +e
  printf "%s\n" "$INPUT" | head -c "$MAX_BYTES" > "$tmp_out"
  pipe_status=("${PIPESTATUS[@]}")
  set -e

  data=$(cat "$tmp_out")
  rm -f -- "$tmp_out"
  trap - EXIT INT TERM

  # pipe_status[0] is producer, pipe_status[1] is consumer (head)
  if [ "${pipe_status[1]}" -ne 0 ]; then
      echo "Consumer failed with exit ${pipe_status[1]}" >&2
      exit "${pipe_status[1]}"
  fi

  # Consumer succeeded: accept producer SIGPIPE (141) as normal early closure, but reject other producer failures
  if [ "${pipe_status[0]}" -ne 0 ] && [ "${pipe_status[0]}" -ne 141 ]; then
      echo "Producer failed with unexpected exit ${pipe_status[0]}" >&2
      exit "${pipe_status[0]}"
  fi
  ```

### 5.5 Safe Temporary Storage & PID Management (`SEC-010`)
- **Remediation Pattern:** Anchor all temporary state, sockets, and lockfiles to `$XDG_RUNTIME_DIR` under an owner-verified, mode `0700` subdirectory:
  ```bash
  #!/usr/bin/bash -p
  # Runnable Helper Script: Secure runtime directory initialization
  set -euo pipefail
  export PATH="/usr/bin:/bin"
  export LC_ALL="C"
  unset BASH_ENV CDPATH GLOBIGNORE

  # Parameter with fail-fast input validation
  PLUGIN_ID="${1:?Error: PLUGIN_ID is required as \$1}"

  RAW_BASE="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  # Normalize: require absolute path and strip trailing slashes to prevent symlink bypass
  if [[ "$RAW_BASE" != /* ]]; then
      echo "Base directory must be absolute: $RAW_BASE" >&2
      exit 1
  fi
  BASE_DIR="${RAW_BASE%"${RAW_BASE##*[!/]}"}"
  [ -z "$BASE_DIR" ] && BASE_DIR="/"

  # Validate base directory: must exist, be a directory, NOT a symlink, owned by UID, mode 0700
  if [ ! -d "$BASE_DIR" ] || [ -L "$BASE_DIR" ]; then
      echo "Insecure or missing runtime base directory: $BASE_DIR" >&2
      exit 1
  fi
  BASE_OWNER=$(stat -c '%u' "$BASE_DIR" 2>/dev/null) || exit 1
  BASE_MODE=$(stat -c '%04a' "$BASE_DIR" 2>/dev/null) || exit 1
  if [ "$BASE_OWNER" -ne "$(id -u)" ] || [ "$BASE_MODE" != "0700" ]; then
      echo "Insecure runtime base ownership ($BASE_OWNER) or mode ($BASE_MODE) on: $BASE_DIR" >&2
      exit 1
  fi

  # Validate plugin identifier format (canonical 3-step validation)
  if [[ ! "$PLUGIN_ID" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || [[ "$PLUGIN_ID" == *..* ]] || [[ "$PLUGIN_ID" == omarchy.* ]]; then
      echo "Invalid plugin identifier: $PLUGIN_ID" >&2
      exit 1
  fi

  RUNTIME_DIR="$BASE_DIR/omarchy-plugin-${PLUGIN_ID}"

  # Verify existing child directory or create securely
  if [ -e "$RUNTIME_DIR" ]; then
      if [ -L "$RUNTIME_DIR" ] || [ ! -d "$RUNTIME_DIR" ]; then
          echo "Runtime path is a symlink or not a directory: $RUNTIME_DIR" >&2
          exit 1
      fi
      DIR_OWNER=$(stat -c '%u' "$RUNTIME_DIR" 2>/dev/null) || exit 1
      DIR_MODE=$(stat -c '%04a' "$RUNTIME_DIR" 2>/dev/null) || exit 1
      if [ "$DIR_OWNER" -ne "$(id -u)" ] || [ "$DIR_MODE" != "0700" ]; then
          echo "Insecure ownership ($DIR_OWNER) or permissions ($DIR_MODE) on: $RUNTIME_DIR" >&2
          exit 1
      fi
  else
      mkdir -m 0700 "$RUNTIME_DIR" || exit 1
  fi

  PID_FILE="$RUNTIME_DIR/daemon.pid"
  ```
- *Process Identity Warning:* Storing PIDs in private directories does not prevent PID recycling issues. Because OS process IDs are recycled after termination, always verify process handles or use session tracking before signaling.

### 5.6 Layer-Shell Surface Focus Safety (`SEC-007`)
- **Vulnerability:** Configuring `WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive` (or literal `1`) on general widget surfaces.
- **Impact:** In Wayland layer-shell protocol implementations, exclusive focus requests compositor routing of all keyboard events exclusively to that surface. If the plugin's UI thread hangs, enters an infinite loop, or fails to release focus, the user can experience a session lockup where desktop shortcuts and other applications cannot receive input.
- **Remediation Pattern:** Standardize on `WlrKeyboardFocus.OnDemand` (2) for interactive popups or `WlrKeyboardFocus.None` (0) for passive status displays:
  ```qml
  // Component Property (Set on ShellSurface or PanelWindow)
  WlrLayershell.keyboardFocus: WlrKeyboardFocus.OnDemand
  ```
  *Note on OnDemand focus:* In Quickshell / wlroots, `OnDemand` surfaces retain keyboard focus once focused until clicked outside or explicitly dismissed; ensure dismiss handlers (`onPressedOutside` or Esc key events) properly restore compositor focus.

### 5.7 Remote Image Asset Security (`SEC-005`)
- **Vulnerability:** Directly binding `Image.source` to untrusted remote HTTP(S) URIs in QML.
- **Remediation Contract:** Delegate remote image retrieval to an explicit, user-authorized background helper that enforces:
  1. **Strict destination validation:** Requires `https://` schemes only. Resolves destination DNS and validates against non-public, loopback, and local-network ranges across both IPv4 (RFC 1918 private `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`; loopback `127.0.0.0/8`; link-local `169.254.0.0/16`) and IPv6 (loopback `::1`; link-local `fe80::/10`; unique local `fc00::/7`), explicitly normalizing and classifying IPv4-mapped IPv6 addresses (`::ffff:0:0/96`).
  2. **Redirect revalidation:** Re-applies scheme, hostname, and resolved IP address validation at every redirect hop, with a strict maximum redirect ceiling (e.g. ≤3 hops).
  3. **IP pinning with TLS hostname authentication:** To prevent time-of-check to time-of-use DNS rebinding, pin the connection directly to the pre-validated IP address while **strictly preserving the original hostname for TLS Server Name Indication (SNI) and X.509 certificate hostname verification** (e.g. using libcurl's `CURLOPT_RESOLVE`). Never disable CA or peer certificate verification.
  4. **Resource bounding:** Enforces a hard byte download limit (e.g. ≤5 MiB), decode dimension cap (e.g. ≤4096×4096 pixels), and connection/transfer timeouts.
  5. **Private cache:** Stores the verified asset into a private, mode `0700` cache directory under `$XDG_CACHE_HOME` and supplies the resulting verified local `file://` URI to QML.
  6. **Local Image Asynchronous Decoding:** For local images, specify `asynchronous: true` to prevent main-thread decoding stalls on large bitmaps.
- **Reference Implementation:** A complete, self-contained Python helper implementing this verification and IP-pinning contract is available at [`tools/helpers/fetch_remote_image.py`](../tools/helpers/fetch_remote_image.py).

### 5.8 Dynamic Evaluation Sinks (`SEC-006`)
- **Vulnerability:** Passing non-literal strings to `Qt.createQmlObject()`.
- **Remediation Pattern:** Replace dynamic component evaluation with declarative `Loader` items referencing developer-controlled static component files, passing dynamic values strictly via properties:
  ```qml
  // Component Fragment (Declarative replacement for dynamic object creation)
  // Required Context Properties: bool showCard, var safeData
  // Required Target Component File: components/DynamicCard.qml
  Loader {
      source: "components/DynamicCard.qml"
      active: root.showCard
      onLoaded: {
          item.cardData = root.safeData;
      }
  }
  ```

### 5.9 Prohibition of AI Agent Steering Directives (`SEC-009`)
- **The Issue:** Shipping AI assistant directive files (`AGENTS.md`, `agent.md`, `CLAUDE.md`, `.cursorrules`) inside the distributable plugin checkout.
- **Attack Vector & Risk:** Plugins are installed via `omarchy plugin add <repo>` through a direct `git clone` into the user's desktop configuration (`~/.config/omarchy/plugins/`). When users operate coding agents configured to inspect directory context (such as Codex, Claude Code, Cursor, OpenCode, or Windsurf) in or above that directory, those tools can discover and ingest root or nested `AGENTS.md` files. Depending on client tooling configuration, an untrusted third-party plugin can thus execute indirect prompt injection, steer the local coding assistant, exfiltrate credentials, or modify system files without the user's informed consent.
- **Maintainer Policy:** Human security reviewers (e.g. `HANCORE-linux` across 161 distinct issues, representing 174 objection entries, including #6873, #7377, #6995, #5772) enforce a hard stop: *"Remove AGENTS.md from the distributable plugin tree (or rename/relocate to ordinary documentation that agents do not auto-load)"*.
- **Remediation Pattern:** Never include `AGENTS.md`, `agent.md`, `CLAUDE.md`, or `.cursorrules` in the plugin repository root or distributable checkout. Rename contributor guides to neutral documentation names that coding agents do not automatically ingest:
  * Rename to `DEVELOPMENT.md` or `CONTRIBUTING.md`.
  * Exclude development-only agent instructions from release tags and source archives.

---

## 6. Pre-Flight Validation CLI Tool

Developers should run the standalone readiness linter locally prior to submitting pull requests or issue verification requests:

### 6.1 Basic Scan
```bash
python3 tools/check_marketplace_readiness.py /path/to/plugin
```

### 6.2 Structured JSON Output
```bash
python3 tools/check_marketplace_readiness.py /path/to/plugin --json
```

### 6.3 Local Update Format Verification with Target Commit SHA
```bash
python3 tools/check_marketplace_readiness.py /path/to/plugin --check-sha 0123456789abcdef0123456789abcdef01234567
```
Validates that the provided update target SHA conforms to the required 40-character hexadecimal format (upstream verification separately checks commit existence and repository default-branch HEAD equality).

### 6.4 Exit Code Contract
- `0`: Clean scan or advisory-only findings (`[OBS-REC]`).
- `1`: Validation failure — compatibility blocker (`[MKT-COMPAT]`), security baseline blocker (`[MKT-BASE]`), or maintainer review policy blocker (`[MKT-POLICY]`, e.g. `SEC-009`) detected.
- `2`: Target path discovery, file-not-directory target, unreadable directory, or argument syntax error.
