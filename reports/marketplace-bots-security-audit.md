# Comprehensive Security & Architectural Audit of Marketplace Bots & GitHub Actions Automation

**Target Repository:** `omacom/omarchy-plugin-marketplace` @ commit `08703e0d729d45d361a919ae1d61e992e7553a84`  
**Audit Scope:** All 10 GitHub Actions workflows (`.github/workflows/*.yml`) and 34 Node.js automation scripts (`scripts/*.mjs`)  
**Auditor:** DeepSeek Harness / Claude Opus / Astra Verification  
**Date:** 2026-09-20  

---

## 1. Executive Summary

The marketplace automation engine orchestrates intake, validation, security baselining, maintainer review, and deployment for community plugins. It operates in an environment where untrusted third-party inputs (issue titles, issue bodies, author comments, external Git commit SHAs, and entire third-party repository file trees) are processed by GitHub Actions runners holding repository write privileges (`contents: write`, `issues: write`, `pages: write`, `id-token: write`).

### Key Audit Conclusions
1. **Runner Script Injection Hygiene (EXCELLENT):** Workflows consistently avoid inline expression interpolation (`${{ github.event... }}`) within shell `run:` blocks. Untrusted metadata is mapped strictly to environment variables and parsed safely via Node.js heredocs (`node <<'NODE'`), preventing arbitrary shell command injection through maliciously formatted issue titles or markdown bodies.
2. **State & Attestation Integrity (STRONG):** State transitions between validation, review, and approval are guarded by a structured marker protocol (Marker Protocol v4 with Base64URL-encoded JSON payloads and issue-event binding). Authentication relies on GitHub API comment author verification (`user.login === "github-actions[bot]"`) and actor permission checks (`canApprove`), rather than cryptographic digital signatures.
3. **Automated Security Baseline Blindspots (CONFIRMED):**
   - **Scope Exclusion in Auxiliary Directories (`security-baseline-scope.mjs`):** The automated security scanner explicitly excludes directories named `docs/`, `fixtures/`, `test/`, `tests/`, `spec/`, `specs/`, `.github/`, and `node_modules/` from general discovery. While manifest-declared entry points are forced into scanning, indirectly invoked runtime helpers or sub-scripts located in these directories are completely bypassed by automated baseline analysis.
   - **Alternative Execution Sinks (`security-baseline-analysis.mjs`):** The baseline's `privilegedKillCommand` detector checks strictly for `executable.basename === "kill"`. It does not detect `pkill -F <file>`, pipelined `xargs kill`, or scripting interpreter sinks (e.g. `sudo python3 -c "import os; os.kill(...)"`).
   - **Absence of Automated `SEC-009` Detection:** The automated baseline has no detector for AI agent directives (`AGENTS.md`, `agent.md`, `CLAUDE.md`, `.cursorrules`). Across marketplace history, 161 distinct submissions were flagged for this vector exclusively during human maintainer review.
4. **Catalog Compiler Resource Characteristics (`build-catalog.mjs`):**
   - Image optimization uses `sharp` with `limitInputPixels = 40_000_000` (40 MP) and `previewByteLimit = 50 * 1024 * 1024` (50 MB). Processing is executed in an awaited sequential loop per repository (`await validateBeforeStagingPreview` in `build-catalog.mjs:2141–2151`), mitigating concurrent memory exhaustion. Resource exhaustion under pathological inputs remains an unmeasured risk pending verified runner capacity benchmarks.

---

## 2. GitHub Actions Workflow Security & Permissions Analysis

### 2.1 Complete Workflow Inventory & Effective Permissions

The repository defines exactly 10 GitHub Actions workflows. Below is the comprehensive mapping of trigger contexts, top-level declared default permissions, and effective job-level privileges:

| Workflow File | Trigger Events | Top-Level Declared Permissions | Job-Level Effective Permissions | Risk & Security Analysis |
| :--- | :--- | :--- | :--- | :--- |
| `route-issue-automation.yml` | `issues: [opened, edited, reopened, labeled, unlabeled]` | `permissions: {}` (Empty) | `route`: `permissions: {}`<br>`validate-submission`: `actions: read`, `contents: read`, `issues: write`<br>`validate-update`: `actions: read`, `contents: read`, `issues: write`<br>`verify-plugin`: `actions: read`, `contents: write`, `issues: write`, `pages: write`, `id-token: write`<br>`publish-snapshot`: `contents: write`, `issues: write`, `pages: write`, `id-token: write` | **Central Entry Router:** Top-level workflow declares empty permissions. Calls reusable workflows via `workflow_call`, explicitly delegating elevated permissions only to target jobs upon verifying issue state, labels, and event actions. |
| `validate-submission.yml` | `workflow_call` | `contents: read`, `issues: read` | `validate`: `contents: read`, `issues: read`<br>`mutation-route`: `issues: read`<br>`publish`: `actions: read`, `issues: write`<br>`publish-fallback`: `actions: read`, `issues: write` | **Intake Validator:** Runs read-only checks against untrusted plugin snapshots; comments validation verdicts back to the issue. |
| `validate-plugin-update.yml`| `workflow_call` | `contents: read`, `issues: read` | `route`: `contents: none`<br>`analyze`: `contents: read`, `issues: read`<br>`mutation-route`: `issues: read`<br>`publish`: `actions: read`, `issues: write`<br>`publish-fallback`: `actions: read`, `issues: write` | **Update Validator:** Validates target update commit SHA against repository default-branch HEAD. |
| `verify-plugin.yml` | `workflow_call` | *(Not declared; inherits caller/default)* | `route`: `contents: none`<br>`analyze`: `contents: read`, `issues: read`<br>`publish`: `actions: read`, `contents: write`, `issues: read`<br>`deploy`: `contents: read`, `pages: write`, `id-token: write`<br>`report`: `actions: read`, `issues: write`<br>`report-failure`: `issues: write` | **Snapshot Verifier:** Enforces maintainer verification attestations before publishing verified records and triggering deployment. |
| `approve-submission.yml` | `workflow_call` | *(Not declared; inherits caller/default)* | `approve`: `contents: read`, `issues: read`<br>`publish`: `contents: write`, `issues: read`<br>`deploy`: `contents: read`, `pages: write`, `id-token: write`<br>`finalize`: `issues: write`<br>`report-failure`: `issues: write` | **Publication Pipeline:** Commits approved plugin to `registry.json` and deploys catalog. Enforces approver role verification (`canApprove`). |
| `delist-plugins.yml` | `workflow_dispatch` (inputs: `plugin_ids`, `confirm_delisting`) | `permissions: {}` (Empty) | `authorize`: `permissions: {}`<br>`delist`: `contents: read`<br>`verify_publication`: `actions: read`, `contents: read`<br>`publish`: `actions: read`, `contents: write`<br>`deploy`: `contents: read`, `pages: write`, `id-token: write` | **Manual Delisting:** Restricts invocation to authorized maintainers; retires plugin listings from `registry.json`. |
| `refresh-catalog.yml` | `schedule: cron "17 4 * * *"`, `workflow_dispatch` | *(Not declared; inherits caller/default)* | `refresh`: `contents: read`<br>`publish`: `contents: write`<br>`deploy`: `contents: read`, `pages: write`, `id-token: write`<br>`alert`: `issues: write` | **Daily Catalog Maintenance:** Scheduled rebuild of marketplace catalog and search index from trusted `main`. |
| `deploy-pages.yml` | `push: branches [main]`, `workflow_dispatch` | *(Not declared; inherits caller/default)* | `prepare`: `contents: read`<br>`deploy`: `contents: read`, `pages: write`, `id-token: write` | **Static Site Deployment:** Deploys pre-built website artifact to GitHub Pages. |
| `provision-labels.yml` | `workflow_dispatch` | `issues: write` | `provision`: `INHERITED` (`issues: write`) | **Repository Management:** Re-provisions canonical issue labels. |
| `verify.yml` | `pull_request`, `workflow_dispatch` | `contents: read` | `verify`: `INHERITED` (`contents: read`) | **PR CI Test:** Runs npm tests on internal pull requests and manual dispatches. |

### 2.2 Script Injection Resistance (`${{ github.event... }}`)
Audit of all 10 YAML files confirms zero instances of inline GitHub context interpolation inside shell `run:` blocks.
All issue metadata (titles, bodies, actor logins, label names) is forwarded strictly as environment variables:
```yaml
env:
  EVENT_ACTION: ${{ github.event.action }}
  ISSUE_BODY: ${{ github.event.issue.body }}
  ISSUE_TITLE: ${{ github.event.issue.title }}
```
The receiving shell steps execute Node.js via quoted heredocs (`node <<'NODE'`), which isolates untrusted strings from shell expansion, variable substitution, and token splitting.

### 2.3 Time-of-Check to Time-of-Use (ToCToU) Defense & Approver Verification
In `approve-submission.mjs` and `approve-plugin-update.mjs`:
- **Approver Role Verification:** `canApprove(permission)` queries the GitHub Collaborators API to verify that `github.actor` holds `admin`, `maintain`, or `write` permission on the marketplace repository.
- **Content Tampering Guard:** The script enforces `assertApprovedIssueBody` and `assertApprovedIssueTitle`. If the submitter modifies the issue text concurrently while maintainers review or label it, the job aborts:
  ```javascript
  if (String(currentBody || "") !== approvedBody) {
    throw new SubmissionApprovalError(
      "approval-body-changed",
      "The submission changed after approval; review it again before reapplying approved-and-verified"
    );
  }
  ```
- **Fresh Live Rescan:** Prior to modifying `registry.json`, `runSecurityBaseline` is executed on the runner against the exact verified commit SHA, preventing race conditions where upstream Git refs change after initial submission.

---

## 3. Automated Security Baseline Vulnerabilities & Bypasses

The Automated Security Baseline (`scripts/security-baseline-analysis.mjs` and `scripts/security-baseline-scope.mjs`) implements Policy v3 and Marker Protocol v4. Our audit identified specific architectural blindspots and pattern bypasses:

### 3.1 Scope Exclusion in Auxiliary Directories (`security-baseline-scope.mjs`)
In `security-baseline-scope.mjs:28-38`:
```javascript
const excludedDirectories = new Set([
  ".github",
  "coverage",
  "docs",
  "fixtures",
  "node_modules",
  "spec",
  "specs",
  "test",
  "tests",
]);
```
- **Scope Contract:** `isSecurityScanPath()` returns `false` for any file located under these directory paths, unless the file is explicitly declared as a root manifest entry point (`security-baseline-scope.mjs:280,327–339`).
- **Blindspot Mechanism:** If a plugin declares entrypoint `Widget.qml` at root, but `Widget.qml` executes a secondary script located under `docs/install.sh` or `fixtures/helper.py` (e.g. `Process { command: ["bash", "docs/install.sh"] }`), `docs/install.sh` is **never scanned** by the security baseline engine.
- *Remediation:* Recursively trace and include all script files referenced by QML components, or restrict directory exclusions strictly to verified unit-test frameworks rather than broad directory name matches.

### 3.2 Process Signaling Execution Sinks Bypass (`security-baseline-analysis.mjs`)
In `security-baseline-analysis.mjs:1118-1129`:
`privilegedKillCommand` detects process termination by matching `executable.basename === "kill"`:
```javascript
if (/\b(?:sudo|pkexec)\b/.test(text)) {
  if (executable.basename === "kill") return true;
  const payload = literalShellPayload(command);
  if (payload && shellExecutable(payload).basename === "kill") return true;
}
```
- **Verified Bypasses (Reproduced against upstream analyzer):**
  1. `sudo pkill -F /tmp/proc.pid`: `pkill` with the `-F` flag reads the target PID directly from the specified file and terminates it with elevated privileges. Because `basename` is `"pkill"` rather than `"kill"`, the baseline returns no finding (`[]`).
  2. `cat /tmp/proc.pid | sudo xargs kill`: Pipelining target PIDs through `xargs` splits execution across commands; `shellExecutable` evaluates `xargs`, missing the downstream `kill`.
  3. `sudo python3 -c "import os; os.kill(int(open('/tmp/proc.pid').read()), 9)"`: Inline interpreter scripts performing process termination evade shell syntax analysis entirely.
  4. Combined interpreter flags: In `literalShellPayload`, the regex `/^-c\s+/i` expects `-c` as the immediate first option. Invoking `sudo bash -lc "kill $(cat /tmp/proc.pid)"` fails to match `/^-c\s+/i` and evades detection.

### 3.3 The Automation Gap: Absence of Automated `SEC-009` Detection
- **Observation:** In `security-baseline-scope.mjs`, markdown files other than the root README are ignored. Neither `build-catalog.mjs` nor `security-baseline-analysis.mjs` contains a rule detecting AI assistant steering files (`AGENTS.md`, `agent.md`, `CLAUDE.md`, `.cursorrules`).
- **Empirical Evidence from Issue Corpus:** In our audit of 7,732 marketplace issues (`reports/marketplace-comprehensive-issues-audit.json`), **161 distinct issues** contain 174 agent-steering-category entries across reviews and follow-up threads, including 157 entries attributed to `HANCORE-linux` citing AI agent directive files. These plugins routinely passed initial structural checks (`✅ Quattro compatibility passed`) and had to be flagged during maintainer review.

---

## 4. Catalog Compiler (`build-catalog.mjs`) Resource & Robustness Analysis

### 4.1 Image Optimization Parameters
In `scripts/build-catalog.mjs:35-37,1069-1089`:
- Previews are processed via `sharp` with explicit bounds:
  ```javascript
  export const previewByteLimit = 50 * 1024 * 1024;  // 50 MB
  export const previewPixelLimit = 40_000_000;       // 40 MP
  ```
- **Sequential Execution:** Catalog compilation processes plugins inside an awaited sequential loop (`await validateBeforeStagingPreview` in `build-catalog.mjs:2141–2151`). Sharp enforces `limitInputPixels: previewPixelLimit`.
- **Resource Assessment:** The sequential pipeline avoids concurrent decoding spikes across hundreds of images. Processing complex 40 MP images on standard GitHub Actions runners (7 GB RAM) consumes significant memory per decode; resource exhaustion remains an unmeasured risk pending benchmark validation under pathological image inputs.

### 4.2 Symlink Validation Rigor
- In `scripts/build-catalog.mjs:833-836`:
  ```javascript
  const entries = context.tree.filter((entry) => !pluginRoot || entry.path.startsWith(prefix));
  if (entries.some((entry) => entry.mode === "120000")) {
    checkError("manifest-invalid", `${manifestPath}: symlinks are not allowed in plugin folders`);
  }
  ```
- **Assessment:** Symlink detection checks Git tree object modes directly (`120000`), which is evaluated at the Git object level and cannot be bypassed via filesystem symlink resolution tricks.

---

## 5. Prioritized Recommendations for Marketplace Maintainers

| Priority | Component | Recommendation | Security Impact |
| :--- | :--- | :--- | :--- |
| **P1** | `validate-submission.mjs` | **Automate `SEC-009` Detection:** Add pre-flight checks rejecting `AGENTS.md`, `agent.md`, `CLAUDE.md`, and `.cursorrules` in plugin repositories. | Eliminates prompt-injection vectors automatically; removes manual review burden from 160+ submissions. |
| **P2** | `security-baseline-analysis.mjs` | **Expand Process Signaling Sinks:** Update `privilegedKillCommand` to detect `pkill` (including `-F`), `xargs kill`, and normalize multi-flag interpreter options (`-lc`, `-ec`). | Closes known local privilege-escalation bypasses. |
| **P3** | `security-baseline-scope.mjs` | **Scan Referenced Scripts:** Ensure secondary scripts invoked by QML components or setup helpers are included in baseline analysis regardless of parent folder name. | Prevents hiding unvetted shell payloads in `docs/` or `fixtures/`. |
| **P4** | `build-catalog.mjs` | **Tighten Image Bounds:** Consider reducing `previewPixelLimit` to 16 MP and `previewByteLimit` to 10 MB. | Protects runner memory during large catalog rebuilds. |

---

## 6. Audit Limitations

This audit was conducted by source inspection, AST tracing, and focused offline script executions against repository snapshot `08703e0d`. It did not perform live adversarial attacks against GitHub Actions infrastructure, execute untrusted third-party plugin binaries, or benchmark runner memory limits under full catalog scale.
