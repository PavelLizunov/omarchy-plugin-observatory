# Agent Readability Audit: docs/marketplace-acceptance-guide.md

# AI Agent Document Evaluation Report: `marketplace-acceptance-guide.md`

## Agent Readability Score: 84 / 100

*The document provides exceptionally strong formal invariants, exact regex patterns, and deterministic validation requirements. However, it suffers from duplicate Rule IDs, uninitialized variables in Bash snippets, fragment-only QML snippets, and conversational token overhead (audit anecdotes).*

---

## 1. Scannability & Anchor Analysis

* **Heading Hierarchy & Discoverability:** **High.** The document is organized logically into Specification, Acceptance Baseline, Advisory Patterns, and CLI tooling. An agent can jump directly to Section 3 for strict manifest schema checks or Section 6 for CLI execution flags.
* **Taxonomy Table (Section 2):** Extremely effective for zero-shot tabular parsing into AST/JSON dictionaries by an agent.
* **Code Fence Tagging:** All code blocks have explicit language identifiers (`bash`, `qml`).
* **Anchor Friction:** Rule IDs in Section 2 map directly to section headings (e.g., `MKT-001` -> `3.1`, `SEC-004` -> `5.2`), but lack explicit anchor tags or unified slug keys for automated lookup tables.

---

## 2. Code Snippet Actionability Audit

| Section | Target | Snippet Utility | Deficiencies / Agent Execution Blockers |
| :--- | :--- | :--- | :--- |
| **4.1** | Bash (Vulnerable) | ⚠️ **Unsafe Negative Pattern** | Lacks a dedicated negative fence annotation. If an agent naively grabs the first code block under `SEC-002`, it risks copying vulnerable code. |
| **5.1** | QML (`Text`) | ⚠️ **Fragment Only** | Missing `import QtQuick 2.15`. References undefined `root.dynamicWindowTitle`. Cannot be directly compiled as a QML component. |
| **5.2** | QML (`Process`) | ⚠️ **Fragment Only** | Missing import statements (`import Quickshell 1.0` or `import Quickshell.Io 1.0`). Uses `root`-level peer timers that require an enclosing `Item` or `QtObject`. |
| **5.3** | Bash (Sanitize) |  **Production-Ready** | Valid, self-contained shell environment reset (`#!/usr/bin/bash -p`). Immediately copy-pasteable. |
| **5.4** | Bash (Pipefail) | ⚠️ **Uninitialized Variable** | References uninitialized `$INPUT`. If executed via `set -u` or in an automated test harness, the pipeline fails or produces empty strings. |
| **5.5** | Bash (Temp Dir) | ⚠️ **Uninitialized Variable** | Checks `[[ ! "$PLUGIN_ID" =~ ... ]]` without initializing `$PLUGIN_ID`. Must be wrapped in a function or declare a fallback/argument parameter. |
| **5.6** | QML (Focus) | ⚠️ **Single Property** | Single property assignment without enclosing surface declaration (`ShellSurface`, `PanelWindow`) or required Wayland import (`import Quickshell.Wayland 1.0`). |
| **5.7** | Specs (Remote URI) | ❌ **Missing Code** | Contains a 6-point bulleted contract (DNS filtering, SNI pinning via `CURLOPT_RESOLVE`, byte caps) but **no implementation snippet**. An LLM must generate complex networking logic from scratch. |
| **5.8** | QML (`Loader`) | ⚠️ **Fragment Only** | Fragment without enclosing parent, missing `root.showCard` and `root.safeData` declarations. |

---

## 3. Identified Ambiguities & Friction Points for LLMs

### A. Duplicate Rule ID Collision (`SEC-002`)
In Section 2 (Taxonomy Table):
* `SEC-002` is assigned to **`privileged-process-control-from-shared-temp`** (Severity: HIGH, Tier: Automated Baseline).
* `SEC-002` is **also** assigned to **`shared-temp-path-state`** (Severity: HIGH, Tier: Advisory).
* *Machine Impact:* Key collision when an agent ingests the rule matrix into a hash map (`rules["SEC-002"]`). One rule will overwrite the other.

### B. Incomplete Manifest `id` Regex vs. Prose Invariants
Section 3.1 specifies:
* Regex: `^[a-z0-9][a-z0-9._-]{0,127}\Z`
* Prose constraints: *"cannot contain `..` or leading/trailing whitespace; reserved namespace `omarchy.*` is prohibited"*.
* *Machine Impact:* The regex permits `foo..bar` and `omarchy.plugin`. An agent relying strictly on regex compilation will fail to reject prohibited IDs unless it synthesizes negative lookaheads (`^(?!omarchy\.)(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}\z`) or separate conditional branches.

### C. Undefined Behavior for Non-Bar Entrypoints
Section 3.1 specifies:
* *"For kind `'bar-widget'`, the object key must be `'barWidget'`."*
* *Machine Impact:* It does not specify the casing convention for other multi-word kinds. If a plugin kind is `"bar"`, `"menu"`, `"overlay"`, `"panel"`, or `"service"`, are keys 1:1 identical to kind strings? Explicit mappings for all 6 kinds must be stated.

---

## 4. Token Efficiency & Overhead Analysis

* **Context Window Waste:** ~350 tokens consumed by non-actionable background narrative.
  * Section 1 (Executive Overview): Explains Quattro architecture and unified sessions. Redundant for coding agents that only need validation rules.
  * Section 5 Preamble: Cites retrospective audit data (*"Empirical static analysis across 242 Wave 3 community repositories identified advisory pattern matches in 168 repositories (69.4% advisory match rate...)*").
  * Section 5.9: Mentions human reviewer trivia (*"e.g. HANCORE-linux across 161 distinct issues, representing 174 objection entries, including #6873, #7377..."*).

---

## 5. Actionable Recommendations to Optimize for Coding Agents

1. **Resolve Rule ID Collisions:**
   * Rename `shared-temp-path-state` from `SEC-002` to `SEC-010` (or `SEC-002B`). Ensure all taxonomy IDs are globally unique keys.

2. **Supply a Single Unified Manifest ID Regex:**
   * Replace the partial regex and prose caveats with an all-in-one enforceable regex:
     ```regex
     ^(?!omarchy\.)(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$
     ```

3. **Complete QML & Bash Snippets:**
   * Provide fully formed, valid QML components with root elements and imports so agents can copy-paste directly into test fixtures.
   * Parameterize Bash snippets with positional defaults:
     ```bash
     PLUGIN_ID="${1:-myplugin}"
     INPUT="${2:-}"
     ```

4. **Add a Reference Implementation for SEC-005:**
   * Add a complete Python/Bash/CURL fetch helper implementing the RFC 1918/IPv6 CIDR checks and `curl --resolve` logic specified in Section 5.7.

5. **Eliminate Narrative Metadata for Agent Prompts:**
   * Condense the document for agent ingestion by moving historical audit metrics and human maintainer references to a separate human-facing changelog.
