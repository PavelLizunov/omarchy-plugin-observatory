# Agent Readability Audit: docs/rule-matrix-specification.md

# Machine Validation & Static Analysis Audit Report

**Specification Evaluated:** `Marketplace Readiness Rule Matrix Specification (v1.2)`  
**Target Architecture:** Omarchy Quattro Linter & Static Analysis Engine  
**Machine Implementation Readiness Score:** **68 / 100**

---

## 1. Executive Summary & Readiness Assessment

While the document excels at architectural clarity, policy categorization, and defining compatibility rules (MKT-001 through MKT-003), it exhibits variance in **machine implementation readiness** across the security catalog (SEC-001 through SEC-008). 

- **MKT Rules (MKT-001..003) & Filename Gates (SEC-009)** are deterministic, highly specified, and ready for immediate AST/JSON-schema implementation.
- **SEC Rules (SEC-001..006, SEC-008)** define hazards and concepts well, but omit formal regex tokens, AST node specifications, boundary conditions (what constitutes a "dynamic" binding vs static binding), and standardized exit code contracts.

---

## 2. Rule-by-Rule Specification Rigor Audit

| Rule ID | Clear Target? | Deterministic? | Machine Actionability | Actionability Status & Gap Analysis |
| :--- | :--- | :--- | :--- | :--- |
| **MKT-001** | **Yes** (`manifest.json`) | **Yes** | **High** | Fully actionable via JSON Schema / scalar regexes. Missing exact schema for additional unlisted manifest keys (are unknown keys forbidden or ignored?). |
| **MKT-002** | **Yes** (Plugin subtree) | **Yes** | **High** | Git mode `120000` / filesystem `lstat` `S_ISLNK`. Deterministic. |
| **MKT-003** | **Yes** (Issue body string) | **Yes** | **High** | Regex provided (`^[0-9a-fA-F]{40}$`). Note: Missing instruction on whether multi-line issue text must extract via regex match or strict full-string match. |
| **SEC-001** | **Partial** (`*.sh`, `bin/*`) | **No** (Heuristic) | **Low** | Shell AST required. Parsing pipelines under `pipefail` preceding `head`/`grep -q`/`sed q` requires complex POSIX AST tracking. |
| **SEC-002** | **Partial** (`*.sh`, `*.py`, `*.qml`) | **No** (Heuristic) | **Low** | Lacks pattern definitions for detecting shared temp paths across 3 distinct languages (Shell/Python/QML). |
| **SEC-003** | **Yes** (`*.qml`) | **No** (Heuristic) | **Medium** | QML AST needed: Detect `Text` / `Label` items lacking `textFormat: Text.PlainText` whose `text` binding is non-literal. |
| **SEC-004** | **Yes** (`*.qml`) | **No** (Heuristic) | **Low** | Watchdog requirement across multiple disconnected QML components (`Timer`, `Process`) cannot be validated by simple static linting without semantic graph analysis. |
| **SEC-005** | **Yes** (`*.qml`) | **No** (Heuristic) | **Medium** | Needs regex / AST rule targeting `Image { source: ... }` matching remote URL schemes (`http://`, `https://`, dynamic bindings). |
| **SEC-006** | **Yes** (`*.qml`, `*.js`) | **Partial** | **Medium** | AST visitor for `CallExpression` where `callee` is `Qt.createQmlObject`. Non-literal detection needs boundary rules. |
| **SEC-007** | **Yes** (`*.qml`) | **Yes** | **High** | Concrete pattern provided: `WlrKeyboardFocus\.Exclusive` or `keyboardFocus:\s*1`. |
| **SEC-008** | **Partial** (`*.sh`, `bin/*`) | **No** (Heuristic) | **Low** | Lacks deterministic criteria: When is a script a "daemon" vs a one-off helper? Unenforceable purely by file path. |
| **SEC-009** | **Yes** (Dist root/nested) | **Yes** | **High** | Exact file path matching (`AGENTS.md`, `agent.md`, `CLAUDE.md`, `.cursorrules`). Deterministic glob check. |

---

## 3. Ambiguities & Edge Cases in Rule Definitions

### 1. Exit Codes & Linter Output Contract
- **Gap:** The specification categorizes rules into `Hard Reject`, `Selective Block`, `Manual Review Blocker`, and `Advisory / Heuristic`, but provides **no standard CLI/machine output interface** (e.g., SARIF 2.1.0, JSON diagnostics, or standardized POSIX exit codes: `0` clean, `1` compatibility error, `2` policy block).

### 2. Missing AST Boundaries in QML Rules
- **SEC-003 (`qml-untrusted-text-markup`):** The spec notes that static strings and static ternaries are exempt. However, an automated parser needs an exhaustive whitelist of exempt AST nodes:
  - `Literal` (e.g. `"foo"`)
  - `BinaryExpression` composed strictly of Literals (`"foo " + "bar"`)
  - `ConditionalExpression` where both `consequent` and `alternate` are exempt Literals
  - *Edge Case:* What about `qsTr("Hello")` or `i18n("Hello")`? Without explicit exemption, linter will trigger massive false positives on localized strings.
- **SEC-004 (`process-unbounded-lifecycle`):** Enforcing a "two-stage watchdog pattern" via static linter is practically impossible without deep control-flow graph (CFG) analysis. A linter cannot verify if a `Timer` in file A guards a `Process` in file B. This rule must be re-scoped to a structural requirement (e.g., "every `Process` instance must have a bound `onStarted` or an adjacent sibling `Timer`") or left strictly to human review.
- **SEC-005 (`image-unvalidated-remote-uri`):** Lacks definition for what expressions constitute an unvalidated URI. Does it flag string literals starting with `http://` / `https://`? Does it flag any non-local property binding?
- **SEC-006 (`dynamic-qml-eval-sink`):** Does not specify whether template literals with interpolations (e.g., ``Qt.createQmlObject(`Item { width: ${w} }`)``) are treated as non-literals (they should be, but must be explicitly documented).

### 3. Shell / Script Scope Ambiguities
- **SEC-001 (`pipefail-sigpipe-crash`):** Requires checking whether `set -o pipefail` or `set -euo pipefail` was set earlier in the script. If a script executes `grep -q` without `pipefail`, it is safe. A regex cannot detect lexical scope or execution flow across source files.
- **SEC-008 (`ambient-path-daemon-exec`):** Target files are `*.sh`, `bin/*`. The spec states this applies to "periodic background daemons". Static analysis cannot distinguish between a short-lived packaging script and a daemon script unless annotated or executed via specific QML hooks.

---

## 4. Recommended Spec Tweaks for 100% Agent Self-Sufficiency

To allow zero-ambiguity codegen (linter/AST visitors), update the specification with the following formal directives:

### 1. Define Machine Output Contract
```yaml
exit_codes:
  0: "Clean / Advisory findings only"
  1: "MKT-COMPAT hard failure (MKT-001..003)"
  2: "MKT-POLICY blocker (SEC-009)"
  3: "Review-Required security baseline warning"
output_format: "SARIF v2.1.0 or JSON with { ruleId, file, line, col, severity, message }"
```

### 2. Formalize AST Visitor Nodes for QML Checks
- **SEC-003:**
  ```text
  Target: QmlObject[name="Text" || name="Label"]
  Condition:
    Property[name="textFormat"].value != "Text.PlainText"
    AND
    Property[name="text"].expression NOT IN [
      StringLiteral,
      TernaryExpression(StringLiteral, StringLiteral),
      CallExpression(callee IN ["qsTr", "i18n", "tr"], args=StringLiteral)
    ]
  ```
- **SEC-006:**
  ```text
  Target: CallExpression[callee="Qt.createQmlObject"]
  Trigger: argument[0].type != "StringLiteral"
  ```
- **SEC-007:**
  ```text
  Target: QmlBinding[name="keyboardFocus" || name="WlrLayershell.keyboardFocus"]
  Trigger: value IN [1, "WlrKeyboardFocus.Exclusive", "WlrLayershell.Exclusive"]
  ```

### 3. Replace Intractable Heuristics with AST Sinks
- **Reclassify SEC-004:** Demote from Automated Static Rule to `[MKT-POLICY]` (Manual Maintainer Review), OR re-specify as a deterministic shallow AST requirement: 
  *Flag any `Process` component that does not declare an `onStarted` handler.*
- **Reclassify SEC-001 & SEC-008:** Restrict deterministic linter enforcement strictly to Shebang inspection:
  - `SEC-008`: Shebang pattern matching: Flag if shebang does NOT match `^#!/usr/bin/(env\s+)?(bash|sh)(\s+-p)?$`. Flag if shebang is `/usr/bin/env bash` without hardened profile.

### 4. SEC-009 Glob Normalization
Explicitly specify the glob matching regex for AI steering artifacts:
```regex
(^|/)(AGENTS\.md|agent\.md|CLAUDE\.md|\.cursorrules)$
```
(Matching must be case-insensitive for `.cursorrules`, `agent.md`, `agents.md`, `claude.md`).
