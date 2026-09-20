# Anti-Slop Audit: Audit Reports (Issues, Bots, Archive)

# Technical Prose Quality Audit & Anti-Slop Evaluation

**Target Reports:**
- Report 1: `reports/marketplace-comprehensive-issues-audit.md`
- Report 2: `reports/marketplace-bots-security-audit.md`
- Report 3: `reports/checkpoint3-archive-audit-report.md`

---

## 1. Overall Anti-Slop Verdict: PASS

The evaluated reports demonstrate high technical precision, concrete source-anchored mechanisms (AST parsing, Git object modes `120000`, SIGPIPE 141, PID signaling semantics), and strict data-grounded metrics. Claims avoid generic hyperbole and uncalibrated dramatic adjectives. A small set of copula displacements, formulaic filler phrases, and minor discrepancies between reports require remediation.

---

## 2. Concrete Findings & Proposed Remediations

| Report & Section | Quoted Text | Anti-Slop Violation Category | Proposed Lean Replacement |
| :--- | :--- | :--- | :--- |
| **Report 1**<br>§ 1 (Provenance Boundary) | `While 600 processed chunk result files demonstrate execution of the pipeline, individual model extractions represent heuristic LLM interpretations.` | Copula Displacement | *The pipeline processed 600 chunk result files; individual model extractions remain heuristic LLM interpretations.* |
| **Report 1**<br>§ 2.1 (Sampling / Count Discrepancy) | `Across marketplace history, 161 distinct submissions were flagged for this vector...` (Report 2, § 1) vs. `A total of 201 distinct plugin issues... were blocked specifically due to AI agent steering directive files...` (Report 1, § 2.1) | Factual / Carrier Inconsistency | Reconcile population filters: state explicitly whether 161 denotes initial reviews while 201 includes re-opened/re-evaluated verification updates. |
| **Report 2**<br>§ 1 (Executive Summary) | `It operates in an environment where untrusted third-party inputs... are processed by GitHub Actions runners holding repository write privileges...` | Verbose Copula / Passive Padding | *GitHub Actions runners with write privileges (`contents: write`, `issues: write`, `pages: write`, `id-token: write`) process untrusted inputs (issue titles, bodies, commit SHAs, and repository trees).* |
| **Report 2**<br>§ 3.3 (Automation Gap) | `In security-baseline-scope.mjs, markdown files other than the root README are ignored.` | Passive Construction | *`security-baseline-scope.mjs` ignores markdown files other than the root README.* |
| **Report 3**<br>§ 1.2 (Scope Note) | `It is worth noting that these metrics represent heuristic and deterministic pattern matches...` *(variant in Note on Terminology)* | Formulaic Filler / Transition | *These metrics record heuristic and deterministic pattern matches produced by the static linter.* |
| **Report 3**<br>§ 3.1 (Stratification) | `While test scripts should ideally reflect secure conventions, they do not expose runtime daemon services in user desktop sessions.` | Advisory Preachiness / Moralizing ("ideally reflect") | *Test scripts do not run as desktop session daemons.* |
| **Report 3**<br>§ 3.2 (Coverage Disambiguation) | `Inspection shows omniscope-search is a 2,446,760-byte compiled ELF executable... manifest presence is not proof of full executable code coverage.` | Copula Displacement | *`bin/omniscope-search` is a 2,446,760-byte compiled ELF binary. Manifest presence does not imply binary source inspection.* |

---

## 3. Summary of Tone, Objectivity, and Precision

- **Tone & Affect:** Highly clinical and objective. The prose avoids hyperbolic markers (*"catastrophic"*, *"game-changing"*, *"critical nightmare"*). Vulnerabilities and parser bypasses are documented via reproducible code snippets and exact regex failure cases (`literalShellPayload` regex `/^-c\s+/i` failing on `-lc`).
- **Mechanism Over Adjectives:** Risks are stated in terms of execution mechanics:
  - *Report 1:* Documents prompt-injection vectors by tracing the clone path into `~/.config/omarchy/plugins/` where local coding agents inherit untrusted context.
  - *Report 2:* Pinpoints POSIX signaling circumvention (`pkill -F <file>` bypassing string checks for `basename === "kill"`).
  - *Report 3:* Details SIGPIPE exit code 141 under bash `set -o pipefail` paired with early-terminating consumers (`head`, `grep -q`).
- **Carrier-Bound Conclusions:** Recommendations map to specific repository scripts (`build-catalog.mjs`, `security-baseline-analysis.mjs`, `security-baseline-scope.mjs`) and configuration paths rather than abstract security homilies.
