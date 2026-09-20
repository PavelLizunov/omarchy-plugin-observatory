# Agent Readability & Data Utility: Issue Audit Reports (MD & JSON)

# Autonomous Security Researcher Audit Evaluation

**Target Evaluated:**
- `reports/marketplace-comprehensive-issues-audit.md`
- `reports/marketplace-comprehensive-issues-audit.json`

---

## Data Structure & Agent Queryability Score: 78 / 100

*The dataset provides valuable high-level security metrics and cleanly parsed category counts, but suffers from inconsistent JSON entity schemas, key fragmentation, truncation in markdown tables, and partial entity serialization (focusing almost exclusively on agent steering while omitting deep-dive items for top categories).*

---

## JSON Schema Evaluation

### Strengths
1. **Direct Aggregations:** Summary keys (`type_distribution`, `outcome_distribution`, `manual_review_categories`, `reviewers_stats`) use uniform integer maps, enabling instantaneous `jq` filtering (e.g., `jq '.manual_review_categories | to_entries | sort_by(.value.blocker_instances) | reverse'`).
2. **Numeric ID Integrity:** In `agent_steering_entries`, `issue_number` and `comment_id` are preserved as clean numeric datatypes (or explicit `null`), preventing quote-stripping issues during programmatic lookups.
3. **Full-Length Text in JSON:** While Markdown truncates maintainer objections with ellipses (`...`), the JSON payload retains the un-truncated `detail` strings (e.g., issue #1683 details directory descriptors and loopback bypasses).

### Weaknesses & Anomalies
1. **Unnormalized Bot Error Keys:** The keys of `bot_validation_errors` conflate slug identifiers (`curl-pipe-shell`, `manifest-invalid`, `cargo-git-unpinned`) with long raw error messages containing formatting artifacts (`"The issue title must start with \`[Plugin]:\` and include the plugin name."`). An agent cannot query these programmatically without regex heuristics or natural language clustering.
2. **Asymmetric Record Representation:** While `manual_review_categories` reports 1,376 QML/Wayland and 1,294 script/binary blockers, the structured JSON array provides granular records *only* for `agent_steering_entries`. The larger categories lack structured queryable entries in this export.
3. **Schema Truncation Risk:** The JSON sample terminates abruptly at entry `#3546` without closing brackets, indicating payload truncation or streaming write issues that would cause strict JSON parsers (`json.loads()`, `jq`) to fail unless repaired.

### Missing Fields
- **Repository Base URL:** Lacks a top-level `repository` field (e.g., `"repository": "omacom/omarchy-plugin-marketplace"`), forcing agents to hardcode URL patterns to resolve `issue_number` into full web/API targets.
- **Rule/Standard Identifiers:** Entries contain free-text descriptions but lack strict classification tags (e.g., `"rule_id": "SEC-009"` or `"rule_id": "SEC-003"`), which are referenced in Markdown but omitted from JSON records.
- **Timestamp & State Metadata:** Missing `created_at`, `closed_at`, and `resolution_status` enum (`RESOLVED`, `TIMED_OUT`, `ABANDONED`).

---

## Markdown Summary Utility (RAG Effectiveness)

* **Executive Framing & RAG Chunking:** High. Sections are delineated with clean H2/H3 headers, markdown tables, and bulleted summaries, making chunking via standard text splitters (MarkdownHeaderTextSplitter) clean and coherent.
* **Contextual Threat Modeling:** Section 2.1 provides exceptional technical explanations of the security mechanics behind `SEC-009` (explaining how local AI agents execute automatic discovery in `~/.config/omarchy/plugins/` leading to indirect prompt injection).
* **Truncation Friction in Markdown Tables:** The Markdown table for sample blockers aggressively truncates both the maintainer objection and author resolution columns (`des...`, `vio...`, `t...`). An LLM querying only the markdown report misses critical context (e.g., path traversal details or full command examples) that exists in the JSON.

---

## Friction Points for Agent Retrieval

1. **Synthetic Permalink Reconstruction:** Comment permalinks are explicitly marked as "heuristically inferred" and lack GitHub API REST endpoints (such as `/repos/{owner}/{repo}/issues/comments/{comment_id}`). An agent attempting to verify a blocker must build web scraping URLs rather than native API calls.
2. **Category Name Inconsistencies:** The Markdown report labels Section 3.2 as `Security Baseline Capabilities Triggering Manual Review`, whereas the JSON key is `bot_capabilities_flagged`. An LLM mapping report text to JSON keys requires fuzzy semantic matching.
3. **Bot Error Disambiguation:** Duplicate error semantics appear under slightly different wording (e.g., `"Only the existing listed commit can be verified in this workflow."` vs. `"Only the existing listed commit can be verified in this workflow"` without period, vs. `"verification-could-not-complete: only existing listed commit can be verified"`). This splits counts across multiple dictionary keys.

---

## Concrete Recommendations to Improve Machine Consumption

1. **Normalize Bot Error Taxonomy:**
   Convert `bot_validation_errors` from arbitrary string keys to an array of normalized objects:
   ```json
   {
     "code": "TITLE_FORMAT_INVALID",
     "raw_message": "The issue title must start with `[Plugin]:` and include the plugin name.",
     "count": 42
   }
   ```

2. **Supply Fully Qualified REST & Web Permalinks:**
   Include pre-constructed URLs directly in the JSON entries:
   ```json
   {
     "issue_number": 1683,
     "comment_id": 5503180248,
     "html_url": "https://github.com/omacom/omarchy-plugin-marketplace/issues/1683#issuecomment-5503180248",
     "api_url": "https://api.github.com/repos/omacom/omarchy-plugin-marketplace/issues/comments/5503180248"
   }
   ```

3. **Avoid Cell Truncation in RAG Exports:**
   Remove arbitrary character boundaries (`...`) in markdown tables, or replace tabular presentation with itemized lists when objection details exceed 80 characters to preserve complete technical descriptions for retrieval embeddings.

4. **Query Utility Answer Verification ("Top 3 Pitfalls"):**
   - *Query Evaluation:* Easily answerable. An LLM can synthesize Section 2's quantitative data or directly cite Section 4:
     1. **Packaging Unapproved Binaries / Precompiled Helpers** (1,294 blockers; must build from source).
     2. **Wayland/QML Integration Defects** (1,376 blockers; unescaped text, focus grabbing).
     3. **Shipping Agent Directive Files / `AGENTS.md`** (203 blockers; indirect prompt injection risks under `SEC-009`).
