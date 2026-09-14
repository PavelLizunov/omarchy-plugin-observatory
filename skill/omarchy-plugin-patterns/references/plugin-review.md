# Review: evidence before verdict

[Entry](../SKILL.md) · [Security](security-review.md) · [Performance](performance-review.md) · [Localization](localization-review.md)

## Worker → frozen draft → independent supervisor

1. State authorized scope and source identity: repository, revision if verified, directory, file hashes when available. Cache names are not revision evidence. List the plugin directory, including hidden/nested files. Personally read **every in-scope file fully** with the host's read tool, continuing beyond 200 lines. Resolve imports, manifest assets, scripts and native helpers. Binary/unavailable/unread content stays `[U]`; no fabricated coverage or regex/batch source audit.
2. Missing local files may reflect incomplete cache. Check only an authorized, verified upstream repository/ref/path. A genuine 404 establishes absence there, not at an unknown revision or across the project. Auth/network errors stay unknown. With consent, retrieve into an isolated cache, record provenance and read fully; never silently modify or execute the user's plugin tree.
3. Record risks **and protections**, surrounding guards, alternative explanations and unresolved checks. Freeze the draft and source snapshot before review.
4. An independent supervisor reopens every quoted line, checks exact characters including whitespace, reads surrounding control/data flow and verifies upstream evidence and actual read coverage. Shifted/invented quotations require rejection/correction. Changed files invalidate affected anchors. Only that reviewer may issue `CONTROLLER_STATUS: APPROVED`; self-review is not independence or revision attestation. If unavailable, deliver an unsigned `REVIEW-REQUIRED` draft, not a simulated supervisor.

## Six dimensions: preserve their identity

| Dimension | Mandatory questions |
|---|---|
| 1 Manifest/delivery | Valid schema/kinds/entryPoints, namespace, paths, assets, imports, executable dependencies and supported versions? |
| 2 Processes/privileges | Actual dispatch paths, argv and environment, input control, authorization, helper ownership, consented writes? |
| 3 Timers/cadence | Interval/repeat/rearm, detail/status distinction, enable/sleep gates, overlap, retries and cancellation? |
| 4 Resilience/data | Transport byte caps, guarded JSON, shape/range checks, truncation, EOF, failure/stale state and recovery? |
| 5 Memory lifecycle | Bounded collections/payloads, dynamic parentage plus eviction, callbacks, requests and native ownership? |
| 6 Multimonitor/theme | Guards covering actual screen dereferences, Variants delegate lifecycle, hotplug, scale and verified theme tokens? |

Localization, translation and a11y cut across all six, including denial/error messages; do not replace a dimension with i18n. For focused review, explicitly mark omitted dimensions, never imply full coverage.

## Anchor and verdict contract

Template only, **not a fabricated corpus finding**:

```text
file: <exact authorized relative path>
line: <actual 1-based integer>
snippet: <verbatim entire cited line including whitespace>
type: <risk OR protective category>
proof: <function/callsite; supporting ranges; evidence grade;
        input → operation → guard → consequence; limits/counterevidence>
```

- `[D]`: directly documented observation from identified source, not automatically observed runtime behavior.
- `[I]`: supported interpretation with explicit preconditions and scope.
- `[H]`: hypothesis with competing explanation and falsifier/test.
- `[U]`: evidence unavailable; list what would resolve it. Missing/null/nonboolean evidence never becomes false.

Protective categories: `GUARDED_JSON_PARSE`, `GATED_TIMER`, `DEBOUNCE_TIMER`, `DISCRETE_ARGV_DISPATCH`, `SYSTEM_AUTH_DELEGATION`. Explain coverage and remaining risk; a protection keyword alone proves no safety.

| Tempting finding | Required false-positive check |
|---|---|
| sudo/pkexec = escalation exploit | Is this executable code, not UI/comment/URL? What authorized action and policy? |
| Process = running subprocess | Identify launch path, lifecycle and frequency; declarations are not executions. |
| concat = injection | Array vs script string? Attacker-controlled operand reaching shell? Inspect actual enum/quoting guard. |
| Subsecond timer = periodic drain | repeat:false? Rearm rate? Animation vs polling? Dispatch gate? No energy inference. |
| screen/Variants = crash/safe | Guard covers exact dereference and hotplug lifetime? JS exception is not proof of native crash. |
| push/parent/splice = leak/safe | Bound every allocation path during root lifetime; distant cleanup is insufficient. |
| try/catch = validated data | Verify schema/ranges, input byte cap and honest fallback. |
| Translation looks fluent = correct | Check meaning, uncertainty, IDs, placeholders, CLDR and actual RTL/a11y tests. |

`pass`: completed scoped static checklist; `warning`: supported shortcoming; `broken`: established delivery/load blocker; `suspicious`: supported serious security-risk mechanism, not inferred malice/exploitation. Incomplete evidence has separate review status and no final pass. Report actual checks separately from proposals; signoff does not grant commit, publication or runtime permission.

## Fixed empirical provenance: e36c37d8

Reproduced Claim Ledger metadata, not a new source audit or live ecosystem census. All IDs below are exact.

| Claim ID | Value and unit |
|---|---|
| CLM-CORPUS-RECORDS | 2,844 report records |
| CLM-CORPUS-CHUNKS | 286 Level-1 chunks |
| CLM-CORPUS-ANCHORS | 9,616 evidence anchors |
| CLM-CORPUS-FILE-REFERENCES | 19,909 files_inspected references |
| CLM-VERDICT-PASS | 1,879 records (66.1%) |
| CLM-VERDICT-WARNING | 739 records (26.0%) |
| CLM-VERDICT-BROKEN | 125 records (4.4%) |
| CLM-VERDICT-SUSPICIOUS | 101 records (3.6%) |
| CLM-JOIN-EXACT | 2,528 ID+directory matches |
| CLM-JOIN-DIRECTORY-CANDIDATE | 5 directory-only candidates |
| CLM-JOIN-UNMATCHED | 311 unmatched records |
| CLM-SOURCE-REVISIONS | 0 independently verified source revisions |
| CLM-METHOD-RUNTIME | Static synthesis, not runtime execution or energy benchmark |

**revision_verified=false for every record (100%).** Matching used names/cache directories, not source revision attestation. References are neither unique files nor independently verified read operations. Rounded verdict percentages sum to 100.1%. Anchors may be protective or neutral. Never substitute early heuristic census totals for this fixed snapshot; when asked about a newer corpus, report unknown until its ledger is verified. Standalone use needs no external database.
