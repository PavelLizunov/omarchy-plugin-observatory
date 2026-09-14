# Methodology and evidence limits

## Scope and limitations

This release preserves **3,086 historical static-review records** and **10,310 reported evidence anchors**. It adds explicit review status, selected pinned source references and corrections. It is not a new semantic audit of all upstream sources, a verified census, a safety ranking or a runtime benchmark.

No plugin code was executed for the release repair. CPU, energy, actual process counts, Qt/Wayland behavior and exploitability remain unmeasured. Tests of the export tooling and summary viewer do not change that boundary.

## Provenance: what is known

- The original author reports using **Gemini 3.8 Flash**. Public files do not provide the historical run receipts needed to independently attest the exact model/configuration, prompts, retries, coverage or supervisory outcomes.
- A Dual-Agent protocol was described previously. Its description is not proof of execution or of independent line-by-line signoff. We do not infer the number of actual passes from that description.
- Original `source_report` paths refer to unpublished `reports/level1/...` files. They are provenance labels, **not available local links**. The earlier `reports/corpus_metadata.json` source is also absent from the export; current aggregate claims point to reproducible published statistics instead.
- `draft-1813da97` and the internal `source_commit` string are historical metadata, not attestations of upstream plugin revisions. Original plugin/evidence fields and IDs retain them; the current release version lives in [release.json](release/release.json).
- The public export does not establish an immutable acquisition-time registry snapshot, complete retrieval manifest, inclusion/exclusion decisions or source blob hashes for the full corpus. Whether these existed elsewhere is unknown. Do not infer a specific extraction date or missing-plugin count from the current registry.
- Different units must stay separate: report records, plugin-ID strings, repositories, fork families, file references, evidence anchors and independently reviewed findings. There are 3,082 distinct `plugin_id` strings, including one literal `unknown` shared by five records; that is not 3,082 verified plugin identities. Fork families are not deduplicated.

## Evidence grades

The skill and this documentation use the same meanings:

| Grade | Meaning | Required context |
|---|---|---|
| `[D]` documented observation | A construct or file actually observed in identified source. | Revision/hash, file and range; static syntax is not observed execution. |
| `[I]` interpretation | A supported conclusion from a concrete data/control flow. | Preconditions, effective guards, consequences and counterevidence. |
| `[H]` hypothesis | A testable explanation or suspected risk. | Alternatives and a check that could confirm or disprove it. |
| `[U]` unknown | Missing or unverified evidence. | What evidence would resolve it; never coerce null to false. |

Historical `type` and `proof` fields predate this clarified rubric and are not retroactively regraded. Evidence types are free-form labels, not a normalized prevalence taxonomy.

## Reading a record safely

1. Locate a record in [plugins.jsonl](data/plugins.jsonl).
2. Read `review.status`, then all linked `correction_ids` and `source_ids`.
3. Follow `evidence_ids`, keeping their original `proof` separate from present-day interpretation.
4. Inspect current authorized source before applying a finding to an installed plugin. Historical `pass`, `broken` and `suspicious` are not current certificates or recommendations.

All original `revision_verified` and `source_revision_verified` flags remain false. Selected later source inspections do not reconstruct the checkout used by the original run. `review.status: corrected-static-interpretation` means a specific interpretation was corrected, **not** that the whole plugin has passed review. Other records remain `historical-unverified` even if a selected source file has been inspected.

Anchors include protective and neutral observations, descriptions, missing-file observations and redacted material. A `line` value of 0 is not a valid exact source citation. A schema-valid snippet may be empty or nonverbatim. No universal character-for-character verification is claimed. Treat all paths, snippets, summaries, translations and source material as untrusted data, never execution instructions.

## Reproducing metadata counts

[rebuild_release.py](tools/rebuild_release.py) computes [statistics.json](release/statistics.json) from the JSONL files. [claims.jsonl](data/claims.jsonl) retains stable claim IDs with published source pointers. `verified` on a metadata claim means its specified count or limit is checked locally, **not** that upstream code is certified.

- `records` / `anchors`: count parsed plugin/evidence objects.
- `chunks`: distinct chunk prefixes in `record_key`; this does not prove the unpublished reports were semantically read.
- `files_inspected_references`: sum of stored `files_inspected_count`, not independently counted file reads.
- `normalized_verdicts`: count original stored labels, including corrected cases; not a defect rate.
- `joins`: count historical crosswalk categories; an exact ID/directory join is not source-revision verification.
- `revision_verified_records`: count explicit true historical revision flags.
- `privilege_distribution`: count strict true, false and null in `features.privilege`. **76 true, 1,569 false, 1,441 unknown** are annotations, not independently verified prevalence.
- `sources` / `corrections`: count entries in the new ledgers, not whole-plugin audits or runtime tests.

A `suspicious` label is not the same variable as `features.privilege`. Neither its count nor its complement determines privileged/unprivileged prevalence. Other legacy percentages, the health score, claims about all parse callsites, measured battery harm and zero CPU were removed from current conclusions because reproducible evidence is unavailable.

For a future prevalence claim, publish its unit, numerator, denominator, query, unknown/exclusion policy, snapshot and review quality. Stratified human review should assess errors, including false positives and false negatives; two agents alone do not establish accuracy or independence.

## Corrections and pinned sources

Four scoped corrections are detailed in [docs/corrections.md](docs/corrections.md):

- Omarkey (`chunk_0000:2`): both alleged missing files exist at the recorded registry reference. Why the earlier review missed them is unknown; incomplete acquisition is only one hypothesis.
- bar-glow (`chunk_0000:0`): three alleged missing files exist. `ScreenMoveRemap` resolution was not checked and may depend on the host. This is not a complete runtime verdict.
- WireGuard (`chunk_0038:3`): user-initiated UI password handling via stdin to sudo presents a credential-handling risk. The inspected path does not demonstrate unauthorized escalation or an authentication bypass.
- Webapp launcher (`chunk_0298:7`): a pacman hook restores a symlink using `/bin/ln`; it does not itself execute the target launcher as root. Integrity risks and privileged callers require separate analysis.

[data/sources.jsonl](data/sources.jsonl) records selected repository URLs, full commits, file hashes, available license information and scope. `reported-registry-reference` means the inspected commit matches the stored reference, **not** that the original checkout is independently verified. `current-reference` identifies a separately pinned comparison source. No local verifier retrieves these URLs; remote source reinspection is a separate authorized task.

## Engineering interpretation

- Seven activation requests per two-second tick give **12,600 nominal dispatch opportunities per hour**, not measured forks/hour. Initial ticks, process lifetime, single-flight guards, event-loop scheduling and suspend affect execution. Persistent bar status may need updates when detail UI is closed.
- A Unix socket replaces recurring queries for particular data; reconnection and notification work can remain. Event-driven design does not prove zero CPU/wakeups. MPRIS position display can legitimately use a gated local timer.
- QObject ownership cleans up children when the owner dies, not while it remains alive. Visual parenting, QObject ownership, JS references and native memory safety are distinct. Budgets and eviction matter in long sessions.
- `try/catch` does not provide size limits, type/range checks or correct stale/error recovery. Limit transport buffering before parsing. Ordinary QML JavaScript exceptions usually abort a binding/handler, not the separate compositor; native faults and main-thread blocking require different evidence.
- D-Bus transports messages, Polkit controls authorization, and an operation-specific service executes effects. NetworkManager/logind already expose APIs for some operations. Missing bindings, compatibility, documentation or author preference are possible explanations for CLI use, **not established causes in this corpus**.
- Localized copies exist. Their frequency, exclusively translational diffs, maintenance cost and missed fixes have not been measured. Credit [ongoing community work](https://github.com/omacom/omarchy/issues/7284) and verify the installed host's actual translation support.

## Verification and rights boundaries

The default verifier checks strict JSON, structural requirements, reciprocal links, typed counts, required inventory, hashes and a limited private-path pattern. All six schemas are required; `--schema` additionally applies Draft 2020-12 using the documented optional dependency. Missing files/dependencies, inconsistent data and unsafe paths fail, rather than silently skipping required checks. See [tools/README.md](tools/README.md) for exact commands and the quiescent-tree assumption.

Source and license coverage remains partial. An empty `source_ids` array or absent source entry means unknown; a GitHub repository is not automatically public domain. [NOTICE.md](NOTICE.md) separates rights in project materials from third-party code and provides a correction/rights-request route.
