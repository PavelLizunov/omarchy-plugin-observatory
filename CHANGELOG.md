# Changelog

## v1.0.1-rc.1 — 2026-09-14

Release candidate correcting the interpretation and verification contract of the historical export.

### Data and evidence

- Preserve all 3,086 original plugin records and 10,310 evidence anchors, their IDs and historical fields.
- Add explicit historical review status, [corrections](data/corrections.jsonl) and [selected pinned sources](data/sources.jsonl).
- Omarkey (`chunk_0000:2`): disprove the missing-files rationale at the stored registry reference; the cause of the earlier error is unknown.
- bar-glow (`chunk_0000:0`): disprove three missing-file assertions; host-dependent `ScreenMoveRemap` resolution and overall runtime behavior remain unverified.
- WireGuard (`chunk_0038:3`): distinguish user-initiated credential handling from demonstrated authorization bypass.
- Webapp launcher (`chunk_0298:7`): distinguish a symlink-restoring pacman hook from execution of its target as root.
- Redirect stable metadata claims to published, reproducible statistics and limits. Keep original source-checkout verification flags false.

### Documentation and skill

- Remove unsupported prevalence, health-score, CPU and causal claims from current conclusions.
- Explain absent historical receipts, partial source/rights coverage and the difference between records and a census.
- Align the six-document skill, add its qualitative static-review matrix and replace competing legacy packs with compatibility links.
- Clarify MIT scope and third-party rights; add a correction/rights-request process and matched EN/RU announcement drafts.

### Tooling

- Require strict JSON, relational checks, mandatory inventory and checksum validation; distinguish stdlib checks from optional full JSON Schema validation.
- Add deterministic statistics/checksum rebuilding and regression tests for malformed inputs, unsafe paths, links, schema references and migration.
- Fix viewer metadata consumption, asynchronous language changes and loading/error/empty states; add desktop/mobile browser tests.
- Align release metadata and citation with a release candidate, without asserting that a tag or publication already exists.
