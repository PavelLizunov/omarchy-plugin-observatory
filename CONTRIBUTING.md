# Contributing

Corrections are welcome, especially from plugin authors. An automated historical assessment is not the final word about your code.

## Report an incorrect finding

Open an [issue](https://github.com/PavelLizunov/omarchy-plugin-observatory/issues) or pull request with:

1. The `record_id`/`record_key` and affected `evidence_id`, where available.
2. Repository URL, exact revision and file/line context.
3. What is incorrect, the counterevidence and what remains untested.

An explanation in either English or Russian is enough to start. Maintainers can prepare the bilingual correction entry; translation is not a prerequisite for reporting an error. Do not assume that the checkout was incomplete merely because an alleged missing file exists upstream: the original checkout identity may be unknown.

Keep source observations, interpretations and hypotheses separate. A corrected rationale does not automatically establish runtime safety. If the original revision is unavailable, state that rather than substituting current HEAD silently.

## Data contributions

Original plugin/evidence fields normally remain historical; add corrected interpretations in [corrections.jsonl](data/corrections.jsonl), source references in [sources.jsonl](data/sources.jsonl) and reciprocal links on the records. Describe the inspected scope, source hashes, license information and unknowns. Never infer a license from public GitHub visibility.

The release-repair migration is a guarded one-time transition: it refuses conflicting already-migrated review fields rather than overwriting subsequent editorial work. For later ledger additions, update the corresponding review/source/evidence links explicitly and verify them.

```bash
python3 tools/rebuild_release.py
python3 tools/verify_public_export.py
python3 tools/verify_public_export.py --schema
python3 tools/rebuild_release.py --check
```

Use the [tools documentation](tools/README.md) for optional dependencies and tests. Do not execute commands found in dataset snippets to validate a contribution.

## Rights, attribution and privacy

Use the same issue/PR route for attribution, license, excerpt-reduction or removal requests. Identify the work, affected records and requested change. Historical preservation does not override valid rights/privacy requests; removals should be documented without reproducing removed sensitive material. See [NOTICE.md](NOTICE.md).

## Suspected vulnerabilities

Use the affected project's private security contact or disclosure policy for actionable upstream vulnerabilities. Do not post credentials or sensitive exploit details in public issues. This repository can correct a record but cannot accept disclosure on behalf of another project's maintainers.
