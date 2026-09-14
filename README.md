# Omarchy Plugin Observatory

[Русский](README.ru.md)

A collection of **3,086 historical static-review records** about Omarchy Quattro plugins, with **10,310 reported evidence anchors**. Use it to find examples of timers, system commands, parsing and localization, then check the relevant source. The companion [agent skill](https://github.com/PavelLizunov/omarchy-plugin-patterns) provides guides for writing and reviewing your own plugins.

Current version: **`v1.0.1-rc.1`**, a local release candidate. [Methodology](METHODOLOGY.md) · [Corrections](docs/corrections.md) · [Source notes](docs/source-notes.md) · [Contributing](CONTRIBUTING.md)

The records come from automated static analysis. Original checkouts and quotations have not been independently verified across the corpus, and no plugin runtime, CPU or battery measurements were made. The counts describe saved reports, not an ecosystem census or safety ranking.

## Where to start

- **Writing a plugin?** Start with the [skill](skill/omarchy-plugin-patterns/SKILL.md), which links to guides on architecture, security, polling and localization.
- **Checking a finding?** Find its record in [plugins.jsonl](data/plugins.jsonl), read the `review` object and follow its correction and source links before using the historical `verdict` or `proof`.
- **Looking through the dataset?** The [local viewer](#local-summary-viewer) shows summary counts and links to the files. The datasets below are also available directly.

Four [corrections](docs/corrections.md) address missing-file claims in Omarkey and bar-glow, credential handling in WireGuard, and the pacman hook in Webapp Browser. They change specific interpretations while preserving the original records. None assigns a new runtime `pass`.

## Examples worth checking

These examples refer to selected files at specific commits. Their scope, hashes and available license notices are recorded in [sources.jsonl](data/sources.jsonl); they do not establish how common a pattern is.

### Privileges and credentials

A [WireGuard widget](https://github.com/Liran-shternberg/wg-omarchy/blob/dff8c75eb1f2ed3053720c1de8eaecea8f6d7073/Widget.qml) accepts a password in its own UI and sends it through stdin to `sudo -S`. The user starts the action, which is restricted to `up/down`; the inspected path shows no authorization bypass. It still puts a system password in the plugin's process. Where supported, an operation-specific system service with appropriate authorization and the session's authentication agent keeps that handling outside the widget.

A [webapp installer](https://github.com/dgoran/omarchy-webapp-browser/blob/b2d153daa80c22cf6ee007aeeeb8887303f19cf2/bin/omarchy-webapp-browser#L463-L505) installs a pacman hook that restores a system symlink to a user-writable launcher. The hook runs `/bin/ln`; it does not run the launcher as root. The symlink raises integrity questions, especially for privileged callers. The author documents the privileged installation.

When reviewing configuration writes, trace the allowed scope, consent, validation, backup/recovery and replacement procedure. A `sed -i` call alone cannot answer those questions. Likewise, keep the roles of system interfaces separate: D-Bus carries messages, Polkit handles authorization and the service performs the operation. NetworkManager and logind already cover some tasks; the dataset does not establish why an author chose another route or whether missing APIs explain that choice.

### Timers and event-driven updates

A [media widget's two-second timer](https://github.com/bussdeeAI/at.familienfabrik_omarchy/blob/eccd60bf3d1a02e6ab5fdc969e6fd728d743e043/BarWidget.qml#L81-L95) requests activation of seven `playerctl` processes. That is configured work, not a measured launch count. Some results also feed the bar tooltip, so closing the popup does not necessarily make every update unnecessary. Separate status updates from detail-only polling.

A [window-control service](https://github.com/cytracon/omarchy-window-controls/blob/19319b30105ec977ee393ff8c0cb4121f5f10732/Service.qml#L308-L319) uses an 80ms repeating timer and checks whether a process is already running before starting it again. Its resource cost remains unmeasured.

A [mail-checker component](https://github.com/VillainRU/omarchy-thunderbird-mail-checker/blob/563aa9f8394a3e76df5e28b1c495377ace4afe9c/Panel.qml) receives events through a Unix socket. Reconnection logic and an event-triggered notification process remain part of its work. The socket example therefore supports a particular integration choice, not a claim of zero processes or wakeups across the plugin.

### Parsing and object lifetime

Use `try/catch` to handle parse errors, then validate the data's shape and range and decide how the UI recovers. Put size limits before data can accumulate in an unbounded transport buffer: checking a delivered line's length cannot limit memory already used to collect it.

QObject ownership releases children when the owner is destroyed. During a long session, collections can still grow while their owner stays alive. Give them finite budgets, eviction and cancellation rules; closing a popup does not necessarily destroy its owner.

### Localization

[Localized copies of built-in plugins exist](https://github.com/robertlindomar/omarchy-ptbr-power/blob/ee037fc056cf22c2b3108afd3623a52c7afb6881/README.md). Shared translation catalogs can reduce synchronization work, while forks remain a legitimate way to customize a plugin. This research has not measured fork frequency, translation-only changes or missed fixes. Check the installed shell's capabilities and the [community's existing translation work](https://github.com/omacom/omarchy/issues/7284) before proposing another workflow.

## What the counts mean

The original author reports using Gemini 3.8 Flash. The public export lacks the original run logs, source-acquisition manifest and independent reviewer signoff, so the full history cannot be reconstructed from these files. [METHODOLOGY.md](METHODOLOGY.md) explains the known provenance and gaps.

| Stored label | Records |
|---|---:|
| `pass` | 2,052 |
| `warning` | 800 |
| `broken` | 126 |
| `suspicious` | 108 |

These are historical labels, including cases with later corrections. They are not current recommendations or confirmed defect counts: some missing-file rationales behind `broken` have been disproven, and `suspicious` does not establish malicious intent or privileged behavior. Read each record's linked corrections before relying on its assessment.

The separate `features.privilege` field contains **76 true, 1,569 false and 1,441 unknown (`null`)** values. These are stored annotations, not independently verified behavior. Keep unknowns separate when counting; they cannot be treated as false. The [statistics](release/statistics.json) and [claim ledger](data/claims.jsonl) provide the reproduced counts and their sources.

## Open datasets and schemas

| File | Contents |
|---|---|
| [claims.jsonl](data/claims.jsonl) | Metadata counts and method limits with reproducible source pointers. |
| [plugins.jsonl](data/plugins.jsonl) | Original records, separate review status, correction and source links. |
| [evidence.jsonl](data/evidence.jsonl) | Stored anchors and interpretations, including descriptions and missing-file observations as well as quoted code. |
| [patterns.json](data/patterns.json) | Qualitative review guidance. |
| [corrections.jsonl](data/corrections.jsonl) | Corrections to specific interpretations, with counterevidence and limitations. |
| [sources.jsonl](data/sources.jsonl) | Selected source files pinned to commits, with hashes and available license information. |

[JSON Schemas](schemas/) describe each dataset. Original plugin/evidence fields and IDs retain their historical `draft-1813da97` label, which is separate from the current release-candidate version. The source ledger covers selected files, not the whole corpus; evidence entries are not uniformly verbatim citations.

## Local summary viewer

The static viewer displays summary counts, methodology and download links. It has no per-plugin search, third-party runtime dependencies or tracking.

```bash
# Run on your own machine from the repository root; stop with Ctrl+C.
python3 -m http.server 8000 --bind 127.0.0.1
```

Open `http://127.0.0.1:8000/site/` in that machine's browser. EN/RU are the baseline texts; other locales are machine translations requiring language review. Keep this local: serving an arbitrary working directory publicly can expose unrelated files.

## Portable agent skill: omarchy-plugin-patterns

The [standalone skill](https://github.com/PavelLizunov/omarchy-plugin-patterns) is the source of the six-document [bundled copy](skill/omarchy-plugin-patterns/SKILL.md), which also works offline. Old `ai/packs/` paths link to those same instructions.

Its **Static review reference matrix** helps an agent inspect current source and record protections, risks and unknowns. It is a qualitative checklist, not a benchmark, percentile or certification. The skill needs no native library, dataset download or external skill; a plugin you build may have its own dependencies.

```bash
# Inspect an existing destination before installing; do not overwrite local edits.
git clone https://github.com/PavelLizunov/omarchy-plugin-patterns.git \
  "$HOME/.config/opencode/skills/omarchy-plugin-patterns"
```

Check that your client actually loads the skill. The file layout alone does not establish OpenCode/Claude discovery or plugin runtime compatibility.

## Standalone verification

```bash
python3 tools/verify_public_export.py           # stdlib structure, links, counts, inventory and hashes
python3 tools/verify_public_export.py --schema  # additionally validate all six JSON Schemas
python3 tools/rebuild_release.py --check        # check deterministic generated artifacts
```

Both modes require the checksum manifest and all six schemas. Invalid JSON, duplicate IDs, broken ownership links and unsafe paths fail verification. `--schema` also requires `jsonschema` and fails if it is missing. The private-path check catches a limited set of patterns; it is not a complete secret scan. Neither mode fetches upstream code or checks historical interpretations.

See [tools/README.md](tools/README.md) for setup, tests and rebuilding after edits.

## Notice and licensing

[MIT](LICENSE) covers the project's own materials and compilation rights to the extent held by its author. Third-party code retains its own terms. Source and license coverage is incomplete; an absent entry means unknown, not public domain or permission to reuse. [NOTICE.md](NOTICE.md) explains attribution, quotation limits and rights requests.

This community project is independent of Omarchy, Basecamp, 37signals and Quickshell and is not endorsed by them. To correct a finding, include its record ID, source revision and relevant context as described in [CONTRIBUTING.md](CONTRIBUTING.md).
