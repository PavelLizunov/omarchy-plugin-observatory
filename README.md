# Omarchy Plugin Observatory 🔭

[Русский](README.ru.md)

An experimental research dataset for Omarchy Quattro plugin development: **3,086 historical static-review records** and **10,310 reported evidence anchors**, accompanied by an [agent skill](https://github.com/PavelLizunov/omarchy-plugin-patterns).

> These are report records, not a verified ecosystem census or safety ranking. The original source checkouts and every quoted line have **not** been independently verified. No plugin runtime, CPU use or battery consumption was measured for this release.

Current artifact: **`v1.0.1-rc.1`**, a release candidate. [Methodology](METHODOLOGY.md) · [Corrections](docs/corrections.md) · [Source notes](docs/source-notes.md) · [Contributing](CONTRIBUTING.md)

## Ecosystem overview

The original research used Gemini 3.8 Flash according to its author. The public export does not contain the original execution receipts, source acquisition manifest or independent supervisory signoff. This release makes the available evidence and its limits explicit rather than reconstructing missing history.

### Historical labels, not current recommendations

| Stored label | Records | How to interpret it |
|---|---:|---|
| `pass` | 2,052 | A historical assessment, not evidence that a plugin is safe. |
| `warning` | 800 | A historical assessment requiring source context. |
| `broken` | 126 | Not a confirmed count of nonfunctional plugins; some missing-file rationales have been disproven. |
| `suspicious` | 108 | Neither a count of privileged plugins nor evidence of malicious intent. |

Counts are reproduced from the stored labels, including corrected cases. Every record has a separate `review` object. **Read linked corrections before relying on a historical `verdict` or evidence `proof`.** Disproving one rationale does not produce a new runtime `pass`.

The separate `features.privilege` field contains **76 true, 1,569 false and 1,441 unknown (`null`)** values. These are historical typed annotations, not independently established behavior. Missing evidence is not equivalent to false. See [statistics](release/statistics.json) and the [claim ledger](data/claims.jsonl).

## Key architectural insights

The following are selected, revision-specific examples, not prevalence estimates. Inspected files, hashes and available license notices are listed in [sources.jsonl](data/sources.jsonl).

### 1. Privileges and credentials

- A [WireGuard widget](https://github.com/Liran-shternberg/wg-omarchy/blob/dff8c75eb1f2ed3053720c1de8eaecea8f6d7073/Widget.qml) accepts a password in its own UI and sends it through stdin to `sudo -S`. The action is user-initiated and restricted to `up/down`; the inspected path does not demonstrate an authorization bypass. Handling system credentials in a plugin UI still expands the trust boundary. Prefer an operation-specific system service with appropriate authorization, using the session's authentication agent where supported.
- A [webapp installer](https://github.com/dgoran/omarchy-webapp-browser/blob/b2d153daa80c22cf6ee007aeeeb8887303f19cf2/bin/omarchy-webapp-browser#L463-L505) installs a pacman hook that restores a system symlink to a user-writable launcher. The hook executes `/bin/ln`, not the launcher as root. This is an integrity concern, not demonstrated automatic root execution. The author documents the privileged installation.
- Configuration writes require an authorized scope, clear consent, validation, backup/recovery and safe replacement. A `sed -i` occurrence alone does not establish lack of consent.

D-Bus is a transport, Polkit handles authorization, and a system service performs the operation. Existing services such as NetworkManager and logind cover some tasks. This corpus does not establish why authors chose a particular integration or that missing platform APIs are the dominant cause.

### 2. Scheduling and resource ownership

- A [media widget's two-second timer](https://github.com/bussdeeAI/at.familienfabrik_omarchy/blob/eccd60bf3d1a02e6ab5fdc969e6fd728d743e043/BarWidget.qml#L81-L95) requests activation of seven `playerctl` processes. This is configured work, not a measured process count. Some results also serve the bar tooltip: separate necessary status updates from detail-only polling rather than disabling everything when a popup closes.
- A [window-control service](https://github.com/cytracon/omarchy-window-controls/blob/19319b30105ec977ee393ff8c0cb4121f5f10732/Service.qml#L308-L319) uses an 80ms repeat timer with guards against restarting already-running processes. Its actual resource cost remains unmeasured.
- A [mail-checker component](https://github.com/VillainRU/omarchy-thunderbird-mail-checker/blob/563aa9f8394a3e76df5e28b1c495377ace4afe9c/Panel.qml) receives events through a Unix socket. It also has reconnection logic and an event-triggered notification process; the example does not establish zero processes or wakeups for the whole plugin.

### 3. Parsing and object lifetime

`try/catch` handles parse failure, not input size, schema validity or recovery correctness. Bound incoming data **before** an unbounded transport buffer can grow, then validate shape and range. A downstream line-length check cannot retroactively limit preceding buffering.

QObject ownership releases children when their owner is destroyed; it does not bound accumulation while that owner remains alive. Long-running plugins also need finite collection budgets, eviction and cancellation. A closed popup is not necessarily a destroyed owner.

### 4. Localization

[Localized copies of built-in plugins exist](https://github.com/robertlindomar/omarchy-ptbr-power/blob/ee037fc056cf22c2b3108afd3623a52c7afb6881/README.md). A shared translation workflow can reduce synchronization work, but this research has not quantified fork frequency, translation-only diffs or missed fixes. Forking is a legitimate customization mechanism. [Existing community work](https://github.com/omacom/omarchy/issues/7284) deserves credit and version-specific evaluation.

## Open datasets and schemas

| File | Contract |
|---|---|
| [claims.jsonl](data/claims.jsonl) | Stable metadata claims with reproducible source pointers; not source-code attestations. |
| [plugins.jsonl](data/plugins.jsonl) | Original records plus a separate review status and correction/source links. |
| [evidence.jsonl](data/evidence.jsonl) | Original anchors and historical interpretations; some entries are descriptions or missing-file observations, not verbatim lines. |
| [patterns.json](data/patterns.json) | Qualitative guidance, not a statistical taxonomy. |
| [corrections.jsonl](data/corrections.jsonl) | Bounded corrections to specific interpretations, with counterevidence and limitations. |
| [sources.jsonl](data/sources.jsonl) | Selected pinned source files and license information, not full-corpus coverage. |

[JSON Schemas](schemas/) describe each dataset. Stable IDs and original plugin/evidence fields are preserved, including the historical `draft-1813da97` provenance label. That label is distinct from the current release-candidate version.

## Local summary viewer

The static viewer displays summary counts, methodology text and links to downloadable data. It is not a searchable per-plugin browser. It has no third-party runtime dependencies or tracking.

```bash
# Run on your own machine from the repository root; stop with Ctrl+C.
python3 -m http.server 8000 --bind 127.0.0.1
```

Open `http://127.0.0.1:8000/site/` in that machine's browser. EN/RU are editorial baselines; other locales are machine translations requiring language review. Do not expose an arbitrary working directory publicly.

## Portable agent skill: omarchy-plugin-patterns

The [standalone skill](https://github.com/PavelLizunov/omarchy-plugin-patterns) is the normative source. An identical six-document [bundled copy](skill/omarchy-plugin-patterns/SKILL.md) supports offline use; old `ai/packs/` paths are compatibility links, not competing instructions.

The qualitative **Static review reference matrix** helps inspect current source and record protections, risks and unknowns. It is not a benchmark, percentile or certification. The skill needs no native library, dataset download or external skill. Plugin dependencies are separate.

```bash
# Inspect an existing destination before installing; do not overwrite local edits.
git clone https://github.com/PavelLizunov/omarchy-plugin-patterns.git \
  "$HOME/.config/opencode/skills/omarchy-plugin-patterns"
```

Confirm actual skill loading in your client. Package layout alone does not verify OpenCode/Claude discovery or plugin runtime compatibility.

## Standalone verification

```bash
python3 tools/verify_public_export.py           # stdlib structure, links, counts, inventory and hashes
python3 tools/verify_public_export.py --schema  # additionally validate all six JSON Schemas
python3 tools/rebuild_release.py --check        # check deterministic generated artifacts
```

The checksum manifest and all six schemas are mandatory. Invalid JSON, duplicate IDs, broken ownership links and unsafe filesystem paths fail verification. `--schema` requires the explicitly documented `jsonschema` dependency and fails if it is missing. The private-path pattern check is limited hygiene, **not** a comprehensive secret scanner. Neither mode fetches upstream sources or verifies their historical interpretations.

See [tools/README.md](tools/README.md) for setup, tests and rebuilding after edits.

## Notice and licensing

[MIT](LICENSE) covers the project's original materials and compilation rights to the extent owned by its author. It does not relicense third-party code. Source/license coverage is incomplete: an absent source entry means **unknown**, not public domain. See [NOTICE.md](NOTICE.md) for attribution, quotation limits and rights requests.

This independent community project is not affiliated with or endorsed by Omarchy, Basecamp, 37signals or Quickshell. Corrections with a record ID, pinned revision and source context are welcome through [CONTRIBUTING.md](CONTRIBUTING.md).
