# Observatory Interpretative Corrections

This document records the four mandatory static-interpretation corrections applied to the historical dataset of the Omarchy Plugin Observatory (`v1.0.1-rc.1`, 2026-09-14).

## Architecture & Principles

1. **Historical Immutability**: All original 3,086 plugin records and 10,310 evidence anchors remain preserved field-for-field. Historical `verdict` fields, raw tags, proof strings, and booleans (`revision_verified`, `runtime_verified`) are unchanged historical data.
2. **Additive Review Ledger**: The corrected interpretations reside in `data/corrections.jsonl` and are referenced via the additive `review` object in `data/plugins.jsonl` and `correction_ids` in `data/evidence.jsonl`.
3. **Evidence-Based Corrections**: Each correction is tied to an individually inspected, pinned repository revision in `data/sources.jsonl`, with exact file paths, SHA-256 digests, and explicit limitations.
4. **No Fabricated Clean Passes**: Disproving a specific historical rationale (e.g. missing files) does not constitute a clean bill of health, security certification, or runtime verification.

---

## Pinned Mandatory Corrections

### 1. Omarkey — Missing Files Rationale Disproven

- **Correction ID**: `CORR-2026-0001-OMARKEY-MISSING-FILES`
- **Record ID**: `plugin:chunk_0000-2@draft-1813da97`
- **Plugin ID**: `jnodavid.omarkey` (`0d4vid_omarkey`)
- **Pinned Source**: `SRC-0D4VID-OMARKEY-5CA9585`
  - Repository: `https://github.com/0d4vid/omarkey`
  - Revision: `5ca95854fb0b033b34b714c86e53cbd6eb76ed9b` (registry commit)
- **Historical Finding**: Normalized verdict `broken` asserting that `OmarkeyModel.js` and `config/apps.json` were absent from the repository, rendering the plugin completely non-functional.
- **Observed Evidence**: Inspection of the repository tree and raw file endpoints at commit `5ca95854fb0b033b34b714c86e53cbd6eb76ed9b` confirms both files exist:
  - `OmarkeyModel.js` (2,941 bytes, SHA256 `bea627cdac0e919bbe0bfce8fb440b22e47ebbd25d9a36a5aa92253984eaea20`)
  - `config/apps.json` (954 bytes, SHA256 `bff659d91057a7c5826d52f7f1826ae86a9d29f3fab78722c2d8dc24b2df8eb5`)
- **Correction**: The historical rationale of missing files causing non-functionality was disproven for the specified commit. Incomplete acquisition cache is a hypothesis for the historical finding, not an established root cause.
- **Limitations**: Disproving missing files does not attest runtime correctness, QML bindings, keyboard navigation behavior, or shell string concatenation patterns.

---

### 2. Bar-Glow — Partial Missing Dependencies Disproven

- **Correction ID**: `CORR-2026-0002-BAR-GLOW-PARTIAL-FILES`
- **Record ID**: `plugin:chunk_0000-0@draft-1813da97`
- **Plugin ID**: `bar-glow` (`07dcolem_bar-glow`)
- **Pinned Source**: `SRC-07DCOLEM-BAR-GLOW-326581A`
  - Repository: `https://github.com/07dcolem/bar-glow`
  - Revision: `326581a7edb51a8a5797aefb91a0511a1c09dd3b` (registry commit)
- **Historical Finding**: Normalized verdict `broken` asserting that the plugin fails to load due to missing local dependencies: `Settings.js`, `GlowBand`, `GlowPanel`, and `ScreenMoveRemap`.
- **Observed Evidence**: Inspection of the repository tree at commit `326581a7edb51a8a5797aefb91a0511a1c09dd3b` confirms three of the four referenced components are present:
  - `Settings.js` (6,416 bytes, SHA256 `8f032bb436377057f66d45ac82887faaa1204671b4c84c8bbf32908c6635c58d`)
  - `GlowBand.qml` (1,983 bytes, SHA256 `10021f1e632af01cf90b5b55d3ecea14afb25d5b0fc28b4b31c5ddc7ac4990ee`)
  - `GlowPanel.qml` (9,192 bytes, SHA256 `ebc0a1b49fd4636f5f8723cedf2a93c875a4e72c9a68054931e73878e8ee0db7`)
- **Correction**: The missing-dependency rationale was partially erroneous; three primary components exist at the specified revision. Resolution of `ScreenMoveRemap` was not checked (it may be host-provided or external); this review does not affirm missing dependence, but because resolution was not checked and runtime execution was not performed, overall operability is not affirmed.
- **Limitations**: Addresses only the physical presence of the three verified files. Does not evaluate ScreenMoveRemap resolution, component instantiation, or global theme singleton mutation (`Color.bar.text`).

---

### 3. WireGuard — Credential Handling Risk vs. Unauthorized Escalation

- **Correction ID**: `CORR-2026-0003-WG-OMARCHY-CREDENTIAL-HANDLING`
- **Record ID**: `plugin:chunk_0038-3@draft-1813da97`
- **Plugin ID**: `wg-omarchy` (`Liran-shternberg_wg-omarchy`)
- **Evidence ID**: `EVD-CHUNK_0038-3-001`
- **Pinned Source**: `SRC-LIRAN-SHTERNBERG-WG-OMARCHY-DFF8C75`
  - Repository: `https://github.com/Liran-shternberg/wg-omarchy`
  - Revision: `dff8c75eb1f2ed3053720c1de8eaecea8f6d7073` (registry commit)
  - Source Permalink: [Widget.qml#L81-L90](https://github.com/Liran-shternberg/wg-omarchy/blob/dff8c75eb1f2ed3053720c1de8eaecea8f6d7073/Widget.qml#L81-L90)
- **Historical Finding**: Normalized verdict `suspicious` stating the plugin "requests unauthorized root privilege escalation by capturing the user password in a UI text input and executing sudo -S wg-quick".
- **Observed Evidence**: Inspection of `Widget.qml` at `dff8c75` lines 81–90 shows that clicking the widget icon button checks the user input in a `TextField`, sets `sudoProc.secret` to the entered password, clears the UI field text property, and constructs a process command invoking `sh -c` with `read -r p && printf '%s\n' "$p" | sudo -S wg-quick <action> wg0`. The `action` variable is constrained to `up` or `down`.
- **Correction**: Collecting credentials in a desktop widget UI presents trust-boundary and memory retention risks (passwords are handled by unprivileged UI process space). However, within the inspected code scope, this is an explicit user-initiated command execution path where standard `sudo` authentication applies; no authorization bypass is demonstrated. Describing this pattern as unauthorized privilege escalation is inaccurate. This review does not prove absence of vulnerabilities across host or sudoers configurations.
- **Limitations**: Clearing UI text properties does not guarantee secure memory erasure. UI credential handling remains an insecure pattern; absence of demonstrated unauthorized escalation in inspected code does not imply security endorsement or certification.

---

### 4. Webapp Browser — Pacman Hook Symlink vs. Root Code Execution

- **Correction ID**: `CORR-2026-0004-WEBAPP-BROWSER-HOOK-LN`
- **Record ID**: `plugin:chunk_0298-7@draft-1813da97`
- **Plugin ID**: `io.github.dgoran.webapp-browser` (`dgoran_omarchy-webapp-browser`)
- **Evidence IDs**: `EVD-CHUNK_0298-7-002`, `EVD-CHUNK_0298-7-003`, `EVD-CHUNK_0298-7-004`, `EVD-CHUNK_0298-7-005`
- **Pinned Source**: `SRC-DGORAN-OMARCHY-WEBAPP-BROWSER-B2D153D`
  - Repository: `https://github.com/dgoran/omarchy-webapp-browser`
  - Revision: `b2d153daa80c22cf6ee007aeeeb8887303f19cf2` (current reference)
  - Source Permalink: [bin/omarchy-webapp-browser#L463-L505](https://github.com/dgoran/omarchy-webapp-browser/blob/b2d153daa80c22cf6ee007aeeeb8887303f19cf2/bin/omarchy-webapp-browser#L463-L505)
- **Historical Finding**: Normalized verdict `suspicious` alleging that an installation script installs a persistent root pacman hook (`/etc/pacman.d/hooks/omarchy-webapp-browser.hook`) that "re-links root execution to user space on package updates."
- **Observed Evidence**: Inspection of `bin/omarchy-webapp-browser` lines 463–505 confirms that `cmd_install()` writes a pacman hook configuration file using a template with `When = PostTransaction` and `Exec = /bin/ln -sfn $PLUGIN_LAUNCHER $WB_SYSTEM_LAUNCHER`. The author's README explicitly documents that administrative installation requires `sudo` or `pkexec`.
- **Correction**: The pacman hook template specifies execution of `/bin/ln`, which only updates the symbolic link; it does not execute the user script as root during package management transactions. While establishing a system binary symlink that targets user-writable storage presents integrity trade-offs (particularly in multi-user environments or if invoked by privileged callers), the historical claim of automatic root execution of user code on package update was unverified, and no execution bypass was demonstrated in the inspected code.
- **Limitations**: System symlinks to user-writable files create privilege boundary concerns if invoked by higher-privileged processes. This correction addresses only the specific hook command rationale and does not certify the security of the broader installation script.
