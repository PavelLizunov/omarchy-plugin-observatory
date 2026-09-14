# Source Inspection & Provenance Notes

The [source ledger](../data/sources.jsonl) records the files inspected for Omarchy Plugin Observatory `v1.0.1-rc.1` (2026-09-14). This page explains the revision labels and lists the hashes and license notices.

## 1. Scope & Verification Boundaries

The Omarchy Plugin Observatory dataset contains 3,086 historical static-analysis records and 10,310 evidence anchors. The historical audit was performed via automated static analysis and did not establish independent checkout provenance for the full corpus.

The ledger covers 9 plugin sources and 2 external context references selected for corrections or examples. Files were fetched and inspected at the listed revisions. Other source mappings remain unknown; local cache names are not enough to establish them. All 3,086 plugin records retain historical `revision_verified: false` and `verdict.runtime_verified: false`.

The `revision_relation` field explains how a later inspection relates to the saved report. It is `reported-registry-reference` when the inspected `revision` matches the plugin's historical `registry_commit`, and `current-reference` when that value is null or differs. Inspecting selected files establishes their contents at that commit, not the original checkout or the plugin's runtime safety, performance or overall correctness.

---

## 2. Catalog of Pinned Sources

| Source ID | Repository URL | Revision | Relation | License (SPDX) | License SHA-256 | Status | Record IDs |
|---|---|---|---|---|---|---|---|
| `SRC-0D4VID-OMARKEY-5CA9585` | `https://github.com/0d4vid/omarkey` | `5ca95854fb0b...` | reported-registry-reference | MIT | `5b153416...` | identified-at-revision | `plugin:chunk_0000-2@draft-1813da97` |
| `SRC-07DCOLEM-BAR-GLOW-326581A` | `https://github.com/07dcolem/bar-glow` | `326581a7edb5...` | reported-registry-reference | MIT | `4631baca...` | identified-at-revision | `plugin:chunk_0000-0@draft-1813da97` |
| `SRC-LIRAN-SHTERNBERG-WG-OMARCHY-DFF8C75` | `https://github.com/Liran-shternberg/wg-omarchy` | `dff8c75eb1f2...` | reported-registry-reference | MIT | `3096179c...` | identified-at-revision | `plugin:chunk_0038-3@draft-1813da97` |
| `SRC-DGORAN-OMARCHY-WEBAPP-BROWSER-B2D153D` | `https://github.com/dgoran/omarchy-webapp-browser` | `b2d153daa80c...` | current-reference | MIT | `b629ab70...` | identified-at-revision | `plugin:chunk_0298-7@draft-1813da97` |
| `SRC-BUSSDEEAI-AT-FAMILIENFABRIK-ECCD60B` | `https://github.com/bussdeeAI/at.familienfabrik_omarchy` | `eccd60bf3d1a...` | current-reference | MIT | `7dadd19c...` | identified-at-revision | `plugin:chunk_0265-1@draft-1813da97` |
| `SRC-CYTRACON-OMARCHY-WINDOW-CONTROLS-19319B3` | `https://github.com/cytracon/omarchy-window-controls` | `19319b30105e...` | current-reference | MIT | `c4648a23...` | identified-at-revision | `plugin:chunk_0297-7@draft-1813da97` |
| `SRC-VILLAINRU-OMARCHY-THUNDERBIRD-563AA9F` | `https://github.com/VillainRU/omarchy-thunderbird-mail-checker` | `563aa9f8394a...` | reported-registry-reference | MIT | `382a21b2...` | identified-at-revision | `plugin:chunk_0062-9@draft-1813da97` |
| `SRC-ROBERTLINDOMAR-OMARCHY-PTBR-NOTIFICATIONS-298AC02` | `https://github.com/robertlindomar/omarchy-ptbr-notifications` | `298ac0237502...` | reported-registry-reference | MIT | `6933cc57...` | identified-at-revision | `plugin:chunk_0206-0@draft-1813da97` |
| `SRC-ROBERTLINDOMAR-OMARCHY-PTBR-POWER-EE037FC` | `https://github.com/robertlindomar/omarchy-ptbr-power` | `ee037fc056cf...` | reported-registry-reference | MIT | `6933cc57...` | identified-at-revision | `plugin:chunk_0206-2@draft-1813da97` |
| `SRC-EXT-QUICKSHELL-V0-2-1` | `https://github.com/quickshell-mirror/quickshell` | `a1a150fab00a...` | current-reference | LGPL-3.0-only | `e3a994d8...` | identified-at-revision | _(External context)_ |
| `SRC-EXT-OMACOM-OMARCHY-QUATTRO` | `https://github.com/omacom/omarchy` | `b679363bed05...` | current-reference | MIT | `717ba194...` | identified-at-revision | _(External context)_ |

---

## 3. Inspected Files, Checksums, and Licenses

### 1. `0d4vid/omarkey` @ `5ca95854fb0b033b34b714c86e53cbd6eb76ed9b`
- `OmarkeyModel.js`: SHA256 `bea627cdac0e919bbe0bfce8fb440b22e47ebbd25d9a36a5aa92253984eaea20`
- `config/apps.json`: SHA256 `bff659d91057a7c5826d52f7f1826ae86a9d29f3fab78722c2d8dc24b2df8eb5`
- License: `LICENSE` (MIT, SHA256 `5b153416bf68538c627b55e4302be55c92dfb76191b5195433e1d60374e1734c`)
- Copyright: `Copyright (c) 2026 Nonagni David`
- Context: Missing files rationale disproven. Cache failure is an unverified hypothesis, not an established root cause.

### 2. `07dcolem/bar-glow` @ `326581a7edb51a8a5797aefb91a0511a1c09dd3b`
- `Settings.js`: SHA256 `8f032bb436377057f66d45ac82887faaa1204671b4c84c8bbf32908c6635c58d`
- `GlowBand.qml`: SHA256 `10021f1e632af01cf90b5b55d3ecea14afb25d5b0fc28b4b31c5ddc7ac4990ee`
- `GlowPanel.qml`: SHA256 `ebc0a1b49fd4636f5f8723cedf2a93c875a4e72c9a68054931e73878e8ee0db7`
- License: `LICENSE` (MIT, SHA256 `4631bacaee75f0523d14153c54c9b5cc0848ae6c96b6bfda7f107fcfbec63a39`)
- Copyright: `Copyright (c) 2026 Dylan Coleman`
- Context: Three of four referenced components present. Resolution of `ScreenMoveRemap` was not checked (may be host-provided); this review does not affirm missing dependence.

### 3. `Liran-shternberg/wg-omarchy` @ `dff8c75eb1f2ed3053720c1de8eaecea8f6d7073`
- `Widget.qml`: SHA256 `083162b13f335b1d2b460fff315e96cd304d3b03912d495c19bb8aef3bef2d17`
- License: `LICENSE` (MIT, SHA256 `3096179c006436b74f8b45033bbaf29687eca1719fe7346d7e8972b5f650c0c7`)
- Copyright: `Copyright (c) 2026 Liran`
- Context: UI credential input handling. Standard sudo authentication applies; no authorization bypass demonstrated in inspected code.

### 4. `dgoran/omarchy-webapp-browser` @ `b2d153daa80c22cf6ee007aeeeb8887303f19cf2`
- `bin/omarchy-webapp-browser`: SHA256 `0c4f1fd278d89fea6a31db5989cce787fd45347456346870f163e8d4e5fa6ff2`
- `Service.qml`: SHA256 `47254157461807d7429f263a8e3d98252dc991603e33d92fd2cf28e2ae04301a`
- `README.md`: SHA256 `585ce3e98f59f9f932750b080c55f1e69acea8f467d29d8958f1e4898d63b915`
- License: `LICENSE` (MIT, SHA256 `b629ab700e0ac9b4c339f4943bad2f4273f69e6a89442ec72645bd1143f0d9f2`)
- Copyright: `Copyright (c) 2026 Goran Draskovic`
- Context: Pacman hook template executes `/bin/ln`, not user launcher as root. System symlink targets user-writable storage.

### 5. `bussdeeAI/at.familienfabrik_omarchy` @ `eccd60bf3d1a02e6ab5fdc969e6fd728d743e043`
- `BarWidget.qml`: SHA256 `bb3b2cf8127648c0d7de46883daa2d4abeec57f7c7fdb9fadd9406bbc1e09aee`
- License: `LICENSE` (MIT, SHA256 `7dadd19cbcc21cc7352a318e7b04ecf864d3adadd82e1282d939563f2caf0ffa`)
- Copyright: `Copyright (c) 2026 Familie BausL – Familienfabrik.at`
- Context: Announcement example of repeated CLI process spawning (seven `playerctl` subprocesses in a 2000ms timer).

### 6. `cytracon/omarchy-window-controls` @ `19319b30105ec977ee393ff8c0cb4121f5f10732`
- `Service.qml`: SHA256 `7a1047b90d6c58061776c180268871629fac00b11d669c35aef871e559905aba`
- License: `LICENSE` (MIT, SHA256 `c4648a231f9c5df156532820faf484c8e35c27b9467d6dc5f9f8c2eee53115bb`)
- Copyright: `Copyright (c) 2026 Cytracon`
- Context: Methodological example of high-frequency polling (80ms timer dispatching `hyprctl`, with `!running` single-flight guard).

### 7. `VillainRU/omarchy-thunderbird-mail-checker` @ `563aa9f8394a3e76df5e28b1c495377ace4afe9c`
- `Panel.qml`: SHA256 `fc639b7d1c663c954db394979d240de09540b2e523d3e4eb075bd54e6f804afd`
- License: `LICENSE` (MIT, SHA256 `382a21b24212c60661285dcb8a970cffa0a5dba99b84d0ece9b3052b9ea2b4d8`)
- Copyright: `Copyright (c) 2026 VillainRU`
- Context: The inspected panel receives events through a Unix domain socket and has reconnect handling. This does not establish zero polling or zero subprocesses for the whole plugin; notification processes can be event-triggered.

### 8. `robertlindomar/omarchy-ptbr-notifications` @ `298ac0237502c63829d1494c5dba46056ea6e266`
- `README.md`: SHA256 `e5cba311587823a9792ca77b400eacabc5037a1798fb9a243aad7d65003359ed`
- License: `LICENSE` (MIT, SHA256 `6933cc5703c0c008e59bfb96997181759d3e2b702d2ad72ba935cc96993516d4`)
- Copyright: `Copyright (c) 2026 Robert Lindomar and Omarchy PT-BR contributors`
- Context: Localization clone example demonstrating translation fork maintenance trade-offs.

### 9. `robertlindomar/omarchy-ptbr-power` @ `ee037fc056cf22c2b3108afd3623a52c7afb6881`
- `README.md`: SHA256 `cd4be857b6c2467714b943b1d63931f7dfb55dbfccd5aed78ff936317330e5da`
- License: `LICENSE` (MIT, SHA256 `6933cc5703c0c008e59bfb96997181759d3e2b702d2ad72ba935cc96993516d4`)
- Copyright: `Copyright (c) 2026 Robert Lindomar and Omarchy PT-BR contributors`
- Context: Localization clone example demonstrating translation fork maintenance trade-offs.

### 10. `quickshell-mirror/quickshell` @ `a1a150fab00a93ea983aaca5df55304bc837f51b` (tag `v0.2.1`)
- `src/services/mpris/player.hpp`: SHA256 `12c2b33fe618dc6f572549e0a7c53da119069738f23eb6121c5fe31f09353f0b`
- `src/io/datastream.cpp`: SHA256 `73edb2a6bc1c9472696adbf87d8041753b53550835fb6655f888f057f3aff7cb`
- License: `LICENSE` (LGPL-3.0-only, SHA256 `e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118`)
- Copyright: `Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>`
- Context: External host framework reference: MPRIS player timer guidelines and SplitParser buffer behavior.

### 11. `omacom/omarchy` @ `b679363bed05415771a1b1dc92c6899a908236f7` (branch `quattro`)
- `manual/32-shell-plugins.md`: SHA256 `3545df41d432d83e66f6ac0ada9d754d3875ef774d5f741108509cad5b30149b`
- License: `LICENSE` (MIT, SHA256 `717ba1949502290f8e47688ae2e323acd06c8ca47aec9f7596b15f678c1af4a2`)
- Copyright: `Copyright (c) David Heinemeier Hansson`
- Context: External host manual documentation on shared-shell security model and unsandboxed plugin environment.

---

## 4. Rights and Attribution

1. **Compilation Rights**: The MIT license of the Omarchy Plugin Observatory covers only the project's original compilation, schemas, tooling, documentation, and analysis.
2. **Third-Party Rights**: All third-party source code remains the intellectual property of its original authors under their respective licenses.
3. **Limited Coverage**: The Observatory does not redistribute full third-party repositories. It records SHA-256 digests, permalinks and historical excerpts. Recorded copyright lines come from the inspected license files (the Quickshell LICENSE line names the license-text owner, not every source author). File-level notices can differ. See [NOTICE.md](../NOTICE.md) for unknown rights coverage and correction/removal requests.
