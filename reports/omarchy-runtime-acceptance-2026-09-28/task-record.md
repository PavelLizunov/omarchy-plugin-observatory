# Omarchy overnight deployment and acceptance

## Request and intended result
User requests a thorough autonomous cyclic test: disable all their Omarchy-related plugins, include skills, upload everything to the existing Omarchy test machine, verify that the agent can discover/use them and capture screenshots. Gemini swarm is authorized. Literal `выключить` means disable, not enable; do not silently reverse it. Temporary activation needed for UI acceptance remains a material ambiguity until clarified; perform independent safe work meanwhile.

## Scope and invariants
- Control workspace initially empty/non-Git; source repositories discovered: omarchy-vpnrouter, omarchy-plugin-patterns, omarchy-plugin-observatory under /var/lib/dsh/Project.
- Target: trusted SSH alias omarchy-test, user tester, live hostname omarchytest, Arch/Hyprland.
- Inventory all user-owned Omarchy packages before claiming completeness. Observatory is research, not 3,086 installed plugins.
- Preserve user configuration/secrets and unrelated changes. No VPN connections, route/firewall edits, privileges, VM rollback, DSH restart, second graphical shell, or production deployment.
- Use committed exact SHAs for remote tests; inspect existing installations; no overwrite of untracked work.
- Disable only precisely identified user plugins through verified supported controls, reversibly. No built-in shell component blanket shutdown.
- Skills must be read and their instructions actually applied; copied files alone do not prove agent discovery.
- Gemini workers are explicitly routed ninitux/gemini-flash-high-latest; no worker recursion or Astra inheritance.

## Acceptance/evidence
1. Inventory sources, revisions, installed/enabled state, actual host contract and tool availability.
2. Exact-version source deployment and remote test execution with retained commands/statuses.
3. Skill presence plus demonstrated read/use; explicitly separate agent catalog discovery from manual file reading.
4. Actual Wayland screenshot fetched and visually inspected; distinguish desktop screenshot from plugin-specific UI acceptance.
5. Packaging/functional/negative-path checks, focused review and iterative fixes in authorized scope.
6. Disabled final plugin state with rollback instructions; no false claim of live UI testing if inactive.
7. Reports and task changes committed/pushed to dedicated task branches on existing GitHub remotes; never main/master.

## Initial observations
- $PROJECTS/omarchy is empty and not a Git repository (initial git commands exit 128); no remote destination is assumed.
- SSH target works. grim, hyprctl, qs, quickshell, git and python3 available. dsh not on SSH PATH (command -v exit 1).
- One Hyprland instance exists; user omarchy-shell.service reports inactive, which does not establish shell process absence.
- ~/.config/omarchy/plugins is empty. Other supported roots and enabled registry still require inspection.
- Local source repositories have clean working trees and existing PavelLizunov GitHub remotes.

## Coordinator verified checkpoint (01:53 MSK)
- Gemini batch 1 used 3 explicitly routed workers. Second owner plugin found: stt-parrot / omarchy-tts, id io.github.hikari112.tts. Worker local test claims are reported-only pending coordinator execution.
- Git bundle fetch + exact detached checkout deployed: VPNRouter plugin bf1446b0a80cdc045139563cd9ec068cb8cba09f; TTS 668ed827c64b0648e3f3d06d770f1f8c8d892539; skill c76dbe01f8b92ac6932afa0f583784a18496035b; observatory 0c78ebb5665a81346b57c96b05500ba27e3bf822. Remote root ~/omarchy-night-test-20260928.
- Both plugins installed through supported `omarchy plugin add <local pinned checkout> --yes` without --enable. Installed SHAs checked. Explicit disable commands succeeded; live registry confirms exactly 2 third-party plugins, enabled=false and active=false. Core shell ping ok; original shell config saved remotely before installation.
- Patterns skill installed into previously absent ~/.agents/skills/omarchy-plugin-patterns. Official Codex 0.155.1 stdio app-server skills/list reports it enabled, alongside stock omarchy and diagnose-crash, errors=[]. Catalog only: no model turn, worker, provider or credential changes.
- Read stock remote omarchy SKILL.md + capture.md/plugins.md and standalone patterns/authoring instructions. Deployed patterns entry SHA-256 matches source.
- Baseline grim screenshot retrieved and visually inspected: real 1920x1080 desktop. Pre-existing terminal says voxtype command not found; unrelated, not repaired.
- Stock skill capture first returned zero with jq errors and no image because SSH lacked HYPRLAND_INSTANCE_SIGNATURE. Retry exported the single observed instance, then `omarchy capture screenshot fullscreen save` produced a visually verified 1920x1080 image. No packaged Omarchy source changed.
- Remote bounded suite job bash-125: five VPNRouter Node suites, packaging, host manifest and offscreen QML have exit 0. TTS/observatory still running. Offscreen is not live plugin UI acceptance.

## Final verification status
- Remote results: VPNRouter 5 Node suites + 38 packaging tests + offscreen PASS 12/0; TTS 243 unittest checks; both host manifests valid. Observatory initial missing Pillow/jsonschema repaired in a per-task venv, then 140 Python + 19 Node checks passed.
- Observatory export/rebuild remain failing: 87 export findings (5 checksum mismatches, 77 inventory omissions, 5 private-path detector hits) and stale release/checksums.json. These pre-existing release artifacts were not modified merely to make tests pass; publication-boundary repair is separate scope.
- Additional TTS component compile: 7 ready; Panel unavailable because the unmodified host KeyboardPanel requires a PanelWindow backend absent offscreen. Initial Qt.quit did not exit Quickshell (timeout 124); probe corrected to terminate only its own process (143 expected). Explicit FAIL 8/1 retained, not relabeled pass.
- Skill catalog check extended to three project contexts with required-skill/error assertions; all passed. Remote Codex model turns deliberately not started; catalog evidence is separate from coordinator reading/applying remote skills.
- Gemini batch 2: 3 independent scoped evidence reviewers. Coordinator rejected overstatements: finite timeout is not deadlock; fail-closed JSON parsing is intentional; freshly discovered compositor signature plus actual image inspection is valid capture evidence, but not plugin UI acceptance.
- Original shell config JSON before/after equal; shell PIDs unchanged; live registry still shows both plugins disabled/inactive. No VPN connection, credentials/provider mutation, system SDK installation, or service restart.
- Testing objective delivered with explicit failures/limits; not a release approval. Live UI activation needs clarification because user said disable. No infinite command loop left running.
- Dedicated documentation backup worktree created from Observatory baseline on branch dsh/omarchy-runtime-acceptance-20260928. Report, probe sources and task record are task-owned changes; raw generated artifacts excluded from Git.

## Remaining decisions
- Whether temporary activation for live UI testing is authorized; current result preserves literal disable request.
- Whether to repair Observatory public-release inventory/redaction policy in a separate task.

## Iteration log
- Round 0: skills loaded, safe inventory begun; no runtime configuration changed.
- Round 1: Read-only inspection of omarchy-test completed. Verified running omarchy-shell process (PID 1268 quickshell via PID 1263 omarchy-launch-shell; no systemd unit), package versions (omarchy 4.0.4-1, quickshell 0.3.1-1), plugin roots (only ~/.config/omarchy/plugins/ scanned for third-party, currently empty; 0 third-party plugins installed/enabled), CLI/IPC contract verified (omarchy plugin list/disable/enable/validate), and grim graphical prerequisites verified (Hyprland on Virtual-1 1920x1080@60Hz, zwlr_screencopy_manager_v1 v3, socket /run/user/1000/wayland-1). Safe rollback-aware disable procedure established.
