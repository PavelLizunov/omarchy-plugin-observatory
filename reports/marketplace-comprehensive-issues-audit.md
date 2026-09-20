# Comprehensive Marketplace Issues & Review Pitfalls Audit

**Dataset Source:** `omacom/omarchy-plugin-marketplace` (All Issues and Pull Requests)
**Total Issues/PRs Analyzed:** 7,732
**Chunks Evaluated by Swarm:** 600 / 600
**Distinct Issues with Human-Authored Maintainer Blockers:** 3,765 (excludes bot-only comments)

> **Document Status: Empirical Historical Evidence (Non-Normative)**  
> This document records historical review observations, objection frequencies, and maintainer feedback patterns across marketplace submissions. It represents **Evidence / Precedent**, not the authoritative platform specification. The canonical normative requirements and enforceable invariants are defined in [`docs/rule-matrix-specification.md`](../docs/rule-matrix-specification.md) and [`docs/marketplace-acceptance-guide.md`](../docs/marketplace-acceptance-guide.md).

---

## 1. Executive Summary & Review Funnel

- **Plugin Submissions & Verifications:** 7,583 requests (5,281 submissions, 2,302 verification updates)
- **Approved & Published Listings:** 4,971
- **Stalled in Review / Needs Fixes:** 1,346
- **Explicitly Rejected:** 707
- **Currently Open / In Review:** 507

*Methodology & Provenance Boundary:* The audit was performed across 600 chunk tasks using an LLM-agent extraction pipeline (`gemini-3.8-flash-high` via internal Gateway). While 600 processed chunk result files demonstrate execution of the pipeline, individual model extractions represent heuristic LLM interpretations. Extracted records reflect documented issue texts and comment transcripts in the marketplace repository. Blocker counts represent documented objections raised in review threads rather than certified vulnerability totals.

### Issue Type Distribution
| Category | Count | % of Total |
| :--- | ---: | ---: |
| `submission` | 5,281 | 68.3% |
| `verification_update` | 2,302 | 29.8% |
| `other` | 120 | 1.6% |
| `discussion` | 17 | 0.2% |
| `bug_report` | 12 | 0.2% |

---

## 2. Manual Security Review Blockers (The Qualitative Review Layer)

While CI bots enforce structural compatibility (`[MKT-COMPAT]`) and basic regex baseline (`[MKT-BASE]`), human security reviewers (primarily `HANCORE-linux` across 3,517 distinct issues with blockers) enforce qualitative security policies.

| Review Category | Blocker Instances | Distinct Issues Affected | Description & Policy Enforced |
| :--- | ---: | ---: | :--- |
| **`other`** | **2,370** | **1,888** | General repository structure, packaging, or documentation defects. |
| **`qml_wayland_quality`** | **1,376** | **1,187** | Unescaped dynamic text markup (`SEC-003`), exclusive keyboard focus (`SEC-007`), or unhandled UI state. |
| **`unapproved_scripts_or_binaries`** | **1,294** | **1,087** | Prebuilt compiled binaries committed to Git or curl-pipe-bash installers lacking build-from-source recipes. |
| **`agent_steering_files`** | **203** | **201** | AI assistant directive files (`AGENTS.md`, `agent.md`, `CLAUDE.md`, `.cursorrules`) shipped in distributable checkout. Blocked for indirect prompt injection risks. |
| **`undeclared_dependencies`** | **63** | **60** | Missing build tools or system libraries (`base-devel`, `cmake`, `hidapi`, `pkgconf`) not declared in `setup` or documentation. |
| **`licensing_or_assets`** | **22** | **22** | Missing copyright attribution for bundled third-party assets, fonts, or preview screenshots. |
| **`installer_or_permissions`** | **1** | **1** | Manual review blocker category |

*(Note: Samples of specific categories in data exports: QML/Wayland quality exports a top-25 sample from 1,376 total recorded blocker instances).* 

### 2.1 Deep Dive: The AGENTS.md / AI Agent Directive Blocker (`SEC-009`)

A total of **201 distinct plugin issues** (203 objection entries, of which 203 were issued by `HANCORE-linux`) were blocked specifically due to AI agent steering directive files in the plugin tree.

**Technical Risk Mechanism:** When an Omarchy user runs `omarchy plugin add <repo>`, the repository is cloned directly into `~/.config/omarchy/plugins/`. When the user subsequently launches an AI coding agent (such as Codex, Claude Code, Cursor, OpenCode, or Windsurf) in or above their user configuration, agents configured to inspect directory context can automatically ingest root or nested `AGENTS.md` files as trusted operational directives. This opens an indirect prompt injection attack vector whereby third-party plugin authors can steer local agent execution, exfiltrate credentials, or alter system configurations without the user's informed consent.

**Sample Blocked Submissions with Inferred Comment Permalinks:**
| Issue # | Candidate Comment Link (Heuristically Inferred) | Plugin Name | Reviewer | Specific Maintainer Objection | Author Documented Resolution |
| ---: | :--- | :--- | :--- | :--- | :--- |
| #209 | Unlinked | `Camera Preview` | `HANCORE-linux` | Repository contained unrelated Entire agent hooks and configs.... | Author removed all unrelated Entire agent hooks and configuration from the repository. |
| #1683 | [#5503180248](https://github.com/omacom/omarchy-plugin-marketplace/issues/1683#issuecomment-5503180248) | `Omakei` | `HANCORE-linux` | Parent paths resolved before mkdir/rename/truncating writes without verified directory des... | None in this issue; issue closed due to 7 days of inactivity |
| #2035 | [#5501457429](https://github.com/omacom/omarchy-plugin-marketplace/issues/2035#issuecomment-5501457429) | `chip402` | `HANCORE-linux` | Current HEAD diverged significantly from validated commit, dropped the root manifest, and ... | Unresolved; closed due to lack of response within 7 days |
| #2296 | [#5443778837](https://github.com/omacom/omarchy-plugin-marketplace/issues/2296#issuecomment-5443778837) | `Context Switcher` | `HANCORE-linux` | plugin persistently linked bundled agent skills into .agents/skills, .claude/skills, .code... | Removed automatic installation of agent skill links. |
| #2556 | [#5501189919](https://github.com/omacom/omarchy-plugin-marketplace/issues/2556#issuecomment-5501189919) | `Bible` | `HANCORE-linux` | Snapshot contained a root AGENTS.md with discoverable coding-agent instructions, which vio... | Removed AGENTS.md from the distributed plugin root and added it to .gitignore. |
| #2610 | [#5467319621](https://github.com/omacom/omarchy-plugin-marketplace/issues/2610#issuecomment-5467319621) | `OmaQuote` | `HANCORE-linux` | Shipped a third-party agent instruction tree under .agents/skills/ with 37 SKILL.md files ... | Removed the .agents/ directory and all SKILL.md files from tracking. |
| #3030 | [#5453250846](https://github.com/omacom/omarchy-plugin-marketplace/issues/3030#issuecomment-5453250846) | `Text Transform` | `HANCORE-linux` | The repository publicly included .gstack/terminal-internal-token and local dev server arti... | Revoked the exposed token, purged .gstack directory from git tracking, and added .gstack t |
| #3081 | [#5622987920](https://github.com/omacom/omarchy-plugin-marketplace/issues/3081#issuecomment-5622987920) | `VPN` | `HANCORE-linux` | approval is blocked because the distributable root contains CLAUDE.md, an agent-control/in... | Unresolved |
| #3098 | [#5732316818](https://github.com/omacom/omarchy-plugin-marketplace/issues/3098#issuecomment-5732316818) | `Omarchy Bitwarden` | `HANCORE-linux` | Root AGENTS.md was included in the marketplace plugin tree; additionally flagged unpinned ... | Relocated AGENTS.md to docs/agents/README.md, pinned workflows to 40-character commit SHAs |
| #3178 | [#5500592694](https://github.com/omacom/omarchy-plugin-marketplace/issues/3178#issuecomment-5500592694) | `Omalaunch` | `HANCORE-linux` | Please remove root automatic agent-instruction files from the distributable tree, trigger ... | None; issue closed due to inactivity after 7 days |
| #3214 | [#5500580406](https://github.com/omacom/omarchy-plugin-marketplace/issues/3214#issuecomment-5500580406) | `Bottom Launcher` | `HANCORE-linux` | Distributable plugin contained root AGENTS.md agent-instruction file and validation commit... | Removed AGENTS.md from the repository and synchronized the commit |
| #3252 | [#5648112683](https://github.com/omacom/omarchy-plugin-marketplace/issues/3252#issuecomment-5648112683) | `Crashes` | `HANCORE-linux` | Repository root contained `CLAUDE.md`, an agent-control/instruction file... | Removed `CLAUDE.md` from the distributable repository tree |
| #3414 | [#5672122602](https://github.com/omacom/omarchy-plugin-marketplace/issues/3414#issuecomment-5672122602) | `Tonearm` | `HANCORE-linux` | Root AGENTS.md was part of the published plugin tree, creating an unintended instruction t... | Removed root AGENTS.md from the distributed plugin repository snapshot. |
| #3420 | [#5501921311](https://github.com/omacom/omarchy-plugin-marketplace/issues/3420#issuecomment-5501921311) | `Omatabs` | `HANCORE-linux` | Root AGENTS.md was distributed with the plugin and included an rsync --delete command targ... | Removed root AGENTS.md from the distributed plugin repository. |
| #3445 | [#5623005413](https://github.com/omacom/omarchy-plugin-marketplace/issues/3445#issuecomment-5623005413) | `DHH` | `HANCORE-linux` | Repository contained AGENTS.md; marketplace plugin payloads must not ship agent steering f... | Added AGENTS.md to .gitignore and removed it from tracking. |
| #3546 | [#5502263116](https://github.com/omacom/omarchy-plugin-marketplace/issues/3546#issuecomment-5502263116) | `Better Omarchy` | `HANCORE-linux` | Plugin auto-installed agent symlinks into ~/.agents, ~/.claude, ~/.codex, and ~/.pi withou... | None; issue closed due to inactivity after seven days without fixes. |
| #3598 | [#5648216360](https://github.com/omacom/omarchy-plugin-marketplace/issues/3598#issuecomment-5648216360) | `Intermission` | `HANCORE-linux` | Security review is categorically blocked because the distributed plugin root contains AGEN... |  |
| #3653 | [#5741237325](https://github.com/omacom/omarchy-plugin-marketplace/issues/3653#issuecomment-5741237325) | `omatodolist` | `HANCORE-linux` | Published tree contained root AGENTS.md and skills/omatodolist-agent/SKILL.md that turned ... | Removed AGENTS.md and moved the agent skill out of the repository. |
| #3666 | [#5503278785](https://github.com/omacom/omarchy-plugin-marketplace/issues/3666#issuecomment-5503278785) | `CodexBar` | `HANCORE-linux` | Distributable root shipped `AGENTS.md`, which automatically imposed repository-specific in... | Removed AGENTS.md from the distribution. |
| #3697 | [#5500629845](https://github.com/omacom/omarchy-plugin-marketplace/issues/3697#issuecomment-5500629845) | `OmaRecorder` | `HANCORE-linux` | Root AGENTS.md embeds automatic coding-agent instructions unrelated to runtime and must be... | Untracked AGENTS.md at commit f9de89e, pinned default branch HEAD to tagged release v1.5.0 |
| #3806 | [#5500646208](https://github.com/omacom/omarchy-plugin-marketplace/issues/3806#issuecomment-5500646208) | `On-screen keyboard` | `HANCORE-linux` | Root AGENTS.md contains automatic coding-agent instructions unrelated to runtime and must ... | Removed root AGENTS.md from the repository. |
| #3934 | [#5604352155](https://github.com/omacom/omarchy-plugin-marketplace/issues/3934#issuecomment-5604352155) | `kheetsheet` | `HANCORE-linux` | submitted tree contains HANDOVER.md (92,184 bytes), whose opening lines explicitly instruc... | Removed HANDOVER.md from the payload and triggered fresh validation |
| #3944 | [#5501102361](https://github.com/omacom/omarchy-plugin-marketplace/issues/3944#issuecomment-5501102361) | `OpenDota` | `HANCORE-linux` | Remove root AGENTS.md from the installed plugin payload; it is automatically interpreted a... | Author claimed removal, but submission was closed due to review timeout before revalidatio |
| #3968 | [#5500330258](https://github.com/omacom/omarchy-plugin-marketplace/issues/3968#issuecomment-5500330258) | `OmaBackup` | `HANCORE-linux` | Repository shipped automatically discoverable coding-agent instruction files (AGENTS.md an... | Untracked AGENTS.md and .herdr/reviewer.md from git. |
| #4074 | [#5501116705](https://github.com/omacom/omarchy-plugin-marketplace/issues/4074#issuecomment-5501116705) | `Web3 Workstation` | `HANCORE-linux` | The installer silently installed an automatically interpreted coding-agent skill under ~/.... | Removed coding-agent skill from automatic installation (requiring explicit opt-in with str |

*Note on Comment Link Resolution:* Comment permalinks are candidate links heuristically inferred by correlating issue number, reviewer username, and text overlap against SQLite corpus comment transcripts with strict tie rejection; ambiguous or below-threshold matches are retained as 'Unlinked'.

---

## 3. Automated Bot Check Failures (`github-actions[bot]`)

### 3.1 Compatibility Blocker Errors
| Bot Validation Error | Occurrences | Root Cause |
| :--- | ---: | :--- |
| `The plugin ID does not identify an existing community listing.` | 71 | CI build-catalog rejection |
| `Only the existing listed commit can be verified in this workflow.` | 65 | CI build-catalog rejection |
| `This repository is already listed in the marketplace.` | 46 | CI build-catalog rejection |
| `The issue title must start with `[Plugin]:` and include the plugin name.` | 40 | CI build-catalog rejection |
| `curl-pipe-shell` | 27 | CI build-catalog rejection |
| `remote-git-execution-unpinned` | 25 | CI build-catalog rejection |
| `The validation result could not be published to the issue.` | 25 | CI build-catalog rejection |
| `The submission fields are missing, reordered, or malformed.` | 21 | CI build-catalog rejection |
| `A license file is required in the repository root.` | 16 | CI build-catalog rejection |
| `The requested commit is already the marketplace listing snapshot.` | 15 | CI build-catalog rejection |
| `The repository URL must be a public GitHub repository root URL.` | 14 | CI build-catalog rejection |
| `The plugin manifest does not match the supported Quattro contract.` | 14 | CI build-catalog rejection |
| `Use the verification issue form without changing its headings.` | 13 | CI build-catalog rejection |
| `The automated security baseline did not complete.` | 12 | CI build-catalog rejection |
| `Select the currently listed snapshot action in the verification form.` | 12 | CI build-catalog rejection |

### 3.2 Security Baseline Capabilities Triggering Manual Review
| Capability | Occurrences | Review Trigger Reason |
| :--- | ---: | :--- |
| `installer` | 1,479 | Automated baseline capability detected |
| `privilege` | 1,399 | Automated baseline capability detected |
| `package-manager` | 1,356 | Automated baseline capability detected |
| `service-management` | 1,106 | Automated baseline capability detected |
| `remote-build` | 1,046 | Automated baseline capability detected |
| `bundled-executable-binary` | 88 | Automated baseline capability detected |
| `sudoers-modification` | 57 | Automated baseline capability detected |
| `curl-pipe-shell` | 11 | Automated baseline capability detected |
| `remote-git-execution-unpinned` | 4 | Automated baseline capability detected |

---

## 4. Synthesis & Recommendations for Plugin Developers

1. **Do Not Ship `AGENTS.md` in Plugin Checkouts (`SEC-009`):** Rename contributor and developer notes to `DEVELOPMENT.md` or `CONTRIBUTING.md`.
2. **Declare All Compilation Tools:** If building C/C++ or Rust helpers, explicitly declare `base-devel`, `cmake`, or compiler dependencies in `setup` and README.
3. **No Prebuilt Binaries:** All native helpers must be compiled from source on the user's machine during setup; prebuilt binaries are consistently blocked on manual review.
4. **No Direct Symlinks (`MKT-002`):** Ensure `.git` submodules or asset symlinks are resolved to regular files before submission.
