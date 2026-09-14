# Omarchy Plugin Observatory 🔭

An empirical security, lifecycle, and architecture dataset covering the entire official Omarchy Quattro community plugin ecosystem (**3,086 plugins**, **10,310 machine-verified evidence citations**).

This repository contains the open-source dataset, static analysis records, and verified code patterns extracted from a line-by-line audit across all public community extensions. It is accompanied by an open-source agent skill, [`omarchy-plugin-patterns`](https://github.com/PavelLizunov/omarchy-plugin-patterns), which codifies these lessons into actionable guidance for AI coding assistants and developers.

> **Scope Note:** This is a static code review of implementation practices, privilege boundaries, and lifecycle declarations. It is not runtime telemetry, an energy/battery benchmark, or an endorsement/certification of plugin safety.

---

## Ecosystem Overview

The audit reviewed 3,086 plugin records across the official marketplace registry using an adversarial Dual-Agent protocol (line-by-line inspection by an auditor agent, verified character-by-character by an independent supervisor agent).

| Audit Verdict | Plugin Records | Share | Description |
| :--- | ---: | ---: | :--- |
| **`pass`** | 2,052 | 66.5% | Clean, defensive, well-structured QML/JS code adhering to platform norms. |
| **`warning`** | 800 | 25.9% | Minor issues: unthrottled background timers, non-standard config edits, or polling loops. |
| **`broken`** | 126 | 4.1% | Confirmed missing local files or broken entry points preventing execution. |
| **`suspicious`** | 108 | 3.5% | Critical privilege escalation (sudo/pkexec), persistent root hooks, or unauthorized system config writes. |
| **Total** | **3,086** | **100.0%** | **Overall Ecosystem Health Score: 7.4 / 10** |

---

## Key Architectural Insights

### 1. Privilege Boundaries & System Integrity
While 96.5% of plugins stay within unprivileged user boundaries, **108 plugins** invoked elevated privileges or altered system configurations:
- **UI Password Prompts:** A VPN widget collected user passwords in a visual QML `TextField` and piped them into `sudo -S`.
- **System Binary Hijacking:** A webapp launcher used `sudo`/`pkexec` to replace the system binary `/usr/bin/omarchy-launch-webapp` with a symlink to user-space code, installing a persistent root hook in `/etc/pacman.d/hooks/` to survive package upgrades.
- **Silent Config Mutation:** Over 60 plugins modified external configs (`~/.config/hypr/hyprland.lua`, terminal configs) via `sed -i` without user consent.
- *Root Cause:* Most cases arise because the platform currently lacks standard unprivileged D-Bus privilege brokers for common desktop tasks (network switching, display brightness, charge thresholds).

### 2. Lifecycle & Battery Preservation
- **Unthrottled Background Polling:** ~11% of plugins ran timers without checking whether the interface was open (`running: true` without `root.opened` gating). A media player widget spawned 7 parallel `playerctl` CLI processes every 2 seconds (12,000 forks/hour in the background), and a window-control plugin queried `hyprctl` every 80ms (12.5 times/sec).
- **Exemplary Event-Driven Pattern:** The highest-rated plugins completely avoid polling: they connect directly to native streaming UNIX domain sockets (`Quickshell.Io.Socket`) or listen to D-Bus signals, eliminating background process wakeups and remaining event-driven at idle.

### 3. Crash Resilience & Memory Safety
- **Defensive JSON Parsing:** 98.9% of all `JSON.parse` invocations across the ecosystem are enclosed in `try/catch` blocks. In QML, an unhandled exception in a property binding can break the component; community authors developed a strong habit of defensive parsing.
- **Parent-Child Ownership:** QML’s declarative parent-child object tree effectively prevents memory leaks; confirmed unbounded array accumulation was detected in less than 1% of plugins.

### 4. The Localization Bottleneck
Because the ecosystem initially lacked a standardized internationalization (i18n) workflow, authors frequently forked entire multi-hundred-line repositories just to translate 2–3 UI buttons into their native language. Maintaining separate forks created maintenance divergence across languages.

---

## Open Datasets & Schemas

The dataset is structured as clean, newline-delimited JSON (`.jsonl`) accompanied by formal JSON Schemas in [`schemas/`](schemas/):

- [`data/claims.jsonl`](data/claims.jsonl): Verified public aggregate claims and dataset limitations with stable identifiers.
- [`data/plugins.jsonl`](data/plugins.jsonl): Normalized metadata, feature flags, and verdicts for all 3,086 plugins.
- [`data/evidence.jsonl`](data/evidence.jsonl): 10,310 machine-verifiable citations with exact file, line, code snippet, and analysis proof.
- [`data/patterns.json`](data/patterns.json): Curated architectural patterns (service-backed UI, streaming workers, visibility-gated timers).

---

## Interactive Explorer

This repository includes a lightweight, client-side web explorer with zero external dependencies, zero tracking, and zero repeating timers:

```bash
# Serve the repository root locally:
python3 -m http.server 8000 --bind 127.0.0.1
```
Open [`http://127.0.0.1:8000/site/`](http://127.0.0.1:8000/site/) in your browser to inspect summary statistics and bilingual documentation.

---

## Portable Agent Skill: `omarchy-plugin-patterns`

To help AI coding assistants (OpenCode, Claude, and others) generate safe, performant Omarchy plugins, all findings were distilled into a modular agent skill:

👉 **[github.com/PavelLizunov/omarchy-plugin-patterns](https://github.com/PavelLizunov/omarchy-plugin-patterns)**

To install in OpenCode:
```bash
git clone https://github.com/PavelLizunov/omarchy-plugin-patterns.git \
  "$HOME/.config/opencode/skills/omarchy-plugin-patterns"
```

---

## Standalone Verification

To verify that the dataset files, schemas, and checksums are intact and free of private environment paths:

```bash
python3 tools/verify_public_export.py
```

---

## Notice & Licensing

- **Code & Tools:** [MIT License](LICENSE).
- **Dataset & Findings:** Released openly for research, safety analysis, and ecosystem education.
- **Third-Party Code Citations:** Brief factual quotations in `data/evidence.jsonl` are governed by their respective authors' licenses.
- **Disclaimer:** This project is an independent community initiative and is not officially affiliated with or endorsed by Omarchy, Basecamp, 37signals, or Quickshell.
