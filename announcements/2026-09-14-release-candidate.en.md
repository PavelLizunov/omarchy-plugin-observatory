# X announcement — EN, long post

Draft. Publish after the corresponding commits have been pushed to both repositories. Gemini attribution comes from the research author's report. Example sources: [README](../README.md) and [source notes](../docs/source-notes.md).

---

Before building my own Omarchy Quattro plugin, I used Gemini 3.8 Flash to assemble 3,086 static-review records. That work became two projects: an open dataset with 10,310 stored source references and observations, and a skill for AI agents writing and reviewing plugins.

The examples have details worth following. A media widget's two-second timer requests seven playerctl processes, but some results also feed the bar tooltip while the popup is closed. Another widget takes a system password in its own UI. A mail-checker component receives events through a Unix socket, with reconnection logic and a notification process still part of its work. Those details give a review somewhere to start: which background updates are needed, who handles the password, and which queries could be replaced by events?

The automated review made mistakes too. Files reported as missing from Omarkey exist at the cited commit. A pacman hook described as running user code as root actually runs a command to create a symlink. The dataset keeps the original assessments alongside separate, sourced corrections so readers can trace the reasoning.

Translation is another useful thread. Localized copies of plugins need to stay in sync with upstream. Shared catalogs can reduce that work; the skill covers translation readiness, message context, plurals and interface checks against the installed shell's capabilities.

I'm sharing a release candidate. The dataset helps locate examples, and the skill provides a structure for reviewing current code. Source checkouts and quotations have not been fully verified across the corpus; no plugins were run, and CPU or battery use was not measured. Stored verdicts still need source review.

Research: https://github.com/PavelLizunov/omarchy-plugin-observatory
Skill: https://github.com/PavelLizunov/omarchy-plugin-patterns

If a finding about your plugin is wrong, send the record ID, commit and relevant code. The project has a correction ledger for those reports.
