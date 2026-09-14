# X announcement draft — EN

Editorial note (not part of the post): publish only after the corresponding commits are available in both repositories. Gemini attribution comes from the research author's report; the copy does not claim personal human verification. Source links are in the [README](../README.md) and [source notes](../docs/source-notes.md).

---

Before building my own Omarchy Quattro plugin, I used Gemini 3.8 Flash to assemble a research dataset of 3,086 static review records and turn the lessons into an experimental skill for coding agents.

The code contains patterns worth checking before reusing them: for example, activation of seven playerctl processes in a two-second timer handler, or a widget that asks for a sudo password. These are code observations, not CPU or battery measurements, and they do not establish the authors' intentions.

There are useful examples too: receiving events through Unix sockets instead of repeated CLI queries. A closed panel does not always make background work unnecessary, though: the bar's status display may still need updates.

Localization is another area worth discussing. Some plugins have separate localized copies that need to track upstream changes. Shared translation catalogs can reduce that work; existing community initiatives and the installed shell's capabilities matter.

Before publication, I revised the research boundaries: historical assessments are separate from corrections, selected examples are pinned to specific revisions, and unsupported percentages have been removed. The automated findings also contained mistakes, which are recorded in an open correction ledger.

I'm sharing a release candidate of the dataset and a skill with a static review reference matrix. This is material to inspect and improve, not a safety ranking. Corrections with a specific commit and source context are welcome.

Research: https://github.com/PavelLizunov/omarchy-plugin-observatory
Skill: https://github.com/PavelLizunov/omarchy-plugin-patterns

What lifecycle, system API or localization problems do you encounter in your own plugins?
