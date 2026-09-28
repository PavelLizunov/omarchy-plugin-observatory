# Unpacked evidence browsing

Requested on 2026-09-28: organize the existing report, screenshots and logs into folders for direct Harness viewing without downloading a ZIP.

- Output: `report/2026-09-28/README.md` under the original Omarchy task workspace, plus seven numbered subdirectories.
- Scope: copy existing report/evidence, add an index with screenshot embeds and per-file links. No remote operations, new tests, result changes or ZIP replacement.
- Reproduction: run `python3 organize-evidence.py <original-task-workspace>`; the workspace must contain the original report-backup, artifacts, scripts and task record.
- Verification: 29 copied files match their source SHA-256 values; every relative index link resolves; a second run succeeds without changing copied files. Markdown source reviewed. Actual browser rendering of relative embeds was not independently tested; PNGs and all evidence files are also presented individually through Harness.
- Git stores this record and the organizer; generated evidence copies remain local deliverables rather than new public raw-log uploads.
- Documentation gate: PASS for preserved evidence counts and explicit limits; no new runtime or UI-acceptance claims.
