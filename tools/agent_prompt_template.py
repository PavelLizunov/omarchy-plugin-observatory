"""agent_prompt_template.py - Prompt template for parallel issue extraction agents."""

import json

def build_agent_prompt(chunk_data: dict) -> str:
    chunk_id = chunk_data.get("chunk_id", 0)
    issues = chunk_data.get("issues", [])
    
    # Compact each issue to essential text to minimize token overhead
    compact_issues = []
    for it in issues:
        compact_it = {
            "number": it["number"],
            "title": it["title"],
            "state": it["state"],
            "author": it["author"],
            "labels": it["labels"],
            "body": it["body"][:2500] if it["body"] else "",
            "comments": [
                {
                    "author": c["author"],
                    "body": c["body"][:2000] if c["body"] else ""
                }
                for c in it.get("comments", [])
            ]
        }
        compact_issues.append(compact_it)

    prompt = f"""You are an expert GitHub Issue Analyst auditing plugin submissions for the Omarchy Quattro Marketplace.
Your task is to analyze the following batch of {len(issues)} GitHub issues/PRs from `omacom/omarchy-plugin-marketplace` (Chunk #{chunk_id}).

For EACH issue in the input, analyze the submission body, bot comments (`github-actions[bot]`), and maintainer comments (`HANCORE-linux`, `dhh`, etc.) to extract:
1. "issue_number": integer
2. "type": "submission" | "verification_update" | "bug_report" | "discussion" | "other"
3. "plugin_id": string or null (e.g. "io.github.user.plugin-name")
4. "plugin_name": string or null
5. "repo_url": string or null
6. "author": string (GitHub login of submitter)
7. "outcome": "approved_published" | "needs_fixes_stalled" | "rejected" | "in_review" | "not_applicable"
8. "bot_validation_errors": array of string codes/messages reported by bot (e.g. "manifest-invalid", "symlink-in-plugin-tree", "entry-point-missing", "reserved-plugin-id", "readme-missing", "license-missing", etc.)
9. "bot_capabilities_flagged": array of strings (e.g. "installer", "package-manager", "polkit", "sudoers")
10. "manual_review_blockers": array of objects:
    - "reviewer": string (e.g. "HANCORE-linux")
    - "category": "agent_steering_files" | "undeclared_dependencies" | "unapproved_scripts_or_binaries" | "qml_wayland_quality" | "licensing_or_assets" | "other"
    - "detail": string (concise quote or summary of what the reviewer objected to)
    - "resolution": string (how the author resolved it, e.g. "renamed AGENTS.md to DEVELOPMENT.md")
11. "key_takeaway": string (one-line practical rule or pitfall learned)

SPECIAL ATTENTION:
- Look for manual security review comments from maintainers (especially `HANCORE-linux`). Look for objections regarding `AGENTS.md`, `agent.md`, `CLAUDE.md`, `.cursorrules`, unlisted compilation dependencies (`base-devel`, `cmake`, `hidapi`), prebuilt binaries, or installer permissions.
- Return ONLY valid JSON matching this schema:
{{
  "chunk_id": {chunk_id},
  "issues_analyzed": {len(issues)},
  "records": [ ... ]
}}

INPUT DATA:
{json.dumps(compact_issues, ensure_ascii=False)}
"""
    return prompt
