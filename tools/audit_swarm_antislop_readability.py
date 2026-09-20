#!/usr/bin/env python3
"""audit_swarm_antislop_readability.py - Parallel Gemini Swarm to audit deliverables for Anti-Slop and Agent Readability.

Dispatches 6 specialized LLM agent workers (gemini-3.8-flash-high) via local AI Gateway:
1. Worker 1: Anti-Slop Audit on Acceptance Guide & Rule Matrix.
2. Worker 2: Anti-Slop Audit on Reports (Issues Audit, Bots Audit, Archive Audit).
3. Worker 3: Agent Readability & Actionability on Acceptance Guide.
4. Worker 4: Agent Readability & Machine-Actionability on Rule Matrix Specification.
5. Worker 5: Agent Readability & Data Utility on Comprehensive Issues Audit (MD & JSON).
6. Worker 6: Cross-Corpus Coherence, Redundancy & Token-Efficiency.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT_DIR = Path("/var/lib/dsh/Project/omarchy-plugin-observatory")
API_URL = "http://ai-gateway:8317/v1/chat/completions"
MODEL = "gemini-3.8-flash-high"
OUTPUT_DIR = ROOT_DIR / "reports" / "anti-slop-and-agent-readability"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Read the deliverables
with open(ROOT_DIR / "docs" / "marketplace-acceptance-guide.md", "r", encoding="utf-8") as f:
    guide_md = f.read()

with open(ROOT_DIR / "docs" / "rule-matrix-specification.md", "r", encoding="utf-8") as f:
    matrix_md = f.read()

with open(ROOT_DIR / "reports" / "marketplace-comprehensive-issues-audit.md", "r", encoding="utf-8") as f:
    issues_audit_md = f.read()

with open(ROOT_DIR / "reports" / "marketplace-bots-security-audit.md", "r", encoding="utf-8") as f:
    bots_audit_md = f.read()

with open(ROOT_DIR / "reports" / "checkpoint3-archive-audit-report.md", "r", encoding="utf-8") as f:
    archive_audit_md = f.read()

with open(ROOT_DIR / "reports" / "marketplace-comprehensive-issues-audit.json", "r", encoding="utf-8") as f:
    issues_audit_json_sample = f.read()[:15000] # Representative header and top entries

TASKS = [
    {
        "id": "worker1_antislop_guidance",
        "title": "Anti-Slop Audit: Acceptance Guide & Rule Matrix",
        "prompt": f"""You are an elite Prose and Documentation Quality Auditor enforcing strict Anti-Slop standards (Prose Doctrine).
Audit the following two primary documents:
Document A: docs/marketplace-acceptance-guide.md
Document B: docs/rule-matrix-specification.md

ANTI-SLOP DOCTRINE & BANNED PATTERNS:
1. Mechanism Over Adjectives: Flag empty praise, decorative intensifiers ('robust', 'seamless', 'revolutionary', 'cutting-edge', 'flawless', 'intelligent', 'comprehensive', 'critical') unless immediately substantiated by a concrete technical mechanism.
2. Copula Displacement: Flag pseudo-verbs ('serves as', 'stands as', 'marks', 'represents', 'features') that should be direct active verbs ('is', 'enforces', 'validates', 'executes').
3. Hedged Symmetry: Flag symmetrical padding ('While X is important, Y is also crucial', 'Whether you are X or Y').
4. Faux-Profundity: Flag staccato drama ('Not X. Y. And that changes everything', decorative em-dashes mimicking deep insight).
5. Boilerplate Openings & Closings: Flag formulaic summaries ('In conclusion', 'As we look forward').
6. Jargon / Corporate Fluff: Flag buzzwords that inflate significance without adding technical precision.

INSPECTION TEXT:
--- DOCUMENT A: marketplace-acceptance-guide.md ---
{guide_md}

--- DOCUMENT B: rule-matrix-specification.md ---
{matrix_md}

OUTPUT FORMAT:
Provide a structured markdown review with:
- Overall Anti-Slop Verdict: PASS / MINOR REVISIONS / HEAVY SLOP
- Concrete Findings Table: [Line / Section | Quoted Text | Anti-Slop Violation Category | Proposed Lean Replacement]
- Summary of Slop Intensity & Cleanliness Score (0-100)
"""
    },
    {
        "id": "worker2_antislop_reports",
        "title": "Anti-Slop Audit: Audit Reports (Issues, Bots, Archive)",
        "prompt": f"""You are an elite Technical Prose Quality Auditor enforcing strict Anti-Slop standards on empirical research reports.
Audit the following three technical audit reports:
Report 1: reports/marketplace-comprehensive-issues-audit.md
Report 2: reports/marketplace-bots-security-audit.md
Report 3: reports/checkpoint3-archive-audit-report.md

ANTI-SLOP DOCTRINE & BANNED PATTERNS:
1. Inflated Significance: Does the text treat heuristic matches or sample data with unwarranted dramatic gravity ('catastrophic', 'game-changing', 'monumental') instead of measured engineering facts?
2. Copula Displacement: Replace 'serves as a primary gate', 'represents a critical vulnerability' with active verbs.
3. Repetitive Formulaic Transitions: Look for robotic AI transition phrases ('It is worth noting that', 'Furthermore, it is essential to remember').
4. Mechanism Over Adjectives: Every technical risk must name the physical mechanism (PID reuse, pipe buffer full, SIGPIPE on closed descriptor), not merely describe it with alarming adjectives.
5. Carrier-Bound Conclusions: Are the conclusions tied to the actual repository and codebase, or are they generic AI advice?

INSPECTION TEXT:
--- REPORT 1: marketplace-comprehensive-issues-audit.md ---
{issues_audit_md}

--- REPORT 2: marketplace-bots-security-audit.md ---
{bots_audit_md}

--- REPORT 3: checkpoint3-archive-audit-report.md ---
{archive_audit_md}

OUTPUT FORMAT:
Provide a structured markdown review with:
- Overall Anti-Slop Verdict across reports: PASS / MINOR REVISIONS / HEAVY SLOP
- Concrete Findings Table: [Report & Section | Quoted Text | Anti-Slop Violation Category | Proposed Lean Replacement]
- Summary of Tone, Objectivity, and Precision
"""
    },
    {
        "id": "worker3_agent_readability_guide",
        "title": "Agent Readability Audit: docs/marketplace-acceptance-guide.md",
        "prompt": f"""You are an Autonomous AI Coding Agent (e.g. Claude Code, Codex, OpenCode) tasked with developing and reviewing Omarchy Quattro plugins.
Evaluate `docs/marketplace-acceptance-guide.md` strictly from the perspective of an AI Agent ingesting this document to write or validate a plugin.

EVALUATION CRITERIA:
1. Information Density & Scannability: Can an agent quickly jump to exact rules without reading redundant prose?
2. Code Snippet Completeness & Copy-Paste Utility: Are code snippets self-contained and syntactically valid? Do they contain missing imports, uninitialized variables, or ambiguous placeholders?
3. Actionable Invariants vs Vague Guidance: Are rules stated as enforceable boolean constraints (e.g. 'Must match ^[a-z0-9]...'), or as vague advice?
4. Token Efficiency: Is there excessive conversational preamble that burns context window tokens unnecessarily?
5. Machine Ambiguity: Are there conflicting statements between sections (e.g. what the local linter checks vs what upstream checks)?

INSPECTION TEXT:
{guide_md}

OUTPUT FORMAT:
Provide a structured markdown report:
- Agent Readability Score: (0-100)
- Scannability & Anchor Analysis: (Quality of Markdown headings, anchors, code fences)
- Code Snippet Actionability Audit: (Review each QML and Bash snippet for agent execution readiness)
- Identified Ambiguities & Friction Points for LLMs
- Actionable Recommendations to Optimize for Coding Agents
"""
    },
    {
        "id": "worker4_agent_readability_matrix",
        "title": "Agent Readability Audit: docs/rule-matrix-specification.md",
        "prompt": f"""You are an Autonomous Static Analysis Agent implementing validation rules for Omarchy Quattro plugins.
Evaluate `docs/rule-matrix-specification.md` strictly from the perspective of a machine agent or linter implementing these checks.

EVALUATION CRITERIA:
1. Rule ID Determinism & Taxonomy: Are MKT-001..003 and SEC-001..009 uniquely and consistently defined?
2. Regular Expression & Pattern Rigor: Are regex patterns explicitly stated, anchored, and free from catastrophic backtracking or edge-case bypasses?
3. Input/Output Contracts: Are target files, detection modes (Deterministic vs Heuristic), and exit codes unambiguously specified?
4. Machine-Parseable Structure: Could a script or LLM directly generate AST visitors or regex rules from this specification without human clarification?
5. False-Positive / False-Negative Boundaries: Does the spec clearly tell an agent what NOT to flag?

INSPECTION TEXT:
{matrix_md}

OUTPUT FORMAT:
Provide a structured markdown report:
- Machine Implementation Readiness Score: (0-100)
- Rule-by-Rule Specification Rigor Audit (Table: Rule ID | Clear Target? | Deterministic? | Machine Actionability)
- Ambiguities or Missing Edge Cases in Rule Definitions
- Recommended Spec Tweaks for 100% Agent Self-Sufficiency
"""
    },
    {
        "id": "worker5_agent_readability_issues_audit",
        "title": "Agent Readability & Data Utility: Issue Audit Reports (MD & JSON)",
        "prompt": f"""You are an Autonomous AI Security Researcher querying marketplace historical review data.
Evaluate `reports/marketplace-comprehensive-issues-audit.md` and the structured JSON dataset `reports/marketplace-comprehensive-issues-audit.json`.

EVALUATION CRITERIA:
1. Machine-Readability of JSON: Is the JSON schema clean, normalized, and easy for an agent to query with jq or Python without complex nested heuristics?
2. Cross-Referencing & Permalinks: Are issue numbers and comment IDs formatted so an agent can directly construct valid API or web queries?
3. Semantic Clarity of Extracted Blockers: Are the maintainer objections clear and actionable, or are they confusingly truncated?
4. Knowledge Retrieval Utility: If a user asks 'What are the top 3 pitfalls when submitting a plugin?', how easily can an LLM extract the answer from these files?

INSPECTION TEXT:
--- MARKDOWN REPORT ---
{issues_audit_md}

--- JSON DATASET SAMPLE ---
{issues_audit_json_sample}

OUTPUT FORMAT:
Provide a structured markdown report:
- Data Structure & Agent Queryability Score: (0-100)
- JSON Schema Evaluation: (Strengths, Weaknesses, Missing Fields)
- Markdown Summary Utility: (Effectiveness as a RAG reference document)
- Friction Points for Agent Retrieval
- Concrete Recommendations to Improve Machine Consumption
"""
    },
    {
        "id": "worker6_cross_corpus_coherence",
        "title": "Cross-Corpus Coherence, Redundancy & Token-Efficiency",
        "prompt": f"""You are a Lead AI Architect evaluating the complete documentation corpus of the Omarchy Plugin Observatory.
Audit the consistency, cross-references, and redundancy across all deliverables:
1. `docs/marketplace-acceptance-guide.md`
2. `docs/rule-matrix-specification.md`
3. `reports/marketplace-comprehensive-issues-audit.md`
4. `reports/marketplace-bots-security-audit.md`
5. `reports/checkpoint3-archive-audit-report.md`

EVALUATION CRITERIA:
1. Terminology Uniformity: Are policy origins (`[MKT-COMPAT]`, `[MKT-BASE]`, `[MKT-POLICY]`, `[OBS-REC]`) and rule IDs (`MKT-001..003`, `SEC-001..009`) used with identical names, severities, and scopes across all files?
2. Cross-Corpus Discrepancies: Do the numbers, percentages, or tool versions conflict anywhere?
3. Redundancy & Token Bloat: Where are identical multi-paragraph blocks duplicated across files, and can they be hyperlinked rather than repeated?
4. Overall Coherence for an AI Agent traversing this workspace: Will an agent get confused by contradictory instructions?

OUTPUT FORMAT:
Provide a structured markdown report:
- Cross-Corpus Coherence Score: (0-100)
- Terminology & Taxonomy Alignment Matrix
- Identified Discrepancies or Contradictions
- Redundancy / Token-Bloat Hotspots
- Final Verdict & Concrete Optimization Plan
"""
    }
]

def run_worker(task: dict) -> dict:
    task_id = task["id"]
    title = task["title"]
    prompt = task["prompt"]

    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }

    t0 = time.time()
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": f"omarchy-audit-worker-{task_id}"}
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.load(resp)
        duration = time.time() - t0
        content = data["choices"][0]["message"]["content"]

        out_path = OUTPUT_DIR / f"{task_id}.md"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"# {title}\n\n" + content.strip() + "\n")

        print(f"  [SUCCESS] {task_id} ({title}) completed in {duration:.2f}s -> {out_path.name}")
        return {"id": task_id, "status": "success", "duration": duration, "path": str(out_path), "content": content}
    except Exception as e:
        duration = time.time() - t0
        print(f"  [FAILED]  {task_id} failed in {duration:.2f}s: {e}", file=sys.stderr)
        return {"id": task_id, "status": "failed", "error": str(e), "duration": duration}

def main():
    print("=" * 70)
    print(f"DISPATCHING GEMINI SWARM (6 SPECIALIST AGENTS)")
    print(f"Model:       {MODEL}")
    print(f"API URL:     {API_URL}")
    print(f"Output Dir:  {OUTPUT_DIR}")
    print("=" * 70, flush=True)

    start_time = time.time()
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(run_worker, t): t["id"] for t in TASKS}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            results[res["id"]] = res

    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"SWARM RUN COMPLETE: {len(results)}/6 tasks finished in {elapsed:.2f}s")
    print("=" * 70)

if __name__ == "__main__":
    main()
