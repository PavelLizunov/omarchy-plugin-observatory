# Anti-Slop Audit: Acceptance Guide & Rule Matrix

### Overall Anti-Slop Verdict: **MINOR REVISIONS**

Both documents demonstrate exceptionally high technical rigor, explicit contracts, concrete code examples, and exact regex/RFC citations. However, minor editorial slop persists:
- **Decorative Intensifiers:** Overuse of redundant intensifiers (`strict`, `strictly`, `distinct`) on binary constraints (e.g., a permission mode of `0700` or a regex match is intrinsically binary; it cannot be "strictly" matched).
- **Copula Displacement:** Instances of pseudo-verbs such as `represent` instead of direct copulas or active assertions.
- **Hedged Symmetry:** Classical "While X avoids A, it necessitates B" syntax framing.

---

### Concrete Findings Table

| Document & Section | Quoted Text | Anti-Slop Violation Category | Proposed Lean Replacement |
| :--- | :--- | :--- | :--- |
| **Doc A — §1 (Executive Overview)** | *"This guide provides community developers, plugin maintainers, and security reviewers with practical community guidance on the acceptance gates..."* | Jargon / Redundant Padding (`practical community guidance`) | *"This guide defines the acceptance gates, validation criteria, common failure modes..."* |
| **Doc A — §1 (Executive Overview)** | *"While this unified design avoids the overhead of separate process multiplexing, it necessitates careful pre-flight validation: a flawed or insecure plugin can destabilize user sessions..."* | Hedged Symmetry (`While X avoids..., it necessitates Y`) | *"The unified design eliminates process multiplexing overhead, but requires pre-flight validation: flawed plugins can destabilize user sessions..."* |
| **Doc A — §1 (Executive Overview)** | *"Marketplace submission evaluations are stratified into four distinct policy layers:"* | Jargon / Decorative Intensifier (`stratified`, `distinct`) | *"Marketplace submissions are evaluated across four policy layers:"* |
| **Doc A — §3.1 (Manifest Schema)** | *"If present, must be strictly one of: `"left"`, `"center"`, `"right"`."* | Decorative Intensifier (`strictly one of`) | *"If present, must be one of: `"left"`, `"center"`, `"right"`."* |
| **Doc A — §3.3 (Manifest Schema)** | *"Strict Symlink Prohibition (`MKT-002`)"* | Decorative Intensifier (`Strict`) | *"Symlink Prohibition (`MKT-002`)"* (Prohibitions are binary). |
| **Doc A — §5 (Hardening Patterns)** | *"These pattern matches represent candidates for contextual review rather than verified runtime vulnerabilities."* | Copula Displacement (`represent candidates for contextual review`) | *"These matches indicate review candidates, not verified runtime vulnerabilities."* |
| **Doc A — §5.2 (Process Watchdogs)** | *"Implement an owned, two-stage watchdog timer with strict cancellation on process exit..."* | Decorative Intensifier (`strict cancellation`) | *"Implement a two-stage watchdog timer that disarms on process exit..."* |
| **Doc A — §5.5 (Safe Temp Storage)** | *"Anchor all temporary state, sockets, and lockfiles to `$XDG_RUNTIME_DIR` under an owner-verified, strict `0700` subdirectory:"* | Decorative Intensifier (`strict 0700`) | *"Anchor all temporary state, sockets, and lockfiles to an owner-verified `0700` subdirectory under `$XDG_RUNTIME_DIR`:* |
| **Doc A — §5.7 (Remote Image Asset Security)** | *"...with a strict maximum redirect ceiling (e.g. ≤3 hops)."* | Decorative Intensifier (`strict maximum`) | *"...with a maximum redirect limit (e.g. ≤3 hops)."* |
| **Doc A — §5.7 (Remote Image Asset Security)** | *"...while **strictly preserving the original hostname for TLS Server Name Indication (SNI)**..."* | Decorative Intensifier (`strictly preserving`) | *"...while preserving the original hostname for TLS Server Name Indication (SNI)..."* |
| **Doc A — §5.9 (AI Agent Directives)** | *"Human security reviewers (...across 161 distinct issues, representing 174 objection entries...) enforce a hard stop:..."* | Copula Displacement / Decorative Intensifiers (`distinct`, `representing`, `hard stop`) | *"Maintainers (...across 161 issues and 174 objections...) enforce a blocking requirement:..."* |
| **Doc B — §1 (Governance & Policy Taxonomy)** | *"Detection modes are strictly separated:"* | Decorative Intensifier (`strictly separated`) | *"Detection modes are separated into two categories:"* |
| **Doc B — §3 (SEC-007)** | *"Hazard: Grabbing exclusive keyboard focus on layer-shell surfaces can freeze desktop interaction or act as a keylogger."* | Copula Displacement / Imprecise Metaphor (`act as a keylogger`) | *"Hazard: Exclusive keyboard focus on layer-shell surfaces freezes desktop interaction and allows unprivileged keystroke interception."* |

---

### Slop Intensity & Cleanliness Score

- **Slop Intensity:** **Low (8/100)**  
  *Context:* The documentation is largely free of typical marketing slop (`seamless`, `revolutionary`, `cutting-edge`), hollow introductory throat-clearing, and artificial conclusions. Technical mechanisms (e.g., POSIX shell traps, subshell unwrapping, IPv4-mapped IPv6 normalization, `CURLOPT_RESOLVE` SNI pinning) are substantiated with working code and exact specifications.
- **Cleanliness Score:** **92 / 100**  
  *Recommendation:* Execute the proposed lean replacements to eliminate redundant adverbs (`strictly`), pseudo-copulas (`represent`), and defensive hedging.
