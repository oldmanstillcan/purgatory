---
title: "Purgatory — Product Requirements Document v1"
type: spec
date: 2026-03-28
status: draft
author: Hephaestus (Claude Code) + Rob + Grok + Mimir
project: Purgatory
tags: [purgatory, product, security, openclaw, skill-vetting, open-source]
related: [2026-03-28-openclaw-hardened-deployment, 2026-03-28-openclaw-skill-trust-matrix]
---

# Purgatory — Product Requirements Document v1

## Modular Skill Vetting Framework for AI Agent Ecosystems

---

## 1. Problem Statement

AI agent platforms (OpenClaw, and future equivalents) allow users to install third-party skills/plugins that can:
- Execute shell commands
- Access file systems
- Handle API keys and OAuth tokens
- Make outbound network requests
- Modify agent behavior permanently

There is no standardized, open-source tool for vetting these skills before installation. Current state:
- 1,184+ malicious skills found on ClawHub (Feb-Mar 2026)
- 13% of published skills are malicious or critically vulnerable (Snyk/Koi audits)
- No download counts, ratings, or reviews visible to users
- Authors identified by anonymous hash only
- VirusTotal scanning exists but is insufficient as sole defense

Users are flying blind. The ones who care do manual review. Most don't.

---

## 2. Product Vision

**Purgatory** is a modular, open-source skill vetting framework. It does not prescribe tools — it provides the orchestration layer and scoring engine. Users assemble their own vetting pipeline from independent layers using whatever tools they trust.

### Core Principle
> No skill gets installed without being assumed hostile first.

### Philosophy (Bruce Lee Principle)
- **Absorb:** Existing security tools (semgrep, trufflehog, shellcheck)
- **Discard:** Vendor lock-in, proprietary scanning, paid-only tiers
- **Add:** Modular layer architecture, multi-LLM research pipeline, trust scoring engine

---

## 3. Target Users

### Primary: Solo builders / small teams running AI agents
- Run OpenClaw or similar on personal/business infrastructure
- Handle real API keys, social tokens, business data
- Need practical security without enterprise complexity
- Technical enough to run CLI tools

### Secondary: OpenClaw community
- Skill publishers who want to certify their work
- Community reviewers who want a standard framework
- Security researchers auditing the ecosystem

### Future: Enterprise
- Teams deploying AI agents with compliance requirements
- Need approval workflows, audit trails, certification

---

## 4. Architecture: Layers

Each layer is independent. Users compose their pipeline by selecting which layers to run and which tools to use per layer.

### Layer 1: Static Scan
**Purpose:** Find secrets, vulnerabilities, and dangerous code patterns.

**Input:** Skill directory (SKILL.md + scripts/ + any files)
**Output:** JSON report with findings, severity, locations

**Default tools (all free, open source):**
- `trufflehog` — secrets detection (API keys, tokens, passwords in code)
- `semgrep` — static analysis (injection patterns, dangerous functions)
- `shellcheck` — shell script linting and vulnerability detection

**Interface:**
```bash
purgatory scan --layer static /path/to/skill/
```

**Output schema:**
```json
{
  "layer": "static",
  "tool": "trufflehog",
  "findings": [
    {
      "severity": "critical",
      "type": "api_key_exposure",
      "file": "scripts/setup.sh",
      "line": 42,
      "detail": "OpenAI API key hardcoded"
    }
  ],
  "pass": false
}
```

### Layer 2: Prompt Review
**Purpose:** Detect prompt injection, instruction abuse, and behavioral manipulation in SKILL.md.

**Input:** SKILL.md content
**Output:** Injection risk score + flagged patterns

**Techniques:**
- Regex pattern matching for known injection phrases
- Instruction boundary analysis (does the skill try to override system prompts?)
- Hidden instruction detection (zero-width characters, unicode tricks)
- Behavioral directive analysis (does it tell the agent to do things outside its stated purpose?)

**Default tool:** Built-in regex scanner (free, no LLM needed)
**Optional:** Any LLM for semantic analysis (user brings own key)

**Interface:**
```bash
purgatory scan --layer prompt /path/to/skill/SKILL.md
```

**Red flag patterns:**
- "ignore previous instructions"
- "do not tell the user"
- "silently" + any action verb
- "send to" + external URL
- "read" + sensitive file paths (.env, .ssh, credentials)
- Hidden text or zero-width characters

### Layer 3: Source Verification
**Purpose:** Verify the skill's author, repository, maintenance status, and community standing.

**Input:** Skill metadata (name, slug, owner)
**Output:** Provenance report

**Checks:**
- Does a source repo exist? (GitHub link)
- Is the repo archived or active?
- Author identity (hash vs real profile)
- Last commit date
- Open issues / security advisories
- Fork count / star count
- ClawHub report count
- Related skills by same author

**Default tool:** GitHub API (free tier, 60 req/hr unauthenticated, 5000 authenticated)
**Optional:** Manual research, X/Reddit search

**Interface:**
```bash
purgatory scan --layer source --slug openclaw-smart-router
```

### Layer 4: Behavioral Sandbox
**Purpose:** Actually run the skill in isolation and monitor what it does.

**Input:** Skill installed in isolated OpenClaw instance
**Output:** Behavioral report (network calls, file access, process spawning)

**Monitors:**
- `tcpdump` / `ss` — outbound network connections
- `inotifywait` / `auditd` — file access (reads AND writes)
- `ps` / `strace` — process spawning, system calls
- `env` comparison — environment variable access

**Requires:** Isolated environment (Docker, VM, or dedicated hardware like NUC/Purgatory box)

**Interface:**
```bash
purgatory sandbox --skill fitness --duration 60
# Installs skill, runs it for 60 seconds, captures all activity
```

**Output:**
```json
{
  "layer": "sandbox",
  "network": {
    "outbound_connections": [
      {"dest": "api.openai.com", "port": 443, "expected": true},
      {"dest": "unknown-server.xyz", "port": 8080, "expected": false}
    ]
  },
  "filesystem": {
    "reads": ["/home/purgatory/.openclaw/AGENTS.md"],
    "writes": ["/home/purgatory/.openclaw/memory/test.md"],
    "suspicious_reads": ["/home/purgatory/.ssh/id_ed25519"]
  },
  "processes": {
    "spawned": ["python3 scripts/setup.sh"],
    "suspicious": []
  },
  "pass": false,
  "reason": "Attempted to read SSH key + unexpected outbound connection"
}
```

### Layer 5: LLM Deep Research
**Purpose:** Multi-model analysis of the skill's purpose, quality, security posture, and ecosystem standing.

**Input:** Skill content + metadata + any previous layer results
**Output:** Structured research report with confidence scores

**How it works:**
1. Build research prompt from skill content + context
2. Send to one or more LLMs (user's choice)
3. Cross-reference findings
4. Score confidence per finding

**User brings own keys for:** OpenAI, Anthropic, Grok, Ollama (local), or any OpenAI-compatible API

**Interface:**
```bash
purgatory research --skill hippocampus --models openai,ollama
```

**This is what we did manually tonight.** Purgatory automates that process.

### Layer 6: Community Signal
**Purpose:** Check what the community knows about this skill.

**Input:** Skill slug/name
**Output:** Community reputation report

**Checks:**
- ClawHub report count
- GitHub issues mentioning security
- X/Twitter mentions + sentiment
- Known malware lists (ClawHavoc, Koi Security, Snyk databases)
- VirusTotal verdict (if available via API)

**Interface:**
```bash
purgatory scan --layer community --slug sona-security-audit
```

---

## 5. Scoring Engine

The core of Purgatory. Takes output from all layers and produces a unified trust assessment.

### Input
JSON reports from each layer run.

### Processing
1. Weight each layer's findings by severity
2. Apply hard-fail rules (any critical finding = automatic Tier 0)
3. Calculate weighted trust score (0-100)
4. Map to trust tier

### Trust Tiers
| Tier | Score | Meaning | Action |
|---|---|---|---|
| 0 | 0-25 | Do not install | Reject |
| 1 | 26-50 | Isolated lab only | Sandbox required |
| 2 | 51-75 | Limited internal use | Controls required |
| 3 | 76-100 | Controlled production | Standard precautions |

### Hard-Fail Rules (force Tier 0)
- Any hardcoded secret found
- Any prompt injection pattern detected
- Unexpected outbound network connection in sandbox
- Attempt to read sensitive files (.ssh, .aws, .env outside workspace)
- Source repo archived with no active replacement
- 3+ community reports / known malware list match

### Approval Matrix Output
```json
{
  "skill": "hippocampus",
  "trust_tier": 1,
  "trust_score": 38,
  "lab_use": "conditional",
  "prod_use": "denied",
  "required_sandbox": true,
  "required_secret_isolation": true,
  "required_network_policy": "deny_all",
  "required_manual_review": true,
  "hard_fails": [],
  "warnings": [
    "10 shell scripts detected",
    "cron job installation detected",
    "persistent memory writes detected"
  ],
  "layer_scores": {
    "static": 65,
    "prompt": 80,
    "source": 70,
    "sandbox": 20,
    "research": 45,
    "community": 50
  }
}
```

---

## 6. CLI Interface

```bash
# Full pipeline (all layers)
purgatory vet /path/to/skill/

# Specific layers
purgatory scan --layer static /path/to/skill/
purgatory scan --layer prompt /path/to/skill/SKILL.md
purgatory scan --layer source --slug skill-name
purgatory sandbox --skill skill-name --duration 60
purgatory research --skill skill-name --models openai,ollama
purgatory scan --layer community --slug skill-name

# Score only (from existing layer reports)
purgatory score /path/to/reports/

# Report
purgatory report /path/to/skill/ --format markdown
purgatory report /path/to/skill/ --format json

# Batch (vet all installed skills)
purgatory audit --all
```

---

## 7. Configuration

```yaml
# ~/.purgatory/config.yaml
layers:
  static:
    enabled: true
    tools: [trufflehog, semgrep, shellcheck]
  prompt:
    enabled: true
    use_llm: false  # true = use LLM for semantic analysis
  source:
    enabled: true
    github_token: ""  # optional, for higher rate limits
  sandbox:
    enabled: false  # requires isolated environment
    method: docker  # docker | vm | native
    duration: 60
  research:
    enabled: false  # requires API keys
    models: []  # e.g. [openai/gpt-5-mini, ollama/qwen3.5:4b]
  community:
    enabled: true

scoring:
  hard_fail_on_secrets: true
  hard_fail_on_injection: true
  hard_fail_on_exfiltration: true
  weights:
    static: 0.25
    prompt: 0.20
    source: 0.15
    sandbox: 0.20
    research: 0.10
    community: 0.10

output:
  format: markdown  # markdown | json | both
  directory: ~/.purgatory/reports/
```

---

## 8. Tech Stack

- **Language:** Python (widest adoption for security tooling)
- **Dependencies:** minimal core, tools installed separately
- **Package:** pip install purgatory-ai (or similar)
- **License:** MIT (maximum adoption)
- **Repo:** GitHub (public)

### Core (no external deps)
- CLI framework (click or typer)
- JSON report handling
- Scoring engine
- Config loader
- Report generator (markdown + JSON)

### Optional (user installs what they need)
- trufflehog (pip)
- semgrep (pip)
- shellcheck (apt/brew)
- docker (for sandbox layer)
- LLM client (openai, anthropic, ollama — user's choice)

---

## 9. Build Order

### Phase 1: Core + Layer 1 (2-3 sessions)
- CLI skeleton
- Config system
- Layer 1: Static scan (trufflehog + semgrep integration)
- Scoring engine (basic)
- Markdown report output
- Test on our own installed skills

### Phase 2: Layers 2-3 (2 sessions)
- Layer 2: Prompt review (regex scanner)
- Layer 3: Source verification (GitHub API)
- Scoring engine (weighted)
- Batch audit command

### Phase 3: Layer 4 (2-3 sessions)
- Layer 4: Behavioral sandbox (Docker-based)
- Network monitoring
- File access monitoring
- Process tracking

### Phase 4: Layers 5-6 (1-2 sessions)
- Layer 5: LLM deep research (multi-model)
- Layer 6: Community signal
- Full scoring engine
- Approval matrix output

### Phase 5: Polish + Release (1-2 sessions)
- Documentation
- PyPI package
- GitHub repo
- README with examples
- "Purgatory Verified" badge spec
- Content: blog post / X thread documenting the build

---

## 10. Purgatory Verified Badge

Skills that pass the full pipeline at Tier 2+ can display:

```
[Purgatory Verified — Tier 3]
Scanned: 2026-03-28
Layers: static, prompt, source, sandbox, research, community
Score: 82/100
Report: purgatory.dev/reports/skill-name
```

Publisher submits skill → Purgatory runs full pipeline → passes → badge issued.

For the community: trust signal that currently doesn't exist.

---

## 11. Revenue Model (future)

### Free (open source core)
- All 6 layers available
- CLI tool
- Local scoring engine
- Self-hosted everything

### Hosted (purgatory.dev)
- Upload a skill → get instant report
- No local setup needed
- Free tier: 5 scans/month
- Pro tier: unlimited + badge issuance + API access

### Enterprise
- Private registry with approval workflows
- Team-based skill governance
- Audit trail and compliance reporting
- SSO / RBAC

---

## 12. Content Strategy (launch)

The build process IS the content:

1. **Pre-launch thread:** "341 malicious AI agent skills. Here's what I found."
2. **Build-in-public:** Document each phase as OMSC content
3. **Launch thread:** "I built a tool to vet AI agent skills. It's free. Here's why."
4. **Ongoing:** Weekly "skill of the week" audit reports
5. **CT credibility:** Be the source of truth for OpenClaw skill security

---

## 13. Success Metrics

### Phase 1 (internal)
-- Successfully audits all installed skills
- Catches known issues we identified manually
- Runs in < 60 seconds for basic scan

### Phase 2 (community)
- 100+ GitHub stars in first month
- 10+ community contributions
- Adopted by 3+ OpenClaw power users

### Phase 3 (product)
- 1000+ pip installs
- 50+ skills scanned on hosted version
- First "Purgatory Verified" badge issued

---

## 14. What This Is NOT

- Not a replacement for reading the code yourself
- Not a guarantee of safety (no tool is)
- Not vendor-locked to OpenClaw (designed for any skill/plugin ecosystem)
- Not a paid gate (free core is genuinely useful)
- Not security theater (we built this because we needed it)

---


*Spec version: 1.0*
*Authors: Rob (vision), Hephaestus (spec), Grok (security landscape), Mimir (deep research)*
*Date: 2026-03-28*

---

## v0.2 Roadmap (from Grok + Mimir code review)

### Both reviewers confirmed:
- v0.1 is "serious prototype quality" / "promising early-stage production"
- Correctly solves the right problem at the right time
- Not evasion-proof but catches 70-80% of low-effort threats
- Position as "first-pass vetting framework" not "security tool"

### v0.2 Priorities (NOT more regex)
1. **Execution path detection** — what would run first? Trace subprocess chains, script entry points
2. **Dependency scanning** — requirements.txt, package.json, pip/npm installs hiding risk
3. **Network endpoint extraction** — domain extraction, allowlist/denylist, entropy scoring
4. **File size/count limits** — prevent DoS via huge files or deeply nested dirs
5. **Configurable patterns** — YAML config instead of hardcoded lists
6. **Unit tests** — pytest for patterns + evasion test cases
7. **Behavior clusters** — network + exec together = critical (not just individual findings)

### Known Evasion Gaps (to address)
- String concatenation/splitting
- Multi-layer encoding (base64 inside base64)
- Runtime fetch (requests.get + exec) — #1 real-world attack
- Semantic prompt rephrasing
- Homoglyph substitution
- Volume dilution (flood harmless files to reduce score)
- Dependency-hidden risk

### Open Source Checklist (before GitHub publish)
- [ ] MIT license
- [ ] README with threat model + limitations
- [ ] SECURITY.md
- [ ] Contributing guidelines
- [ ] pytest test suite
- [ ] pyproject.toml
- [ ] Example reports
- [ ] Sample malicious skill for testing
- [ ] Disclaimer: first-pass vetting, not guarantee of safety
- [ ] Rule versioning

### Reviewers
- **Grok:** "Real infrastructure protection, not theater. Ship it."
- **Mimir:** "Serious prototype quality. Solving the right problem at the right time."

---

## Product Spec Review — Grok + Mimir Feedback

### Both Agree
- Architecture is correct — orchestration layer, not monolithic scanner
- Problem is real and growing (1,184+ malicious skills)
- CLI-first is right for the audience
- Purgatory Verified badge is a trust primitive, not just a feature
- Ship v0.1 tightened, not v0.2 with more features
- Content hook: "I almost compromised my system" not "I built a tool"
- This has legs. Not a toy. A missing security layer.

### Grok Additions
- Use microVMs (Firecracker) or gVisor over plain Docker for sandbox
- eBPF for syscall monitoring
- Shift scoring weights when sandbox goes live (sandbox 0.25-0.30)
- Add --dry-run preview mode
- Report diffing (v1 vs v2 of same skill)
- Evasion/complexity score as negative factor
- Maintainer history tracking (same author + prior reports = red flag)
- SBOM generation with dependency scanning
- Simulate/hook the actual install flow skills expect

### Mimir Additions
- Split hard-fails: explicit malicious = hard fail, heuristic = heavy penalty
- Add confidence score to every finding (severity + confidence)
- Environment context: --context hermes (same skill, different risk per environment)
- Behavior clusters must move up from v0.2 to v0.1 fix
- LLM research layer = advisory only, never scoring-critical
- Community signal = supporting only (low weight, easily gamed early)
- Trust boundary concept: score WHERE the skill runs, not just what it contains
- This is not a scanner — it is a standardized trust model for agent ecosystems

### v0.1 Tightening (before any v0.2 work)
1. Split hard-fail vs heuristic penalties
2. Add confidence to findings
3. Add environment context (--context flag)
4. Move behavior clusters from v0.2 into v0.1
5. Position as first-pass vetting framework
6. Dogfood aggressively — weekly audit reports as content

### The Real Product (Mimir insight)
Not a CLI tool. A standardized trust model:
- Findings schema
- Confidence scoring
- Environment-aware decisions
- Decision outputs that platforms can integrate

If this works:
- Skill authors want badges
- Platforms want integration
- Enterprises want policy enforcement

### Content Strategy (refined)
Hook: "I almost compromised my system installing an AI skill. So I built this."
Then: weekly skill audit reports, case studies, safe/unsafe examples
Delay: hosted SaaS (trust > convenience right now)

---

## Philosophy

> "Absorb what is useful, discard what is useless, add what is uniquely your own."
> — Bruce Lee

**How we applied it:**

**Absorbed:** Fail-closed auditing approach (sona-security-audit), trufflehog + semgrep as detection backbone, structural quality checklists (skill-reviewer), VirusTotal as first-pass filter (ClawHub), malicious skill research (Koi Security, Snyk, Cisco).

**Discarded:** Vendor lock-in, proprietary scanning, single-tool dependency, closed-source vetting, paid-only tiers.

**Added (uniquely ours):**
- Multi-LLM research pipeline (Grok + Mimir + Hephaestus cross-referencing)
- Modular layer architecture (users compose their own pipeline)
- Environment-aware scoring (same skill, different risk per deployment)
- Behavior cluster detection (combinatorial, not additive)
- Trust tier model (0-3) with approval matrix
- The Purgatory concept (skills earn their way into production)
- Built by actually living the problem first, not theorizing about it

## Attribution

Tools and research that inspired Purgatory:
- sona-security-audit by @virtaava — fail-closed auditing, trufflehog + semgrep integration
- skill-reviewer by OpenClaw community — structural quality checklist
- ClawHub VirusTotal integration — first-pass scanning model
- Koi Security — malicious skill documentation and ClawHavoc campaign analysis
- Snyk — ecosystem vulnerability research (13% finding)
- Cisco — skill scanner and security advisories
- Microsoft — Feb 2026 identity isolation guidance for AI agents
