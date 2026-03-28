# Purgatory

**Modular skill vetting framework for AI agent ecosystems.**

Skills earn their way into production. Or they don't.

---

> "Absorb what is useful, discard what is useless, add what is uniquely your own."
> — Bruce Lee

Purgatory was born from discovering that **1,184+ malicious skills** were uploaded to OpenClaw's ClawHub marketplace in early 2026. We needed a vetting tool. Nothing existed. So we built one.

## What It Does

Scans AI agent skills/plugins for:
- Dangerous code patterns (shell injection, reverse shells, privilege escalation)
- Hardcoded secrets (API keys, tokens, credentials)
- Prompt injection in instruction files (override attempts, hidden directives, exfiltration)
- Unicode tricks (zero-width characters, bidirectional text manipulation)
- Suspicious binaries (ELF, Mach-O executables in skill packages)
- Risky dependencies (requirements.txt, package.json, npm install hooks)
- Behavior clusters (network + exec together = critical, not just individually)

Produces:
- **Trust score** (0-100)
- **Trust tier** (0 = do not install, 1 = lab only, 2 = internal with controls, 3 = production)
- **Environment-aware scoring** (same skill scores differently for lab vs production)
- **Markdown reports** (Obsidian-compatible with YAML frontmatter)

## Quick Start

```bash
git clone https://github.com/oldmanstillcan/purgatory.git
cd purgatory
pip install -e .

# Vet a single skill
purgatory vet /path/to/skill/

# Audit all installed OpenClaw skills
purgatory audit --openclaw-dir ~/.openclaw

# Vet with production context (stricter scoring)
purgatory vet /path/to/skill/ --context production

# Scan a specific layer
purgatory scan --layer static /path/to/skill/
purgatory scan --layer prompt /path/to/skill/SKILL.md
```

## Optional Tools (enhance detection)

Purgatory works without these, but they add depth:

```bash
# Secret detection
pip install trufflehog

# Static analysis
pip install semgrep

# Shell script linting
apt install shellcheck  # or brew install shellcheck
```

## Architecture: Layers

Purgatory doesn't prescribe tools — it provides orchestration and scoring. Users compose their own pipeline.

| Layer | Purpose | Default Tool | Status |
|---|---|---|---|
| 1. Static Scan | Secrets, dangerous patterns, binaries | Built-in regex + trufflehog + semgrep | ✅ v0.1.1 |
| 2. Prompt Review | Injection, instruction abuse, unicode tricks | Built-in regex scanner | ✅ v0.1.1 |
| 3. Source Verification | Author, repo, maintenance status | GitHub API | Planned |
| 4. Behavioral Sandbox | Run skill in isolation, monitor activity | Docker/Firejail | Planned |
| 5. LLM Deep Research | Multi-model analysis | Bring your own keys | Planned |
| 6. Community Signal | Reviews, reports, known issues | ClawHub/GitHub | Planned |

## Scoring

### Trust Tiers

| Tier | Score | Meaning |
|---|---|---|
| 0 | 0-25 | Do not install |
| 1 | 26-50 | Isolated lab only |
| 2 | 51-75 | Limited internal use with controls |
| 3 | 76-100 | Controlled production |

### Hard Fails vs Heavy Penalties

Not all critical findings are equal:
- **Hard fail** (explicit malicious): reverse shells, confirmed secrets, prompt override attempts → forces Tier 0
- **Heavy penalty** (heuristic): regex matches that could be false positives → reduces score but doesn't force Tier 0

### Environment Context

Same skill, different risk:

```bash
# Lab context (default) — more permissive
purgatory vet skill/ --context lab

# Production context — strictest scoring
purgatory vet skill/ --context production
```

### Behavior Clusters

Individual findings are scored independently. But combinations escalate:
- Network access + code execution = critical (exfiltration risk)
- Environment file read + network access = critical (credential theft)
- Config modification + cron/persistence = critical (long-term compromise)

## Example Output

```
Purgatory vetting: /path/to/skill
============================================================

[Layer 1] Static Scan...
  Result: PASS (2 findings)

[Layer 2] Prompt Review...
  Result: PASS (1 findings)

[Scoring] (context: lab)...

============================================================
Trust Score: 85/100
Trust Tier:  3 — Controlled production
Lab Use:     approved
Prod Use:    approved

Warnings:
  · Environment file access (setup.sh)
  · Upload directive (SKILL.md)

Report saved: /path/to/skill/PURGATORY-REPORT.md
```

## Threat Model

### What Purgatory catches
- Low-effort malware (hardcoded keys, obvious shells, known injection patterns)
- Accidental secrets left in code
- Common prompt injection techniques
- Suspicious file types and binaries
- Risky dependency patterns
- Behavioral risk combinations

### What Purgatory does NOT catch
- Sophisticated obfuscation (multi-layer encoding, string splitting)
- Runtime-fetched payloads (code that downloads malware at execution time)
- Semantic prompt manipulation (subtle rephrasing that avoids regex patterns)
- Homoglyph attacks (visually similar characters from different scripts)
- Supply chain attacks through legitimate-looking dependencies

### Important

**Purgatory is a first-pass vetting framework, not a guarantee of safety.** It raises the bar significantly over blind installation, but it does not replace manual code review for high-risk skills. Always review skills that handle API keys, social tokens, or financial data.

## How It Was Built

This tool was designed, built, and code-reviewed using a multi-LLM pipeline:

- **Hephaestus** (Claude Code) — architecture and implementation
- **Grok** (X/Twitter AI) — security landscape research, code review, CT market validation
- **Mimir** (ChatGPT) — source verification, deep code review, product strategy
- **Rob** (human) — vision, requirements, security instincts, pushback on bad ideas

Two rounds of independent code review. Both reviewers said: "This is real infrastructure protection, not theater. Ship it."

## Attribution

Tools and research that inspired Purgatory:
- `sona-security-audit` by @virtaava — fail-closed auditing approach
- `skill-reviewer` by OpenClaw community — structural quality checklist
- ClawHub VirusTotal integration — first-pass scanning model
- Koi Security — ClawHavoc campaign documentation
- Snyk — ecosystem vulnerability research (13% of skills vulnerable)
- Cisco — skill scanner and security advisories
- Microsoft — Feb 2026 identity isolation guidance for AI agents

## License

MIT — use it, fork it, improve it. Security tools should be free.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add patterns, report evasions, or submit fixes.

## Links

- [Full Product Spec](docs/PRODUCT-SPEC.md)
- [Security Policy](SECURITY.md)
- [Trust Matrix Methodology](docs/TRUST-MATRIX.md)
