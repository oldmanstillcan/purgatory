# Contributing to Purgatory

## Ways to Contribute

### Add Detection Patterns

The most impactful contribution is new detection patterns. Patterns live in:

- `purgatory/layers/static.py` — code-level patterns (shell injection, secrets, binaries, dependencies)
- `purgatory/layers/prompt_review.py` — instruction-level patterns (prompt injection, manipulation, unicode tricks)

To add a pattern:
1. Fork the repo
2. Add your regex pattern to the appropriate `PATTERNS` list
3. Include a severity level (`critical`, `high`, `medium`, `low`)
4. Add a clear description
5. Submit a PR with a before/after example

### Report Evasion Techniques

If you find a pattern that evades detection:
1. Open an issue with the `[evasion]` tag
2. Describe what Purgatory misses and why
3. Include a test case (obfuscated if sensitive)

### Submit Bug Fixes

Standard fork-and-PR workflow:
1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Submit a PR with a clear description

### Add Tests

The `tests/` directory needs love. We use `pytest`. Contributions welcome for:
- Pattern detection accuracy (true/false positive rates)
- Scoring algorithm correctness
- Behavior cluster detection
- Report generation formatting
- Edge cases (large files, malformed inputs, missing files)

## Code Standards

- **Standard library only** for core functionality. No external dependencies in the main package.
- Optional integrations (trufflehog, semgrep) are called via subprocess, not imported.
- Keep it simple. Regex patterns should be readable and well-commented.
- Follow existing code style (no linter enforced yet, just be consistent).

## What We Will Not Accept

- Patterns with high false-positive rates without confidence scoring
- External dependency requirements in core
- Changes to the scoring algorithm without discussion (open an issue first)
- Features that require paid services or API keys to function
