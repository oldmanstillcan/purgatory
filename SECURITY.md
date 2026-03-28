# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Purgatory, please report it responsibly:

**Email:** taoerwreckords@gmail.com

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide an initial assessment within 7 days.

## Scope

This policy covers the Purgatory codebase itself. If you find an evasion technique that bypasses Purgatory's detection:

1. Open a GitHub issue with the `[evasion]` tag
2. Describe the pattern that evades detection (obfuscated if needed)
3. We will add detection patterns and credit you in the changelog

## Important Disclaimer

Purgatory is a **first-pass vetting framework**, not a guarantee of safety. It catches low-effort malware, accidental secrets, common injection patterns, and behavioral risk combinations. It does not catch sophisticated obfuscation, runtime-fetched payloads, or semantic prompt manipulation.

Always perform manual code review for skills that handle API keys, financial data, or social tokens.
