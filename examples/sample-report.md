---
title: "Purgatory Security Report: weather-lookup"
type: security-report
date: 2026-03-28
skill: weather-lookup
tier: 2
score: 62
---

# Purgatory Report: weather-lookup

## Summary

| Field | Value |
|---|---|
| Trust Score | 62/100 |
| Trust Tier | 2 — Limited internal use with controls |
| Context | lab |
| Lab Use | approved |
| Prod Use | conditional |

## Hard Fails

None detected.

## Warnings

| # | Severity | Layer | Type | File | Detail |
|---|---|---|---|---|---|
| 1 | high | static | outbound_http | scripts/fetch.py:14 | `requests.get()` to external API |
| 2 | medium | static | env_access | scripts/setup.sh:7 | Reads `WEATHER_API_KEY` from environment |
| 3 | medium | prompt | upload_directive | SKILL.md:23 | "send forecast data to" + URL pattern |
| 4 | low | static | subprocess_call | scripts/fetch.py:31 | `subprocess.run()` with fixed arguments |

## Behavior Clusters

| Cluster | Finding Types | Severity | Detail |
|---|---|---|---|
| credential_access | env_access + outbound_http | high | Environment variable read combined with network access |

## Layer Scores

| Layer | Weight | Findings | Score |
|---|---|---|---|
| Static Scan | 40% | 3 | 68 |
| Prompt Review | 35% | 1 | 78 |
| Source Verification | 10% | — | not run |
| Behavioral Sandbox | 10% | — | not run |
| Community Signal | 5% | — | not run |

## Controls Required

- `required_secret_isolation`: true
- `required_manual_review`: true
- `required_sandbox`: false

## Recommendation

Skill reads environment variables and makes outbound HTTP requests. This is expected behavior for a weather lookup, but the combination triggers credential access cluster detection. Isolate API keys and review the target URLs before production deployment.
