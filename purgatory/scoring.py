"""Purgatory Scoring Engine — aggregates layer results into trust assessment.

v0.1.1 — Tightened per Grok + Mimir review:
- Split hard-fail (explicit malicious) vs heavy penalty (heuristic)
- Added confidence to findings
- Added environment context
- Added behavior cluster detection (combinatorial, not additive)
- Community signal low-weighted (easily gamed early)
"""

from typing import Any

# Finding types that are EXPLICIT malicious — always hard fail
HARD_FAIL_TYPES = {
    "secret_detected",          # trufflehog confirmed secret
    "binary_executable",        # compiled binary in skill package
    "reverse_shell",            # confirmed reverse shell pattern
}

# Finding details that are EXPLICIT malicious — always hard fail
HARD_FAIL_PATTERNS = {
    "Reverse shell pattern",
    "TCP device access (reverse shell)",
    "Netcat listener (reverse shell indicator)",
    "Pipe-to-shell execution",
    "Data exfiltration to URL",
    "Possible hardcoded OpenAI key",
    "Possible hardcoded GitHub token",
    "Possible hardcoded Slack token",
    "Possible hardcoded AWS key",
    "Zero-width character detected",
    "Prompt override attempt",
    "Hidden action directive",
    "Silent action directive",
    "Deceptive action",
    "Memory wipe attempt",
    "Safety override attempt",
    "Phone-home pattern",
    "SSH key read directive",
    "AWS credentials read directive",
}

# Behavior clusters — combinations that escalate severity
BEHAVIOR_CLUSTERS = [
    ({"Outbound HTTP request", "Eval execution"}, "critical", "Network + code execution = exfiltration risk"),
    ({"Outbound HTTP request", "Exec execution"}, "critical", "Network + exec = exfiltration risk"),
    ({"Outbound HTTP request", "Pipe-to-shell execution"}, "critical", "Network + shell = remote code execution"),
    ({"Environment file access", "Outbound HTTP request"}, "critical", "Env read + network = credential exfiltration"),
    ({"SSH directory access", "Outbound HTTP request"}, "critical", "SSH access + network = key exfiltration"),
    ({"Agent config modification directive", "Cron job creation directive"}, "critical", "Config mutation + persistence = long-term compromise"),
    ({"Persistent behavioral modification", "Agent config modification directive"}, "high", "Behavioral change + config mutation = drift risk"),
]

# Environment risk multipliers
ENV_RISK = {
    "production": 1.5,    # strictest
    "oraokol": 1.3,       # business data
    "aurelius": 1.3,      # health data
    "hermes": 1.0,        # isolated outbound
    "lab": 0.7,           # testing
    "purgatory": 0.5,     # sandbox
}


class ScoringEngine:
    """Takes layer scan results and produces unified trust score + tier."""

    WEIGHTS = {
        "static": 0.40,
        "prompt": 0.35,
        "source": 0.10,
        "sandbox": 0.10,
        "research": 0.03,
        "community": 0.02,
    }

    TIER_LABELS = {
        0: "Do not install",
        1: "Isolated lab only",
        2: "Limited internal use with controls",
        3: "Controlled production",
    }

    def score(self, layer_results: list[dict], context: str = "lab") -> dict[str, Any]:
        """Score skill based on layer results and deployment context."""
        hard_fails = []
        heavy_penalties = []
        warnings = []
        layer_scores = {}
        all_finding_details = set()

        for result in layer_results:
            layer = result.get("layer", "unknown")
            findings = result.get("findings", [])

            for f in findings:
                detail = f.get("detail", "")
                ftype = f.get("type", "")
                severity = f.get("severity", "medium")
                confidence = f.get("confidence", "high" if ftype in HARD_FAIL_TYPES else "medium")
                all_finding_details.add(detail)

                # Explicit malicious = hard fail
                if ftype in HARD_FAIL_TYPES or detail in HARD_FAIL_PATTERNS:
                    hard_fails.append({
                        "detail": detail,
                        "file": f.get("file", ""),
                        "line": f.get("line", 0),
                        "confidence": "high",
                        "reason": "explicit_malicious",
                    })
                elif severity == "critical":
                    # Heuristic critical = heavy penalty, not hard fail
                    heavy_penalties.append({
                        "detail": detail,
                        "file": f.get("file", ""),
                        "confidence": confidence,
                        "reason": "heuristic_critical",
                    })
                elif severity in ("high", "medium"):
                    warnings.append(f"{detail} ({f.get('file', '')})")

            # Calculate layer score
            explicit_count = sum(1 for f in findings if f.get("type", "") in HARD_FAIL_TYPES or f.get("detail", "") in HARD_FAIL_PATTERNS)
            heuristic_critical = sum(1 for f in findings if f.get("severity") == "critical") - explicit_count
            high = sum(1 for f in findings if f.get("severity") == "high")
            medium = sum(1 for f in findings if f.get("severity") == "medium")

            penalty = (explicit_count * 50) + (heuristic_critical * 25) + (high * 12) + (medium * 4)
            layer_scores[layer] = max(0, 100 - penalty)

        # Behavior cluster detection
        cluster_fails = []
        for cluster_set, cluster_severity, cluster_desc in BEHAVIOR_CLUSTERS:
            if cluster_set.issubset(all_finding_details):
                cluster_fails.append({
                    "detail": cluster_desc,
                    "findings": list(cluster_set),
                    "severity": cluster_severity,
                    "confidence": "high",
                })
                if cluster_severity == "critical":
                    hard_fails.append({
                        "detail": f"CLUSTER: {cluster_desc}",
                        "file": "multiple",
                        "line": 0,
                        "confidence": "high",
                        "reason": "behavior_cluster",
                    })

        # Calculate weighted trust score
        total_weight = 0
        weighted_score = 0
        for layer, lscore in layer_scores.items():
            weight = self.WEIGHTS.get(layer, 0.05)
            weighted_score += lscore * weight
            total_weight += weight

        trust_score = int(weighted_score / total_weight) if total_weight > 0 else 0

        # Apply heavy penalties (reduce score but don't force tier 0)
        if heavy_penalties:
            penalty_factor = max(0.5, 1.0 - (len(heavy_penalties) * 0.15))
            trust_score = int(trust_score * penalty_factor)

        # Apply environment risk multiplier
        env_multiplier = ENV_RISK.get(context, 1.0)
        if env_multiplier > 1.0:
            # Higher risk env = lower effective score
            trust_score = int(trust_score / env_multiplier)

        # Hard fail override — only for EXPLICIT malicious
        if hard_fails:
            trust_score = min(trust_score, 20)

        # Clamp
        trust_score = max(0, min(100, trust_score))

        # Determine tier
        if trust_score >= 76:
            trust_tier = 3
        elif trust_score >= 51:
            trust_tier = 2
        elif trust_score >= 26:
            trust_tier = 1
        else:
            trust_tier = 0

        # Force tier 0 only on explicit malicious hard fails
        if hard_fails:
            trust_tier = 0

        # Determine approval
        lab_use = "denied" if trust_tier == 0 else "conditional" if trust_tier == 1 else "approved"
        prod_use = "denied" if trust_tier <= 1 else "conditional" if trust_tier == 2 else "approved"

        return {
            "trust_score": trust_score,
            "trust_tier": trust_tier,
            "tier_label": self.TIER_LABELS[trust_tier],
            "context": context,
            "lab_use": lab_use,
            "prod_use": prod_use,
            "required_sandbox": trust_tier <= 1,
            "required_secret_isolation": trust_tier <= 2,
            "required_manual_review": trust_tier <= 2,
            "hard_fails": [f"{hf['detail']} [{hf['confidence']}] ({hf['file']})" for hf in hard_fails],
            "heavy_penalties": [f"{hp['detail']} [{hp['confidence']}]" for hp in heavy_penalties],
            "behavior_clusters": [f"{cf['detail']}" for cf in cluster_fails],
            "warnings": warnings[:10],
            "layer_scores": layer_scores,
        }
