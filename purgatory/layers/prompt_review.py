"""Layer 2: Prompt Review — detect injection, instruction abuse, behavioral manipulation."""

import re
from pathlib import Path
from typing import Any


class PromptReviewer:
    """Scans SKILL.md for prompt injection and instruction abuse patterns."""

    INJECTION_PATTERNS = [
        (r'ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?)', "critical", "Prompt override attempt"),
        (r'do\s+not\s+tell\s+the\s+user', "critical", "Hidden action directive"),
        (r'silently\s+(send|post|upload|exfiltrate|copy|move|delete|execute|run)', "critical", "Silent action directive"),
        (r'without\s+(the\s+)?user\s+know', "critical", "Deceptive action"),
        (r'pretend\s+(to\s+be|you\s+are)', "high", "Identity override attempt"),
        (r'you\s+are\s+now\s+', "high", "Identity override attempt"),
        (r'forget\s+(everything|all|your)', "critical", "Memory wipe attempt"),
        (r'override\s+(your|the|all)\s+(rules?|instructions?|safety)', "critical", "Safety override attempt"),
        (r'jailbreak', "critical", "Explicit jailbreak reference"),
    ]

    EXFILTRATION_PATTERNS = [
        (r'send\s+to\s+https?://', "critical", "Data exfiltration to URL"),
        (r'curl\s+.*https?://', "high", "Outbound HTTP request"),
        (r'wget\s+.*https?://', "high", "Outbound HTTP request"),
        (r'post\s+.*to\s+.*external', "high", "External data posting"),
        (r'upload\s+.*to\s+', "medium", "Upload directive"),
        (r'phone\s+home', "critical", "Phone-home pattern"),
    ]

    SENSITIVE_ACCESS_PATTERNS = [
        (r'read\s+.*\.env', "high", "Environment file read directive"),
        (r'read\s+.*\.ssh', "critical", "SSH key read directive"),
        (r'read\s+.*\.aws', "critical", "AWS credentials read directive"),
        (r'read\s+.*credentials', "high", "Credentials read directive"),
        (r'read\s+.*password', "high", "Password read directive"),
        (r'read\s+.*token', "medium", "Token read directive"),
        (r'read\s+.*secret', "high", "Secret read directive"),
        (r'access\s+.*api.key', "high", "API key access directive"),
    ]

    BEHAVIORAL_PATTERNS = [
        (r'on\s+every\s+(message|response|request)', "medium", "Persistent behavioral modification"),
        (r'always\s+(include|add|append|prepend)', "medium", "Persistent output modification"),
        (r'modify\s+.*AGENTS\.md', "high", "Agent config modification directive"),
        (r'modify\s+.*SOUL\.md', "high", "Agent identity modification directive"),
        (r'write\s+to\s+.*cron', "high", "Cron job creation directive"),
        (r'install\s+.*globally', "medium", "Global installation directive"),
        (r'add\s+.*startup', "high", "Startup modification directive"),
    ]

    UNICODE_TRICKS = [
        (r'[\u200b\u200c\u200d\u2060\ufeff]', "critical", "Zero-width character detected (hidden content)"),
        (r'[\u202a\u202b\u202c\u202d\u202e]', "critical", "Bidirectional text override (text direction manipulation)"),
        (r'[\u2066\u2067\u2068\u2069]', "critical", "Bidirectional isolate (text display manipulation)"),
    ]

    def scan(self, path: Path) -> dict[str, Any]:
        """Scan a SKILL.md file for prompt injection and abuse patterns."""
        findings = []

        try:
            content = path.read_text(errors="ignore")
        except Exception as e:
            return {
                "layer": "prompt",
                "path": str(path),
                "findings": [{"severity": "medium", "type": "read_error", "file": str(path), "line": 0, "detail": str(e), "match": ""}],
                "pass": False,
                "finding_count": 1,
            }

        content_lower = content.lower()

        # Check all pattern groups
        for patterns in [
            self.INJECTION_PATTERNS,
            self.EXFILTRATION_PATTERNS,
            self.SENSITIVE_ACCESS_PATTERNS,
            self.BEHAVIORAL_PATTERNS,
        ]:
            for pattern, severity, description in patterns:
                matches = list(re.finditer(pattern, content_lower))
                for match in matches:
                    line_num = content_lower[:match.start()].count("\n") + 1
                    findings.append({
                        "severity": severity,
                        "type": "prompt_injection",
                        "file": str(path),
                        "line": line_num,
                        "detail": description,
                        "match": match.group()[:100],
                    })

        # Unicode tricks (check original content, not lowered)
        for pattern, severity, description in self.UNICODE_TRICKS:
            matches = list(re.finditer(pattern, content))
            for match in matches:
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "severity": severity,
                    "type": "unicode_trick",
                    "file": str(path),
                    "line": line_num,
                    "detail": description,
                    "match": repr(match.group()),
                })

        # Check for excessive script references
        script_refs = len(re.findall(r'scripts?/', content_lower))
        if script_refs > 5:
            findings.append({
                "severity": "medium",
                "type": "high_script_count",
                "file": str(path),
                "line": 0,
                "detail": f"Skill references {script_refs} scripts — larger trust surface",
                "match": f"{script_refs} script references",
            })

        # Check for cron references
        cron_refs = re.findall(r'cron|schedule|periodic|recurring', content_lower)
        if cron_refs:
            findings.append({
                "severity": "medium",
                "type": "persistence_mechanism",
                "file": str(path),
                "line": 0,
                "detail": f"Skill references scheduling/cron — persistence mechanism",
                "match": ", ".join(set(cron_refs)),
            })

        has_critical = any(f["severity"] == "critical" for f in findings)

        return {
            "layer": "prompt",
            "path": str(path),
            "findings": findings,
            "pass": not has_critical,
            "finding_count": len(findings),
            "critical_count": sum(1 for f in findings if f["severity"] == "critical"),
            "high_count": sum(1 for f in findings if f["severity"] == "high"),
            "medium_count": sum(1 for f in findings if f["severity"] == "medium"),
        }
