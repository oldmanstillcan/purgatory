"""Layer 1: Static Scan — secrets, vulnerabilities, dangerous patterns.

v0.1.1 — Tightened per Grok + Mimir review:
- Added file size limits (prevent DoS)
- Added file count limits
- Added confidence to findings
- Added dependency scanning (requirements.txt, package.json)
- Added subshell pattern detection
"""

import subprocess
import json
import re
from pathlib import Path
from typing import Any

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB per file
MAX_FILE_COUNT = 500  # max files to scan


class StaticScanner:
    """Scans skill directory for secrets, dangerous patterns, and vulnerabilities."""

    # Dangerous patterns to search for in scripts
    DANGEROUS_PATTERNS = [
        (r'curl\s+.*\|.*sh', "critical", "Pipe-to-shell execution"),
        (r'wget\s+.*\|.*sh', "critical", "Pipe-to-shell execution"),
        (r'eval\s*\(', "high", "Eval execution"),
        (r'exec\s*\(', "high", "Exec execution"),
        (r'base64\s+(-d|--decode)', "high", "Base64 decode (possible obfuscation)"),
        (r'nc\s+-[le]', "critical", "Netcat listener (reverse shell indicator)"),
        (r'bash\s+-i\s+>&\s+/dev/tcp', "critical", "Reverse shell pattern"),
        (r'/dev/tcp/', "critical", "TCP device access (reverse shell)"),
        (r'rm\s+-rf\s+/', "critical", "Recursive delete from root"),
        (r'chmod\s+777', "high", "World-writable permissions"),
        (r'\.ssh/', "high", "SSH directory access"),
        (r'\.aws/', "high", "AWS credentials access"),
        (r'\.kube/', "high", "Kubernetes config access"),
        (r'\.env', "medium", "Environment file access"),
        (r'OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET', "high", "Hardcoded API key reference"),
        (r'sk-[a-zA-Z0-9]{20,}', "critical", "Possible hardcoded OpenAI key"),
        (r'ghp_[a-zA-Z0-9]{36}', "critical", "Possible hardcoded GitHub token"),
        (r'xoxb-|xoxp-', "critical", "Possible hardcoded Slack token"),
        (r'AKIA[0-9A-Z]{16}', "critical", "Possible hardcoded AWS key"),
        # Subshell / indirect execution (Mimir + Grok flagged)
        (r'\$\(curl', "critical", "Subshell curl execution"),
        (r'\$\(wget', "critical", "Subshell wget execution"),
        (r'requests\.get\(.*\)\.text', "high", "Python runtime fetch"),
        (r'urllib\.request', "medium", "Python URL request"),
        (r'subprocess\.run\(.*shell\s*=\s*True', "high", "Shell=True subprocess"),
        (r'os\.system\(', "high", "os.system execution"),
        (r'os\.popen\(', "high", "os.popen execution"),
        (r'__import__\(', "high", "Dynamic import"),
        (r'importlib\.import_module', "medium", "Dynamic module import"),
    ]

    # Suspicious file types
    SUSPICIOUS_FILES = [
        ".exe", ".dll", ".so", ".dylib", ".bin",
        ".pyc", ".class", ".jar",
    ]

    def scan(self, path: Path) -> dict[str, Any]:
        """Run static scan on a skill directory."""
        findings = []
        file_count = 0

        if path.is_file():
            findings.extend(self._scan_file(path))
        elif path.is_dir():
            for f in self._walk_files(path):
                file_count += 1
                if file_count > MAX_FILE_COUNT:
                    findings.append({"severity": "high", "type": "excessive_files", "file": str(path), "line": 0, "detail": f"Skill contains {file_count}+ files — possible DoS or obfuscation", "match": "", "confidence": "high"})
                    break
                findings.extend(self._scan_file(f))
            findings.extend(self._check_suspicious_files(path))
            findings.extend(self._check_binaries(path))
            findings.extend(self._scan_dependencies(path))

        # Try trufflehog if available
        findings.extend(self._run_trufflehog(path))

        # Try semgrep if available
        findings.extend(self._run_semgrep(path))

        has_critical = any(f["severity"] == "critical" for f in findings)

        return {
            "layer": "static",
            "path": str(path),
            "findings": findings,
            "pass": not has_critical,
            "finding_count": len(findings),
            "critical_count": sum(1 for f in findings if f["severity"] == "critical"),
            "high_count": sum(1 for f in findings if f["severity"] == "high"),
            "medium_count": sum(1 for f in findings if f["severity"] == "medium"),
        }

    def _walk_files(self, path: Path):
        """Walk directory, skip hidden dirs and node_modules."""
        for item in path.rglob("*"):
            if item.is_file():
                parts = item.relative_to(path).parts
                if any(p.startswith(".") or p == "node_modules" for p in parts):
                    continue
                yield item

    def _scan_file(self, filepath: Path) -> list[dict]:
        """Scan a single file for dangerous patterns."""
        findings = []

        # File size check
        try:
            size = filepath.stat().st_size
            if size > MAX_FILE_SIZE:
                findings.append({"severity": "medium", "type": "large_file", "file": str(filepath), "line": 0, "detail": f"File is {size // 1024}KB — skipping content scan", "match": "", "confidence": "high"})
                return findings
        except Exception:
            return findings

        try:
            content = filepath.read_text(errors="ignore")
        except Exception:
            return findings

        for pattern, severity, description in self.DANGEROUS_PATTERNS:
            matches = list(re.finditer(pattern, content))
            for match in matches:
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "severity": severity,
                    "type": "dangerous_pattern",
                    "file": str(filepath),
                    "line": line_num,
                    "detail": description,
                    "match": match.group()[:100],
                })

        return findings

    def _check_suspicious_files(self, path: Path) -> list[dict]:
        """Check for suspicious file types."""
        findings = []
        for f in self._walk_files(path):
            if f.suffix.lower() in self.SUSPICIOUS_FILES:
                findings.append({
                    "severity": "high",
                    "type": "suspicious_file",
                    "file": str(f),
                    "line": 0,
                    "detail": f"Suspicious file type: {f.suffix}",
                    "match": f.name,
                })
        return findings

    def _check_binaries(self, path: Path) -> list[dict]:
        """Check for binary/compiled files."""
        findings = []
        for f in self._walk_files(path):
            try:
                with open(f, "rb") as fh:
                    header = fh.read(4)
                    # ELF binary
                    if header[:4] == b"\x7fELF":
                        findings.append({
                            "severity": "critical",
                            "type": "binary_executable",
                            "file": str(f),
                            "line": 0,
                            "detail": "ELF binary detected — skills should not contain compiled executables",
                            "match": "ELF header",
                        })
                    # Mach-O binary
                    elif header[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
                        findings.append({
                            "severity": "critical",
                            "type": "binary_executable",
                            "file": str(f),
                            "line": 0,
                            "detail": "Mach-O binary detected — skills should not contain compiled executables",
                            "match": "Mach-O header",
                        })
            except Exception:
                pass
        return findings

    def _scan_dependencies(self, path: Path) -> list[dict]:
        """Scan dependency files for risky packages."""
        findings = []

        # Python requirements
        for req_file in ["requirements.txt", "requirements.in", "setup.py", "pyproject.toml"]:
            req_path = path / req_file
            if req_path.exists():
                findings.append({"severity": "medium", "type": "dependency_file", "file": str(req_path), "line": 0, "detail": f"Dependency file found: {req_file} — review for malicious packages", "match": req_file, "confidence": "high"})
                try:
                    content = req_path.read_text(errors="ignore")
                    # Check for pip install from URL (not PyPI)
                    url_deps = re.findall(r'https?://\S+', content)
                    for url in url_deps:
                        findings.append({"severity": "high", "type": "url_dependency", "file": str(req_path), "line": 0, "detail": f"Dependency installed from URL: {url[:100]}", "match": url[:100], "confidence": "high"})
                    # Check for git+ installs
                    git_deps = re.findall(r'git\+\S+', content)
                    for dep in git_deps:
                        findings.append({"severity": "medium", "type": "git_dependency", "file": str(req_path), "line": 0, "detail": f"Dependency from git: {dep[:100]}", "match": dep[:100], "confidence": "medium"})
                except Exception:
                    pass

        # Node.js
        pkg_json = path / "package.json"
        if pkg_json.exists():
            findings.append({"severity": "medium", "type": "dependency_file", "file": str(pkg_json), "line": 0, "detail": "package.json found — review dependencies and scripts", "match": "package.json", "confidence": "high"})
            try:
                import json as _json
                data = _json.loads(pkg_json.read_text())
                scripts = data.get("scripts", {})
                for name, cmd in scripts.items():
                    if any(d in cmd for d in ["curl", "wget", "eval", "exec", "rm -rf"]):
                        findings.append({"severity": "high", "type": "dangerous_npm_script", "file": str(pkg_json), "line": 0, "detail": f"npm script '{name}' contains dangerous command: {cmd[:100]}", "match": cmd[:100], "confidence": "high"})
                    if name in ("preinstall", "postinstall", "prepare"):
                        findings.append({"severity": "medium", "type": "install_hook", "file": str(pkg_json), "line": 0, "detail": f"npm install hook '{name}': {cmd[:80]}", "match": cmd[:80], "confidence": "medium"})
            except Exception:
                pass

        return findings

    def _run_trufflehog(self, path: Path) -> list[dict]:
        """Run trufflehog for secret detection if available."""
        try:
            result = subprocess.run(
                ["trufflehog", "filesystem", str(path), "--json", "--no-update"],
                capture_output=True, text=True, timeout=60
            )
            findings = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append({
                        "severity": "critical",
                        "type": "secret_detected",
                        "file": data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "unknown"),
                        "line": 0,
                        "detail": f"Secret detected by trufflehog: {data.get('DetectorName', 'unknown')}",
                        "match": "[REDACTED]",
                    })
                except json.JSONDecodeError:
                    pass
            return findings
        except FileNotFoundError:
            return []  # trufflehog not installed — skip silently
        except subprocess.TimeoutExpired:
            return [{"severity": "medium", "type": "tool_timeout", "file": "", "line": 0, "detail": "trufflehog timed out", "match": ""}]

    def _run_semgrep(self, path: Path) -> list[dict]:
        """Run semgrep for static analysis if available."""
        try:
            result = subprocess.run(
                ["semgrep", "--config", "auto", str(path), "--json", "--quiet"],
                capture_output=True, text=True, timeout=120
            )
            findings = []
            try:
                data = json.loads(result.stdout)
                for r in data.get("results", []):
                    severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
                    findings.append({
                        "severity": severity_map.get(r.get("extra", {}).get("severity", ""), "medium"),
                        "type": "semgrep_finding",
                        "file": r.get("path", "unknown"),
                        "line": r.get("start", {}).get("line", 0),
                        "detail": r.get("extra", {}).get("message", "Semgrep finding"),
                        "match": r.get("extra", {}).get("lines", "")[:100],
                    })
            except json.JSONDecodeError:
                pass
            return findings
        except FileNotFoundError:
            return []  # semgrep not installed — skip silently
        except subprocess.TimeoutExpired:
            return [{"severity": "medium", "type": "tool_timeout", "file": "", "line": 0, "detail": "semgrep timed out", "match": ""}]
