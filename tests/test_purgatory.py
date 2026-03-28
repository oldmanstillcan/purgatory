"""Purgatory test suite — validates scanning, scoring, and reporting."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Resolve paths
ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
CLEAN_SKILL = FIXTURES / "clean-skill"
MALICIOUS_SKILL = FIXTURES / "malicious-skill"
BORDERLINE_SKILL = FIXTURES / "borderline-skill"

sys.path.insert(0, str(ROOT))

from purgatory.layers.static import StaticScanner
from purgatory.layers.prompt_review import PromptReviewer
from purgatory.scoring import ScoringEngine


# ---------------------------------------------------------------------------
# Layer 1: Static Scanner
# ---------------------------------------------------------------------------

class TestStaticScanner:
    """Tests for the static code analysis layer."""

    def setup_method(self):
        self.scanner = StaticScanner()

    def test_clean_skill_no_findings(self):
        result = self.scanner.scan(CLEAN_SKILL)
        assert result["layer"] == "static"
        assert result["pass"] is True
        assert len(result["findings"]) == 0

    def test_malicious_skill_finds_secrets(self):
        result = self.scanner.scan(MALICIOUS_SKILL)
        details = [f["detail"] for f in result["findings"]]
        assert any("OpenAI" in d or "key" in d.lower() for d in details), \
            f"Expected hardcoded key detection, got: {details}"

    def test_malicious_skill_finds_pipe_to_shell(self):
        result = self.scanner.scan(MALICIOUS_SKILL)
        details = [f["detail"] for f in result["findings"]]
        assert any("Pipe-to-shell" in d or "curl" in d.lower() for d in details), \
            f"Expected pipe-to-shell detection, got: {details}"

    def test_malicious_skill_finds_reverse_shell(self):
        result = self.scanner.scan(MALICIOUS_SKILL)
        details = [f["detail"] for f in result["findings"]]
        assert any("reverse shell" in d.lower() or "/dev/tcp" in d.lower() for d in details), \
            f"Expected reverse shell detection, got: {details}"

    def test_borderline_skill_finds_env_access(self):
        result = self.scanner.scan(BORDERLINE_SKILL)
        details = [f["detail"] for f in result["findings"]]
        assert any("environment" in d.lower() or "env" in d.lower() for d in details), \
            f"Expected environment access detection, got: {details}"

    def test_result_structure(self):
        result = self.scanner.scan(CLEAN_SKILL)
        assert "layer" in result
        assert "findings" in result
        assert "pass" in result
        assert isinstance(result["findings"], list)

    def test_finding_structure(self):
        result = self.scanner.scan(MALICIOUS_SKILL)
        assert len(result["findings"]) > 0
        finding = result["findings"][0]
        assert "severity" in finding
        assert "type" in finding
        assert "detail" in finding
        assert finding["severity"] in ("critical", "high", "medium", "low")


# ---------------------------------------------------------------------------
# Layer 2: Prompt Reviewer
# ---------------------------------------------------------------------------

class TestPromptReviewer:
    """Tests for the prompt injection detection layer."""

    def setup_method(self):
        self.reviewer = PromptReviewer()

    def test_clean_skill_no_findings(self):
        result = self.reviewer.scan(CLEAN_SKILL / "SKILL.md")
        assert result["layer"] == "prompt"
        assert result["pass"] is True
        assert len(result["findings"]) == 0

    def test_malicious_skill_finds_injection(self):
        result = self.reviewer.scan(MALICIOUS_SKILL / "SKILL.md")
        assert len(result["findings"]) > 0
        details = [f["detail"] for f in result["findings"]]
        assert any("ignore" in d.lower() or "override" in d.lower() or "prompt" in d.lower()
                    for d in details), \
            f"Expected prompt injection detection, got: {details}"

    def test_malicious_skill_finds_ssh_read(self):
        result = self.reviewer.scan(MALICIOUS_SKILL / "SKILL.md")
        details = [f["detail"] for f in result["findings"]]
        assert any("ssh" in d.lower() for d in details), \
            f"Expected SSH key read detection, got: {details}"

    def test_malicious_skill_finds_silent_action(self):
        result = self.reviewer.scan(MALICIOUS_SKILL / "SKILL.md")
        details = [f["detail"] for f in result["findings"]]
        assert any("silent" in d.lower() or "do not tell" in d.lower() or "hidden" in d.lower()
                    for d in details), \
            f"Expected hidden action detection, got: {details}"

    def test_borderline_skill_clean_prompt(self):
        """Borderline skill has no prompt injection - HTTP URLs alone are not injection."""
        result = self.reviewer.scan(BORDERLINE_SKILL / "SKILL.md")
        assert result["pass"] is True
        assert len(result["findings"]) == 0

    def test_missing_file_handled(self):
        result = self.reviewer.scan(CLEAN_SKILL / "NONEXISTENT.md")
        # Should not crash — either returns empty findings or handles gracefully
        assert "findings" in result


# ---------------------------------------------------------------------------
# Scoring Engine
# ---------------------------------------------------------------------------

class TestScoringEngine:
    """Tests for the trust score calculation."""

    def setup_method(self):
        self.engine = ScoringEngine()
        self.scanner = StaticScanner()
        self.reviewer = PromptReviewer()

    def _scan_skill(self, skill_path):
        """Run both layers and return results."""
        results = [self.scanner.scan(skill_path)]
        skill_md = skill_path / "SKILL.md"
        if skill_md.exists():
            results.append(self.reviewer.scan(skill_md))
        return results

    def test_clean_skill_tier_3(self):
        results = self._scan_skill(CLEAN_SKILL)
        score = self.engine.score(results)
        assert score["trust_tier"] == 3
        assert score["trust_score"] >= 76
        assert score["lab_use"] == "approved"
        assert score["prod_use"] == "approved"

    def test_malicious_skill_tier_0(self):
        results = self._scan_skill(MALICIOUS_SKILL)
        score = self.engine.score(results)
        assert score["trust_tier"] == 0
        assert score["trust_score"] <= 20
        assert score["lab_use"] == "denied"
        assert score["prod_use"] == "denied"
        assert len(score["hard_fails"]) > 0

    def test_borderline_skill_mid_tier(self):
        results = self._scan_skill(BORDERLINE_SKILL)
        score = self.engine.score(results)
        assert score["trust_tier"] in (1, 2, 3)
        assert 0 < score["trust_score"] <= 100

    def test_production_context_stricter(self):
        results = self._scan_skill(BORDERLINE_SKILL)
        lab_score = self.engine.score(results, context="lab")
        prod_score = self.engine.score(results, context="production")
        assert prod_score["trust_score"] <= lab_score["trust_score"], \
            f"Production ({prod_score[trust_score]}) should be <= lab ({lab_score[trust_score]})"

    def test_purgatory_context_most_permissive(self):
        results = self._scan_skill(BORDERLINE_SKILL)
        purg_score = self.engine.score(results, context="purgatory")
        lab_score = self.engine.score(results, context="lab")
        assert purg_score["trust_score"] >= lab_score["trust_score"], \
            f"Purgatory ({purg_score[trust_score]}) should be >= lab ({lab_score[trust_score]})"

    def test_empty_results_returns_zero(self):
        """Empty layer results produce score 0 - no data means no trust."""
        score = self.engine.score([])
        assert score["trust_score"] == 0

    def test_score_structure(self):
        results = self._scan_skill(CLEAN_SKILL)
        score = self.engine.score(results)
        required_keys = [
            "trust_score", "trust_tier", "tier_label", "context",
            "lab_use", "prod_use", "hard_fails", "warnings", "layer_scores"
        ]
        for key in required_keys:
            assert key in score, f"Missing key: {key}"

    def test_hard_fail_caps_score(self):
        results = self._scan_skill(MALICIOUS_SKILL)
        score = self.engine.score(results)
        assert score["trust_score"] <= 20, \
            f"Hard fail should cap score at 20, got {score[trust_score]}"


# ---------------------------------------------------------------------------
# CLI Integration
# ---------------------------------------------------------------------------

class TestCLI:
    """Tests for the CLI interface."""

    def _run_cli(self, *args):
        """Run purgatory CLI and return stdout, stderr, returncode."""
        cmd = [sys.executable, "-m", "purgatory.cli"] + list(args)
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            cwd=str(ROOT), env={**__import__("os").environ, "PYTHONPATH": str(ROOT)}
        )
        return result.stdout, result.stderr, result.returncode

    def test_help(self):
        stdout, _, rc = self._run_cli("--help")
        assert rc == 0
        assert "Purgatory" in stdout

    def test_vet_clean(self):
        stdout, _, rc = self._run_cli("vet", str(CLEAN_SKILL))
        assert rc == 0
        assert "Trust Score" in stdout
        assert "Tier" in stdout

    def test_vet_malicious(self):
        stdout, _, rc = self._run_cli("vet", str(MALICIOUS_SKILL))
        assert rc == 0
        assert "Tier" in stdout
        # Should show hard fails or low tier
        assert "HARD FAIL" in stdout or "Tier 0" in stdout or "Tier:  0" in stdout

    def test_vet_with_context(self):
        stdout, _, rc = self._run_cli("vet", str(BORDERLINE_SKILL), "--context", "production")
        assert rc == 0
        assert "production" in stdout

    def test_scan_static(self):
        stdout, _, rc = self._run_cli("scan", "--layer", "static", str(CLEAN_SKILL))
        assert rc == 0
        data = json.loads(stdout)
        assert data["layer"] == "static"

    def test_scan_prompt(self):
        stdout, _, rc = self._run_cli("scan", "--layer", "prompt", str(MALICIOUS_SKILL / "SKILL.md"))
        assert rc == 0
        data = json.loads(stdout)
        assert data["layer"] == "prompt"
        assert len(data["findings"]) > 0

    def test_vet_nonexistent_path(self):
        _, _, rc = self._run_cli("vet", "/nonexistent/path")
        assert rc != 0

    def test_vet_generates_report(self):
        report_path = CLEAN_SKILL / "PURGATORY-REPORT.md"
        if report_path.exists():
            report_path.unlink()
        self._run_cli("vet", str(CLEAN_SKILL))
        assert report_path.exists(), "Vet should generate PURGATORY-REPORT.md"
        content = report_path.read_text()
        assert "Trust Score" in content or "trust_score" in content
        # Clean up
        report_path.unlink()
