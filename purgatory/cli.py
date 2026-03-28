#!/usr/bin/env python3
"""Purgatory CLI — skill vetting from the command line."""

import argparse
import json
import sys
from pathlib import Path

from purgatory.layers.static import StaticScanner
from purgatory.layers.prompt_review import PromptReviewer
from purgatory.scoring import ScoringEngine
from purgatory.report import generate_report


def main():
    parser = argparse.ArgumentParser(
        prog="purgatory",
        description="Purgatory — Modular Skill Vetting Framework"
    )
    subparsers = parser.add_subparsers(dest="command")

    # vet command (full pipeline)
    vet_parser = subparsers.add_parser("vet", help="Run full vetting pipeline on a skill")
    vet_parser.add_argument("path", type=str, help="Path to skill directory")
    vet_parser.add_argument("--format", choices=["markdown", "json", "both"], default="markdown")
    vet_parser.add_argument("--context", type=str, default="lab",
                           choices=["production", "oraokol", "aurelius", "hermes", "lab", "purgatory"],
                           help="Deployment context (affects risk scoring)")

    # scan command (individual layers)
    scan_parser = subparsers.add_parser("scan", help="Run a specific scan layer")
    scan_parser.add_argument("--layer", required=True,
                            choices=["static", "prompt", "source", "community"],
                            help="Which layer to run")
    scan_parser.add_argument("path", type=str, help="Path to skill directory or file")
    scan_parser.add_argument("--slug", type=str, help="Skill slug for source/community lookups")

    # score command
    score_parser = subparsers.add_parser("score", help="Score from existing layer reports")
    score_parser.add_argument("path", type=str, help="Path to reports directory")

    # audit command (all installed skills)
    audit_parser = subparsers.add_parser("audit", help="Audit all installed skills")
    audit_parser.add_argument("--openclaw-dir", type=str,
                             default=str(Path.home() / ".openclaw"),
                             help="OpenClaw workspace directory")

    # report command
    report_parser = subparsers.add_parser("report", help="Generate report from scan results")
    report_parser.add_argument("path", type=str, help="Path to skill directory")
    report_parser.add_argument("--format", choices=["markdown", "json"], default="markdown")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "vet":
        run_vet(args)
    elif args.command == "scan":
        run_scan(args)
    elif args.command == "score":
        run_score(args)
    elif args.command == "audit":
        run_audit(args)
    elif args.command == "report":
        run_report(args)


def run_vet(args):
    """Run full vetting pipeline."""
    skill_path = Path(args.path)
    if not skill_path.exists():
        print(f"Error: {skill_path} does not exist")
        sys.exit(1)

    print(f"Purgatory vetting: {skill_path}")
    print("=" * 60)

    results = []

    # Layer 1: Static scan
    print("\n[Layer 1] Static Scan...")
    static = StaticScanner()
    static_result = static.scan(skill_path)
    results.append(static_result)
    status = "PASS" if static_result["pass"] else "FAIL"
    print(f"  Result: {status} ({len(static_result['findings'])} findings)")

    # Layer 2: Prompt review
    skill_md = skill_path / "SKILL.md"
    if skill_md.exists():
        print("\n[Layer 2] Prompt Review...")
        reviewer = PromptReviewer()
        prompt_result = reviewer.scan(skill_md)
        results.append(prompt_result)
        status = "PASS" if prompt_result["pass"] else "FAIL"
        print(f"  Result: {status} ({len(prompt_result['findings'])} findings)")

    # Score
    context = getattr(args, 'context', 'lab')
    print(f"\n[Scoring] (context: {context})...")
    engine = ScoringEngine()
    score = engine.score(results, context=context)

    print(f"\n{'=' * 60}")
    print(f"Trust Score: {score['trust_score']}/100")
    print(f"Trust Tier:  {score['trust_tier']} — {score['tier_label']}")
    print(f"Lab Use:     {score['lab_use']}")
    print(f"Prod Use:    {score['prod_use']}")

    if score["hard_fails"]:
        print(f"\nHARD FAILS (explicit malicious):")
        for fail in score["hard_fails"]:
            print(f"  ✘ {fail}")

    if score.get("behavior_clusters"):
        print(f"\nBEHAVIOR CLUSTERS:")
        for cluster in score["behavior_clusters"]:
            print(f"  ⚡ {cluster}")

    if score.get("heavy_penalties"):
        print(f"\nHEAVY PENALTIES (heuristic):")
        for hp in score["heavy_penalties"]:
            print(f"  ⚠ {hp}")

    if score["warnings"]:
        print(f"\nWarnings:")
        for warn in score["warnings"][:5]:
            print(f"  · {warn}")

    # Generate report
    report = generate_report(skill_path, results, score, fmt=args.format)
    report_path = skill_path / "PURGATORY-REPORT.md"
    report_path.write_text(report)
    print(f"\nReport saved: {report_path}")


def run_scan(args):
    """Run a specific scan layer."""
    path = Path(args.path)

    if args.layer == "static":
        scanner = StaticScanner()
        result = scanner.scan(path)
    elif args.layer == "prompt":
        reviewer = PromptReviewer()
        result = reviewer.scan(path)
    else:
        print(f"Layer '{args.layer}' not yet implemented")
        sys.exit(1)

    print(json.dumps(result, indent=2))


def run_score(args):
    """Score from existing reports."""
    print("Score from reports not yet implemented")


def run_audit(args):
    """Audit all installed skills."""
    openclaw_dir = Path(args.openclaw_dir)
    skills_dir = openclaw_dir / "workspace" / "skills"

    if not skills_dir.exists():
        print(f"No skills directory found at {skills_dir}")
        sys.exit(1)

    skills = [d for d in skills_dir.iterdir() if d.is_dir() and not d.name.startswith(".")]
    print(f"Found {len(skills)} installed skills")
    print("=" * 60)

    engine = ScoringEngine()

    for skill_dir in sorted(skills):
        print(f"\n--- {skill_dir.name} ---")
        results = []

        static = StaticScanner()
        static_result = static.scan(skill_dir)
        results.append(static_result)

        skill_md = skill_dir / "SKILL.md"
        if skill_md.exists():
            reviewer = PromptReviewer()
            prompt_result = reviewer.scan(skill_md)
            results.append(prompt_result)

        score = engine.score(results)
        tier = score["trust_tier"]
        label = score["tier_label"]
        trust = score["trust_score"]

        status_icon = "✅" if tier >= 2 else "⚠️" if tier == 1 else "❌"
        print(f"  {status_icon} Tier {tier} ({label}) — Score: {trust}/100")

        if score["hard_fails"]:
            for fail in score["hard_fails"]:
                print(f"     ✘ {fail}")


def run_report(args):
    """Generate report."""
    print("Report generation not yet implemented as standalone")


if __name__ == "__main__":
    main()
