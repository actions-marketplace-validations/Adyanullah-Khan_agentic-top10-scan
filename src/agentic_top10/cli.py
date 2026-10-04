"""Command-line interface: agentic-top10 [scan] PATH | rules | coverage."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, report
from .models import Severity
from .rules import RULES
from .scanner import scan
from .settings import SETTINGS_FILES, Settings, load_settings_file, parse_fail_on

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
SEVERITIES = [s.label for s in Severity]


def _scan_parser(prog: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="Static security checks for AI-agent projects, organised by the OWASP Top 10 for Agentic "
                    "Applications (ASI01-ASI10).",
        epilog="Other commands: 'agentic-top10 rules' lists every rule, 'agentic-top10 coverage' explains what each "
               "OWASP category check covers. Exit codes: 0 pass, 1 findings at/above --fail-on, 2 error.",
    )
    p.add_argument("path", nargs="?", default=".", help="directory or file to scan (default: .)")
    p.add_argument("--format", choices=["text", "json", "sarif", "markdown"], default="text",
                   help="format written to stdout or --output (default: text)")
    p.add_argument("--output", "-o", help="write the --format report to this file instead of stdout")
    p.add_argument("--sarif", metavar="FILE", help="also write a SARIF 2.1.0 report")
    p.add_argument("--json", metavar="FILE", dest="json_file", help="also write a JSON report")
    p.add_argument("--markdown", metavar="FILE", help="also append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    p.add_argument("--github-annotations", action="store_true", help="print GitHub Actions ::error/::warning lines")
    p.add_argument("--fail-on", default=None, help=f"exit 1 on findings at/above this severity: none, "
                   f"{', '.join(SEVERITIES)} (default: high)")
    p.add_argument("--min-severity", default=None, choices=SEVERITIES, help="hide findings below this severity")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching this glob (repeatable, relative to the working directory)")
    p.add_argument("--disable", action="append", default=[], metavar="RULE_ID", help="disable a rule (repeatable)")
    p.add_argument("--config", metavar="FILE", help=f"settings file (default: {SETTINGS_FILES[0]} if present)")
    p.add_argument("--include-tests", action="store_true",
                   help="also scan test code (tests/, test_*.py, *.test.ts, ...), which is skipped by default")
    p.add_argument("--online", action="store_true",
                   help="look up exactly pinned dependencies in the OSV advisory database (sends package names and "
                        "versions to api.osv.dev; everything else stays local)")
    p.add_argument("--no-color", action="store_true", help="disable coloured terminal output")
    p.add_argument("--quiet", "-q", action="store_true", help="print only the summary line in text mode")
    p.add_argument("--version", action="version", version=f"agentic-top10 {__version__}")
    return p


def _write(path: str, content: str, append: bool = False) -> None:
    mode = "a" if append else "w"
    with open(path, mode, encoding="utf-8") as fh:
        fh.write(content if content.endswith("\n") else content + "\n")


def run_scan(argv: List[str]) -> int:
    args = _scan_parser("agentic-top10").parse_args(argv)
    target = Path(args.path)
    if not target.exists():
        print(f"agentic-top10: path not found: {args.path}", file=sys.stderr)
        return EXIT_ERROR

    settings = Settings()
    warnings: List[str] = []
    config = Path(args.config) if args.config else None
    if config is None:
        for candidate_dir in (target if target.is_dir() else target.parent, Path.cwd()):
            for name in SETTINGS_FILES:
                if (candidate_dir / name).is_file():
                    config = candidate_dir / name
                    break
            if config:
                break
    elif not config.is_file():
        print(f"agentic-top10: settings file not found: {config}", file=sys.stderr)
        return EXIT_ERROR
    if config:
        warnings.extend(load_settings_file(config, settings))
    try:
        if args.fail_on is not None:
            settings.fail_on = parse_fail_on(args.fail_on)
        if args.min_severity:
            settings.min_severity = Severity.parse(args.min_severity)
    except ValueError as exc:
        print(f"agentic-top10: {exc}", file=sys.stderr)
        return EXIT_ERROR
    for rule_id in args.disable:
        if rule_id not in RULES:
            print(f"agentic-top10: unknown rule id: {rule_id}", file=sys.stderr)
            return EXIT_ERROR
    settings.exclude.extend(args.exclude)
    settings.disable.extend(args.disable)
    settings.online = args.online
    settings.include_tests = settings.include_tests or args.include_tests

    try:
        result = scan(target, settings)
    except Exception as exc:  # noqa: BLE001
        print(f"agentic-top10: scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    result.warnings[:0] = warnings

    color = not args.no_color and args.output is None and sys.stdout.isatty()
    renderers = {"text": lambda: report.to_text(result, color=color), "json": lambda: report.to_json(result),
                 "sarif": lambda: report.to_sarif(result), "markdown": lambda: report.to_markdown(result)}
    try:
        if args.sarif:
            _write(args.sarif, report.to_sarif(result))
        if args.json_file:
            _write(args.json_file, report.to_json(result))
        if args.markdown:
            _write(args.markdown, report.to_markdown(result), append=True)
        if args.output:
            _write(args.output, renderers[args.format]())
    except OSError as exc:
        print(f"agentic-top10: could not write report: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.github_annotations and result.findings:
        print(report.to_annotations(result))
    if not args.output:
        if args.format == "text" and args.quiet:
            print(report.summary_line(result))
        else:
            print(renderers[args.format]())
    for w in result.warnings:
        print(f"agentic-top10: warning: {w}", file=sys.stderr)

    if settings.fail_on is not None and any(f.severity >= settings.fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def run_rules(argv: List[str]) -> int:
    p = argparse.ArgumentParser(prog="agentic-top10 rules", description="List every rule.")
    p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    args = p.parse_args(argv)
    if args.format == "markdown":
        print(report.rules_markdown())
    elif args.format == "json":
        print(json.dumps([{"id": r.id, "title": r.title, "severity": r.severity.label, "categories": list(r.categories),
                           "summary": r.summary, "remediation": r.remediation} for r in RULES.values()], indent=2))
    else:
        for r in RULES.values():
            print(f"{r.id:<14} {r.severity.label:<8} {','.join(r.categories):<12} {r.title}")
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "rules":
        return run_rules(argv[1:])
    if argv and argv[0] == "coverage":
        print(report.coverage_text())
        return EXIT_OK
    if argv and argv[0] == "scan":
        argv = argv[1:]
    return run_scan(argv)


if __name__ == "__main__":
    sys.exit(main())
