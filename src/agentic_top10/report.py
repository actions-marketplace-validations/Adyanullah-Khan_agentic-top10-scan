"""Output formats: terminal text, JSON, SARIF 2.1.0, Markdown (job summary) and GitHub annotations."""
from __future__ import annotations

import json
from collections import Counter
from typing import Dict, List

from . import __version__
from .categories import CATEGORIES, category_label
from .models import Finding, Severity
from .rules import RULES, rules_for_category
from .scanner import ScanResult

TOOL_NAME = "agentic-top10-scan"
INFO_URI = "https://github.com/Adyanullah-Khan/agentic-top10-scan"
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0",
                     Severity.INFO: "1.0"}
SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note",
               Severity.INFO: "note"}
DISCLAIMER = ("Static checks only: a clean result does not mean the agent is secure or compliant with the OWASP Top 10 "
              "for Agentic Applications. Not affiliated with OWASP.")


def _category_counts(findings: List[Finding]) -> Dict[str, int]:
    counts: Counter = Counter()
    for f in findings:
        for cat in set(f.categories):
            counts[cat] += 1
    return counts


# ── text ─────────────────────────────────────────────────────────────────────

_COLORS = {Severity.CRITICAL: "\033[1;35m", Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[33m",
           Severity.LOW: "\033[36m", Severity.INFO: "\033[37m"}


def summary_line(result: ScanResult) -> str:
    counts = Counter(f.severity for f in result.findings)
    sev_line = ", ".join(f"{counts[s]} {s.label}" for s in sorted(Severity, reverse=True) if counts[s])
    return (f"Scanned {result.files_scanned} file(s) in {result.duration:.1f}s: "
            f"{len(result.findings)} finding(s){' (' + sev_line + ')' if sev_line else ''}.")


def to_text(result: ScanResult, color: bool = False) -> str:
    def paint(sev: Severity, text: str) -> str:
        return f"{_COLORS[sev]}{text}\033[0m" if color else text

    out = []
    for f in result.findings:
        rule = RULES[f.rule_id]
        out.append(f"{paint(f.severity, '[' + f.severity.label.upper() + ']')} {f.rule_id} {f.path}:{f.line}")
        out.append(f"    {f.message}")
        if f.evidence:
            out.append(f"    > {f.evidence}")
        out.append(f"    {', '.join(f.categories)} · {rule.title}")
        out.append("")
    out.append(summary_line(result))
    cat_counts = _category_counts(result.findings)
    out.append("")
    out.append("OWASP Agentic Top 10 coverage (findings / rules):")
    for cat_id in CATEGORIES:
        out.append(f"  {category_label(cat_id):<42} {cat_counts.get(cat_id, 0):>4} / {len(rules_for_category(cat_id))}")
    for w in result.warnings:
        out.append(f"warning: {w}")
    out.append("")
    out.append(DISCLAIMER)
    return "\n".join(out)


# ── JSON ─────────────────────────────────────────────────────────────────────

def to_dict(result: ScanResult) -> dict:
    return {
        "tool": TOOL_NAME,
        "version": __version__,
        "files_scanned": result.files_scanned,
        "agent_project_detected": result.project.is_agent_project,
        "summary": {
            "total": len(result.findings),
            "by_severity": {s.label: sum(1 for f in result.findings if f.severity == s) for s in Severity},
            "by_category": {c: _category_counts(result.findings).get(c, 0) for c in CATEGORIES},
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": RULES[f.rule_id].title,
                "severity": f.severity.label,
                "categories": list(f.categories),
                "path": f.path,
                "line": f.line,
                "column": f.column,
                "message": f.message,
                "evidence": f.evidence,
                "remediation": RULES[f.rule_id].remediation,
                "fingerprint": f.fingerprint(),
            }
            for f in result.findings
        ],
        "warnings": result.warnings,
        "disclaimer": DISCLAIMER,
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2)


# ── SARIF ────────────────────────────────────────────────────────────────────

def _sarif_rule(rule) -> dict:
    cats = ", ".join(category_label(c) for c in rule.categories)
    return {
        "id": rule.id,
        "name": "".join(w.capitalize() for w in rule.title.replace("-", " ").split() if w.isalnum())[:100] or rule.id,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.summary},
        "helpUri": f"{INFO_URI}/blob/main/docs/rules.md#{rule.id.lower()}",
        "help": {
            "text": f"{rule.summary}\n\nFix: {rule.remediation}\n\nOWASP Agentic Top 10: {cats}",
            "markdown": f"{rule.summary}\n\n**Fix:** {rule.remediation}\n\n**OWASP Agentic Top 10:** {cats}",
        },
        "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
        "properties": {
            "tags": ["security", "ai-agents"] + [f"owasp-agentic-{c.lower()}" for c in rule.categories],
            "security-severity": SECURITY_SEVERITY[rule.severity],
            "precision": rule.precision,
            "problem.severity": "error" if rule.severity >= Severity.HIGH else
            "warning" if rule.severity == Severity.MEDIUM else "recommendation",
        },
    }


def to_sarif(result: ScanResult) -> str:
    rule_ids = list(RULES)
    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_ids.index(f.rule_id),
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }],
            "partialFingerprints": {"agenticTop10/v1": f.fingerprint()},
            "properties": {"severity": f.severity.label, "security-severity": SECURITY_SEVERITY[f.severity],
                           "owasp-agentic": list(f.categories)},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFO_URI,
                "rules": [_sarif_rule(r) for r in RULES.values()],
            }},
            "automationDetails": {"id": "agentic-top10/"},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


# ── Markdown ─────────────────────────────────────────────────────────────────

def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(result: ScanResult, limit: int = 50) -> str:
    counts = Counter(f.severity for f in result.findings)
    cat_counts = _category_counts(result.findings)
    lines = ["## Agentic Top 10 Scan", ""]
    if result.findings:
        badges = " · ".join(f"**{counts[s]}** {s.label}" for s in sorted(Severity, reverse=True) if counts[s])
        lines.append(f"{len(result.findings)} finding(s) in {result.files_scanned} file(s): {badges}")
    else:
        lines.append(f"No findings in {result.files_scanned} file(s).")
    lines += ["", "| OWASP Agentic category | Findings | Rules |", "|---|---:|---:|"]
    for cat_id in CATEGORIES:
        lines.append(f"| {category_label(cat_id)} | {cat_counts.get(cat_id, 0)} | {len(rules_for_category(cat_id))} |")
    if result.findings:
        lines += ["", "| Severity | Rule | Location | Finding |", "|---|---|---|---|"]
        for f in result.findings[:limit]:
            lines.append(f"| {f.severity.label.upper()} | `{f.rule_id}` | `{f.path}:{f.line}` | {_md(f.message)} |")
        if len(result.findings) > limit:
            lines.append(f"\n…and {len(result.findings) - limit} more (see the SARIF/JSON report).")
    for w in result.warnings:
        lines.append(f"\n> warning: {_md(w)}")
    lines += ["", f"_{DISCLAIMER}_", ""]
    return "\n".join(lines)


# ── GitHub annotations ───────────────────────────────────────────────────────

def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_prop(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def to_annotations(result: ScanResult) -> str:
    out = []
    for f in result.findings:
        kind = "error" if f.severity >= Severity.HIGH else "warning" if f.severity == Severity.MEDIUM else "notice"
        title = _escape_prop(f"{f.rule_id} ({f.severity.label}) {RULES[f.rule_id].title}")
        out.append(f"::{kind} file={_escape_prop(f.path)},line={f.line},col={f.column},title={title}::"
                   f"{_escape_data(f.message)}")
    return "\n".join(out)


# ── rule catalogue ───────────────────────────────────────────────────────────

def rules_markdown() -> str:
    lines = ["# Rules", "", "Rule IDs are this project's own. The `ASIxx` part names the primary category of the "
             "[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/); secondary categories are listed per "
             "rule. Generated by `agentic-top10 rules --format markdown`.", ""]
    for cat_id, meta in CATEGORIES.items():
        lines += [f"## {cat_id} {meta['name']}", "", f"**Checked statically:** {meta['checks']}", "",
                  f"**Not visible to static analysis:** {meta['blind_spots']}", ""]
        for rule in RULES.values():
            if rule.primary_category != cat_id:
                continue
            lines += [f"### {rule.id}", "", f"**{rule.title}** · default severity `{rule.severity.label}` · "
                      f"categories {', '.join(rule.categories)}", "", rule.summary, "", f"**Fix:** {rule.remediation}",
                      ""]
    return "\n".join(lines)


def coverage_text() -> str:
    out = []
    for cat_id, meta in CATEGORIES.items():
        rules = rules_for_category(cat_id)
        out.append(f"{category_label(cat_id)}  ({len(rules)} rules)")
        out.append(f"  checks:      {meta['checks']}")
        out.append(f"  blind spots: {meta['blind_spots']}")
        out.append("")
    out.append(DISCLAIMER)
    return "\n".join(out)
