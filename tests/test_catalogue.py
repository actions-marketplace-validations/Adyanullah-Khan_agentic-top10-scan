"""Whole-catalogue checks: every rule fires on the vulnerable fixture, none on the clean one."""
import re
import shutil

from agentic_top10.categories import CATEGORIES
from agentic_top10.rules import RULES

from conftest import FIXTURES, fake_token, rule_ids, run_scan

ONLINE_ONLY = {"ATS-ASI04-05"}


def test_rules_are_well_formed():
    for rule in RULES.values():
        assert re.fullmatch(r"ATS-ASI(0[1-9]|10)-\d{2}", rule.id), rule.id
        assert rule.id.split("-")[1] == rule.primary_category, rule.id
        assert all(c in CATEGORIES for c in rule.categories), rule.id
        assert rule.title and rule.summary and rule.remediation, rule.id


def test_every_category_has_several_primary_rules():
    for cat_id in CATEGORIES:
        assert sum(1 for r in RULES.values() if r.primary_category == cat_id) >= 4, cat_id


def test_vulnerable_fixture_triggers_every_rule(tmp_path):
    root = tmp_path / "vulnerable"
    shutil.copytree(FIXTURES / "vulnerable", root)
    (root / "settings.py").write_text(f'ANTHROPIC_KEY = "{fake_token("sk-ant-api03-", 93)}"\n', encoding="utf-8")
    (root / "prompts" / "hidden.md").write_text("Be helpful.​\U000E0049\U000E0047\U000E004E\n", encoding="utf-8")
    result = run_scan(root)
    missing = set(RULES) - ONLINE_ONLY - rule_ids(result)
    assert not missing, f"rules never triggered by the vulnerable fixture: {sorted(missing)}"
    assert not result.warnings


def test_clean_fixture_has_no_findings():
    result = run_scan(FIXTURES / "clean")
    assert result.findings == [], [(f.rule_id, f.path, f.line, f.message) for f in result.findings]
    assert result.project.is_agent_project
