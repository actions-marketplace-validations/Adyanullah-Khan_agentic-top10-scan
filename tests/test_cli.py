"""CLI behaviour: exit codes, report formats, settings, suppressions and the opt-in OSV lookup."""
import io
import json
import shutil

from agentic_top10 import cli
from agentic_top10.analyzers import dependencies
from agentic_top10.rules import RULES

from conftest import FIXTURES


def run(argv, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_exit_codes(capsys, tmp_path):
    assert run([str(FIXTURES / "clean")], capsys)[0] == 0
    assert run([str(FIXTURES / "vulnerable")], capsys)[0] == 1
    assert run([str(FIXTURES / "vulnerable"), "--fail-on", "none"], capsys)[0] == 0
    assert run([str(tmp_path / "missing")], capsys)[0] == 2
    assert run([str(FIXTURES / "clean"), "--disable", "NOPE"], capsys)[0] == 2


def test_sarif_structure(capsys, tmp_path):
    sarif_path = tmp_path / "out.sarif"
    code, _, _ = run(["scan", str(FIXTURES / "vulnerable"), "--sarif", str(sarif_path), "-q"], capsys)
    assert code == 1
    doc = json.loads(sarif_path.read_text())
    assert doc["version"] == "2.1.0"
    run_ = doc["runs"][0]
    rules = run_["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == list(RULES)
    assert all("security-severity" in r["properties"] for r in rules)
    for res in run_["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]
        assert not loc["artifactLocation"]["uri"].startswith("/")
        assert loc["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["agenticTop10/v1"]


def test_markdown_and_annotations(capsys, tmp_path):
    md = tmp_path / "summary.md"
    code, out, _ = run([str(FIXTURES / "vulnerable"), "--markdown", str(md), "--github-annotations", "-q"], capsys)
    text = md.read_text()
    for n in range(1, 11):
        assert f"ASI{n:02d}" in text
    assert "::error file=" in out and "::warning file=" in out


def test_inline_suppression_and_settings(capsys, tmp_path):
    (tmp_path / "a.py").write_text(
        "eval(x)  # agentic-top10: ignore\n"
        "# agentic-top10: ignore[ATS-ASI05-01]\n"
        "eval(y)\n"
        "eval(z)  # agentic-top10: ignore[ATS-ASI05-05]\n"
    )
    (tmp_path / "skip").mkdir()
    (tmp_path / "skip" / "b.py").write_text("eval(q)\n")
    (tmp_path / "c.py").write_text("import pickle\npickle.loads(b)\n")
    (tmp_path / ".agentic-top10.yml").write_text(
        "exclude: [skip]\nseverity:\n  ATS-ASI05-05: low\nfail_on: high\n"
    )
    code, out, _ = run([str(tmp_path), "--format", "json"], capsys)
    data = json.loads(out)
    got = sorted((f["path"], f["line"], f["severity"]) for f in data["findings"])
    assert got == [("a.py", 4, "high"), ("c.py", 2, "low")]
    assert code == 1


def test_rules_and_coverage_commands(capsys):
    code, out, _ = run(["rules"], capsys)
    assert code == 0 and all(rule_id in out for rule_id in RULES)
    code, out, _ = run(["rules", "--format", "markdown"], capsys)
    assert code == 0 and "## ASI10 Rogue Agents" in out
    code, out, _ = run(["coverage"], capsys)
    assert code == 0 and "blind spots" in out


def test_online_osv_lookup(capsys, tmp_path, monkeypatch):
    shutil.copy(FIXTURES / "clean" / "requirements.txt", tmp_path / "requirements.txt")
    seen = {}

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout):
        queries = json.loads(req.data)["queries"]
        seen["queries"] = queries
        results = [{"vulns": [{"id": "GHSA-test-0001"}]} if q["package"]["name"] == "requests" else {}
                   for q in queries]
        return FakeResponse(json.dumps({"results": results}).encode())

    monkeypatch.setattr(dependencies.urllib.request, "urlopen", fake_urlopen)
    code, out, _ = run([str(tmp_path), "--online", "--format", "json"], capsys)
    data = json.loads(out)
    assert len(seen["queries"]) == 4
    assert [(f["rule_id"], f["line"]) for f in data["findings"]] == [("ATS-ASI04-05", 4)]
    assert code == 1


def test_tests_are_skipped_unless_requested(capsys, tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "helpers.py").write_text("eval(x)\n")
    (tmp_path / "test_app.py").write_text("eval(y)\n")
    (tmp_path / "app.py").write_text("eval(z)\n")
    _, out, _ = run([str(tmp_path), "--format", "json"], capsys)
    assert [f["path"] for f in json.loads(out)["findings"]] == ["app.py"]
    _, out, _ = run([str(tmp_path), "--format", "json", "--include-tests"], capsys)
    assert len(json.loads(out)["findings"]) == 3


def test_explicit_target_wins_over_exclude(capsys, tmp_path, monkeypatch):
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "a.py").write_text("eval(x)\n")
    (tmp_path / ".agentic-top10.yml").write_text("exclude: [samples]\n")
    monkeypatch.chdir(tmp_path)
    _, out, _ = run([".", "--format", "json"], capsys)
    assert json.loads(out)["findings"] == []
    _, out, _ = run(["samples", "--format", "json"], capsys)
    assert [f["path"] for f in json.loads(out)["findings"]] == ["samples/a.py"]


def test_exclude_patterns_are_gitignore_like(tmp_path):
    from conftest import run_scan
    for rel in ("app/web/a.py", "app/core/b.py", "app/core/gen/c.py", "lib/core/gen/d.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("eval(x)\n")
    # bare names match at any depth; patterns with a slash are anchored at the root
    paths = {f.path for f in run_scan(tmp_path, exclude=["web", "app/core/gen"]).findings}
    assert paths == {"app/core/b.py", "lib/core/gen/d.py"}
    paths = {f.path for f in run_scan(tmp_path, exclude=["**/gen"]).findings}
    assert paths == {"app/web/a.py", "app/core/b.py"}
