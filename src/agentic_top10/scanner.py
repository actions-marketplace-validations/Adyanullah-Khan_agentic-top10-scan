"""File discovery, classification and orchestration of the analyzers."""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import textutil
from .analyzers import (containers, dependencies, javascript, manifest, mcp_config, python_code, text_checks,
                        workflows)
from .models import FileContext, Finding, ProjectState
from .rules import SUPERSEDES
from .settings import Settings, is_suppressed

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".nox",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", ".next", ".nuxt", ".turbo", "coverage",
             ".cache", ".idea", ".gradle", "target", "vendor", ".terraform", ".eggs", "bower_components", ".yarn"}
TEXT_EXTS = {".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".json", ".jsonc", ".yaml", ".yml",
             ".toml", ".md", ".mdc", ".markdown", ".txt", ".prompt", ".prompty", ".j2", ".jinja", ".jinja2", ".tmpl",
             ".hbs", ".mustache", ".sh", ".bash", ".zsh", ".ps1", ".cfg", ".ini", ".conf", ".env", ".in", ".rst",
             ".lock", ".xml"}
SPECIAL_NAMES = {"Dockerfile", "Makefile", ".cursorrules", ".windsurfrules", ".clinerules", ".goosehints", "Procfile"}
JS_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
MAX_BYTES = 2_000_000
TEST_DIRS = {"tests", "test", "testing", "__tests__", "integration_tests", "e2e", "spec", "specs"}
TEST_FILE_RE = re.compile(r"^(test_.*\.py|.*_test\.py|conftest\.py|.*\.(test|spec)\.[cm]?[jt]sx?|"
                          r"test_.*\.[cm]?[jt]sx?)$")
AGENT_HINT_RE = re.compile(
    r"(langchain|langgraph|crewai|autogen|\bopenai\b|anthropic|llama_index|llamaindex|smolagents|pydantic_ai|"
    r"semantic_kernel|modelcontextprotocol|fastmcp|\bfrom mcp\b|\bimport mcp\b|litellm|\bollama\b|mem0|@ai-sdk|"
    r"google\.genai|google-genai|\bagno\b|\bletta\b|claude[-_]agent[-_]sdk|\ba2a\b|mcpServers)"
)


@dataclass
class ScanResult:
    findings: List[Finding]
    files_scanned: int
    project: ProjectState
    warnings: List[str] = field(default_factory=list)
    duration: float = 0.0
    root: str = "."


def _wanted(path: Path) -> bool:
    name = path.name
    return path.suffix.lower() in TEXT_EXTS or name in SPECIAL_NAMES or name.startswith((".env", "Dockerfile")) or \
        name.endswith(".Dockerfile")


def discover(root: Path, settings: Settings, base: Path) -> List[Path]:
    if root.is_file():
        return [root]
    found: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS or d.endswith(".egg-info") or (d in TEST_DIRS and not settings.include_tests):
                continue
            if settings.is_excluded(_relpath(current / d, base), _relpath(current / d, root.resolve())):
                continue
            kept.append(d)
        dirnames[:] = kept
        for fname in sorted(filenames):
            path = current / fname
            if path.is_symlink() or not _wanted(path):
                continue
            if not settings.include_tests and TEST_FILE_RE.match(fname):
                continue
            if settings.is_excluded(_relpath(path, base), _relpath(path, root.resolve())):
                continue
            found.append(path)
    return found


def _relpath(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def _read(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def classify(rel: str, text: str) -> str:
    lower = rel.lower()
    name = lower.rsplit("/", 1)[-1]
    suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    if workflows.is_workflow(rel):
        return "workflow"
    if manifest.is_manifest(rel):
        return "manifest"
    if manifest.is_a2a_card(rel):
        return "a2a"
    if mcp_config.is_agent_settings(rel):
        return "agent-settings"
    if mcp_config.is_mcp_file(rel, text):
        return "mcp"
    if manifest.is_crewai_config(rel, text):
        return "crewai"
    if containers.is_compose(rel):
        return "compose"
    if containers.is_devcontainer(rel):
        return "devcontainer"
    if containers.is_dockerfile(rel):
        return "dockerfile"
    if dependencies.is_requirements(rel):
        return "requirements"
    if name == "pyproject.toml":
        return "pyproject"
    if name == "package.json":
        return "package-json"
    if name == "package-lock.json":
        return "package-lock"
    if text_checks.is_prompt_file(rel):
        return "prompt"
    if suffix == ".py":
        return "python"
    if suffix in JS_EXTS and not name.endswith((".d.ts", ".min.js")):
        return "javascript"
    return "text"


ANALYZERS: Dict[str, Callable[[FileContext], None]] = {
    "workflow": workflows.analyze,
    "manifest": manifest.analyze_manifest,
    "a2a": manifest.analyze_a2a,
    "agent-settings": mcp_config.analyze_settings,
    "mcp": mcp_config.analyze_mcp,
    "crewai": manifest.analyze_crewai,
    "compose": containers.analyze_compose,
    "devcontainer": containers.analyze_devcontainer,
    "dockerfile": containers.analyze_dockerfile,
    "requirements": dependencies.analyze_requirements,
    "pyproject": dependencies.analyze_pyproject,
    "package-json": dependencies.analyze_package_json,
    "python": python_code.analyze,
    "javascript": javascript.analyze,
}


def project_checks(project: ProjectState, contexts: Dict[str, FileContext]) -> None:
    tools = project.tools
    if tools and not any(t.logs for t in tools) and not project.tracing_signals:
        first = tools[0]
        ctx = contexts.get(first.path)
        if ctx is not None:
            names = ", ".join(sorted({t.name for t in tools})[:5])
            ctx.report("ATS-ASI10-04", first.line, f"{len({t.name for t in tools})} agent tool(s) ({names}) neither log "
                       "their calls nor run under a tracing library.")


def scan(target: Path, settings: Settings, base: Optional[Path] = None) -> ScanResult:
    started = time.time()
    target = target.resolve()
    base = (base or Path.cwd()).resolve()
    if target != base and base not in target.parents:
        base = target if target.is_dir() else target.parent
    project = ProjectState(root=target)
    warnings: List[str] = []
    target_rel = _relpath(target, base)
    if target != base and settings.is_excluded(target_rel):
        # An explicitly requested path wins over exclude patterns that would hide all of it.
        settings.exclude = [p for p in settings.exclude if not Settings(exclude=[p]).is_excluded(target_rel)]

    contexts: Dict[str, FileContext] = {}
    for path in discover(target, settings, base):
        text = _read(path)
        if text is None:
            continue
        rel = _relpath(path, base)
        name = path.name.lower()
        if name in dependencies.PY_LOCKS + dependencies.JS_LOCKS:
            project.lockfiles.append(rel)
        if AGENT_HINT_RE.search(text) and path.suffix.lower() in {".py", ".json", ".toml", ".txt"} | JS_EXTS:
            project.is_agent_project = True
        contexts[rel] = FileContext(path, rel, text, classify(rel, text), project)

    for rel, ctx in contexts.items():
        try:
            if ctx.kind != "package-lock" and not name_is_lock(rel):
                text_checks.analyze(ctx)
            analyzer = ANALYZERS.get(ctx.kind)
            if analyzer:
                analyzer(ctx)
            if ctx.kind == "package-lock" and settings.online:
                dependencies.collect_package_lock(ctx)
        except RecursionError:
            warnings.append(f"{rel}: skipped (file too deeply nested to analyze)")
        except Exception as exc:  # noqa: BLE001 - one bad file must not abort the scan
            warnings.append(f"{rel}: analyzer error: {type(exc).__name__}: {exc}")

    project_checks(project, contexts)
    if settings.online:
        warnings.extend(dependencies.query_osv(project, contexts))

    findings = _postprocess(contexts, settings)
    return ScanResult(findings=findings, files_scanned=len(contexts), project=project, warnings=warnings,
                      duration=time.time() - started, root=_relpath(target, base) if target != base else ".")


def name_is_lock(rel: str) -> bool:
    return rel.lower().endswith((".lock", "-lock.json", "lock.yaml", "lock.json"))


def _postprocess(contexts: Dict[str, FileContext], settings: Settings) -> List[Finding]:
    best: Dict[tuple, Finding] = {}
    for ctx in contexts.values():
        for f in ctx.findings:
            if f.rule_id in settings.disable or is_suppressed(ctx.lines, f.line, f.rule_id):
                continue
            if f.rule_id in settings.severity_overrides:
                f.severity = settings.severity_overrides[f.rule_id]
            if f.severity < settings.min_severity:
                continue
            f.evidence = textutil.truncate(textutil.redact(f.evidence), 300)
            f.message = textutil.redact(f.message)
            key = (f.rule_id, f.path, f.line)
            if key not in best or f.severity > best[key].severity:
                best[key] = f
    by_line: Dict[tuple, set] = {}
    for f in best.values():
        by_line.setdefault((f.path, f.line), set()).add(f.rule_id)
    out = []
    for f in best.values():
        present = by_line[(f.path, f.line)]
        if any(f.rule_id in SUPERSEDES.get(other, ()) for other in present if other != f.rule_id):
            continue
        out.append(f)
    return sorted(out, key=Finding.sort_key)
