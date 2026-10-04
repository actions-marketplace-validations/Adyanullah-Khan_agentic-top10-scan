"""Dependency manifests: unpinned agent frameworks, risky install sources, and opt-in OSV advisory lookups."""
from __future__ import annotations

import json
import re
import urllib.request
from typing import Dict, List

from ..configfiles import load_toml
from ..models import FileContext, ProjectState, Severity

PY_AGENT_PKG_RE = re.compile(
    r"(?i)^(langchain[\w-]*|langgraph[\w-]*|langsmith|crewai[\w-]*|autogen[\w-]*|pyautogen|ag2|openai(-agents)?|"
    r"anthropic|claude-agent-sdk|llama[-_]index[\w-]*|smolagents|pydantic-ai[\w-]*|semantic-kernel|mcp|fastmcp|"
    r"haystack-ai|dspy(-ai)?|google-adk|google-genai|google-generativeai|litellm|ollama|agno|letta|mem0ai|instructor|"
    r"open-interpreter|a2a-sdk|strands-agents[\w-]*|transformers)$"
)
JS_AGENT_PKG_RE = re.compile(
    r"^(langchain|@langchain/.+|openai|@openai/agents|@anthropic-ai/.+|@modelcontextprotocol/.+|ai|@ai-sdk/.+|"
    r"llamaindex|@llamaindex/.+|@google/genai|@google/generative-ai|@mastra/.+|mastra|ollama|@mistralai/.+|groq-sdk|"
    r"cohere-ai|@a2a-js/.+)$"
)
PY_LOCKS = ("uv.lock", "poetry.lock", "pipfile.lock", "pdm.lock", "requirements.lock", "pylock.toml")
JS_LOCKS = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock", "npm-shrinkwrap.json")
REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(.*)$")

def is_requirements(rel: str) -> bool:
    name = rel.lower().rsplit("/", 1)[-1]
    return bool(re.fullmatch(r"requirements[\w.\-]*\.(txt|in)", name)) or name == "constraints.txt"


def _has_lock(project: ProjectState, locks) -> bool:
    return any(lf.lower().rsplit("/", 1)[-1] in locks for lf in project.lockfiles)


def analyze_requirements(ctx: FileContext) -> None:
    locked = _has_lock(ctx.project, PY_LOCKS)
    for i, raw in enumerate(ctx.lines, start=1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("--extra-index-url", "--index-url", "-i ")):
            if "--extra-index-url" in line:
                ctx.report("ATS-ASI04-03", i, "--extra-index-url lets a public package shadow a private one "
                           "(dependency confusion).", severity=Severity.MEDIUM)
            continue
        if re.search(r"git\+https?://", line) and not re.search(r"@[0-9a-f]{40}\b", line):
            ctx.report("ATS-ASI04-03", i, "Dependency installed from a git URL without a pinned commit.",
                       severity=Severity.MEDIUM)
            continue
        if line.startswith("-"):
            continue
        m = REQ_LINE_RE.match(line)
        if not m:
            continue
        name, spec = m.group(1), m.group(3).split(";", 1)[0].strip()
        exact = re.match(r"===?\s*([\w.\-+!]+)$", spec)
        if exact:
            ctx.project.pinned.append(("PyPI", name, exact.group(1), ctx.rel, i))
        elif PY_AGENT_PKG_RE.match(name) and not locked:
            ctx.report("ATS-ASI04-03", i, f"Agent dependency '{name}' is not pinned to an exact version"
                       + (f" ('{spec}')." if spec else "."))


def analyze_pyproject(ctx: FileContext) -> None:
    if _has_lock(ctx.project, PY_LOCKS):
        return
    data = load_toml(ctx.text)
    deps: List[str] = []
    if isinstance(data, dict):
        project = data.get("project") or {}
        deps = [d for d in project.get("dependencies") or [] if isinstance(d, str)]
        poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
        deps += [f"{k}{'' if isinstance(v, dict) else v}" for k, v in poetry.items() if k != "python"]
    for dep in deps:
        m = REQ_LINE_RE.match(dep)
        if not m or not PY_AGENT_PKG_RE.match(m.group(1)):
            continue
        spec = m.group(3).split(";", 1)[0].strip()
        if re.match(r"===?\s*[\w.\-+!]+$", spec):
            continue
        line = next((i for i, text in enumerate(ctx.lines, start=1) if m.group(1) in text), 1)
        ctx.report("ATS-ASI04-03", line, f"Agent dependency '{m.group(1)}' floats ('{spec or 'any version'}') and "
                   "no lockfile was found.")


def analyze_package_json(ctx: FileContext) -> None:
    try:
        data = json.loads(ctx.text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    locked = _has_lock(ctx.project, JS_LOCKS)
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not JS_AGENT_PKG_RE.match(name) or not isinstance(spec, str):
                continue
            floating = spec in ("*", "latest", "") or spec.startswith(("^", "~", ">", "<")) or " " in spec or "x" in spec
            if floating and not locked:
                line = next((i for i, t in enumerate(ctx.lines, start=1) if f'"{name}"' in t), 1)
                ctx.report("ATS-ASI04-03", line, f"Agent dependency '{name}' uses floating range '{spec}' and no "
                           "lockfile was found.")


def collect_package_lock(ctx: FileContext) -> None:
    try:
        data = json.loads(ctx.text)
    except ValueError:
        return
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return
    for path, meta in packages.items():
        if path.startswith("node_modules/") and isinstance(meta, dict) and meta.get("version"):
            name = path.split("node_modules/")[-1]
            line = next((i for i, t in enumerate(ctx.lines, start=1) if f'"{path}"' in t), 1)
            ctx.project.pinned.append(("npm", name, str(meta["version"]), ctx.rel, line))


def query_osv(project: ProjectState, contexts: Dict[str, FileContext], timeout: float = 20.0) -> List[str]:
    """Look up collected pinned packages in OSV. Returns warnings; findings go to the owning FileContext."""
    warnings: List[str] = []
    entries = list(dict.fromkeys(project.pinned))
    for start in range(0, len(entries), 500):
        batch = entries[start:start + 500]
        body = json.dumps({"queries": [{"package": {"ecosystem": eco, "name": name}, "version": version}
                                       for eco, name, version, _, _ in batch]}).encode()
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "agentic-top10-scan"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
                results = json.loads(resp.read().decode()).get("results", [])
        except Exception as exc:  # noqa: BLE001 - network problems become a warning, not a failed scan
            warnings.append(f"OSV lookup failed: {exc}")
            return warnings
        for (eco, name, version, path, line), result in zip(batch, results):
            vulns = [v.get("id") for v in (result or {}).get("vulns", []) if v.get("id")]
            if vulns and path in contexts:
                ids = ", ".join(vulns[:5]) + (f" (+{len(vulns) - 5} more)" if len(vulns) > 5 else "")
                contexts[path].report("ATS-ASI04-05", line, f"{name} {version} ({eco}) has known advisories: {ids}.")
    if not entries:
        warnings.append("--online was set but no exactly pinned dependencies were found")
    return warnings
