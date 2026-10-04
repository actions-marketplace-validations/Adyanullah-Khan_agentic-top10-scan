"""Declarative agent configuration: this tool's agent manifest, A2A agent cards and CrewAI YAML configs."""
from __future__ import annotations

import re
from typing import Any, Dict

from .. import textutil
from ..configfiles import as_list, find_line, key_line, load_structured
from ..models import FileContext, Severity
from . import text_checks

MANIFEST_NAMES = {"agent-manifest.yaml", "agent-manifest.yml", "agent-manifest.json", "agent_manifest.yaml",
                  "agent_manifest.yml", "agent_manifest.json", ".agent-manifest.yaml", ".agent-manifest.yml"}
A2A_NAMES = {"agent-card.json", "agent_card.json", "agentcard.json"}
RISKY_CAP_RE = re.compile(r"(?i)(write|delete|remove|exec|shell|command|payment|pay|transfer|email|send|deploy|admin|"
                          r"filesystem|database\.write|sql|purchase|refund|merge|push|publish|post)")
WILDCARD_RE = re.compile(r"(?i)^(\*|\*:\*|admin|all|root|write-all|full_access|full-access)$|[:.]\*$")
NO_AUTH = {None, "", "none", "no", "false", "anonymous", "public", False}
APPROVAL_KEYS = ("requires_approval", "approval_required", "require_approval", "human_approval", "needs_approval")
LIMIT_KEYS = ("max_iterations", "max_turns", "max_steps", "max_runtime", "max_runtime_seconds", "timeout",
              "timeout_seconds", "max_cost_usd", "budget")


def is_manifest(rel: str) -> bool:
    return rel.lower().rsplit("/", 1)[-1] in MANIFEST_NAMES


def is_a2a_card(rel: str) -> bool:
    lower = rel.lower()
    return lower.rsplit("/", 1)[-1] in A2A_NAMES or lower.endswith(".well-known/agent.json")


def is_crewai_config(rel: str, text: str) -> bool:
    name = rel.lower().rsplit("/", 1)[-1]
    if name not in ("agents.yaml", "agents.yml", "tasks.yaml", "tasks.yml"):
        return False
    return bool(re.search(r"^\s+(role|goal|backstory|expected_output)\s*:", text, re.M))


def _approval(entry: Dict[str, Any]) -> bool:
    return any(entry.get(k) is True or str(entry.get(k)).lower() in ("required", "always") for k in APPROVAL_KEYS)


def _line_for(ctx: FileContext, name: Any, default: int = 1) -> int:
    if name is None:
        return default
    return find_line(ctx.lines, rf"""(name|id)["']?\s*[:=]\s*["']?{re.escape(str(name))}\b""", 1, default) or default


def _check_endpoint(ctx: FileContext, what: str, url: Any, auth: Any, line: int) -> None:
    if not isinstance(url, str):
        return
    if textutil.is_remote_plain_http(url):
        ctx.report("ATS-ASI07-01", line, f"{what} uses plaintext HTTP ({url}).")
    auth_value = auth.get("type") if isinstance(auth, dict) else auth
    if (auth_value in NO_AUTH or str(auth_value).lower() in NO_AUTH) and not textutil.is_local_url(url) \
            and url.startswith(("http", "ws")):
        ctx.report("ATS-ASI03-05", line, f"{what} ({url}) is declared without authentication.")


def analyze_manifest(ctx: FileContext) -> None:
    data = load_structured(ctx.text, ctx.path.suffix)
    if not isinstance(data, dict):
        return
    ctx.project.manifests.append(ctx.rel)

    for tool in as_list(data.get("tools")):
        if not isinstance(tool, dict):
            continue
        name = tool.get("name", "?")
        line = _line_for(ctx, name)
        perms = [str(p) for p in as_list(tool.get("permissions")) + as_list(tool.get("scopes"))]
        wild = [p for p in perms if WILDCARD_RE.search(p)]
        if wild:
            ctx.report("ATS-ASI02-07", line, f"Tool '{name}' has wildcard/admin permissions: {', '.join(wild)}.")
        caps = [str(c) for c in as_list(tool.get("capabilities"))] + perms
        risk = str(tool.get("risk", "")).lower()
        if (risk in ("high", "critical") or any(RISKY_CAP_RE.search(c) for c in caps)) and not _approval(tool):
            ctx.report("ATS-ASI09-05", line, f"High-risk tool '{name}' ({', '.join(caps[:4]) or risk}) does not require "
                       "human approval.")
        _check_endpoint(ctx, f"Tool '{name}' endpoint", tool.get("endpoint") or tool.get("url"),
                        tool.get("auth", tool.get("authentication")), line)
        if isinstance(tool.get("description"), str):
            text_checks.check_prompt_text(ctx, tool["description"], key_line(ctx.lines, "description", line, line),
                                          "tool-description")

    for ep in as_list(data.get("endpoints")):
        if isinstance(ep, dict):
            _check_endpoint(ctx, f"Endpoint '{ep.get('name', '?')}'", ep.get("url"),
                            ep.get("auth", ep.get("authentication")), _line_for(ctx, ep.get("name")))

    for agent in as_list(data.get("agents")):
        if not isinstance(agent, dict):
            continue
        name = agent.get("name", "?")
        line = _line_for(ctx, name)
        limits = agent.get("limits") if isinstance(agent.get("limits"), dict) else {}
        if not any(k in limits or k in agent for k in LIMIT_KEYS):
            ctx.report("ATS-ASI08-05", line, f"Agent '{name}' declares no iteration, runtime or cost limit.")
        delegates = [str(d) for d in as_list(agent.get("delegates_to") or agent.get("can_delegate_to"))]
        if any(d in ("*", "any", "all") for d in delegates):
            ctx.report("ATS-ASI03-07", line, f"Agent '{name}' may delegate to any agent.", severity=Severity.MEDIUM)
        for channel in as_list(agent.get("communication")):
            if not isinstance(channel, dict):
                continue
            peer = channel.get("peer", channel.get("name", "peer"))
            problems = []
            transport = str(channel.get("transport", "")).lower()
            url = channel.get("url", "")
            if transport in ("http", "ws", "tcp") or (isinstance(url, str) and textutil.is_remote_plain_http(url)):
                problems.append(f"plaintext transport ({transport or url})")
            if transport != "stdio" and (channel.get("auth") in NO_AUTH or str(channel.get("auth")).lower() in NO_AUTH):
                problems.append("no authentication")
            if channel.get("signed_messages") is False:
                problems.append("unsigned messages")
            if problems:
                ctx.report("ATS-ASI07-05", key_line(ctx.lines, "communication", line, line),
                           f"Channel {name} → {peer}: {', '.join(problems)}.")
        for key in ("system_prompt", "instructions", "prompt", "backstory", "goal"):
            if isinstance(agent.get(key), str):
                text_checks.check_prompt_text(ctx, agent[key], key_line(ctx.lines, key, line, line), "prompt")

    for mem in as_list(data.get("memory")):
        if not isinstance(mem, dict):
            continue
        if not (mem.get("persistent") or str(mem.get("type", "")).lower() in ("long_term", "long-term", "vector",
                                                                            "persistent")):
            continue
        name = mem.get("name", "memory")
        problems = []
        scope = str(mem.get("scope", "")).lower()
        if scope in ("", "none"):
            problems.append("has no isolation scope")
        elif scope in ("shared", "global", "all", "public"):
            problems.append(f"is shared ({scope})")
        if mem.get("write_validation") is not True and mem.get("validation") is not True:
            problems.append("has no write validation")
        if not any(k in mem for k in ("ttl", "ttl_days", "expiry", "expires_after", "retention_days")):
            problems.append("never expires")
        if problems:
            only_ttl = problems == ["never expires"]
            ctx.report("ATS-ASI06-04", _line_for(ctx, name), f"Persistent memory '{name}' {', '.join(problems)}.",
                       severity=Severity.LOW if only_ttl else None)

    oversight = data.get("oversight") if isinstance(data.get("oversight"), dict) else {}
    missing = [k for k in ("kill_switch", "audit_log") if not oversight.get(k)]
    if missing:
        ctx.report("ATS-ASI10-05", key_line(ctx.lines, "oversight", 1, 1),
                   f"Manifest oversight does not declare: {', '.join(missing)}.")


def analyze_a2a(ctx: FileContext) -> None:
    data = load_structured(ctx.text, ".json")
    if not isinstance(data, dict) or not ("skills" in data or "capabilities" in data):
        return
    schemes = data.get("securitySchemes") or data.get("security") or data.get("authentication")
    if isinstance(schemes, dict) and "schemes" in schemes:
        schemes = schemes.get("schemes")
    name_line = key_line(ctx.lines, "name")
    if not schemes:
        ctx.report("ATS-ASI07-02", name_line, f"A2A agent card '{data.get('name', '?')}' declares no security schemes.")
    urls = [data.get("url")] + [i.get("url") for i in as_list(data.get("additionalInterfaces")) if isinstance(i, dict)]
    for url in urls:
        if isinstance(url, str) and textutil.is_remote_plain_http(url):
            ctx.report("ATS-ASI07-01", key_line(ctx.lines, "url"), f"A2A agent endpoint uses plaintext HTTP ({url}).")
    for skill in as_list(data.get("skills")):
        if isinstance(skill, dict) and isinstance(skill.get("description"), str):
            line = _line_for(ctx, skill.get("id") or skill.get("name"), name_line)
            text_checks.check_prompt_text(ctx, skill["description"], key_line(ctx.lines, "description", line, line),
                                          "tool-description")


def analyze_crewai(ctx: FileContext) -> None:
    text_checks.check_prompt_text(ctx, ctx.text, 1, "prompt")
