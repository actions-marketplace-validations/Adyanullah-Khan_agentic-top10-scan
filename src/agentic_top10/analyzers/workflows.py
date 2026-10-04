"""GitHub Actions workflows that run AI agents."""
from __future__ import annotations

import re
from typing import Any, Dict, Set

from ..configfiles import find_line, load_yaml
from ..models import FileContext, Severity

AGENT_ACTION_RE = re.compile(
    r"(?i)^(anthropics/claude-code(-base)?-action|openai/codex-action|google-github-actions/run-gemini-cli|"
    r"actions/ai-inference|github/copilot|coderabbitai/|qodo-ai/pr-agent|codium-ai/pr-agent|"
    r"[\w.-]+/[\w.-]*(claude|codex|gemini|openai|gpt|llm|copilot|aider|cline|goose|opencode|ai-agent|ai-review|"
    r"langchain|crewai)[\w.-]*)"
)
AGENT_RUN_RE = re.compile(
    r"(?im)(^|[\s;&|/])(claude|codex|gemini|aider|goose|opencode|cursor-agent|amp|llm|openhands|interpreter|qwen)\s+"
    r"(-p\b|--print\b|exec\b|--prompt\b|-m\b|run\b|--message\b|[\"'])|@anthropic-ai/claude-code|@openai/codex|"
    r"@google/gemini-cli"
)
UNTRUSTED_EXPR_RE = re.compile(
    r"\$\{\{[^}]*\b(github\.event\.(issue\.(title|body)|comment\.body|pull_request\.(title|body|head\.ref|head\.label)|"
    r"review\.body|review_comment\.body|discussion\.(title|body)|head_commit\.(message|author\.(name|email))|"
    r"commits\[[^\]]*\]\.(message|author)|pages\[[^\]]*\]\.page_name|workflow_run\.(head_branch|display_title|"
    r"head_commit\.message))|github\.head_ref)[^}]*\}\}"
)
UNTRUSTED_TRIGGERS = {"issues", "issue_comment", "pull_request_target", "pull_request_review",
                      "pull_request_review_comment", "discussion", "discussion_comment", "workflow_run"}
HIGH_IMPACT_SCOPES = {"contents", "actions", "id-token", "packages", "workflows", "deployments", "security-events"}
ACTOR_GATE_RE = re.compile(r"author_association|github\.actor|github\.triggering_actor|sender\.login|permission|"
                           r"github\.event\.sender|contains\(\s*fromJSON")
SHA_RE = re.compile(r"@[0-9a-f]{40}$")


def is_workflow(rel: str) -> bool:
    lower = rel.lower()
    return "/.github/workflows/" in "/" + lower and lower.endswith((".yml", ".yaml"))


def _triggers(wf: Dict[Any, Any]) -> Set[str]:
    on = wf.get("on", wf.get(True))  # PyYAML parses a bare `on:` key as boolean True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(t) for t in on}
    return set()


def _is_agent_step(step: Dict[str, Any]) -> bool:
    uses = str(step.get("uses", ""))
    return bool((uses and AGENT_ACTION_RE.search(uses.split("@")[0])) or AGENT_RUN_RE.search(str(step.get("run", ""))))


def analyze(ctx: FileContext) -> None:
    wf = load_yaml(ctx.text)
    if not isinstance(wf, dict) or not isinstance(wf.get("jobs"), dict):
        return
    triggers = _triggers(wf)
    untrusted = sorted(triggers & UNTRUSTED_TRIGGERS)
    top_perms = wf.get("permissions")
    agent_workflow = False
    last_seen: Dict[str, int] = {}

    for job_id, job in wf["jobs"].items():
        if not isinstance(job, dict):
            continue
        job_line = find_line(ctx.lines, rf"^\s+{re.escape(str(job_id))}\s*:", 1, 1)
        steps = [s for s in job.get("steps") or [] if isinstance(s, dict)]
        agent_steps = [s for s in steps if _is_agent_step(s)]
        reusable = str(job.get("uses", ""))
        uses_refs = [(str(s.get("uses")), s) for s in steps if s.get("uses")] + ([(reusable, job)] if reusable else [])

        if agent_steps:
            agent_workflow = True
            perms = job.get("permissions", top_perms)
            if perms is None:
                ctx.report("ATS-ASI03-03", job_line, f"AI agent job '{job_id}' has no explicit permissions; GITHUB_TOKEN "
                           "may default to write access.")
            elif perms == "write-all":
                ctx.report("ATS-ASI03-03", job_line, f"AI agent job '{job_id}' runs with permissions: write-all.",
                           severity=Severity.HIGH)
            elif isinstance(perms, dict) and untrusted:
                writes = sorted(k for k, v in perms.items() if v == "write" and k in HIGH_IMPACT_SCOPES)
                if writes:
                    only_oidc = writes == ["id-token"]
                    ctx.report("ATS-ASI03-03", job_line, f"AI agent job '{job_id}' triggered by {', '.join(untrusted)} "
                               f"has write access to: {', '.join(writes)}" +
                               (" (lets the job mint OIDC tokens; keep cloud trust policies narrow)." if only_oidc else "."),
                               severity=Severity.MEDIUM if only_oidc else Severity.HIGH)
            if "pull_request_target" in triggers:
                for s in steps:
                    ref = str((s.get("with") or {}).get("ref", "")) if isinstance(s.get("with"), dict) else ""
                    if str(s.get("uses", "")).startswith("actions/checkout") and re.search(
                            r"pull_request\.head|head_ref|refs/pull", ref):
                        ctx.report("ATS-ASI03-03", find_line(ctx.lines, re.escape(ref), 1, job_line),
                                   "pull_request_target checks out untrusted PR code in an AI agent job that holds "
                                   "repository secrets.", severity=Severity.CRITICAL)
            if untrusted:
                gated = ACTOR_GATE_RE.search(str(job.get("if", ""))) or any(
                    ACTOR_GATE_RE.search(str(s.get("if", ""))) for s in agent_steps)
                for s in agent_steps:
                    uses = str(s.get("uses", ""))
                    inputs = s.get("with") if isinstance(s.get("with"), dict) else {}
                    if uses.startswith("anthropics/claude-code"):
                        if str(inputs.get("allowed_non_write_users", "")).strip() == "*":
                            ctx.report("ATS-ASI01-07", find_line(ctx.lines, "allowed_non_write_users", 1, job_line),
                                       "allowed_non_write_users: '*' lets anyone trigger Claude.",
                                       severity=Severity.MEDIUM)
                        gated = True
                if not gated:
                    ctx.report("ATS-ASI01-07", job_line, f"AI agent job '{job_id}' runs on {', '.join(untrusted)} with "
                               "no author/permission check.")
            for s in agent_steps:
                inputs = s.get("with") if isinstance(s.get("with"), dict) else {}
                for key in ("allowed_tools", "allowedTools"):  # flags inside claude_args are caught by the text check
                    value = str(inputs.get(key, ""))
                    if re.search(r"Bash\(\*\)|(^|[,\s\"'\[])Bash($|[,\s\"'\]])", value):
                        ctx.report("ATS-ASI09-02", find_line(ctx.lines, rf"\b{key}\b", 1, job_line),
                                   f"Agent step allows unrestricted Bash via '{key}'.")

        for uses, _node in uses_refs:
            if uses.startswith("./") or not uses:
                continue
            line = find_line(ctx.lines, re.escape(uses), last_seen.get(uses, 0) + 1, None) or \
                find_line(ctx.lines, re.escape(uses), 1, 1)
            last_seen[uses] = line
            if uses.startswith("docker://"):
                if "@sha256:" not in uses:
                    ctx.report("ATS-ASI04-04", line, f"Docker action '{uses}' is not pinned to a digest.",
                               severity=Severity.MEDIUM if agent_steps else None)
                continue
            owner = uses.split("/", 1)[0].lower()
            if owner in ("actions", "github") or SHA_RE.search(uses):
                continue
            ctx.report("ATS-ASI04-04", line, f"Action '{uses}' is pinned to a mutable ref, not a commit SHA.",
                       severity=Severity.MEDIUM if agent_steps else None)

    if agent_workflow:
        for i, text in enumerate(ctx.lines, start=1):
            m = UNTRUSTED_EXPR_RE.search(text)
            if m:
                ctx.report("ATS-ASI01-06", i, f"Untrusted event text {m.group(1)} is interpolated into an AI agent "
                           "workflow" + (f" triggered by {', '.join(untrusted)}." if untrusted else "."),
                           severity=Severity.CRITICAL if untrusted else Severity.HIGH)
