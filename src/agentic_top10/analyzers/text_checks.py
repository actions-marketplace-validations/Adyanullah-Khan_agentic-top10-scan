"""Checks that work on raw text: secrets, hidden Unicode, prompt files, agent CLI flags, env files."""
from __future__ import annotations

import re

from .. import textutil
from ..models import FileContext, Severity

DOC_SUFFIXES = {".md", ".markdown", ".rst", ".txt", ".adoc"}

# Agent CLI flags that switch off human approval. Generic flags need an agent CLI name on the same line.
_AGENT_CLI = r"(claude|codex|gemini|aider|goose|opencode|cline|cursor-agent|amp|copilot|openhands|interpreter|qwen)"
APPROVAL_BYPASS_FLAGS = [
    (re.compile(r"--dangerously-skip-permissions\b"), Severity.HIGH, "--dangerously-skip-permissions"),
    (re.compile(r"--dangerously-bypass-approvals-and-sandbox\b"), Severity.CRITICAL,
     "--dangerously-bypass-approvals-and-sandbox"),
    (re.compile(r"--permission-mode[\s=]+[\"']?bypassPermissions"), Severity.HIGH, "--permission-mode bypassPermissions"),
    (re.compile(r"--(?:ask-for-approval|approval-mode|approval-policy)[\s=]+[\"']?(?:never|yolo)\b"), Severity.HIGH,
     "approval policy 'never'"),
    (re.compile(r"--sandbox[\s=]+[\"']?danger-full-access\b"), Severity.HIGH, "--sandbox danger-full-access"),
    (re.compile(r"(?i)\b" + _AGENT_CLI + r"\b[^\n]*\s--yolo\b"), Severity.HIGH, "--yolo"),
    (re.compile(r"(?i)\b" + _AGENT_CLI + r"\b[^\n]*\s--(?:auto-approve|yes-always|auto_run)\b"), Severity.MEDIUM,
     "auto-approve flag"),
    (re.compile(r"(?i)\binterpreter\b[^\n]*\s(?:-y|--auto_run)\b"), Severity.HIGH, "interpreter -y (auto run)"),
    (re.compile(r"--allowed-?[Tt]ools[\s=]+[\"']?[^\"'\n]*(?:Bash\(\*\)|\bBash\b(?!\())"), Severity.HIGH,
     "unrestricted Bash tool allowed"),
]

PUBLIC_KEY_RE = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|GATSBY)_[A-Z0-9_]*(?:OPENAI|ANTHROPIC|CLAUDE|"
    r"GEMINI|GOOGLE_AI|GROQ|MISTRAL|COHERE|XAI|DEEPSEEK|PERPLEXITY|TOGETHER|FIREWORKS|OPENROUTER|LLM|AI)[A-Z0-9_]*"
    r"(?:KEY|TOKEN|SECRET)\b"
)

INSTRUCTION_NAMES = {
    "agents.md", "claude.md", "gemini.md", "copilot-instructions.md", ".cursorrules", ".windsurfrules",
    ".clinerules", "conventions.md", ".goosehints", "skill.md", "agent.md",
}
PROMPT_SUFFIXES = (".prompt", ".prompt.md", ".prompty", ".mdc", ".prompt.yml", ".prompt.yaml", ".instructions.md",
                   ".chatmode.md", ".agent.md")
_PROMPT_EXTS = {".md", ".txt", ".j2", ".jinja", ".jinja2", ".tmpl", ".hbs", ".mustache", ".prompt", ".mdc", ""}


def is_prompt_file(rel: str) -> bool:
    lower = rel.lower()
    name = lower.rsplit("/", 1)[-1]
    if name in INSTRUCTION_NAMES or lower.endswith(PROMPT_SUFFIXES):
        return True
    if re.search(r"(system[_-]?prompt|instructions?)\.(md|txt|j2|jinja2?)$", name):
        return True
    parts = lower.split("/")[:-1]
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    if ext not in _PROMPT_EXTS:
        return False
    if any(p in ("prompts", "prompt", "system_prompts", "system-prompts") for p in parts):
        return True
    joined = "/".join(parts)
    agent_dirs = (".cursor/rules", ".github/instructions", ".github/prompts", ".github/chatmodes", ".claude/commands",
                  ".claude/agents", ".claude/skills", ".windsurf/rules", ".clinerules", ".roo/rules", ".kiro/steering",
                  ".continue/prompts", ".gemini/commands")
    return any(joined.endswith(d) or (d + "/") in (joined + "/") for d in agent_dirs)


def check_prompt_text(ctx: FileContext, text: str, start_line: int, context: str) -> None:
    """Run phrase detectors on text the model will read. context: prompt | instruction | tool-description."""

    def line_at(offset: int) -> int:
        return start_line + text.count("\n", 0, offset)

    where = {"prompt": "prompt", "instruction": "agent instruction file", "tool-description": "tool description"}[context]
    for offset, label, match in textutil.iter_pattern_hits(text, textutil.INJECTION_PATTERNS, negatable=True):
        sev = Severity.CRITICAL if context == "tool-description" else None
        ctx.report("ATS-ASI01-03", line_at(offset), f"Prompt-injection text in {where}: {label} ({textutil.truncate(match, 80)!r}).",
                   severity=sev)
    if context == "tool-description":
        for offset, label, match in textutil.iter_pattern_hits(text, textutil.TOOL_POISONING_PATTERNS):
            ctx.report("ATS-ASI01-03", line_at(offset),
                       f"Possible tool poisoning in tool description: {label} ({textutil.truncate(match, 80)!r}). "
                       "The model reads tool descriptions as instructions.", severity=Severity.CRITICAL)
        return
    for offset, label, _match in textutil.iter_pattern_hits(text, textutil.EXFIL_PATTERNS):
        ctx.report("ATS-ASI01-05", line_at(offset), f"Exfiltration channel in {where}: {label}.")
    for offset, label, match in textutil.iter_pattern_hits(text, textutil.DECEPTION_PATTERNS, negatable=True):
        ctx.report("ATS-ASI09-03", line_at(offset), f"The {where} tells the agent to {label} ({textutil.truncate(match, 80)!r}).",
                   severity=Severity.LOW if label == "conceal actions from the user" else None)
    for offset, label, match in textutil.iter_pattern_hits(text, textutil.NO_CONFIRM_PATTERNS):
        # Coding-agent instruction files often (reasonably) say "run the tests without asking"; product prompts matter more.
        ctx.report("ATS-ASI09-04", line_at(offset), f"The {where} tells the agent to {label} ({textutil.truncate(match, 80)!r}).",
                   severity=Severity.LOW if context == "instruction" else None)


def check_secrets(ctx: FileContext) -> None:
    lower = ctx.rel.lower()
    if lower.endswith((".lock", "-lock.json", "lock.yaml", ".sum", ".min.js", ".map", ".svg")):
        return
    for start, _end, kind, _value in textutil.iter_secrets(ctx.text):
        line = ctx.line_of_offset(start)
        ctx.report("ATS-ASI03-01", line, f"Hardcoded credential: {kind}. Rotate it and load it from a secret store.")


SENSITIVE_KINDS = {"prompt", "manifest", "mcp", "agent-settings", "crewai", "a2a", "workflow"}
CODE_KINDS = {"python", "javascript"}


def check_hidden_unicode(ctx: FileContext) -> None:
    if not textutil.HIDDEN_CHAR_RE.search(ctx.text):
        return
    for i, line in enumerate(ctx.lines, start=1):
        desc = textutil.find_hidden_unicode(line, is_first_line=(i == 1))
        if not desc:
            continue
        # Tag characters and bidi overrides are attack tools; a stray zero-width space in docs usually is not.
        attack = any(k in desc for k in ("TAG", "EMBEDDING", "OVERRIDE", "ISOLATE", "smuggling"))
        if attack or ctx.kind in SENSITIVE_KINDS:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM if ctx.kind in CODE_KINDS else Severity.LOW
        ctx.report("ATS-ASI01-04", i, f"Invisible/bidi Unicode characters: {desc}.", severity=severity,
                   evidence=line.encode("unicode_escape").decode("ascii")[:200])


def check_agent_cli_flags(ctx: FileContext) -> None:
    if ctx.path.suffix.lower() in DOC_SUFFIXES:
        return
    for i, line in enumerate(ctx.lines, start=1):
        for pattern, severity, label in APPROVAL_BYPASS_FLAGS:
            if pattern.search(line):
                ctx.report("ATS-ASI09-02", i, f"Agent human-approval bypass: {label}.", severity=severity)
                break


def check_public_llm_keys(ctx: FileContext) -> None:
    if ctx.path.suffix.lower() in DOC_SUFFIXES:
        return
    for i, line in enumerate(ctx.lines, start=1):
        m = PUBLIC_KEY_RE.search(line)
        if m:
            ctx.report("ATS-ASI03-04", i, f"LLM provider key in client-exposed variable {m.group(0)}; it is bundled into "
                       "browser code where anyone can read it.")


def analyze(ctx: FileContext) -> None:
    check_secrets(ctx)
    check_hidden_unicode(ctx)
    check_agent_cli_flags(ctx)
    check_public_llm_keys(ctx)
    if ctx.kind == "prompt":
        context = "instruction" if ctx.name.lower() in INSTRUCTION_NAMES or ctx.name.lower().endswith(".mdc") else "prompt"
        check_prompt_text(ctx, ctx.text, 1, context)
