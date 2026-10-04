"""MCP server configs and coding-agent settings (Claude Code, VS Code/Copilot, Cursor, Cline, Gemini CLI, Codex)."""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from .. import textutil
from ..configfiles import key_line, load_structured
from ..models import FileContext, Severity

MCP_FILE_NAMES = {"mcp.json", ".mcp.json", "mcp_config.json", "claude_desktop_config.json", "cline_mcp_settings.json",
                  "mcp_settings.json", "mcp-servers.json", "mcp_servers.json"}
SECRET_KEY_RE = re.compile(r"(?i)(key|token|secret|password|passwd|auth|credential|\bpat\b|cookie)")
NOT_LITERAL_RE = re.compile(r"(?i)(\$\{|\$[A-Z_]|<|>|your|xxx|placeholder|example|\{\{|env:|input:|changeme|redacted|"
                            r"^\*+$|^Bearer\s*$)")
DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "-w", "--workdir", "--network",
                      "--net", "--mount", "--env-file", "-u", "--user", "--entrypoint", "--platform", "--memory", "-m",
                      "--cpus", "--label", "-l", "--add-host", "--cap-add", "--cap-drop", "--pid", "--ipc",
                      "--security-opt", "--device", "--hostname", "-h", "--restart", "--ulimit", "--tmpfs", "--gpus"}
HIGH_IMPACT_TOOL_RE = re.compile(r"(?i)(\*|write|delete|remove|exec|run|shell|command|push|merge|create|update|send|"
                                 r"post|deploy|transfer|pay|edit|move|kill|drop)")
BROAD_BASH = {"Bash", "Bash(*)", "Bash(:*)", "Bash(*:*)", "*", "Bash(**)"}
RISKY_BASH_RE = re.compile(r"^Bash\((curl|wget|rm|sudo|python3?|node|sh|bash|zsh|npx|pip3?|npm|docker|ssh|scp|"
                           r"git push|chmod|chown|eval|nc|kubectl|terraform)[\s:]")


def is_mcp_file(rel: str, text: str) -> bool:
    lower = rel.lower()
    name = lower.rsplit("/", 1)[-1]
    if name in MCP_FILE_NAMES or lower.endswith((".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json",
                                                 ".windsurf/mcp_config.json", ".amazonq/mcp.json")):
        return True
    return name.endswith((".json", ".jsonc")) and '"mcpServers"' in text


def is_agent_settings(rel: str) -> bool:
    lower = rel.lower()
    return bool(re.search(r"(^|/)\.claude/settings(\.local)?\.json$|(^|/)managed-settings\.json$|"
                          r"(^|/)\.vscode/settings\.json$|(^|/)\.codex/config\.toml$", lower))


def _first_package(args: List[str]) -> Optional[str]:
    it = iter(args)
    for tok in it:
        if tok in ("-p", "--package", "--from", "--with"):
            return next(it, None)
        if tok.startswith("-"):
            continue
        return tok
    return None


def _npm_pinned(pkg: str) -> bool:
    body = pkg[1:] if pkg.startswith("@") else pkg
    if "@" not in body:
        return False
    version = body.split("@", 1)[1]
    return bool(re.fullmatch(r"v?\d+\.\d+\.\d+([-+][\w.]+)?", version))


def _py_pinned(pkg: str) -> bool:
    return bool(re.search(r"(==|@)v?\d+(\.\d+)+", pkg))


def _docker_image(args: List[str]) -> Optional[str]:
    if "run" not in args:
        return None
    rest = args[args.index("run") + 1:]
    skip = False
    for tok in rest:
        if skip:
            skip = False
            continue
        if tok.startswith("-"):
            if tok in DOCKER_VALUE_FLAGS:
                skip = True
            continue
        return tok
    return None


def check_server(ctx: FileContext, name: str, cfg: Dict[str, Any], start: int) -> None:
    line = key_line(ctx.lines, name, start, start)
    command = str(cfg.get("command") or "")
    args = [str(a) for a in (cfg.get("args") or []) if isinstance(a, (str, int, float))]
    if command and " " in command and not args:
        parts = command.split()
        command, args = parts[0], parts[1:]
    exe = os.path.basename(command).lower()
    full = " ".join([command] + args)

    pkg = None
    if exe in ("npx", "bunx", "pnpx") or (exe in ("pnpm", "yarn", "npm") and args[:1] in (["dlx"], ["exec"])):
        pkg = _first_package(args[1:] if exe in ("pnpm", "yarn", "npm") else args)
        if pkg and not _npm_pinned(pkg) and not pkg.startswith((".", "/")):
            ctx.report("ATS-ASI04-01", line, f"MCP server '{name}' runs '{pkg}' via {exe} without a pinned version; "
                       "every launch executes the newest release.")
    elif exe in ("uvx", "pipx", "uv"):
        if exe == "uvx":
            pargs = args
        elif exe == "pipx":
            pargs = args[1:] if args[:1] == ["run"] else []
        else:
            pargs = args[2:] if args[:2] == ["tool", "run"] else []
        pkg = _first_package(pargs)
        if pkg and not _py_pinned(pkg) and not pkg.startswith((".", "/")):
            ctx.report("ATS-ASI04-01", line, f"MCP server '{name}' runs '{pkg}' via {exe} without a pinned version.")
    if exe in ("docker", "podman"):
        image = _docker_image(args)
        if image and "@sha256:" not in image:
            tag = image.rsplit("/", 1)[-1]
            if ":" not in tag or tag.endswith(":latest"):
                ctx.report("ATS-ASI04-01", line, f"MCP server '{name}' runs image '{image}' without a version tag or "
                           "digest.", severity=Severity.LOW if ":" in tag else None)
        reasons = []
        if "--privileged" in args:
            reasons.append("--privileged")
        if "docker.sock" in full:
            reasons.append("Docker socket mount")
        if re.search(r"(^|\s|=)/:/", full):
            reasons.append("host root mount")
        if re.search(r"--(network|net)[=\s]host\b", full):
            reasons.append("host network")
        if re.search(r"--pid[=\s]host\b", full):
            reasons.append("host PID namespace")
        if re.search(r"--cap-add[=\s](ALL|SYS_ADMIN)\b", full):
            reasons.append("dangerous capabilities")
        if reasons:
            ctx.report("ATS-ASI03-06", line, f"MCP server '{name}' container gets host access: {', '.join(reasons)}.")
    if re.search(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", full):
        ctx.report("ATS-ASI04-02", line, f"MCP server '{name}' is launched by piping a download into a shell.")

    for key in ("url", "serverUrl", "httpUrl"):
        url = cfg.get(key)
        if isinstance(url, str) and textutil.is_remote_plain_http(url):
            ctx.report("ATS-ASI07-01", key_line(ctx.lines, key, line, line),
                       f"MCP server '{name}' is reached over plaintext HTTP ({url}).")

    for section in ("env", "headers"):
        values = cfg.get(section)
        if not isinstance(values, dict):
            continue
        for k, v in values.items():
            if isinstance(v, str) and len(v) >= 8 and SECRET_KEY_RE.search(str(k)) and not NOT_LITERAL_RE.search(v):
                ctx.report("ATS-ASI03-01", key_line(ctx.lines, k, line, line),
                           f"MCP server '{name}' has a hardcoded {section} credential '{k}'.")

    for key in ("alwaysAllow", "autoApprove", "auto_approve", "autoApprovedTools"):
        allowed = cfg.get(key)
        if allowed is True or (isinstance(allowed, list) and allowed):
            listed = allowed if isinstance(allowed, list) else ["*"]
            risky = [str(t) for t in listed if HIGH_IMPACT_TOOL_RE.search(str(t))]
            ctx.report("ATS-ASI09-02", key_line(ctx.lines, key, line, line),
                       f"MCP server '{name}' auto-approves tools without confirmation: "
                       f"{', '.join(map(str, listed[:6]))}{' …' if len(listed) > 6 else ''}.",
                       severity=Severity.HIGH if risky else Severity.MEDIUM)
    if cfg.get("trust") is True:
        ctx.report("ATS-ASI09-02", key_line(ctx.lines, "trust", line, line),
                   f"MCP server '{name}' has trust: true, which skips every tool-call confirmation.")


def _servers(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    servers: Dict[str, Any] = {}
    for key in ("mcpServers", "servers", "mcp_servers"):
        block = data.get(key)
        if isinstance(block, dict):
            servers.update({k: v for k, v in block.items() if isinstance(v, dict)})
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        servers.update({k: v for k, v in mcp["servers"].items() if isinstance(v, dict)})
    return {k: v for k, v in servers.items() if any(f in v for f in ("command", "url", "serverUrl", "httpUrl", "args"))}


def analyze_mcp(ctx: FileContext) -> None:
    data = load_structured(ctx.text, ctx.path.suffix or ".json")
    for name, cfg in _servers(data).items():
        check_server(ctx, name, cfg, 1)


def analyze_settings(ctx: FileContext) -> None:
    lower = ctx.rel.lower()
    data = load_structured(ctx.text, ctx.path.suffix)
    if not isinstance(data, dict):
        return
    for name, cfg in _servers(data).items():
        check_server(ctx, name, cfg, 1)
    if lower.endswith(".toml"):  # Codex CLI
        if str(data.get("approval_policy", "")).lower() == "never":
            ctx.report("ATS-ASI09-02", key_line(ctx.lines, "approval_policy"), "Codex approval_policy = \"never\" runs "
                       "every command without asking.")
        if str(data.get("sandbox_mode", "")).lower() == "danger-full-access":
            ctx.report("ATS-ASI09-02", key_line(ctx.lines, "sandbox_mode"), "Codex sandbox_mode = \"danger-full-access\""
                       " disables the sandbox.")
        return
    if ".vscode/" in lower:
        for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove"):
            if data.get(key) is True:
                ctx.report("ATS-ASI09-02", key_line(ctx.lines, key), f"{key}: true lets Copilot agent mode run every "
                           "tool (including terminal commands) without confirmation.")
        term = data.get("chat.tools.terminal.autoApprove")
        if isinstance(term, dict) and any(v is True and str(k) in ("/.*/", "/.+/", "*") for k, v in term.items()):
            ctx.report("ATS-ASI09-02", key_line(ctx.lines, "chat.tools.terminal.autoApprove"),
                       "Terminal auto-approve matches every command.")
        return
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    if perms.get("defaultMode") == "bypassPermissions":
        ctx.report("ATS-ASI09-02", key_line(ctx.lines, "defaultMode"), "Claude Code defaultMode is bypassPermissions; "
                   "every tool call runs without approval.")
    for entry in perms.get("allow") or []:
        entry_s = str(entry)
        line = key_line(ctx.lines, "allow")
        for i, text in enumerate(ctx.lines, start=1):
            if f'"{entry_s}"' in text:
                line = i
                break
        if entry_s in BROAD_BASH:
            ctx.report("ATS-ASI09-02", line, f"Permission rule '{entry_s}' pre-approves every shell command.")
        elif RISKY_BASH_RE.match(entry_s):
            ctx.report("ATS-ASI09-02", line, f"Permission rule '{entry_s}' pre-approves a command that can download, "
                       "execute or delete arbitrary content.", severity=Severity.MEDIUM)
    if data.get("enableAllProjectMcpServers") is True:
        ctx.report("ATS-ASI04-07", key_line(ctx.lines, "enableAllProjectMcpServers"),
                   "enableAllProjectMcpServers: true starts any MCP server added to .mcp.json without review.")
