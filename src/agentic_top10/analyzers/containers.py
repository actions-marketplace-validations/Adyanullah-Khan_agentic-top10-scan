"""Container definitions for agent runtimes: docker-compose, devcontainer.json and Dockerfiles."""
from __future__ import annotations

import re

from ..configfiles import as_list, key_line, load_jsonc, load_yaml
from ..models import FileContext, Severity


def is_compose(rel: str) -> bool:
    name = rel.lower().rsplit("/", 1)[-1]
    return bool(re.fullmatch(r"(docker-)?compose(\.[\w-]+)?\.ya?ml", name))


def is_devcontainer(rel: str) -> bool:
    return rel.lower().endswith("devcontainer.json")


def is_dockerfile(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def _host_access(entry: dict) -> list:
    reasons = []
    if entry.get("privileged") is True:
        reasons.append("privileged: true")
    for vol in as_list(entry.get("volumes")) + as_list(entry.get("mounts")):
        text = str(vol.get("source", "")) + ":" if isinstance(vol, dict) else str(vol)
        if "docker.sock" in text:
            reasons.append("Docker socket mount")
        elif re.match(r"^(source=)?/:", text) or text.startswith("/:"):
            reasons.append("host root mount")
    if str(entry.get("network_mode", "")) == "host":
        reasons.append("network_mode: host")
    if str(entry.get("pid", "")) == "host":
        reasons.append("pid: host")
    caps = [str(c).upper() for c in as_list(entry.get("cap_add"))]
    if "ALL" in caps or "SYS_ADMIN" in caps:
        reasons.append(f"cap_add: {', '.join(caps)}")
    return reasons


def analyze_compose(ctx: FileContext) -> None:
    if not ctx.project.is_agent_project:
        return
    data = load_yaml(ctx.text)
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return
    for name, svc in services.items():
        if isinstance(svc, dict):
            reasons = _host_access(svc)
            if reasons:
                ctx.report("ATS-ASI03-06", key_line(ctx.lines, name), f"Service '{name}' gets host access: "
                           f"{', '.join(reasons)}.")


def analyze_devcontainer(ctx: FileContext) -> None:
    try:
        data = load_jsonc(ctx.text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    reasons = _host_access(data)
    run_args = " ".join(str(a) for a in as_list(data.get("runArgs")))
    if "--privileged" in run_args:
        reasons.append("--privileged")
    if "docker.sock" in run_args:
        reasons.append("Docker socket mount")
    if reasons:
        ctx.report("ATS-ASI03-06", key_line(ctx.lines, "runArgs" if "runArgs" in data else "name"),
                   f"Dev container (where coding agents run) gets host access: {', '.join(reasons)}.")


def analyze_dockerfile(ctx: FileContext) -> None:
    if not ctx.project.is_agent_project:
        return
    users = [(i, line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else "")
             for i, line in enumerate(ctx.lines, start=1) if line.strip().upper().startswith("USER ")]
    if not any(ctx.lines) or not any(line.strip().upper().startswith("FROM ") for line in ctx.lines):
        return
    if not users or users[-1][1].split(":")[0] in ("root", "0"):
        line = users[-1][0] if users else 1
        ctx.report("ATS-ASI03-06", line, "Agent container runs as root; code it executes has root inside the "
                   "container.", severity=Severity.LOW)
