"""Line-based checks for JavaScript/TypeScript agent code (no JS parser is bundled, so these are heuristics)."""
from __future__ import annotations

import re

from .. import textutil
from ..models import FileContext, Severity

AGENT_IMPORT_RE = re.compile(
    r"""(from\s+|require\(\s*|import\s*\(\s*)['"](langchain|@langchain/[\w-]+|openai|@openai/agents|@anthropic-ai/[\w-]+|"""
    r"""@modelcontextprotocol/[\w-]+|ai|@ai-sdk/[\w-]+|llamaindex|@llamaindex/[\w-]+|@google/genai|"""
    r"""@google/generative-ai|@mastra/[\w-]+|ollama|@mistralai/[\w-]+|groq-sdk|cohere-ai|@a2a-js/[\w-]+|"""
    r"""@langchain/langgraph)(/[\w./-]*)?['"]"""
)
TOOL_DEF_RE = re.compile(r"(server\.tool\s*\(|\.registerTool\s*\(|\btool\s*\(\s*\{|new\s+DynamicTool|"
                         r"new\s+DynamicStructuredTool|createTool\s*\(|\bfunction_tool\b|\btools\s*:\s*\{)")
EVAL_RE = re.compile(r"(?<![\w.$])eval\s*\(|new\s+Function\s*\(|\bvm\.(runInNewContext|runInThisContext|runInContext|"
                     r"compileFunction)\s*\(|new\s+vm\.Script\s*\(")
EXEC_RE = re.compile(r"\b(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(")
SHELL_EXEC_RE = re.compile(r"\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+|[A-Za-z_$][\w$.]*\s*[,)])")
SPAWN_SHELL_RE = re.compile(r"\bshell\s*:\s*true\b")
LLM_CALL_RE = re.compile(r"(completions\.create|messages\.create|responses\.create|generateText|streamText|"
                         r"generateObject|\.invoke\s*\(|\.stream\s*\(|\.chat\s*\(|run\(\s*agent)")
LLM_OUTPUT_EXEC_RE = re.compile(r"\b(eval|exec|execSync|Function)\s*\([^)]*(\.content|\.text\b|output_text|completion|"
                                r"response\.|result\.text|message\.content|choices\[)")
SYSTEM_USER_INPUT_RE = re.compile(r"""(role\s*:\s*['"](system|developer)['"]\s*,\s*content\s*:|\bsystem\s*:|"""
                                  r"""\binstructions\s*:)\s*`[^`]*\$\{[^}]*\b(req|request|ctx\.request|event)\."""
                                  r"""(body|query|params|headers)""")
LOOP_LIMIT_RE = re.compile(r"\b(maxIterations|maxSteps|maxTurns|recursionLimit|maxRounds)\s*:\s*(Infinity|null|"
                           r"Number\.MAX_SAFE_INTEGER|\d+)")
LIMITS = {"maxIterations": 50, "maxSteps": 100, "maxTurns": 50, "recursionLimit": 200, "maxRounds": 100}
WHILE_TRUE_RE = re.compile(r"\bwhile\s*\(\s*(true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)")
TLS_RE = re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0")
BROWSER_KEY_RE = re.compile(r"dangerouslyAllowBrowser\s*:\s*true")
HTTP_URL_RE = re.compile(r"""(baseURL|baseUrl|url|serverUrl|endpoint)\s*[:=]\s*['"`](http://[^'"`\s]+)""")
NEW_URL_RE = re.compile(r"""new\s+(SSEClientTransport|StreamableHTTPClientTransport|A2AClient|WebSocket)\s*\(\s*"""
                        r"""(new\s+URL\(\s*)?['"`](http://|ws://)([^'"`\s]+)""")
LISTEN_ALL_RE = re.compile(r"""\.listen\s*\([^)]*['"](0\.0\.0\.0|::)['"]""")
PERSIST_RE = re.compile(r"(crontab|systemctl\s+enable|launchctl\s+load|schtasks|nohup|\.bashrc|\.zshrc|"
                        r"LaunchAgents|authorized_keys)")
INSTALL_RE = re.compile(r"\b(npm|pnpm|yarn|pip3?|bun)\s+(install|add|i)\b")
DELETE_TOOL_RE = re.compile(r"""(server\.tool|registerTool|tool)\s*\(\s*['"`]?(send|delete|remove|drop|transfer|pay|"""
                            r"""refund|deploy|merge|purchase|wire|post|publish)[\w-]*""", re.I)
APPROVAL_RE = re.compile(r"(?i)(needsApproval|requireApproval|requiresApproval|confirm|approval|humanInTheLoop|"
                         r"interrupt\(|elicit)")


def analyze(ctx: FileContext) -> None:
    text = ctx.text
    is_agent = bool(AGENT_IMPORT_RE.search(text))
    if is_agent:
        ctx.project.is_agent_project = True
    defines_tools = bool(TOOL_DEF_RE.search(text))
    has_llm = bool(LLM_CALL_RE.search(text))
    has_approval = bool(APPROVAL_RE.search(text))

    for i, line in enumerate(ctx.lines, start=1):
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")) or len(line) > 1000:
            continue
        if LLM_OUTPUT_EXEC_RE.search(line) and has_llm:
            ctx.report("ATS-ASI05-02", i, "Model output appears to be passed to code/command execution.")
        elif EVAL_RE.search(line):
            ctx.report("ATS-ASI05-01", i, "Dynamic code evaluation (eval / new Function / vm).")
        if EXEC_RE.search(line) and ("child_process" in text or "execa" in text or "Bun.spawn" in text):
            if defines_tools:
                ctx.report("ATS-ASI02-01", i, "Agent tool module runs OS commands.",
                           severity=Severity.CRITICAL if SHELL_EXEC_RE.search(line) else Severity.HIGH)
            elif SHELL_EXEC_RE.search(line) or SPAWN_SHELL_RE.search(line):
                ctx.report("ATS-ASI05-03", i, "child_process exec with string interpolation or shell:true.")
            if PERSIST_RE.search(line) and (defines_tools or is_agent):
                ctx.report("ATS-ASI10-02", i, f"Agent code invokes a persistence mechanism ({PERSIST_RE.search(line).group(0)}).")
            if INSTALL_RE.search(line) and defines_tools:
                ctx.report("ATS-ASI10-03", i, "Agent tool installs packages at runtime.")
        if SYSTEM_USER_INPUT_RE.search(line):
            ctx.report("ATS-ASI01-02", i, "Request data is interpolated into the system prompt.")
        m = LOOP_LIMIT_RE.search(line)
        if m:
            key, value = m.group(1), m.group(2)
            if not value.isdigit() or int(value) > LIMITS[key]:
                ctx.report("ATS-ASI08-01", i, f"{key}: {value} effectively removes the agent's step limit.")
        if WHILE_TRUE_RE.search(line) and has_llm and is_agent:
            window = "\n".join(ctx.lines[i: i + 40])
            if LLM_CALL_RE.search(window) and not re.search(r"\b(break|return|throw)\b", window):
                ctx.report("ATS-ASI08-01", i, "Infinite loop around LLM calls without a visible exit.")
        if TLS_RE.search(line):
            ctx.report("ATS-ASI02-06", i, "TLS certificate verification disabled.")
        if BROWSER_KEY_RE.search(line):
            ctx.report("ATS-ASI03-04", i, "dangerouslyAllowBrowser: true ships the provider API key to browsers.")
        for um in list(HTTP_URL_RE.finditer(line)) + list(NEW_URL_RE.finditer(line)):
            url = um.group(2) if um.re is HTTP_URL_RE else um.group(3) + um.group(4)
            if url.split("://", 1)[-1].startswith("${"):
                continue  # host comes from the page (e.g. window.location.host)
            if (is_agent or um.re is NEW_URL_RE) and (url.startswith("ws://") or textutil.is_remote_plain_http(url)):
                if not url.startswith("ws://") or not textutil.is_local_url("http://" + url[5:]):
                    ctx.report("ATS-ASI07-01", i, f"Agent/MCP connection over plaintext ({url}).")
        if LISTEN_ALL_RE.search(line) and is_agent:
            ctx.report("ATS-ASI07-04", i, "Agent service listens on all interfaces.")
        dm = DELETE_TOOL_RE.search(line)
        if dm and not has_approval:
            ctx.report("ATS-ASI09-01", i, "High-impact tool is registered with no approval step in this module.")
