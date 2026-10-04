"""The ten OWASP Top 10 for Agentic Applications (2026) categories and what static analysis can and cannot see."""
from __future__ import annotations

from collections import OrderedDict

CATEGORIES = OrderedDict(
    [
        (
            "ASI01",
            {
                "name": "Agent Goal Hijack",
                "checks": "Untrusted web/document/tool content flowing into prompts (taint tracking), user input in "
                "system prompts, prompt-injection phrases and invisible Unicode in prompts, instruction files and "
                "tool descriptions, exfiltration channels, untrusted GitHub event text fed to CI agents.",
                "blind_spots": "Whether the model actually resists an injection at runtime. Red-team the running "
                "agent (e.g. garak, promptfoo, PyRIT) and add runtime input/output guardrails.",
            },
        ),
        (
            "ASI02",
            {
                "name": "Tool Misuse and Exploitation",
                "checks": "Agent tools that run shell commands, write/delete files, fetch model-chosen URLs or build "
                "SQL from model input; dangerous built-in toolkits; wildcard tool permissions; disabled TLS.",
                "blind_spots": "How tools are chained at runtime and whether runtime argument validation holds up.",
            },
        ),
        (
            "ASI03",
            {
                "name": "Identity and Privilege Abuse",
                "checks": "Hardcoded credentials, secrets placed into prompts, over-scoped CI tokens for agents, LLM "
                "keys exposed to browsers, unauthenticated endpoints, privileged containers, unrestricted delegation.",
                "blind_spots": "Real IAM policies, cloud role scopes and token lifetimes, and runtime confused-deputy "
                "behaviour.",
            },
        ),
        (
            "ASI04",
            {
                "name": "Agentic Supply Chain Vulnerabilities",
                "checks": "Unpinned MCP servers, actions and agent dependencies, remote code/model loading, dynamic "
                "imports, auto-trusted project MCP servers, known-vulnerable packages (opt-in OSV lookup).",
                "blind_spots": "Publisher integrity, malicious packages that look clean, and tool descriptions that "
                "change after install (MCP rug pulls). Use signed/pinned artifacts and an allowlist.",
            },
        ),
        (
            "ASI05",
            {
                "name": "Unexpected Code Execution (RCE)",
                "checks": "eval/exec, LLM output reaching exec/shell/SQL, shell=True, unsandboxed code executors "
                "(AutoGen, CrewAI, smolagents, LangChain, Open Interpreter), unsafe deserialization.",
                "blind_spots": "How strong your sandbox really is (container escape, network egress).",
            },
        ),
        (
            "ASI06",
            {
                "name": "Memory and Context Poisoning",
                "checks": "Untrusted content written to long-term memory or vector stores without validation, memory "
                "objects shared across users, retrieval without tenant filters, declared memory policy.",
                "blind_spots": "Content already sitting in your vector DB and poisoning of external knowledge bases.",
            },
        ),
        (
            "ASI07",
            {
                "name": "Insecure Inter-Agent Communication",
                "checks": "Plaintext HTTP for agent/MCP/A2A links, A2A agent cards without security schemes, "
                "unauthenticated agent endpoints, agent services bound to all interfaces, declared channel auth.",
                "blind_spots": "Runtime message integrity, replay protection and protocol downgrade.",
            },
        ),
        (
            "ASI08",
            {
                "name": "Cascading Failures",
                "checks": "Missing iteration/turn limits, infinite loops around LLM calls, network calls without "
                "timeouts, unbounded retries, silently swallowed tool errors, declared limits.",
                "blind_spots": "Real fan-out and blast radius, rate limiting and circuit breakers in infrastructure.",
            },
        ),
        (
            "ASI09",
            {
                "name": "Human-Agent Trust Exploitation",
                "checks": "High-impact tools without human approval, approval-bypass settings and CLI flags, prompts "
                "telling the agent to deceive users or never ask for confirmation.",
                "blind_spots": "UI design that over-trusts agent output and user over-reliance.",
            },
        ),
        (
            "ASI10",
            {
                "name": "Rogue Agents",
                "checks": "Agents that can rewrite their own code, prompts or permissions, persistence mechanisms, "
                "runtime package installs, tools with no audit logging or tracing, declared kill switch.",
                "blind_spots": "Behavioural drift, collusion and goal misalignment. These need runtime monitoring.",
            },
        ),
    ]
)


def category_label(cat_id: str) -> str:
    meta = CATEGORIES.get(cat_id)
    return f"{cat_id} {meta['name']}" if meta else cat_id
