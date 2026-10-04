"""Rule catalogue. Rule IDs are this tool's own; the ASIxx part names the primary OWASP category."""
from __future__ import annotations

from collections import OrderedDict
from typing import Dict, List

from .models import Rule, Severity

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

_RULES: List[Rule] = [
    # ── ASI01 Agent Goal Hijack ─────────────────────────────────────────────
    Rule("ATS-ASI01-01", "Untrusted content flows into an LLM prompt without delimiting", ("ASI01", "ASI06"), H,
         "Web pages, documents, search results, retrieved chunks or tool output reach a system prompt or chat "
         "message as raw text. Instructions hidden in that content can take over the agent's goal.",
         "Wrap untrusted content in clear delimiters (e.g. <untrusted_document>...</untrusted_document>), tell the "
         "model it is data not instructions, keep it out of the system prompt, and filter it with an injection "
         "classifier before use."),
    Rule("ATS-ASI01-02", "User-controlled input is interpolated into a system prompt", ("ASI01",), H,
         "Request data or model-chosen tool arguments are formatted into the system/developer prompt, giving "
         "users the same authority as the developer.",
         "Keep the system prompt static. Pass user input only as a user-role message."),
    Rule("ATS-ASI01-03", "Prompt-injection or tool-poisoning text in prompts, instructions or tool descriptions",
         ("ASI01",), H,
         "Phrases such as 'ignore previous instructions', chat-template control tokens, or hidden directives "
         "inside tool descriptions (tool poisoning) were found in text the model will read.",
         "Remove the text. Review where it came from; treat third-party prompt files, rules files and MCP tool "
         "descriptions as untrusted code.", "high"),
    Rule("ATS-ASI01-04", "Invisible or bidirectional Unicode characters", ("ASI01", "ASI04"), H,
         "Zero-width, bidi-override or Unicode tag characters can hide instructions from human reviewers while "
         "the model still reads them (ASCII smuggling / Trojan Source).",
         "Delete the characters (the evidence shows their code points and any decoded hidden text). Add a "
         "pre-commit check that rejects them.", "high"),
    Rule("ATS-ASI01-05", "Data-exfiltration channel in a prompt or instruction", ("ASI01",), M,
         "Templated markdown images/links or instructions to send conversation data to a URL let an attacker "
         "who hijacks the agent leak data through rendered output or tool calls.",
         "Do not render model-produced images/links from untrusted domains; strip URLs with dynamic query "
         "strings; allowlist outbound domains."),
    Rule("ATS-ASI01-06", "Untrusted GitHub event text is interpolated into an AI agent workflow", ("ASI01", "ASI03"), C,
         "Issue/PR/comment titles or bodies are inserted with ${{ }} into an AI agent's prompt or a run step, so "
         "anyone who can open an issue can steer an agent that holds repository credentials.",
         "Pass event text through environment variables, never ${{ }} interpolation; restrict who can trigger "
         "the agent; give the job read-only permissions."),
    Rule("ATS-ASI01-07", "AI agent workflow can be triggered by any GitHub user", ("ASI01", "ASI03"), L,
         "The agent runs on issue/comment/PR-target events with no check on the author's association or "
         "permission, so outsiders can feed it instructions.",
         "Add an if: condition on github.event.comment.author_association (OWNER/MEMBER/COLLABORATOR) or check "
         "the actor's permission before running the agent."),
    # ── ASI02 Tool Misuse and Exploitation ──────────────────────────────────
    Rule("ATS-ASI02-01", "Agent tool executes operating-system commands", ("ASI02", "ASI05"), H,
         "A function exposed to the model as a tool runs shell or OS commands. A hijacked or confused agent can "
         "run arbitrary commands with the agent's privileges.",
         "Replace generic command execution with narrow, purpose-built tools; never pass model-chosen strings "
         "to a shell; run tools in a sandbox and require approval for anything destructive."),
    Rule("ATS-ASI02-02", "Agent tool accesses the file system with a model-controlled path", ("ASI02",), H,
         "A tool opens, writes, moves or deletes a path taken from model-chosen arguments without confining it "
         "to an allowed directory (path traversal).",
         "Resolve the path and verify it stays inside an allowed root (Path.resolve().is_relative_to(root)); "
         "make destructive operations require approval."),
    Rule("ATS-ASI02-03", "Agent tool fetches a model-controlled URL (SSRF)", ("ASI02", "ASI01"), M,
         "A tool sends HTTP requests to a URL chosen by the model or a user, which can reach internal services, "
         "cloud metadata endpoints, or exfiltrate data.",
         "Allowlist schemes and hosts, block private/link-local ranges, and do not forward credentials."),
    Rule("ATS-ASI02-04", "SQL built from model or user input", ("ASI02", "ASI05"), H,
         "A query string is assembled from model output, tool arguments or request data, enabling SQL injection "
         "or destructive queries chosen by the model.",
         "Use parameterised queries, a read-only database role, and an allowlist of query shapes."),
    Rule("ATS-ASI02-05", "Dangerous built-in agent tool or toolkit enabled", ("ASI02", "ASI05"), H,
         "Shell, Python REPL, unrestricted HTTP or file-management toolkits give the model general-purpose "
         "capabilities far beyond what most tasks need.",
         "Remove the toolkit or replace it with narrow custom tools; if unavoidable, sandbox it and restrict it "
         "to a root directory / allowlisted hosts."),
    Rule("ATS-ASI02-06", "TLS certificate verification disabled", ("ASI02", "ASI07"), M,
         "Tool or agent traffic accepts any certificate, so a network attacker can read or alter tool results "
         "and inter-agent messages.",
         "Remove verify=False / rejectUnauthorized:false; pin a CA bundle if you use private certificates."),
    Rule("ATS-ASI02-07", "Tool granted wildcard or admin permissions", ("ASI02", "ASI03"), H,
         "A tool in the agent manifest has '*', admin or write-all permissions, violating least privilege.",
         "List the exact scopes the tool needs."),
    # ── ASI03 Identity and Privilege Abuse ─────────────────────────────────
    Rule("ATS-ASI03-01", "Hardcoded credential", ("ASI03", "ASI04"), H,
         "A secret is committed to the repository. Agents that read the repository (or attackers who steal it) "
         "inherit the credential.",
         "Revoke and rotate the secret, then load it from a secret manager or environment variable.", "high"),
    Rule("ATS-ASI03-02", "Secret placed into an LLM prompt or context", ("ASI03", "ASI01"), H,
         "An API key, password or token is inserted into text sent to the model, where prompt injection or "
         "logging can leak it.",
         "Keep credentials in tool code only; the model should never see them."),
    Rule("ATS-ASI03-03", "AI agent workflow runs with broad repository permissions", ("ASI03",), M,
         "An AI agent job has write-all or high-impact write scopes (or no explicit permissions), so a hijacked "
         "agent can push code, change workflows or mint cloud credentials.",
         "Declare minimal permissions per job (contents: read; add pull-requests: write only if needed)."),
    Rule("ATS-ASI03-04", "LLM API key exposed to the browser", ("ASI03",), H,
         "The client is configured to run in the browser or the key is in a public build-time variable, so any "
         "visitor can extract and abuse it.",
         "Call the model from a server route; never ship provider keys to the client."),
    Rule("ATS-ASI03-05", "Agent endpoint or tool declared without authentication", ("ASI03", "ASI07"), H,
         "A remote endpoint the agent calls or exposes is declared with auth: none.",
         "Require OAuth2, mTLS or scoped API keys for every remote endpoint."),
    Rule("ATS-ASI03-06", "Privileged container or host access for the agent runtime", ("ASI03", "ASI05"), H,
         "The agent or one of its MCP servers runs privileged, mounts the Docker socket or host root, or shares "
         "the host network/PID namespace, so code execution becomes host compromise.",
         "Run as a non-root user without --privileged, host mounts or the Docker socket; drop capabilities."),
    Rule("ATS-ASI03-07", "Unrestricted agent delegation", ("ASI03", "ASI02"), L,
         "Agents may delegate work to any other agent, which can launder privileges through a more powerful "
         "agent (confused deputy).",
         "Restrict delegation to named agents and propagate the original caller's permissions."),
    # ── ASI04 Agentic Supply Chain ─────────────────────────────────────────
    Rule("ATS-ASI04-01", "MCP server or agent tool launched from an unpinned package", ("ASI04",), M,
         "npx/uvx/docker launches fetch whatever version is newest at runtime, so a compromised release is "
         "executed automatically with the agent's access.",
         "Pin an exact version (pkg@1.2.3, pkg==1.2.3) or an image digest, and review upgrades."),
    Rule("ATS-ASI04-02", "Remote code, model or prompt loaded at runtime", ("ASI04", "ASI05"), H,
         "trust_remote_code, pickle-based model files, unpinned prompt-hub pulls, curl|sh launches or exec of "
         "downloaded content run code you have not reviewed.",
         "Vendor and pin reviewed artifacts; use safetensors; pin hub pulls to a commit hash."),
    Rule("ATS-ASI04-03", "Agent framework dependency is not pinned", ("ASI04",), L,
         "An LLM/agent framework dependency floats to new versions and no lockfile was found.",
         "Pin exact versions or commit a lockfile, and update deliberately."),
    Rule("ATS-ASI04-04", "GitHub Action not pinned to a commit SHA", ("ASI04",), L,
         "A third-party action is referenced by a mutable tag or branch, which its owner (or an attacker) can "
         "repoint. Severity is raised for workflows that run AI agents.",
         "Pin to a full 40-character commit SHA and let Dependabot update it."),
    Rule("ATS-ASI04-05", "Dependency with a known vulnerability", ("ASI04",), H,
         "OSV reports a published advisory for this exact package version (only checked with --online).",
         "Upgrade to a fixed version."),
    Rule("ATS-ASI04-06", "Module imported from a dynamic name", ("ASI04", "ASI05"), M,
         "importlib/__import__ with a non-literal name lets configuration, users or the model choose which code "
         "is loaded.",
         "Map allowed plugin names to modules explicitly."),
    Rule("ATS-ASI04-07", "Project MCP servers or agent extensions are auto-trusted", ("ASI04", "ASI09"), M,
         "Settings automatically enable every MCP server defined in the repository, so a malicious pull request "
         "can add a server that runs on the next agent session.",
         "Approve MCP servers individually."),
    # ── ASI05 Unexpected Code Execution ────────────────────────────────────
    Rule("ATS-ASI05-01", "Dynamic code evaluation", ("ASI05",), H,
         "eval/exec/compile (or JavaScript eval/new Function/vm) runs a non-literal string.",
         "Remove dynamic evaluation; use ast.literal_eval/JSON parsing or an explicit dispatch table."),
    Rule("ATS-ASI05-02", "LLM output reaches code, command or query execution", ("ASI05", "ASI01"), C,
         "Text produced by a model is executed. Anyone who can influence the model's input (including indirect "
         "prompt injection) gets code execution.",
         "Never execute model output directly. If code execution is the feature, run it in an isolated sandbox "
         "(container/VM with no secrets or network) and require approval.", "high"),
    Rule("ATS-ASI05-03", "Shell command execution", ("ASI05",), H,
         "shell=True, os.system, os.popen or child_process.exec with string interpolation enables command "
         "injection.",
         "Pass an argument list without a shell, validate inputs, or use a library API instead."),
    Rule("ATS-ASI05-04", "Agent code execution is not sandboxed", ("ASI05",), H,
         "The agent framework is configured to run model-written code directly on the host (AutoGen without "
         "Docker, CrewAI unsafe mode, smolagents local executor with broad imports, LangChain "
         "allow_dangerous_code, PAL chains).",
         "Use a container/VM/remote sandbox executor, restrict imports, and remove secrets from the environment."),
    Rule("ATS-ASI05-05", "Unsafe deserialization", ("ASI05", "ASI06"), H,
         "pickle/marshal/dill/unsafe YAML loading runs code embedded in the data; loaded memories, vector stores "
         "or messages become an execution vector.",
         "Use JSON or yaml.safe_load; never deserialize pickles from untrusted locations."),
    # ── ASI06 Memory and Context Poisoning ─────────────────────────────────
    Rule("ATS-ASI06-01", "Untrusted content written to long-term memory without validation", ("ASI06",), M,
         "User input, tool arguments or fetched content is stored in a vector store or persistent memory with no "
         "validation step, so a single poisoned item influences future sessions and other users.",
         "Validate/classify content before storing it, record provenance, separate trusted and untrusted "
         "memory, and expire entries."),
    Rule("ATS-ASI06-02", "Agent memory shared across users or sessions", ("ASI06", "ASI03"), M,
         "A memory object is created once at module level in a web service, or memory is read/written without a "
         "user/session identifier, so one user's (poisoned) context leaks into another's.",
         "Create memory per session and scope every read/write by user_id/session_id/tenant."),
    Rule("ATS-ASI06-03", "Retrieval in a request handler without a tenant filter", ("ASI06",), L,
         "A vector search inside a request handler has no metadata filter or namespace, so users can retrieve "
         "(or be steered by) other tenants' documents.",
         "Filter every retrieval by tenant/user metadata or use per-tenant namespaces."),
    Rule("ATS-ASI06-04", "Declared persistent memory lacks isolation, validation or expiry", ("ASI06",), M,
         "The agent manifest declares persistent memory that is shared, unvalidated or never expires.",
         "Set scope: per_user (or per_session), write_validation: true and a ttl."),
    # ── ASI07 Insecure Inter-Agent Communication ───────────────────────────
    Rule("ATS-ASI07-01", "Agent, MCP or A2A link over plaintext HTTP", ("ASI07",), M,
         "Messages between agents or to tool servers travel unencrypted to a non-local host, so they can be "
         "read or altered in transit.",
         "Use https:// (TLS 1.2+), ideally with mutual TLS between agents."),
    Rule("ATS-ASI07-02", "A2A agent card declares no authentication", ("ASI07", "ASI03"), H,
         "The published agent card has no securitySchemes/security, so any client can call the agent and peers "
         "cannot verify each other.",
         "Declare securitySchemes (OAuth2/OIDC, mTLS or API key) and require them on every skill."),
    Rule("ATS-ASI07-03", "Agent invocation endpoint without authentication", ("ASI07", "ASI03"), M,
         "A web route runs an agent or LLM call with no visible authentication dependency, decorator or header "
         "check, so anyone can drive the agent and spend its privileges.",
         "Require authentication (e.g. FastAPI Depends(verify_user), @login_required) on agent routes."),
    Rule("ATS-ASI07-04", "Agent service listens on all network interfaces", ("ASI07",), L,
         "An agent/MCP server binds to 0.0.0.0, exposing it beyond the local machine.",
         "Bind to 127.0.0.1 unless remote access is intended, and put authentication in front of it."),
    Rule("ATS-ASI07-05", "Declared inter-agent channel lacks authentication or integrity", ("ASI07",), M,
         "The manifest declares agent-to-agent communication with no auth, plaintext transport or unsigned "
         "messages.",
         "Use mTLS or OAuth2 between agents and sign messages."),
    # ── ASI08 Cascading Failures ───────────────────────────────────────────
    Rule("ATS-ASI08-01", "Agent loop has no iteration or turn limit", ("ASI08",), M,
         "An agent loop is unbounded (None/very large iteration limit, or while True around LLM calls with no "
         "exit), so errors and injected goals can run away and spread.",
         "Set explicit max iterations/turns, a wall-clock timeout and a cost budget."),
    Rule("ATS-ASI08-02", "Network call without a timeout", ("ASI08",), L,
         "A tool or LLM client can hang indefinitely, stalling the agent and everything waiting on it.",
         "Pass an explicit timeout to every outbound call."),
    Rule("ATS-ASI08-03", "Unbounded retries", ("ASI08",), M,
         "A retry decorator has no stop condition, so a failing dependency is hammered forever and failures "
         "amplify across agents.",
         "Add stop_after_attempt/max_tries and exponential backoff with jitter."),
    Rule("ATS-ASI08-04", "Tool or agent-loop errors silently swallowed", ("ASI08", "ASI10"), L,
         "Exceptions in a tool or agent loop are caught and ignored, hiding failures that then cascade "
         "downstream.",
         "Log the error and return an explicit failure result to the agent."),
    Rule("ATS-ASI08-05", "Declared agent has no execution limits", ("ASI08",), L,
         "An agent in the manifest has no max_iterations / max_runtime limit.",
         "Declare limits for iterations, runtime and cost."),
    # ── ASI09 Human-Agent Trust Exploitation ───────────────────────────────
    Rule("ATS-ASI09-01", "High-impact tool runs without human approval", ("ASI09", "ASI02"), H,
         "A tool that sends messages, moves money, deletes data or deploys code has no confirmation or "
         "interrupt step, so a manipulated agent acts with the user's trust.",
         "Add a human-in-the-loop approval (e.g. LangGraph interrupt, needs_approval, an explicit confirm step) "
         "for irreversible actions."),
    Rule("ATS-ASI09-02", "Human approval disabled or bypassed", ("ASI09", "ASI05"), H,
         "Settings or flags auto-approve agent actions (bypassPermissions, --dangerously-skip-permissions, "
         "alwaysAllow, auto_run, require_approval: never, human_input_mode NEVER with code execution).",
         "Keep approval on for writes, shell and network tools; scope auto-approval to read-only tools."),
    Rule("ATS-ASI09-03", "Prompt instructs the agent to deceive or manipulate users", ("ASI09",), M,
         "The prompt tells the agent to hide that it is an AI, pretend to be human, hide risks or pressure the "
         "user, which exploits user trust.",
         "Remove deceptive instructions; disclose AI involvement and uncertainty."),
    Rule("ATS-ASI09-04", "Prompt instructs the agent to act without confirmation", ("ASI09",), M,
         "The prompt tells the agent never to ask for confirmation or permission.",
         "Instruct the agent to confirm irreversible or high-impact actions with the user."),
    Rule("ATS-ASI09-05", "Declared high-risk tool does not require approval", ("ASI09", "ASI02"), H,
         "A tool with write/delete/payment/shell/send capabilities is declared without requires_approval: true.",
         "Set requires_approval: true for the tool."),
    # ── ASI10 Rogue Agents ──────────────────────────────────────────────────
    Rule("ATS-ASI10-01", "Agent can modify its own code, prompts or permissions", ("ASI10",), H,
         "A tool (or code acting on LLM output) writes to the agent's own source, prompt files, manifest or "
         "permission settings, letting a compromised agent entrench itself.",
         "Make agent code, prompts and settings read-only to the agent; change them only through reviewed "
         "deployments."),
    Rule("ATS-ASI10-02", "Persistence mechanism reachable from agent code", ("ASI10",), H,
         "Agent code can install cron jobs, services, launch agents, shell profile hooks, SSH keys or detach "
         "background processes, letting a rogue agent survive restarts.",
         "Remove the capability; agents should not be able to schedule or daemonise processes."),
    Rule("ATS-ASI10-03", "Agent tool installs packages at runtime", ("ASI10", "ASI04"), M,
         "A tool runs pip/npm/apt install, letting the agent expand its own capabilities with unreviewed code.",
         "Bake dependencies into the image; deny package installation in the sandbox."),
    Rule("ATS-ASI10-04", "Agent tool calls are not audit-logged", ("ASI10",), L,
         "Agent tools were found but none of them log their calls and no tracing library (LangSmith, Langfuse, "
         "OpenTelemetry, ...) is used, so rogue behaviour cannot be detected or investigated.",
         "Log every tool call (who, what, arguments, result) or enable agent tracing."),
    Rule("ATS-ASI10-05", "Declared agent system lacks a kill switch or audit log", ("ASI10",), L,
         "The manifest's oversight section does not declare a kill switch and audit logging.",
         "Provide a way to halt agents immediately and record their actions; declare both in the manifest."),
]

RULES: Dict[str, Rule] = OrderedDict((r.id, r) for r in _RULES)

# When one of these fires on a line, the listed weaker rules on the same line are dropped.
SUPERSEDES: Dict[str, tuple] = {
    "ATS-ASI05-02": ("ATS-ASI05-01", "ATS-ASI05-03", "ATS-ASI02-01", "ATS-ASI02-04", "ATS-ASI04-02"),
    "ATS-ASI02-01": ("ATS-ASI05-03", "ATS-ASI05-01"),
    "ATS-ASI04-02": ("ATS-ASI05-01", "ATS-ASI05-05"),
}


def rules_for_category(cat_id: str) -> List[Rule]:
    return [r for r in RULES.values() if cat_id in r.categories]
