# Agentic Top 10 Scan

Static security checks for AI-agent projects, organised by all ten categories of the
[OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/), ASI01–ASI10.
It ships as a GitHub Action and a command-line tool.

The scanner reads Python and JavaScript/TypeScript agent code, prompt and instruction files, MCP server configs,
coding-agent settings, A2A agent cards, CrewAI configs, GitHub workflows that run agents, container definitions and
dependency files. It reports findings as SARIF for GitHub code scanning, as inline annotations on the run, and as a
job summary that shows every category.

> **Scope, honestly stated.** Static analysis can only see what is written in the repository. This tool has checks
> in every one of the ten categories, but none of them can prove an agent is secure, and several risks (for example
> behavioural drift in ASI10 or real blast radius in ASI08) only show up at runtime. A clean scan is not an OWASP
> compliance result. This project is independent and not affiliated with OWASP.

## Step-by-step: add the scanner to your agent project

Pick one route. Route A runs on every push with nothing to install. Route B runs on your own computer. Step C
is optional and makes the scan more precise.

### A. On GitHub (recommended)

1. **Open your agent's repository on GitHub** (the repo that holds your agent code, prompts or MCP config).
2. **Create the workflow file.** Click **Add file → Create new file**. In the name box type
   `.github/workflows/agentic-top10.yml`; typing the `/` characters creates the folders for you.
3. **Paste this into the file:**

   ```yaml
   name: Agentic Top 10 Scan
   on:
     push:
       branches: [main]
     pull_request:
     workflow_dispatch:        # adds a "Run workflow" button

   permissions:
     contents: read

   jobs:
     scan:
       runs-on: ubuntu-latest
       permissions:
         contents: read
         security-events: write   # lets results appear in the Security tab
       steps:
         - uses: actions/checkout@v4
         - uses: Adyanullah-Khan/agentic-top10-scan@v0.1.0
           with:
             fail-on: none        # report only; change to "high" once you have cleared the backlog
   ```

   If your default branch is called `master` (or something else), change `main` on line 4.
4. **Save it.** Click **Commit changes…**, leave *Commit directly to the main branch* selected, and click
   **Commit changes**. This push starts the first scan.
5. **Watch it run.** Open the **Actions** tab and click the **Agentic Top 10 Scan** run. It takes about a minute.
   If it didn't start, select the workflow on the left and click **Run workflow**.
6. **Read the results.** Findings appear in three places:
   - **Run summary.** Scroll down on the run page for a table of all 10 OWASP categories, plus every finding with
     its file and line.
   - **Annotations.** Findings are marked inline on the run, and in the *Files changed* tab of pull requests.
   - **Security → Code scanning.** The full list, with fix advice and a dismiss button. This tab is free on public
     repositories; on private ones it needs GitHub Advanced Security. Without it, the upload step shows a warning and
     the other two places still work.
7. **Fix what it found.** Each finding says what's wrong and how to fix it, and
   [docs/rules.md](docs/rules.md) explains every rule. To have the fixes written for you, add
   [Agentic Top 10 Fix](https://github.com/Adyanullah-Khan/agentic-top10-fix), which opens a pull request.
8. **Turn on the gate.** Once the important findings are fixed, change `fail-on: none` to `fail-on: high`. From then
   on, any pull request that adds a high or critical finding fails its check.

### B. On your computer

1. **Check Python.** Run `python3 --version` in a terminal; you need 3.9 or newer.
2. **Install the scanner:**

   ```bash
   pip install "git+https://github.com/Adyanullah-Khan/agentic-top10-scan@v0.1.0"
   ```

3. **Go to your agent project:** `cd path/to/your-agent`
4. **Scan it:** `agentic-top10 .`
   Findings are listed most severe first, followed by a table of all 10 OWASP categories.
5. **Optional extras:**
   - `agentic-top10 . --format sarif -o results.sarif` writes a report file.
   - `agentic-top10 coverage` explains what each category check covers.
   - `agentic-top10 . --include-tests` also scans test code, which is skipped by default.

### C. Optional: describe your agent

Some checks can only compare your code against what you *intend*. For example: should this tool need human
approval? Should this memory be per-user? Telling the scanner that unlocks 7 more checks.

1. **Create the file.** In your repository root, create `agent-manifest.yaml` (on GitHub: **Add file → Create new
   file**).
2. **List your agents.** For each one, give its name, the tools it can use, and its limits:

   ```yaml
   version: 1
   agents:
     - name: support-agent
       tools: [search_kb, refund_order]
       limits: { max_iterations: 15, max_runtime_seconds: 300 }
   ```

3. **List your tools.** For each one, say what it can do and who must approve it:

   ```yaml
   tools:
     - name: refund_order
       capabilities: [payments.refund]   # words like write, delete, send, pay, deploy mark a tool as high-risk
       permissions: ["orders:refund"]    # exact scopes, never "*"
       requires_approval: true           # high-risk tools need a human to say yes
       endpoint: https://billing.internal.example/refund
       auth: oauth2                      # oauth2 | mtls | api_key | none
     - name: search_kb
       capabilities: [docs.read]
   ```

4. **Describe memory and oversight**, if your agent remembers things between sessions:

   ```yaml
   memory:
     - name: customer-memory
       persistent: true
       scope: per_user          # per_user | per_session | shared
       write_validation: true
       ttl_days: 30
   oversight:
     kill_switch: true
     audit_log: true
   ```

5. **If agents talk to each other,** add `communication` under each agent, and `delegates_to` to list the agents it
   may hand work to (see the full example in [Declaring your agent](#declaring-your-agent-optional-manifest)).
6. **Commit the file.** The next scan checks it. Only declare what the running system really does; the manifest
   describes your system, it doesn't change it.

## What it checks

| Category | Checked statically | Not visible to static analysis |
|---|---|---|
| **ASI01** Agent Goal Hijack | Untrusted web/document/search/tool content flowing into prompts (taint tracking), user input in system prompts, prompt-injection phrases and invisible Unicode in prompts, rules files and tool descriptions (tool poisoning), exfiltration channels, untrusted issue/PR text fed to CI agents | Whether the model resists an injection at runtime |
| **ASI02** Tool Misuse & Exploitation | Tools that run shell commands, write/delete files, fetch model-chosen URLs or build SQL from model input; dangerous built-in toolkits; wildcard tool permissions; disabled TLS | How tools get chained at runtime |
| **ASI03** Identity & Privilege Abuse | Hardcoded credentials, secrets placed in prompts, over-scoped `GITHUB_TOKEN` for agent jobs, LLM keys shipped to browsers, unauthenticated endpoints, privileged containers, unrestricted delegation | Real IAM policies and token lifetimes |
| **ASI04** Agentic Supply Chain | Unpinned MCP servers (`npx`, `uvx`, `docker`), unpinned actions and agent dependencies, `trust_remote_code`, unpinned prompt-hub pulls, `curl \| sh` launches, dynamic imports, auto-trusted project MCP servers, known CVEs (opt-in) | Malicious packages that look clean; MCP rug pulls |
| **ASI05** Unexpected Code Execution | `eval`/`exec`, LLM output reaching exec/shell/SQL, `shell=True`, unsandboxed executors (AutoGen, CrewAI, smolagents, LangChain, Open Interpreter), unsafe deserialization | Sandbox strength |
| **ASI06** Memory & Context Poisoning | Untrusted content written to vector stores and long-term memory without validation, memory shared across users, retrieval without tenant filters, declared memory policy | Content already in your vector DB |
| **ASI07** Insecure Inter-Agent Communication | Plaintext HTTP for agent/MCP/A2A links, A2A agent cards without security schemes, unauthenticated agent routes, services bound to `0.0.0.0`, declared channel auth/signing | Runtime replay protection and message integrity |
| **ASI08** Cascading Failures | Unbounded iteration limits (`max_iterations=None`, `while True` around LLM calls), missing timeouts, unbounded retries, swallowed tool errors, declared limits | Real fan-out, rate limits and circuit breakers |
| **ASI09** Human-Agent Trust Exploitation | High-impact tools (send, pay, delete, deploy) without human approval, approval bypasses (`bypassPermissions`, `--dangerously-skip-permissions`, `alwaysAllow`, `chat.tools.autoApprove`, `human_input_mode="NEVER"`), prompts that tell the agent to deceive users or never ask for confirmation | UI over-trust and user over-reliance |
| **ASI10** Rogue Agents | Tools that can rewrite the agent's own code, prompts or permissions; persistence (cron, services, shell profiles, SSH keys); runtime package installs; tools with no audit logging or tracing; declared kill switch | Behavioural drift, collusion, misalignment |

There are 57 rules in all, listed with their fixes in [docs/rules.md](docs/rules.md). You can also run
`agentic-top10 rules` or `agentic-top10 coverage`.

### How the Python checks work

Python files are parsed into an AST, not matched with regexes. Within each function the scanner tracks where values
come from:

- request data,
- web pages, documents and search results,
- model-chosen tool arguments,
- LLM output,
- secrets.

It follows them through assignments, f-strings, method calls, import aliases (`import subprocess as sp`) and
helper-function returns, and reports when one reaches a dangerous sink: a prompt, a shell, SQL, `eval`, a file path,
an HTTP request or a long-term memory write. Content wrapped in explicit delimiters such as
`<untrusted_document>…</untrusted_document>` is treated as fenced and not reported as an injection risk.

Functions count as agent tools when they are registered with any of these:

- **LangChain:** `@tool`, `Tool(...)`, `BaseTool._run`
- **CrewAI:** `@tool`, `BaseTool`
- **OpenAI Agents SDK:** `@function_tool`
- **MCP:** `@mcp.tool()`
- **pydantic-ai:** `@agent.tool`
- **Semantic Kernel:** `@kernel_function`
- **AutoGen:** `register_for_llm`
- **Any framework:** `tools=[...]` lists

JavaScript/TypeScript is covered by line-based heuristics (no JS parser is bundled).

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory or file to scan |
| `fail-on` | `high` | Fail on findings at or above `none`/`info`/`low`/`medium`/`high`/`critical` |
| `min-severity` | `info` | Hide findings below this severity |
| `exclude` | | Newline/comma-separated globs to skip (gitignore-like: a bare name matches at any depth) |
| `disable` | | Newline/comma-separated rule IDs to disable |
| `config` | | Settings file (defaults to `.agentic-top10.yml` if present) |
| `include-tests` | `false` | Also scan test code, which is skipped by default |
| `online` | `false` | Look up exactly pinned dependencies in [OSV](https://osv.dev) |
| `sarif-file` | `agentic-top10.sarif` | Where to write the SARIF report |
| `upload-sarif` | `true` | Upload SARIF to code scanning |
| `annotations` | `true` | Emit inline annotations |
| `python-version` | `3.12` | Python used to run the scanner |

## Outputs

| Output | Description |
|---|---|
| `sarif-file` | Path to the SARIF report |
| `finding-count` | Number of findings |
| `exit-code` | `0` passed, `1` findings at/above `fail-on`, `2` scan error |

## Command line

```bash
pip install "git+https://github.com/Adyanullah-Khan/agentic-top10-scan@v0.1.0"

agentic-top10 .                                   # human-readable report
agentic-top10 . --format sarif -o results.sarif   # SARIF
agentic-top10 . --format json --fail-on none      # JSON, never fail
agentic-top10 . --include-tests --exclude docs    # scan tests too, skip docs/
agentic-top10 rules                               # list rules
agentic-top10 coverage                            # what each category check covers
```

Requires Python 3.9+. The only runtime dependency is PyYAML, plus `tomli` on Python < 3.11.

## Privacy

Scans run entirely on the runner or your machine. The scanner makes no LLM calls and uploads no source code.
Evidence snippets are redacted before any report is written. The only network calls are:

- `--online`, which sends package names and versions (nothing else) to `api.osv.dev`.
- The action's SARIF upload, which goes to GitHub code scanning in your own repository.

## Suppressing findings

Add a comment on the line or the line above:

```python
result = eval(expr)  # agentic-top10: ignore[ATS-ASI05-01]
# agentic-top10: ignore            <- suppresses every rule on the next line
```

Or add a `.agentic-top10.yml` at the repository root:

```yaml
exclude:
  - examples          # a bare name matches at any depth
  - src/legacy        # a path with a slash is anchored at the repository root
disable:
  - ATS-ASI04-04
severity:
  ATS-ASI08-02: info
fail_on: high
```

Findings uploaded to code scanning can also be dismissed there. Fingerprints stay stable across runs.

## Declaring your agent (optional manifest)

Some risks can only be checked against intent, for example "does this tool require approval?" or "is this memory
per-user?". Add an `agent-manifest.yaml` to enable the manifest checks (ATS-ASI02-07, ASI03-05, ASI06-04, ASI07-05,
ASI08-05, ASI09-05, ASI10-05):

```yaml
version: 1
agents:
  - name: support-agent
    tools: [refund_order, search_kb]
    limits: { max_iterations: 15, max_runtime_seconds: 300, max_cost_usd: 2 }
    delegates_to: [billing-agent]
    communication:
      - peer: billing-agent
        transport: https
        auth: mtls            # mtls | oauth2 | api_key | none
        signed_messages: true
tools:
  - name: refund_order
    capabilities: [payments.refund]
    permissions: ["orders:refund"]
    requires_approval: true
    endpoint: https://billing.internal.example/refund
    auth: oauth2
memory:
  - name: customer-memory
    persistent: true
    scope: per_user           # per_user | per_session | shared
    write_validation: true
    ttl_days: 30
oversight:
  kill_switch: true
  audit_log: true
```

## Files it reads

| Kind | Files |
|---|---|
| Code | `*.py`, `*.js`, `*.ts`, `*.jsx`, `*.tsx`, `*.mjs`, `*.cjs` |
| Prompts and instructions | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*.mdc`, `.github/copilot-instructions.md`, `.github/prompts`, `.claude/commands`, `.claude/agents`, `.claude/skills`, `SKILL.md`, `*.prompt(.md)`, `prompts/**` |
| MCP and agent settings | `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.vscode/settings.json`, `.claude/settings*.json`, `.gemini/settings.json`, `.codex/config.toml`, any JSON with `mcpServers` |
| Agent definitions | `agent-manifest.yaml`, CrewAI `agents.yaml` and `tasks.yaml`, A2A `agent-card.json` and `.well-known/agent.json` |
| CI and containers | `.github/workflows/*.yml`, `docker-compose*.yml`, `compose*.yml`, `devcontainer.json`, `Dockerfile` |
| Dependencies | `requirements*.txt`, `pyproject.toml`, `package.json`, `package-lock.json` (with `--online`) |
| Everything above, plus `.env*`, shell scripts and Makefiles | Secrets, invisible Unicode, agent approval-bypass flags |

Skipped automatically: `.git`, `node_modules`, virtualenvs, `dist`, `build`, files over 2 MB and binary files.
Test code is also skipped by default (`tests/`, `test/`, `__tests__/`, `integration_tests/`, `e2e/`, `test_*.py`,
`*_test.py`, `conftest.py`, `*.test.ts`, `*.spec.js`, and so on), because it is full of deliberate fake keys and
dangerous calls. Pass `--include-tests` (or `include-tests: true`) to scan it.

## Limitations

- The Python taint tracking works within a function, plus one level of same-module helper returns. It does not follow
  values across modules, class attributes or containers populated elsewhere.
- JavaScript/TypeScript checks are line-based heuristics.
- Phrase detectors (prompt injection, deception) are pattern lists. A determined author can word around them, and a
  prompt that *discusses* injection can trigger them; suppress those lines.
- "No auth" and "no approval" checks look for common patterns (`Depends(...)`, `@login_required`, `interrupt()`,
  `needs_approval`). Custom mechanisms may need a suppression comment.
- Runtime behaviour (actual model responses, sandbox escapes, drift) is out of reach. Pair this with red-teaming
  (garak, promptfoo, PyRIT), runtime guardrails and monitoring.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
pytest
```

`tests/fixtures/vulnerable` must trigger every rule and `tests/fixtures/clean` must trigger none; `pytest` enforces
both.

## License

MIT. See [LICENSE](LICENSE).
