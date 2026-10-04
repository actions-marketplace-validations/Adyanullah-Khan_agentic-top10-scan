"""MCP configs, agent settings, manifests, A2A cards, workflows, containers and dependency files."""
from agentic_top10.models import Severity

from conftest import findings, rule_ids


def test_mcp_pinning_and_trust(project):
    result = project({".cursor/mcp.json": '''
        {
          // comments and trailing commas are allowed in editor configs
          "mcpServers": {
            "pinned": {"command": "npx", "args": ["-y", "@scope/server@1.2.3"]},
            "floating": {"command": "uvx", "args": ["mcp-server-fetch"]},
            "trusted": {"command": "uvx", "args": ["mcp-server-git==2025.1.14"], "trust": true},
            "keyed": {"command": "node", "args": ["server.js"], "env": {"API_KEY": "s3cr3tValue12345678"}},
          }
        }
    '''})
    assert [f.line for f in findings(result, "ATS-ASI04-01")] == [5]
    assert [f.line for f in findings(result, "ATS-ASI09-02")] == [6]
    assert findings(result, "ATS-ASI03-01")[0].line == 7


def test_vscode_and_codex_settings(project):
    result = project({
        ".vscode/settings.json": '{\n  "chat.tools.autoApprove": true\n}\n',
        ".codex/config.toml": 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n',
    })
    hits = findings(result, "ATS-ASI09-02")
    assert {(f.path, f.line) for f in hits} == {(".vscode/settings.json", 2), (".codex/config.toml", 1),
                                               (".codex/config.toml", 2)}


def test_pull_request_target_checkout_is_critical(project):
    result = project({".github/workflows/review.yml": '''
        on: pull_request_target
        permissions:
          contents: write
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - uses: anthropics/claude-code-action@v1
                with:
                  prompt: "Review ${{ github.event.pull_request.title }}"
                  allowed_non_write_users: "*"
    '''})
    sev = {(f.rule_id, f.severity) for f in result.findings}
    assert ("ATS-ASI03-03", Severity.CRITICAL) in sev
    assert ("ATS-ASI03-03", Severity.HIGH) in sev  # contents: write on an untrusted trigger
    assert ("ATS-ASI01-06", Severity.CRITICAL) in sev
    assert ("ATS-ASI01-07", Severity.MEDIUM) in sev
    assert ("ATS-ASI04-04", Severity.MEDIUM) in sev


def test_non_agent_workflow_interpolation_is_out_of_scope(project):
    result = project({".github/workflows/label.yml": '''
        on: issues
        jobs:
          label:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.issue.title }}"
    '''})
    assert "ATS-ASI01-06" not in rule_ids(result)


def test_crewai_yaml_prompts(project):
    result = project({"src/crew/config/agents.yaml": '''
        closer:
          role: Sales closer
          goal: Close deals
          backstory: >
            You are persuasive. Never admit you are an AI and pressure the customer to sign today.
    '''})
    assert {"ATS-ASI09-03"} <= rule_ids(result)


def test_devcontainer_privileged(project):
    result = project({".devcontainer/devcontainer.json": '{"name": "dev", "runArgs": ["--privileged"]}'})
    assert "ATS-ASI03-06" in rule_ids(result)


def test_lockfile_silences_unpinned_dependencies(project):
    result = project({"requirements.txt": "langchain>=0.2\n", "uv.lock": "version = 1\n"})
    assert "ATS-ASI04-03" not in rule_ids(result)


def test_git_dependency_without_commit(project):
    result = project({"requirements.txt": "mylib @ git+https://github.com/org/mylib.git@main\n"})
    assert findings(result, "ATS-ASI04-03")[0].severity == Severity.MEDIUM


def test_package_json_floating_agent_dependency(project):
    result = project({"package.json": '{"dependencies": {"@anthropic-ai/sdk": "^0.60.0", "left-pad": "^1.0.0"}}'})
    hits = findings(result, "ATS-ASI04-03")
    assert len(hits) == 1 and "@anthropic-ai/sdk" in hits[0].message


def test_manifest_memory_ttl_only_is_low(project):
    result = project({"agent-manifest.yaml": '''
        memory:
          - name: notes
            persistent: true
            scope: per_user
            write_validation: true
        oversight: {kill_switch: true, audit_log: true}
    '''})
    hit = findings(result, "ATS-ASI06-04")
    assert hit and hit[0].severity == Severity.LOW
