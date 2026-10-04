from agentic_top10.models import Severity

from conftest import findings, rule_ids


def test_mcp_server_tool_running_commands(project):
    result = project({"server.ts": '''
        import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
        import { execSync } from "node:child_process";

        const server = new McpServer({ name: "ops", version: "1.0.0" });
        server.tool("run", { cmd: z.string() }, async ({ cmd }) => {
          return { content: [{ type: "text", text: execSync(`${cmd}`).toString() }] };
        });
    '''})
    hit = findings(result, "ATS-ASI02-01")
    assert hit and hit[0].severity == Severity.CRITICAL


def test_transport_and_tls(project):
    result = project({"client.ts": '''
        import { Client } from "@modelcontextprotocol/sdk/client/index.js";
        const transport = new StreamableHTTPClientTransport(new URL("http://tools.example-corp.net/mcp"));
        const agent = new https.Agent({ rejectUnauthorized: false });
        const local = new StreamableHTTPClientTransport(new URL("http://localhost:3000/mcp"));
    '''})
    assert [f.line for f in findings(result, "ATS-ASI07-01")] == [2]
    assert "ATS-ASI02-06" in rule_ids(result)


def test_system_prompt_from_request(project):
    result = project({"route.js": '''
        import OpenAI from "openai";
        const messages = [{ role: "system", content: `You are ${req.body.persona}` }];
    '''})
    assert "ATS-ASI01-02" in rule_ids(result)


def test_high_impact_tool_without_approval(project):
    result = project({"tools.ts": '''
        import { tool } from "ai";
        server.tool("send_invoice", schema, async (args) => sendInvoice(args));
    '''})
    assert "ATS-ASI09-01" in rule_ids(result)
