# Changelog

## v0.1.0 (2026-10-04)

First release.

- 57 rules across all ten OWASP Top 10 for Agentic Applications categories (ASI01–ASI10).
- Python analysis with intra-procedural taint tracking (user input, external content, model-chosen tool arguments,
  LLM output, secrets) and import-alias resolution.
- Checks for MCP server configs, Claude Code / VS Code / Codex / Gemini settings, A2A agent cards, CrewAI YAML,
  GitHub workflows that run agents, containers, dependency files, prompts and instruction files.
- Heuristic JavaScript/TypeScript checks.
- SARIF 2.1.0, JSON, Markdown and text output; GitHub annotations; inline suppressions and a settings file.
- Opt-in OSV advisory lookup for exactly pinned dependencies.
