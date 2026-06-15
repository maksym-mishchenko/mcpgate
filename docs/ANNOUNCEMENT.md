# MCP-GATE launch announcement

Use this copy for GitHub release notes, LinkedIn, or a short project announcement.

## Short post

MCP tools make AI agents useful, but they also create a new privilege boundary.

I built **mcpgate** as a zero-trust gateway for the Model Context Protocol: it sits between an agent and an MCP server, evaluates sensitive calls against a deny-by-default YAML policy, writes an audit record before forwarding, and can park risky calls for human approval.

What it covers:

- `tools/call`, `resources/read`, `prompts/get`, and reverse-channel `sampling/createMessage`
- allow / deny / ask policy decisions
- local approval dashboard with live audit feed
- HMAC-verifiable audit exports
- deterministic prompt-injection and tool-poisoning warnings
- stdio and HTTP MCP server transports

The 60-second demo shows the core flow: allow a safe read, ask before a write, deny a dangerous delete, and preserve the decision trail.

Repository: https://github.com/maksym-mishchenko/mcpgate

## Longer post

The Model Context Protocol is becoming the connection layer between AI agents and real tools. That is powerful, but it also means agent prompts, model output, MCP server descriptions, and tool responses now sit near filesystem access, local automation, and other high-impact operations.

**mcpgate** is my answer to that boundary: a small, local, deny-by-default MCP gateway.

It runs between an AI agent and an MCP server. For gated methods, it evaluates a YAML policy, writes an audit row before forwarding, and returns an explicit allow, deny, or human-approval path. It also scans traffic for prompt-injection and tool-poisoning indicators so suspicious content is visible in the audit trail and can be blocked when operators choose strict mode.

The project is now open-source ready with:

- MIT license
- contributor and security disclosure docs
- release binaries with checksums
- artifact provenance guidance
- a narrated 60-second showcase demo

If you are experimenting with agent tooling, MCP servers, or local AI automation, I would love feedback on the policy model and the operator workflow.

Repository: https://github.com/maksym-mishchenko/mcpgate
Showcase: https://github.com/maksym-mishchenko/mcpgate/blob/main/docs/SHOWCASE.md
