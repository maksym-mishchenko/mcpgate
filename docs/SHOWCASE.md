# Showcase Demo

This demo positions mcpgate as a zero-trust security layer for MCP-enabled agents. It is designed for a README GIF, short screen recording, conference demo, or portfolio walkthrough.

## Story

An AI agent is connected to a filesystem MCP server. Without a gateway, the agent can read, write, or delete anything that server exposes. With mcpgate in the middle, each sensitive method is evaluated by policy, written to a tamper-evident audit log, and either allowed, denied, or parked for human approval.

## Setup

```bash
export MCPGATE_TOKEN=$(openssl rand -hex 32)
mcpgate --config examples/simple-policy.yaml
```

Open the local dashboard printed on startup:

```text
http://127.0.0.1:18789/?token=<token>
```

Configure the MCP client to run `mcpgate --config /path/to/examples/simple-policy.yaml` instead of connecting directly to the filesystem MCP server.

## Demo beats

| Beat | Agent action | Expected mcpgate behavior | What to show |
|---|---|---|---|
| 1 | Read `/home/user/safe/notes.txt` | `ALLOW` | Audit feed records the allowed `read_file` call |
| 2 | Write `/home/user/safe/agent-note.txt` | `ASK` | Approval card appears; click Allow or Deny |
| 3 | Delete `/home/user/safe/notes.txt` | `DENY` | Agent receives a policy error; audit feed records deny |
| 4 | Return content containing "ignore previous instructions" | `WARN` or `DENY` with `block_on_warn` | Warning badge appears in the signed audit entry |

## Assets

- Static dashboard screenshot: [`docs/assets/showcase-dashboard.png`](assets/showcase-dashboard.png)
- Short demo GIF: [`docs/assets/showcase-flow.gif`](assets/showcase-flow.gif)
- Audit verification terminal screenshot: [`docs/assets/showcase-verify-terminal.png`](assets/showcase-verify-terminal.png)

## Screenshot and recording checklist

1. Dashboard connected state. Captured in [`docs/assets/showcase-dashboard.png`](assets/showcase-dashboard.png).
2. Pending approval card for `write_file`.
3. Live audit table showing `ALLOW`, `DENY`, warning badge rows, and filters.
4. Terminal showing `mcpgate verify --file audit.jsonl` succeeding after export. Captured in [`docs/assets/showcase-verify-terminal.png`](assets/showcase-verify-terminal.png).
5. Policy YAML beside the dashboard to show the allow/ask/deny mapping.

## Talk track

> MCP tools make agents useful, but they also create a new privilege boundary. mcpgate puts a deny-by-default control plane at that boundary. It does not trust the model, the prompt, or the MCP server response: it evaluates policy, writes the audit record first, and fails closed if anything goes wrong.

## Operator commands

Export and verify the audit trail:

```bash
mcpgate export --db mcpgate.db --out audit.jsonl
mcpgate verify --file audit.jsonl
```

Generate an HMAC key for signed audit rows:

```bash
mcpgate keygen audit.key
```

Use `heuristics.block_on_warn: true` when the demo should show poisoned content being withheld instead of only warned.
