# mcpgate

**Zero-Trust MCP Gateway** — a deny-by-default firewall/proxy for the [Model Context Protocol](https://modelcontextprotocol.io).

mcpgate sits between an AI agent and an MCP server. Every gated `tools/call`, `resources/read`, `prompts/get`, and reverse-channel `sampling/createMessage` is evaluated against a YAML policy before it reaches the other side. Unknown or denied calls are blocked and logged; nothing passes through without an explicit allow decision.

---

## How it works

```
AI Agent (e.g. Claude)
       │  JSON-RPC over stdio
       ▼
  ┌──────────┐
  │ mcpgate  │──── enforce policy ────► allow / deny / ask
  │  proxy   │                              │
  └──────────┘                              │ allow
       │ JSON-RPC over stdio                ▼
       ▼                          ┌─────────────────┐
  MCP Server                      │  SQLite audit DB │
  (filesystem, git, …)            └─────────────────┘
```

1. The agent's stdin/stdout is piped through mcpgate instead of directly to the MCP server.
2. mcpgate connects to the configured MCP server over stdio or HTTP.
3. For every gated method (`tools/call`, `resources/read`, `prompts/get`, and reverse-channel `sampling/createMessage`) the policy engine runs.
4. The verdict (`ALLOW` / `DENY` / `ASK`) is written to a SQLite audit log **before** the call is forwarded.
5. A small HTTP server on `127.0.0.1:18789` exposes the browser dashboard, `/health`, `/approve`, `/pending`, `/audit`, and `/events`.

---

## Quick start

### Prerequisites

- Go 1.21+ (module path: `github.com/maksym-mishchenko/mcpgate`)
- An MCP server binary (e.g. `mcp-filesystem`)

### Install

```bash
git clone https://github.com/maksym-mishchenko/mcpgate
cd mcpgate
go install ./cmd/mcpgate
```

### Create a policy file

```yaml
# mcpgate.yaml
version: 1
mode: enforce
default: "false"

servers:
  filesystem:
    command: ["/usr/local/bin/mcp-filesystem", "--root", "/home/user/safe"]
    tools:
      read_file:
        allow: "true"
        constraints:
          path:
            within: ["/home/user/safe"]
      write_file:
        allow: ask
        constraints:
          path:
            within: ["/home/user/safe"]
      delete_file:
        allow: "false"
    resources:
      allow: "true"

# Injection / tool-poisoning heuristics (v1.1).
heuristics:
  enabled: true          # WARN-only detection (default)
  block_on_warn: false   # set true to deny on a match and withhold poisoned content
```

### Run

```bash
# Set a high-entropy token for the web API (required)
export MCPGATE_TOKEN="$(openssl rand -hex 32)"

# Run — mcpgate wraps the MCP server command
mcpgate --config mcpgate.yaml -- /usr/local/bin/mcp-filesystem --root /home/user/safe
```

Configure your AI client to use mcpgate's stdio instead of the MCP server directly. For example in Claude Desktop's `mcp.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpgate",
      "args": ["--config", "/path/to/mcpgate.yaml", "--", "/usr/local/bin/mcp-filesystem", "--root", "/home/user/safe"],
      "env": { "MCPGATE_TOKEN": "<generate-a-random-token>" }
    }
  }
}
```

---

## Policy config reference

```yaml
version: 1           # must be 1
mode: enforce        # "enforce" (block violations) | "observe" (log only, allow all)
default: "false"     # default verdict for unmatched calls: "true" | "false" | "ask"

servers:
  <server-name>:     # must match the executable name passed as the first arg after --
    command: []      # stdio server command; omit when using url
    url: ""          # HTTP JSON-RPC endpoint; omit when using command
    egress_allow: [] # optional hostname allowlist for HTTP transport
    tools:
      <tool-name>:
        allow: "true" | "false" | ask
        constraints:          # optional; only evaluated when allow is "true"
          path:
            within: ["/allowed/prefix"]   # path must be under one of these roots
            equals: "/exact/path"         # path must equal this exactly
            one_of: ["/a", "/b"]          # path must be one of these values
            matches: "regex"              # path must match this anchored regex
    resources:
      allow: "true" | "false" | ask
    prompts:
      allow: true | false
    sampling:
      allow: true | false

heuristics:
  enabled: true        # default when omitted
  block_on_warn: false # opt in to deny and withhold on deterministic scanner matches
```

**Modes:**

| Mode | Behaviour |
|------|-----------|
| `enforce` | `DENY` all calls not explicitly `allow: "true"`. `ask` parks the call for human approval and auto-denies on timeout. |
| `observe` | All calls pass through. Useful for discovering what an agent actually calls. |

**Allow values:**

| Value | Verdict |
|-------|---------|
| `"true"` | Allow (after constraint check) |
| `"false"` | Deny immediately |
| `ask` | Interactive approval through the local browser UI; timeout resolves as deny |

---

## CLI reference

```
mcpgate [flags] -- <server-command> [server-args...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `mcpgate.yaml` | Path to policy YAML file |
| `--token` | `$MCPGATE_TOKEN` | Bearer token for web API authentication |
| `--addr` | `127.0.0.1:18789` | Web server listen address |
| `--approval-timeout` | `30s` | How long an `ask` call waits before auto-deny |

The double-dash `--` separator is required. Everything after it is the MCP server command.

---

## Web API reference

All endpoints require authentication. Pass the token as a `Bearer` header or `?token=` query param. Requests from non-localhost `Host` headers are rejected (anti-DNS-rebinding).

### `GET /health`

Returns `{"status":"ok"}` when the gateway is running.

```bash
curl -H "Authorization: Bearer $MCPGATE_TOKEN" http://127.0.0.1:18789/health
```

### `GET /pending`

Returns currently parked `ask` calls, so a browser can reconnect without losing pending approvals.

```bash
curl -H "Authorization: Bearer $MCPGATE_TOKEN" http://127.0.0.1:18789/pending
```

### `GET /audit`

Returns the latest 100 audit entries from SQLite, newest first.

```bash
curl -H "Authorization: Bearer $MCPGATE_TOKEN" http://127.0.0.1:18789/audit
```

### `POST /approve`

Resolve a pending `ask` approval.

```bash
curl -X POST -H "Authorization: Bearer $MCPGATE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key":"filesystem:42","verdict":"allow"}' \
  http://127.0.0.1:18789/approve
```

| Field | Values |
|-------|--------|
| `key` | `"<server-name>:<request-id>"` |
| `verdict` | `"allow"` or `"deny"` |

### `GET /events`

Server-Sent Events stream of audit events. Connect with any SSE client.

```bash
curl -N -H "Authorization: Bearer $MCPGATE_TOKEN" http://127.0.0.1:18789/events
```

Events are broadcast as `event: <name>\ndata: <json>\n\n`.

---

## Security model

- **Fail-closed:** Any audit write failure causes the call to be denied. mcpgate never allows a call if it cannot record it.
- **Token authentication:** All web API endpoints require a matching Bearer token. There is no guest mode.
- **Anti-DNS-rebinding:** The `Host` header is checked on every request. Only `localhost` and `127.0.0.1` are accepted, regardless of the token.
- **Deny by default:** Unmatched calls return `DENY` in enforce mode. You must explicitly opt in to allow a tool.
- **Interactive approval:** `ask` calls are parked for approval in the local UI and denied automatically on timeout.
- **Prompt-poisoning detection:** Deterministic scanner warnings are signed into the audit chain and can be escalated with `heuristics.block_on_warn`.
- **Process isolation:** stdio MCP servers are spawned with process-group isolation so `SIGTERM`/`SIGKILL` reaches the whole subprocess tree, not just the direct child.

---

## Architecture

```
cmd/mcpgate/       — CLI entry point, flag parsing, wiring
internal/
  policy/          — YAML config types, policy engine (pure function)
  proxy/           — core message loop, verdict dispatch
  audit/           — SQLite write-ahead audit log
  approval/        — coordinator for pending human approvals
  child/           — spawn/stop child MCP server process
  codec/           — newline-delimited JSON-RPC reader/writer
  transport/       — Transport interface (stdio and HTTP implementations)
  web/             — HTTP server (/health, /approve, /pending, /audit, /events)
  jsonrpc/         — minimal JSON-RPC message type
  scanner/         — deterministic injection/exfiltration signatures
```

---

## License

MIT
