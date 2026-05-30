# mcpgate

**Zero-Trust MCP Gateway** — a deny-by-default firewall/proxy for the [Model Context Protocol](https://modelcontextprotocol.io).

mcpgate sits between an AI agent and an MCP server. Every `tools/call` and `resources/read` the agent tries to make is evaluated against a YAML policy before it reaches the real server. Unknown or denied calls are blocked and logged; nothing passes through without an explicit `allow: true`.

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
2. mcpgate spawns the real MCP server as a child process (in its own process group).
3. For every gated method (`tools/call`, `resources/read`) the policy engine runs.
4. The verdict (`ALLOW` / `DENY` / `ASK`) is written to a SQLite audit log **before** the call is forwarded.
5. A small HTTP server on `127.0.0.1:18789` exposes `/health`, `/approve`, and `/events`.

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
```

### Run

```bash
# Set a token for the web API (required)
export MCPGATE_TOKEN=my-secret-token

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
      "env": { "MCPGATE_TOKEN": "my-secret-token" }
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
    command: []      # informational — not used to spawn the process (args come from CLI)
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
```

**Modes:**

| Mode | Behaviour |
|------|-----------|
| `enforce` | `DENY` all calls not explicitly `allow: "true"`. `ask` is currently treated as deny (v0.1). |
| `observe` | All calls pass through. Useful for discovering what an agent actually calls. |

**Allow values:**

| Value | Verdict |
|-------|---------|
| `"true"` | Allow (after constraint check) |
| `"false"` | Deny immediately |
| `ask` | Interactive approval — treated as deny in v0.1 headless mode |

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

The double-dash `--` separator is required. Everything after it is the MCP server command.

---

## Web API reference

All endpoints require authentication. Pass the token as a `Bearer` header or `?token=` query param. Requests from non-localhost `Host` headers are rejected (anti-DNS-rebinding).

### `GET /health`

Returns `{"status":"ok"}` when the gateway is running.

```bash
curl -H "Authorization: Bearer $MCPGATE_TOKEN" http://127.0.0.1:18789/health
```

### `POST /approve`

Resolve a pending `ask` approval (reserved for v0.2 interactive mode).

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
- **Process isolation:** The MCP server is spawned with `Setpgid: true` so `SIGTERM`/`SIGKILL` reaches the whole subprocess tree, not just the direct child.

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
  transport/       — Transport interface (stdio implementation)
  web/             — HTTP server (/health, /approve, /events)
  jsonrpc/         — minimal JSON-RPC message type
```

---

## License

MIT
