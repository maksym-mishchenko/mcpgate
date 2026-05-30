# Design

## Problem

Large Language Models can call MCP tools at will. When a model is connected to a filesystem, git, database, or shell MCP server, it has — by default — full access to everything that server exposes. There is no review step, no audit trail, and no way to say "allow read but not delete."

This is not a hypothetical risk. Prompt injection attacks, overly-capable system prompts, and simple LLM mistakes can cause an agent to call tools it should not. The consequences range from data loss to credential exfiltration.

## Solution

mcpgate is an **interposing stdio proxy**. It sits between the agent and the MCP server and enforces a declarative policy on every gated call. The agent never communicates directly with the MCP server; all traffic flows through the gateway.

The key design choices are:

1. **Deny by default, explicit allowlist** — operators must opt in to every tool they want available.
2. **Write-ahead audit** — calls are logged before they are forwarded; audit failure blocks the call.
3. **Fail-closed everywhere** — any unexpected condition (audit error, unknown verdict, missing server config) results in a deny, never an allow.
4. **Interposition, not wrapping** — mcpgate does not re-implement MCP. It passes non-gated traffic through untouched, only intercepting the two methods that have side effects: `tools/call` and `resources/read`.

## Core invariants

These invariants are maintained throughout the codebase and tested explicitly:

| Invariant | Where enforced |
|-----------|---------------|
| A call is never forwarded without a prior audit entry | `proxy.handleGated` — audit write precedes `ServerTransport.Send` |
| Audit write failure → deny | `proxy.handleGated` — `sendError` on `store.Append` error |
| Unknown verdict → deny in enforce mode | `proxy.handleGated` — `VerdictUnknown` and `VerdictAsk` → deny |
| Non-localhost Host header → 403 | `web.auth` middleware |
| Child exit drains all pending approvals with deny | `main.go` goroutine watching `mgr.Done()` |
| Process group kill on shutdown | `child.Manager.Stop` — `SIGTERM` to `-pgid`, then `SIGKILL` |

## Package breakdown

```
cmd/mcpgate/    Entry point. Parses flags, wires dependencies, runs proxy + web server.
                Nothing interesting lives here by design.

internal/policy/
  types.go      Config structs — direct YAML representation.
  loader.go     yaml.Unmarshal + basic validation.
  engine.go     Evaluate() — pure function, no I/O. All policy logic lives here.
                Easily unit-tested.

internal/proxy/
  proxy.go      The core loop: recv from agent, gate check, forward or deny.
                Depends on Transport (not stdio directly) and AuditStore (not SQLite directly).

internal/audit/
  store.go      AuditStore interface. Injected into proxy, so tests can use a failing stub.
  sqlite.go     SQLite implementation using modernc/sqlite (pure Go, no CGo).
  canonical.go  Canonical serialisation for audit chain hash (integrity verification).

internal/approval/
  coordinator.go  Park/Resolve/DrainAll — goroutine-safe pending-approval map.
                  Channels + sync.Once prevent double-delivery.

internal/child/
  manager.go    exec.Cmd + Setpgid + stdio pipes. Returns a Transport.

internal/codec/
  codec.go      Newline-delimited JSON reader/writer. Handles batch arrays by splitting.
                256 KB buffer to handle large MCP responses.

internal/transport/
  transport.go  Transport interface (Recv/Send/Close).
  stdio.go      Wraps an io.Reader + io.Writer pair with a codec.Reader/Writer.

internal/web/
  server.go     /health, /approve, /events. Auth middleware checks token + Host.
                /events uses Server-Sent Events; clients are tracked with a channel map.

internal/jsonrpc/
  message.go    Minimal JSON-RPC 2.0 message type. Carries Raw []byte for pass-through.
```

## Data flow

```
Agent (e.g. Claude Desktop)
  |
  |  stdio (stdin/stdout of mcpgate process)
  |
  v
transport.Stdio (agent-side)
  |
  v
proxy.Run() ---- loop -----------------------------------------------+
  |                                                                   |
  +-- codec.IsGated(msg)?                                            |
  |     NO  --> forward immediately to server transport              |
  |             wait for server response --> forward to agent        |
  |                                                                  |
  |     YES --> proxy.handleGated(ctx, msg)                          |
  |              |                                                   |
  |              +-- policy.Evaluate(server, method, name, args, cfg)|
  |              |     returns: ALLOW | DENY | ASK | UNKNOWN         |
  |              |                                                   |
  |              +-- mode=enforce + (ASK|UNKNOWN) --> DENY           |
  |              |                                                   |
  |              +-- audit.Append(entry)   <-- WRITE-AHEAD           |
  |              |     error --> sendError (deny)                    |
  |              |                                                   |
  |              +-- ALLOW --> forward to server transport            |
  |              |             recv server response --> forward agent |
  |              |                                                   |
  |              +-- DENY  --> sendError(-32001) to agent            |
  |                                                                  |
  +------------------------------------------------------------------+
  |
  v
transport.Stdio (server-side)
  |
  |  stdio (stdin/stdout of child MCP server process)
  |
  v
MCP Server (child process, own process group)
```

## v0.2.0

- Interactive approval: `ask` verdicts park the call and push a card to the browser UI
- Browser dashboard at `GET /` — dark terminal theme, approval cards + live audit feed
- `/pending` endpoint returns current parked calls (for reconnecting clients)
- `/audit` endpoint returns last 100 entries from SQLite
- `--approval-timeout` flag (default 30s); structured `slog` verdict logging

## What is NOT in v0.1

These are deliberate scope cuts, not oversights:

| Missing feature | Rationale |
|-----------------|-----------|
| Interactive approval UI | `ask` verdicts are deny today. A browser/TUI approval flow is planned for v0.2. The `approval.Coordinator` and `/approve` endpoint are the infrastructure hooks. |
| Multi-server support | Only one MCP server per mcpgate instance. Multiple servers need multiple mcpgate processes (or a future multiplexer). |
| TLS on the web API | The web API binds only to `127.0.0.1`. Adding TLS is straightforward but adds operational complexity (certificate management) that is out of scope for a local tool. |
| Symlink resolution in path constraints | Requires disk I/O in the policy engine, which would make it impure and harder to test. Defence-in-depth: the OS and MCP server are expected to enforce their own boundaries. |
| Structured argument constraints beyond `path` | The constraint system is extensible (`Constraints` struct), but only `path` is implemented. Other field types (numeric ranges, enum values) are future work. |
| Audit log rotation / retention policy | The SQLite file grows indefinitely. Production deployments should configure external log rotation or use a different `AuditStore` implementation. |
| Authentication of the child process | mcpgate trusts its own child process. A compromised MCP server binary could bypass policy by speaking JSON-RPC directly. This is a deployment concern, not a gateway concern. |
