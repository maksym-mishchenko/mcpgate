# Changelog

## v0.2.0 — Human-in-the-Loop Approvals

### What's new

- **Real `ask` handling** — gated calls now park for human approval with configurable timeout (`--approval-timeout`, default 30s); auto-DENY on timeout
- **`internal/event` package** — `PendingCall`, `Resolved`, `Notifier` interface shared between proxy and web server
- **`AuditQuerier` interface** — `Recent(n int)` on SQLite store; powers `/audit` endpoint
- **`/pending` endpoint** — `GET /pending` returns current parked calls as JSON array (auth required)
- **`/audit` endpoint** — `GET /audit` returns last 100 audit entries newest-first (auth required)
- **Browser UI** — dark terminal dashboard at `http://127.0.0.1:18789/?token=<token>`: pending approval cards + live audit feed via SSE; reconnection-safe (loads initial state on mount)
- **`--approval-timeout` flag** — configures Park timeout; zero = 30s
- **Startup URL** — mcpgate prints the UI URL to stderr on startup

### Breaking changes

None.

## v0.1.0 — Initial Release

- Core MCP proxy with request/response interception
- Policy-based tool access control
- SQLite audit store
- Basic approval workflow (placeholder)
