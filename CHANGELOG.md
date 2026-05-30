# Changelog

## v0.3.0 — "Prove what your agent did"

### What's new

- **HMAC-keyed hash chain** — `OpenWithHMAC(path, key)` signs every audit row; `VerifyChain()` validates signatures; wrong key → verification fails
- **`mcpgate keygen <path>`** — generates a 32-byte HMAC key file (mode 0400); refuses to overwrite
- **Genesis record** — first-ever startup writes a GENESIS sentinel (seq=1) anchoring the chain; re-open skips if already present
- **`VerifyGap()`** — detects truncation attacks by scanning for sequence number gaps
- **Chain export** — `Export(w io.Writer)` writes the full chain as JSON Lines; safe to share without the key
- **`mcpgate export [--db mcpgate.db] [--out audit.jsonl]`** — exports audit chain to a file or stdout
- **`VerifyFile(r, key)`** — verifies a JSON Lines export: hash chain + optional HMAC; (false, nil) on tamper detected
- **`mcpgate verify [--file export.jsonl] [--key audit.key]`** — verifies chain from export file; exits 2 on tamper

### Breaking changes

None (genesis record means fresh DBs start with seq=2 for the first real entry; existing DBs without a genesis row continue to work).

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
