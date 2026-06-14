# Changelog

## Unreleased

### Added
- **Deterministic configured-server selection** — `--server` selects a named policy server and is required when multiple servers are configured, avoiding accidental map-order selection.
- **Showcase documentation** — demo script, HTTP policy example, release checklist, and portfolio-oriented README sections.
- **Dashboard audit filtering** — local UI filters audit rows by verdict, method, server, and warning presence, with expandable warning details.
- **Audit retention guidance** — documented export/verify-first rotation workflow for long-running deployments.
- **Structured argument constraints** — policy can constrain non-path fields with exact values, enums, anchored regexes, numeric ranges, and booleans.
- **Symlink-aware path checks** — optional `path.resolve_within` resolves existing paths and roots before allowing filesystem operations.
- **Showcase dashboard screenshot** — README and showcase docs now include a safe static dashboard capture.
- **Showcase flow GIF** — docs include a compact safe demo recording asset for portfolio use.
- **Operational secrets runbook** — token storage and rotation guidance now lives in `docs/OPERATIONAL_SECRETS.md`.
- **Approval source audit metadata** — audit rows and JSON Lines exports now include `approval_source` for policy, human, timeout, and heuristic decisions, and the dashboard can filter by source.
- **Policy discovery workflow** — `mcpgate discover` converts verified observe-mode audit exports into conservative enforce-mode draft policies.
- **Audit review handoff guide** — documented export, verify, review, and discovery examples for JSON Lines audit evidence.

### Changed
- Constraint-evaluated `allow: "true"` path rules now fail closed when `arguments.path` is missing, instead of treating the path constraint as not applicable.
- Policy examples now treat `servers.<name>.command` as the source of the stdio server command instead of requiring the fallback `-- <server-command>` form.
- Web API token checks now compare SHA-256 digests with constant-time comparison.
- The multiplexing model is now explicit: one active selected MCP server per mcpgate process.
- The module Go directive now targets the dependency-required Go 1.25 baseline.
- GoReleaser archive configuration now uses the v2 `formats` key for Windows zip archives.

### Removed
- Removed the unused internal proxy router abstraction that implied future in-process multiplexing.

## [1.1.0] - 2026-05-31 — "See the poison"

### Added
- **Injection / tool-poisoning heuristics** (`internal/scanner`) — deterministic, versioned signature set (ignore-previous-instructions, jailbreak fragments, base64/data-URI/credential exfil) scanned over MCP traffic in both directions
- **`heuristics` config block** — `enabled` (default true, WARN-only) and `block_on_warn` (opt-in escalation of ALLOW→DENY)
- **Signed warnings** — heuristic matches are stored in the audit chain and HMAC-signed, so they are tamper-evident; surfaced as a ⚠ badge in the dashboard
- **Inbound content withholding** — with `block_on_warn`, poisoned `resources/read` results and `sampling/createMessage` content are withheld from the agent

### Security
- `SECURITY.md` documents the heuristic control, its WARN semantics, and the opt-in blocking model

## [1.0.0] - 2026-05-31 — "Gate the whole surface"

### Added
- **Reverse-channel gating** — server-initiated `sampling/createMessage` calls are now intercepted and policy-evaluated before reaching the agent's LLM; default-deny when no `sampling` rule is configured
- **`prompts/get` gating** — agent→server prompt-template fetches are now gated (default-deny without a `prompts` rule), closing a prompt-injection vector
- **Policy schema** — `SamplingRule` and `PromptsRule` blocks on `ServerConfig` (`Sampling *SamplingRule`, `Prompts *PromptsRule`), each with an `Allow` toggle
- **`TestServerNotificationRelayedThenResponse`** — covers server notifications interleaved with responses

### Fixed
- **Server notification relay** — `recvServerResponse` now switches on frame kind: requests are policy-handled, notifications are relayed to the agent and the loop continues, only genuine responses are returned. Previously a server notification could be mistaken for the response and desync the proxy.

### Security
- Threat model (`SECURITY.md`) now documents both-direction interception and a gated-surfaces table (`tools/call`, `resources/read`, `prompts/get`, `sampling/createMessage`)

## [0.4.0] - 2026-05-30

### Added
- HTTP transport (`internal/transport/http_client.go`) — POST JSON-RPC to remote MCP servers
- Egress allowlist (`NewHTTPWithEgress`) — blocks outbound dials to non-listed hostnames
- `ServerConfig.URL` and `EgressAllow` fields with `TransportKind()` helper
- Multi-server `Router` (`internal/proxy/router.go`) — named transport registry
- `main.go` wires HTTP or stdio transport per server based on config; falls back to CLI args

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
