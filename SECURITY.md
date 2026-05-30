# Security

## Threat model

mcpgate defends against an AI agent (or a compromised prompt) that attempts to call MCP tools it should not be allowed to call — exfiltrating files, deleting data, or executing arbitrary commands through an MCP server.

The gateway is **not** a network-facing service. It is designed to run on the same machine as the agent and the MCP server, communicating over localhost and stdio.

---

## Controls

### Token authentication

Every web API endpoint (`/health`, `/approve`, `/events`) requires a `Bearer` token. The token is set via `--token` flag or the `MCPGATE_TOKEN` environment variable.

- There is no unauthenticated guest mode.
- Tokens are compared with `==` (constant-time comparison is appropriate here since the token never travels over a real network — it stays on localhost — but callers should use a high-entropy random value).
- Recommendation: generate with `openssl rand -hex 32`.

### Anti-DNS-rebinding (Host header check)

Every request validates the `Host` header before checking the token. Only `localhost` and `127.0.0.1` are accepted. Any other host value results in an immediate `403 Forbidden`, regardless of token.

This prevents a web page from making cross-origin requests to the local API server by abusing DNS rebinding to point a domain at `127.0.0.1`.

### Fail-closed audit log

mcpgate uses a **write-ahead audit** strategy: the verdict is written to the SQLite audit log **before** the call is forwarded to the MCP server. If the audit write fails for any reason (disk full, I/O error, database corruption), the call is denied with a `-32001` JSON-RPC error and the request is never forwarded.

This means the audit log is always authoritative: every call that reached the MCP server has a corresponding log entry. There is no window where a call is forwarded but not recorded.

The audit store interface (`audit.AuditStore`) is injected, making it possible to test fail-closed behaviour with a failing stub — the test suite does this.

### Process isolation (Setpgid)

The MCP server child process is started with `syscall.SysProcAttr{Setpgid: true}`. This places the child in its own process group.

When mcpgate shuts down (or the context is cancelled), it sends `SIGTERM` to the **entire process group** (`-pid`). If the child has not exited within 3 seconds, `SIGKILL` is sent. This ensures that MCP server subprocesses (e.g. shells spawned by a tool) are also killed, not just the top-level process.

### Policy model

- **Deny by default:** In `enforce` mode, any tool call not matched by an explicit policy rule returns `DENY`. There is no implicit allow.
- **Explicit allowlist:** Tools must be listed under `servers.<name>.tools` with `allow: "true"` to be forwarded.
- **Path traversal protection:** The `path.within` constraint rejects relative paths, empty paths, and paths that are not component-wise children of the allowed roots. For example, `/home/safe-evil` will not pass a `/home/safe` constraint. See `internal/policy/engine.go` for the `pathWithin` function.
- **Constraint coverage:** Constraints are checked on the tool's `arguments.path` field. If no `path` argument is present, the constraint is not applicable and the allow value alone determines the verdict. This is intentional — constraints are defence-in-depth, not the primary gate.
- **Observe mode:** Setting `mode: observe` bypasses enforcement and allows all calls through. This mode is intended for discovery, not production use. Do not use `observe` mode in any environment where the MCP server has access to sensitive resources.

---

## Known limitations (v0.1)

- **No TLS:** The web API listens on plain HTTP. The localhost-only bind and Host-check mitigate this for local use, but do not use mcpgate as a remotely-accessible service without adding a TLS terminator.
- **No symlink resolution in path checks:** Path constraints check the string value of the `path` argument. They do not resolve symlinks. A tool that follows a symlink out of the allowed root will not be caught by mcpgate's path constraint — it depends on the MCP server or OS to enforce filesystem boundaries.
- **TOCTOU:** Path validation occurs at policy-check time, not at actual filesystem access time. This is a known limitation documented in the source (`internal/policy/engine.go`).
- **`ask` verdict is deny in headless mode:** Interactive approval (v0.2) is not yet implemented. Any tool marked `allow: ask` will be denied in the current release.

---

## Responsible disclosure

mcpgate is a personal project. If you find a security issue:

1. **Do not open a public GitHub issue** for undisclosed vulnerabilities.
2. Open a [GitHub Security Advisory](https://github.com/maksym-mishchenko/mcpgate/security/advisories/new) (private disclosure).
3. Include a description of the issue, reproduction steps, and impact.

For general bugs and non-security issues, open a regular GitHub issue.
