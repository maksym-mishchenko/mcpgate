# Security

## Threat model

mcpgate defends against an AI agent (or a compromised prompt) that attempts to call MCP tools it should not be allowed to call — exfiltrating files, deleting data, or executing arbitrary commands through an MCP server.

As of v1.0 it also defends against a **malicious or compromised MCP server** that abuses the reverse channel — using `sampling/createMessage` to drive the agent's LLM, or `prompts/get` to inject untrusted prompt templates.

The gateway is **not** a network-facing service. It is designed to run on the same machine as the agent and the MCP server, communicating over localhost and stdio.

### Gated surfaces

mcpgate interposes on the JSON-RPC stream in **both directions** and applies policy to every method with side effects:

| Method | Direction | Gated since |
|--------|-----------|-------------|
| `tools/call` | agent → server | v0.1 |
| `resources/read` | agent → server | v0.1 |
| `prompts/get` | agent → server | v1.0 |
| `sampling/createMessage` | server → agent (reverse channel) | v1.0 |

All other methods (initialization, capability negotiation, notifications, etc.) pass through untouched.

---

## Controls

### Heuristic detection (v1.1)

mcpgate scans tool arguments, prompt fetches, resource results, and reverse-channel
sampling content against a built-in, versioned signature set (`scanner.SignatureSetVersion`)
for known prompt-injection and tool-poisoning patterns.

- Matches are recorded as **WARN** annotations on the audit entry — they do **not** block by
  default (false positives degrade to noise, not outages).
- Set `heuristics.block_on_warn: true` to escalate: an otherwise-`ALLOW` call is denied, and
  poisoned inbound content is withheld from the agent. `DENY`/`ASK` are never downgraded.
- Warnings are part of the signed audit row, so they are tamper-evident like every other field.
- Detection is deterministic pattern matching only; it is a defence-in-depth signal, not a
  guarantee.

### Token authentication

Every web API endpoint (`/health`, `/approve`, `/pending`, `/audit`, `/events`) requires a `Bearer` token. The token is set via `--token`, `--token-file`, `MCPGATE_TOKEN`, or `MCPGATE_TOKEN_FILE`.

- There is no unauthenticated guest mode.
- Tokens are hashed with SHA-256 and compared with constant-time comparison.
- Recommendation: generate with `openssl rand -hex 32`.
- Prefer `--token-file` or `MCPGATE_TOKEN_FILE` for repeatable launches so the token is not present in command-line arguments.
- Startup output prints the local dashboard URL with a token placeholder, not the real token. The browser UI prefers `#token=...` so the token is not sent on the initial static-page request. Avoid sharing screenshots, logs, shell history, or browser history entries that include real tokens.
- Do not commit operational tokens, dashboard API tokens, or `MCPGATE_TOKEN` values to repositories or shared instruction files. Store them in a secret manager or environment-specific secret store and rotate any value that has been exposed outside that boundary.

### Anti-DNS-rebinding (Host header check)

Every request validates the `Host` header before checking the token. Only `localhost` and `127.0.0.1` are accepted. Any other host value results in an immediate `403 Forbidden`, regardless of token.

This prevents a web page from making cross-origin requests to the local API server by abusing DNS rebinding to point a domain at `127.0.0.1`.

### Fail-closed audit log

mcpgate uses a **write-ahead audit** strategy: the verdict is written to the SQLite audit log **before** the call is forwarded to the MCP server. If the audit write fails for any reason (disk full, I/O error, database corruption), the call is denied with a `-32001` JSON-RPC error and the request is never forwarded.

This means the audit log is always authoritative: every call that reached the MCP server has a corresponding log entry. There is no window where a call is forwarded but not recorded.

Approval-sensitive audit rows include an `approval_source` value (`policy`, `human`, `timeout`, or `heuristic`) so exports and the local dashboard can separate manual UI decisions from automatic timeout denials and policy-only decisions.

The audit store interface (`audit.AuditStore`) is injected, making it possible to test fail-closed behaviour with a failing stub — the test suite does this.

Use `--audit-key` or `MCPGATE_AUDIT_KEY_FILE` to sign runtime audit rows with a 32-byte HMAC key. Keyed verification requires contiguous sequence numbers and a valid signature on every row except the bootstrap `seq=1` `GENESIS` row; unsigned rows fail keyed verification. For retention and rotation, export and verify audit chains before archival. Do not delete rows in place; see `docs/AUDIT_RETENTION.md`.

### Process isolation (Setpgid)

The MCP server child process is started with `syscall.SysProcAttr{Setpgid: true}`. This places the child in its own process group.

When mcpgate shuts down (or the context is cancelled), it sends `SIGTERM` to the **entire process group** (`-pid`). If the child has not exited within 3 seconds, `SIGKILL` is sent. This ensures that MCP server subprocesses (e.g. shells spawned by a tool) are also killed, not just the top-level process.

### Policy model

- **Deny by default:** In `enforce` mode, any tool call not matched by an explicit policy rule returns `DENY`. There is no implicit allow.
- **Explicit allowlist:** Tools must be listed under `servers.<name>.tools` with `allow: "true"` to be forwarded.
- **Path traversal protection:** When evaluated, the `path.within` constraint rejects missing, relative, empty, non-clean, and prefix-trick paths. For example, `/home/safe-evil` will not pass a `/home/safe` constraint. This is a string-level check and does not resolve symlinks.
- **Symlink-aware path checks:** Use `path.resolve_within` when a tool operates on existing filesystem paths and the gateway should resolve symlinks before allowing the call. It fails closed when the path or root cannot be resolved.
- **Constraint coverage:** For constraint-evaluated `allow: "true"` rules, missing constrained fields deny the call. For path-constrained allow rules, a missing `arguments.path` denies instead of falling back to the rule's allow value. `ask` rules do not evaluate constraints; approvers must inspect proposed paths manually.
- **TOCTOU boundary:** Path validation occurs at policy-check time, before the child MCP server performs filesystem I/O. Use MCP server root restrictions, read-only mounts, containers, or OS-level permissions when race-free filesystem confinement matters.
- **Structured argument constraints:** `constraints.fields` can enforce exact values, enums, anchored regexes, numeric ranges, and booleans for non-path arguments. Missing or malformed constrained arguments deny the call.
- **Typed JSON arguments:** Constraint evaluation preserves JSON types internally. String constraints require JSON strings, numeric constraints accept JSON numbers or numeric strings, and boolean constraints accept JSON booleans or boolean strings.
- **Observe mode:** Setting `mode: observe` bypasses enforcement and allows all calls through. This mode is intended for discovery, not production use. Do not use `observe` mode in any environment where the MCP server has access to sensitive resources.
- **One active server per process:** Each mcpgate process fronts one selected server. Run one process per MCP client server entry instead of adding an in-process routing layer that could blur audit attribution.
- **Bounded remote transport:** HTTP MCP calls use a default timeout and response body limit, and `--server-timeout` bounds gateway waits for server responses.

---

## Known limitations

- **No TLS:** The web API listens on plain HTTP. The localhost-only bind and Host-check mitigate this for local use, but do not use mcpgate as a remotely-accessible service without adding a TLS terminator.
- **Symlink checks are opt-in and existing-path only:** `path.resolve_within` uses filesystem resolution and fails closed if the path does not exist. Use `path.within` for create/write flows where the final path may not exist yet.
- **TOCTOU:** Path validation occurs at policy-check time, not at actual filesystem access time. MCP-GATE reduces risk before forwarding, but race-free enforcement belongs in the child MCP server sandbox or the operating system.
- **One active configured server per process:** mcpgate can define multiple policy servers, but one process runs one selected server. Use `--server` when a config contains multiple servers, or run one mcpgate process per MCP server.

Operational token storage and rotation guidance lives in `docs/OPERATIONAL_SECRETS.md`.

---

## Responsible disclosure

### Supported versions

Security fixes are prioritized for the latest released version. Older tags are kept for reproducibility, but only the current release line receives routine fixes unless a disclosure clearly affects supported users.

### Vulnerability scope

Please report vulnerabilities that affect mcpgate's policy enforcement, authentication, audit integrity, transport boundaries, dashboard rendering, release artifacts, or documented security guarantees. General MCP server bugs, vulnerabilities in an upstream MCP server, or unsafe local policies are usually out of scope unless mcpgate incorrectly forwards or documents them.

### Disclosure process

mcpgate is a personal project. If you find a security issue:

1. **Do not open a public GitHub issue** for undisclosed vulnerabilities.
2. Open a [GitHub Security Advisory](https://github.com/maksym-mishchenko/mcpgate/security/advisories/new) (private disclosure).
3. Include a description of the issue, reproduction steps, and impact.

I will acknowledge valid reports as quickly as possible, usually within a few days, and will coordinate a fix or public advisory before disclosure when practical.

### Safe harbor

Good-faith testing that avoids data destruction, persistence, spam, social engineering, and access to unrelated systems is welcome. Stop testing and report privately if you find a path to execute tools, bypass policy, expose tokens, tamper with audit evidence, or access data outside your own environment.

For general bugs and non-security issues, open a regular GitHub issue.
