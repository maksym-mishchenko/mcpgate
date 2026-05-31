# Decisions — mcpgate

<!-- Tag vocabulary (controlled, edit per repo): #api #ui #data #auth #infra #build -->

<!-- Newest entries on top. Template:

## [YYYY-MM-DD] <short title>  #tag
**What:** <what changed>
**Why:** <reasoning / problem solved>
**Rejected:** <alternatives and why not> (optional)

-->
## [2026-05-31] Deterministic injection/exfil signature scanner  #auth
**What:** A pure, no-I/O scanner detects prompt-injection patterns (ignore-previous, jailbreak) and exfil methods (base64, data-URI, AWS credentials, SSH keys), returning Threat objects with ID/Severity/Snippet; verdicts escalate on block_on_warn (11c4d30).
**Why:** Defense-in-depth against poisoning — heuristics catch common attack vectors in both outbound args and reverse-channel content.

## [2026-05-30] Deny-by-default policy engine with write-ahead audit  #auth
**What:** The proxy evaluates policy before forwarding and audits every call to SQLite first; an audit write failure blocks the call (fail-closed) (864e905, c8f41ab).
**Why:** Core security invariant — mcpgate must never forward a call it cannot record, preventing audit-bypass and ensuring accountability even if policy/forwarding fails.

## [2026-05-30] HMAC-keyed signed audit log with hash chain  #data
**What:** The SQLite audit log uses canonical JSON + SHA-256 hashing with optional HMAC-256 signing (key from an external file); the chain is verifiable via VerifyChain() (a747b2c).
**Why:** Tamper-evidence — a compromised DB cannot silently rewrite past entries without breaking the chain signature, enabling post-facto verification of what the gateway allowed.

## [2026-05-30] Transport interface abstraction (stdio + HTTP)  #infra
**What:** An abstract Transport interface (Recv/Send/Close) with StdioTransport and HTTPTransport implementations supports both child-process and remote HTTP MCP servers (b597c53).
**Why:** Decouples policy/proxy logic from the transport mechanism, enabling a multi-server architecture with local or remote servers and room for future transports.

## [2026-05-30] Multi-server config via ServerConfig.URL + EgressAllow  #infra
**What:** Policy config lets each server specify a Command (stdio) or URL (HTTP) plus an optional EgressAllow hostname allowlist; the gateway wires the right Transport from TransportKind() (c8f41ab).
**Why:** Removes the v0.1 one-server-per-gateway limit, letting a single gateway control multiple remote/co-located servers with per-server egress restrictions.

## [2026-05-30] Embedded localhost web UI with token auth + Host check + SSE  #ui
**What:** A 127.0.0.1-only HTTP server with Bearer/?token= auth, anti-DNS-rebinding Host-header validation, and /health, /approve, /events (SSE) plus a browser UI for approval cards and the audit feed (8807ae3).
**Why:** Enables safe local control of interactive approvals without TLS/cert complexity; localhost binding + Host check block DNS-rebinding, and SSE gives real-time updates.

## [2026-05-30] Platform-specific child-process management  #infra
**What:** Child spawning is split into manager_unix.go (Setpgid, SIGTERM/SIGKILL to the process group) and manager_windows.go (job objects) behind a unified Start/Stop interface (7e8c252).
**Why:** Guarantees subprocess-tree termination on shutdown without killing unrelated processes, since Unix process groups and Windows job objects are fundamentally different APIs.
