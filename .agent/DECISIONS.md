# Decisions — mcpgate

<!-- Tag vocabulary (controlled, edit per repo): #api #ui #data #auth #infra #build -->

<!-- Newest entries on top. Template:

## [YYYY-MM-DD] <short title>  #tag
**What:** <what changed>
**Why:** <reasoning / problem solved>
**Rejected:** <alternatives and why not> (optional)

-->
## [2026-06-14] Approval source is explicit audit metadata  #data
**What:** Audit rows now carry `approval_source` for policy, human, timeout, and heuristic decisions, and exports include the same field when present.
**Why:** Governance review needs to filter and verify manual UI decisions separately from automatic timeout denials and policy-only outcomes without parsing free-form reason strings.
**Rejected:** Inferring the source only from `reason`; this was brittle for exports and dashboard filters.

## [2026-06-14] Missing constrained allow paths fail closed  #auth
**What:** Path-constrained `allow: "true"` rules now deny calls that omit `arguments.path`.
**Why:** A configured path constraint on an allow rule means the rule is only safe when the target path is available for evaluation. Allowing missing paths contradicted the deny-by-default constraint model and weakened the TOCTOU hardening story.
**Rejected:** Keeping missing path as "constraint not applicable"; this preserved compatibility but allowed path-scoped allow rules to pass calls without the scoped argument. Evaluating constraints for `ask` prompts was left out of scope because current approval semantics require manual approver inspection.

## [2026-06-14] One process per MCP server  #infra
**What:** Kept the supported model as one selected MCP server per mcpgate process, documented the decision, and removed the unused internal proxy router abstraction.
**Why:** MCP clients already route by server entry; in-process multiplexing would require synthetic routing semantics that make policy and audit attribution harder to reason about.
**Rejected:** Full runtime multiplexing inside one mcpgate process.

## [2026-06-13] Repository roadmap as backlog source  #build
**What:** Added `ROADMAP.md` and aligned README/DESIGN/SECURITY with v1.1 behavior, including interactive approvals, reverse-channel gating, heuristic warnings, deterministic configured-server selection, and the current one-active-server-per-process limitation.
**Why:** GitHub issues and `.agent/STATE.md` had no active backlog, so future agents needed an in-repo source of truth before continuing feature work.

## [2026-06-13] Explicit server selection for multi-server configs  #infra
**What:** Added `--server` selection for policy configs with multiple `servers` entries. Single-server configs still auto-select, while ambiguous multi-server configs fail fast instead of choosing a map iteration order.
**Why:** Showcase behavior must be deterministic and honest: mcpgate can configure stdio/HTTP servers, but one process actively fronts one selected MCP server.

## [2026-06-13] Showcase hardening pass  #ui
**What:** Added constant-time web token comparison, dashboard audit filters with expandable warning details, and audit retention/rotation guidance.
**Why:** Showcase-quality governance needs visible triage, safer auth defaults, and an operator story for preserving tamper-evident logs over time.

## [2026-06-13] Structured constraints and symlink checks  #auth
**What:** Added `constraints.fields` for exact/enum/regex/numeric/bool arguments and opt-in `path.resolve_within` for symlink-aware existing-path containment.
**Why:** Showcase policies need to control more than file paths, while filesystem reads need an optional defense against symlink escapes without changing the default pure string check behavior.

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
