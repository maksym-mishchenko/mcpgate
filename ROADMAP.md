# Roadmap

This roadmap tracks the next practical work for mcpgate after v1.4.0. GitHub issues can mirror these items when work starts, but this file is the repository-local backlog source.

## Current baseline

- Latest release: v1.4.0, "Govern the gateway".
- Core security invariants are implemented: deny-by-default policy, write-ahead SQLite audit, fail-closed forwarding, HMAC-verifiable audit exports, interactive approval, reverse-channel gating, deterministic heuristic warnings, deterministic configured-server selection, structured constraints, symlink-aware path checks, approval-source audit metadata, and conservative audit-based policy discovery.
- Local worktree note: Go commands in this Copilot worktree may need `-buildvcs=false` because VCS stamping can fail in the generated worktree path.

## v1.4.1 — Security and reliability hardening

| Priority | Item | Outcome |
|---|---|---|
| In progress | Dashboard approval XSS fix | Pending-call IDs are treated as data, not inline JavaScript |
| In progress | Runtime audit HMAC signing | Normal gateway runs can produce signed audit rows and keyed verification requires signatures |
| In progress | Transport and server response bounds | Remote MCP calls cannot hang forever or return unbounded response bodies |
| In progress | Typed policy arguments | Structured constraints evaluate JSON values without string-flattening surprises |

## v1.2.0 — Documentation and operator hardening

| Priority | Item | Outcome |
|---|---|---|
| Done | Keep README, DESIGN, SECURITY, and examples aligned with v1.1 behavior | Operators do not follow stale v0.1/v0.2 guidance |
| Done | Make configured-server selection deterministic | `--server` selects a configured server and multi-server configs fail fast without an explicit choice |
| Done | Design full MCP multiplexing, if still needed | Decided to keep one active server per process and removed the unused internal router abstraction |
| Done | Document production-safe secret handling | Repo guidance points real tokens to external secret storage and rotation workflows |
| Done | Add operator examples for stdio and HTTP policies | Users can configure local and remote MCP servers without reading source |
| Done | Add release checklist | Tags, changelog, tests, and GoReleaser checks are explicit before every release |
| Done | Add static dashboard screenshot | README and showcase docs include a safe demo screenshot with no live secrets |
| Done | Record showcase GIF or short video | Portfolio/demo flow can be shown without a live setup |

## v1.3.0 — Policy and path hardening

| Priority | Item | Outcome |
|---|---|---|
| Done | Symlink-aware path enforcement option | Operators can opt into realpath checks when filesystem access is available |
| Done | TOCTOU guidance and tests | Path checks document the boundary between policy-time validation and child-process I/O, and missing path arguments fail closed for constraint-evaluated `allow: "true"` rules |
| Done | Structured constraints beyond `path` | Policy can constrain enum/string/numeric arguments without custom tool wrappers |
| Done | Constant-time token comparison | Web authentication avoids token-comparison side-channel concerns even for localhost-only deployment |
| Done | Audit retention and rotation guidance | Long-running deployments have an operational story for SQLite growth |

## v1.4.0 — Governance UX

| Priority | Item | Outcome |
|---|---|---|
| Done | Human approval audit improvements | Approval source, timeout, and UI decisions are easy to filter and export |
| Done | Warning triage in the dashboard | Operators can inspect signature IDs/snippets without reading raw audit rows |
| Done | Policy discovery mode workflow | Observe-mode output can be converted into least-privilege draft policy safely |
| Done | Import/export examples for audit review | Security review handoff is reproducible from JSON Lines exports |

## Blocked / needs explicit approval

- No blocked repository-local roadmap items.
