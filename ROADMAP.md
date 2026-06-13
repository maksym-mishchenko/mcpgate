# Roadmap

This roadmap tracks the next practical work for mcpgate after v1.1.0. GitHub issues can mirror these items when work starts, but this file is the repository-local backlog source.

## Current baseline

- Latest release: v1.1.0, "See the poison".
- Core security invariants are implemented: deny-by-default policy, write-ahead SQLite audit, fail-closed forwarding, HMAC-verifiable audit exports, interactive approval, reverse-channel gating, deterministic heuristic warnings, and deterministic configured-server selection.
- Local worktree note: Go commands in this Copilot worktree may need `-buildvcs=false` because VCS stamping can fail in the generated worktree path.

## v1.2.0 — Documentation and operator hardening

| Priority | Item | Outcome |
|---|---|---|
| Done | Keep README, DESIGN, SECURITY, and examples aligned with v1.1 behavior | Operators do not follow stale v0.1/v0.2 guidance |
| Done | Make configured-server selection deterministic | `--server` selects a configured server and multi-server configs fail fast without an explicit choice |
| P0 | Design full MCP multiplexing, if still needed | Decide whether one mcpgate process should ever expose multiple MCP servers at once, or whether clients should run one gateway per MCP server |
| P1 | Document production-safe secret handling | No project guidance should hardcode API tokens; dashboard/mission-control tokens must live in a secret manager or environment variable and be rotated outside the repo |
| Done | Add operator examples for stdio and HTTP policies | Users can configure local and remote MCP servers without reading source |
| Done | Add release checklist | Tags, changelog, tests, and GoReleaser checks are explicit before every release |

## v1.3.0 — Policy and path hardening

| Priority | Item | Outcome |
|---|---|---|
| P0 | Symlink-aware path enforcement option | Operators can opt into realpath checks when filesystem access is available |
| P0 | TOCTOU guidance and tests | Path checks document the boundary between policy-time validation and child-process I/O |
| P1 | Structured constraints beyond `path` | Policy can constrain enum/string/numeric arguments without custom tool wrappers |
| P1 | Constant-time token comparison | Web authentication avoids token-comparison side-channel concerns even for localhost-only deployment |
| P2 | Audit retention and rotation guidance | Long-running deployments have an operational story for SQLite growth |

## v1.4.0 — Governance UX

| Priority | Item | Outcome |
|---|---|---|
| P0 | Human approval audit improvements | Approval source, timeout, and UI decisions are easy to filter and export |
| P1 | Warning triage in the dashboard | Operators can inspect signature IDs/snippets without reading raw audit rows |
| P1 | Policy discovery mode workflow | Observe-mode output can be converted into least-privilege draft policy safely |
| P2 | Import/export examples for audit review | Security review handoff is reproducible from JSON Lines exports |

## Blocked / needs explicit approval

- Rotate any existing dashboard or Mission Control API token that has appeared in shared project instructions. This is intentionally not done from this repo because secret rotation changes live infrastructure credentials and must be performed through the owning secret-management workflow.
