# State — mcpgate
Last updated: 2026-06-14 by copilot

## Done
- Synced README, DESIGN, SECURITY, and examples with current v1.1 behavior.
- Added ROADMAP.md as the repository-local backlog for v1.2+.
- Added deterministic `--server` selection for configs with multiple servers.
- Added showcase demo docs, HTTP policy example, and release checklist.
- Created GitHub issues for remaining showcase/hardening work.
- Added constant-time web token comparison, dashboard audit filters/warning details, and audit retention guidance.
- Added structured field constraints and opt-in symlink-aware `path.resolve_within` checks.
- Added a safe static dashboard screenshot at `docs/assets/showcase-dashboard.png`.
- Documented the one-active-server-per-process multiplexing decision and removed the unused proxy router abstraction.
- Added operational secret storage/rotation guidance and a safe showcase GIF asset.
- Tightened path-constrained `allow: "true"` rules so missing `arguments.path` fails closed.
- Added deterministic TOCTOU/path-boundary tests and updated operator guidance for `path.within` versus `path.resolve_within`.
- Added `approval_source` audit metadata and dashboard filtering for policy, human, timeout, and heuristic decisions.

## In progress

## Known issues
- Plain Go VCS stamping can fail in generated Copilot worktrees; use `-buildvcs=false` locally if needed.

## Next steps
- Continue v1.4 governance UX with the policy discovery mode workflow.
