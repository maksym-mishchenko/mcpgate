# State — mcpgate
Last updated: 2026-06-13 by copilot

## Done
- Synced README, DESIGN, SECURITY, and examples with current v1.1 behavior.
- Added ROADMAP.md as the repository-local backlog for v1.2+.

## In progress

## Known issues
- Plain Go VCS stamping can fail in generated Copilot worktrees; use `-buildvcs=false` locally if needed.
- Full named multi-server runtime routing is not complete; current proxy runtime uses the primary configured server.
- Any dashboard or Mission Control API token that appeared in shared instructions must be rotated through the owning secret-management workflow.

## Next steps
- Open/track implementation issues from ROADMAP.md when starting v1.2 work.
