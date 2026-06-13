# State — mcpgate
Last updated: 2026-06-13 by copilot

## Done
- Synced README, DESIGN, SECURITY, and examples with current v1.1 behavior.
- Added ROADMAP.md as the repository-local backlog for v1.2+.
- Added deterministic `--server` selection for configs with multiple servers.
- Added showcase demo docs, HTTP policy example, and release checklist.
- Created GitHub issues for remaining showcase/hardening work.

## In progress

## Known issues
- Plain Go VCS stamping can fail in generated Copilot worktrees; use `-buildvcs=false` locally if needed.
- Full MCP multiplexing remains a roadmap decision; one mcpgate process currently runs one selected MCP server.
- Any dashboard or Mission Control API token that appeared in shared instructions must be rotated through the owning secret-management workflow.

## Next steps
- Use the GitHub issue backlog for remaining hardening work and demo media capture.
