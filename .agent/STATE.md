# State — mcpgate
Last updated: 2026-06-17 by copilot

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
- Added `mcpgate discover` for conservative observe-mode policy drafting from verified audit exports.
- Added audit review handoff documentation with export, verify, review, and discovery examples.
- Prepared v1.4.0 release notes and roadmap baseline.
- Completed v1.4.1 security/reliability hardening: dashboard XSS fix, runtime audit HMAC signing, strict keyed verification, HTTP/proxy bounds, and typed policy arguments.
- Published v1.4.1 release metadata and GitHub release.
- Completed post-release non-video polish: richer `/health`, hot policy decision reload, release-binary install docs, and roadmap cleanup.
- Added the narrated 60-second showcase video asset and linked it from README/SHOWCASE docs.
- Added MIT licensing and contributor setup guidance for open-source readiness.
- Hardened public launch blockers: startup output no longer prints dashboard tokens, the dashboard prefers `#token=` over query-token links, public PR checks use GitHub-hosted runners, local secret artifacts are ignored, and public security/docs claims are narrowed.
- Completed final open-source launch polish for v1.4.3: issue templates, code of conduct, README badges, release provenance, tag-driven release automation, and announcement copy.
- Published and verified the v1.4.3 GitHub release with GoReleaser binaries, `checksums.txt`, GitHub artifact attestations, announcement-style release notes, and showcase demo assets.
- Moved public showcase video links to the v1.4.3 release asset because GitHub does not preview the large MP4 through the repository file viewer.

## In progress
- CI gate normalization and branch-protection rollout is in progress on `maksym-mishchenko/ci-gate-hardening`; live PR evidence and negative enforcement proof are still pending.

## Known issues
- Plain Go VCS stamping can fail in generated Copilot worktrees; use `-buildvcs=false` locally if needed.

## Next steps
- No repository-local completion items are currently queued.
