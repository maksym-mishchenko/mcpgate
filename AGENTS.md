# AGENTS.md



> 📍 **Project status / focus tier:** see [PORTFOLIO.md](https://github.com/maksym-mishchenko/openclaw-workspace/blob/main/PORTFOLIO.md) in `openclaw-workspace` (canonical source).
<!-- agent-memory:start (managed by scripts/seed-agent-memory.sh — edit canonical source: docs/operations/agent-memory-protocol.md) -->
## Agent Memory Protocol (condensed)

**Before work (substantive tasks):** read `.agent/STATE.md` (check `Last updated`); before changing a subsystem, `grep .agent/DECISIONS.md` for its tag. Trivial tasks: this file only.

**After work:** update `.agent/STATE.md` (merge, preserve untouched in-progress items). If a non-trivial decision was made, append a tagged entry to `.agent/DECISIONS.md`.

**Boundary:** cross-project/stack-wide → ADR in the `docs` repo; single-project → `.agent/DECISIONS.md`.

**Non-trivial =** a future agent would be confused or break something without knowing it.

Full protocol: `docs/operations/agent-memory-protocol.md` in the `docs` repo.
<!-- agent-memory:end -->
