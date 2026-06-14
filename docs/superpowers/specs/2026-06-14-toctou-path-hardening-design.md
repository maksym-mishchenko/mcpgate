# TOCTOU Path Hardening Design

## Purpose

MCP-GATE already supports deny-by-default tool policy, string-level path containment with `path.within`, and opt-in symlink-aware containment with `path.resolve_within`. The next milestone should make that security boundary sharper and easier to defend publicly: constraint-evaluated `allow: "true"` path rules should fail closed when the path argument is missing, tests should cover deterministic boundary cases, and operator docs should explain what MCP-GATE can and cannot guarantee before a child MCP server performs I/O.

## Scope

In scope:

- Tighten path-constraint evaluation for missing path arguments in `allow: "true"` rules.
- Add deterministic policy tests around missing paths, malformed paths, symlink escapes, missing targets, and missing roots.
- Document the TOCTOU boundary for `path.within` and `path.resolve_within`.
- Update examples so operators know when to use string-only checks versus disk-aware checks.

Out of scope:

- Building a filesystem sandbox inside MCP-GATE.
- Adding flaky race-condition integration tests that depend on timing symlink swaps.
- Changing the one-active-server-per-process architecture.
- Replacing child MCP server permissions; operators still need server-side root restrictions, read-only mounts, containers, or OS sandboxing for race-free enforcement.

## Recommended Approach

Keep this as a focused v1.3 hardening pass in `internal/policy` and docs.

The recommended implementation is:

1. Change `checkConstraints` so a configured `constraints.path` denies when an `allow: "true"` call does not include a `path` argument.
2. Keep `path.within` as a pure string-level check for absolute, clean, component-contained paths.
3. Keep `path.resolve_within` as an opt-in realpath check that fails closed when the candidate path or configured root cannot be resolved.
4. Document that both checks happen before forwarding; the child MCP server performs actual file I/O later, so operators must also constrain the server runtime.

This preserves the current architecture while making the documented security invariant match the code.

## Alternatives Considered

### Docs and tests only

This would avoid behavior changes, but it would leave a gap where a path-constrained allow rule can forward a call with no `path` argument. That contradicts the deny-by-default story and makes the showcase weaker.

### Full runtime sandboxing

MCP-GATE could try to enforce filesystem operations itself, but that would blur the gateway boundary and require tool-specific behavior for each MCP server. It is better to keep MCP-GATE as the policy/audit layer and recommend OS/container/server-level sandboxing for actual I/O confinement.

### Race-condition integration tests

A symlink-swap race test would look impressive but be unreliable. The useful guarantee is deterministic fail-closed policy behavior before forwarding, paired with clear documentation that race-free enforcement belongs in the child server sandbox.

## Component Design

| Component | Design |
|---|---|
| `internal/policy/engine.go` | Treat missing `args["path"]` as `VerdictDeny` when `constraints.path` is configured on a constraint-evaluated `allow: "true"` rule. Preserve existing `within`, `resolve_within`, `equals`, `one_of`, and `matches` behavior. |
| `internal/policy/engine_test.go` | Add focused table cases for missing path, non-clean path, relative path, prefix-trick path, symlink inside root, symlink outside root, missing candidate path, and missing configured root. |
| `README.md` / `SECURITY.md` / `ROADMAP.md` | Explain path-check semantics and the TOCTOU boundary in operator-facing language. |
| `examples/*.yaml` | Use `resolve_within` in read examples where existing files are expected. For ask-gated write examples, state that ask prompts do not evaluate constraints and approvers must inspect proposed paths manually. |

## Data Flow

1. MCP client sends a gated `tools/call`.
2. MCP-GATE extracts string arguments for policy evaluation.
3. `policy.Evaluate` applies server, method, tool, and argument constraints for `allow: "true"` rules.
4. Evaluated path constraints return `ALLOW`, `DENY`, or `UNKNOWN` before forwarding.
5. The proxy writes the audit record before forwarding allowed calls.
6. The child MCP server performs the actual I/O after the policy decision.

The docs should explicitly call out step 6 as the TOCTOU boundary.

## Error Handling

All ambiguous evaluated path-policy cases should fail closed:

- Missing `path` under `constraints.path` on an `allow: "true"` rule: deny.
- Relative path: deny.
- `filepath.Clean` changes the path: deny.
- Prefix tricks such as `/safe-evil` for root `/safe`: deny.
- `resolve_within` candidate cannot be resolved: deny.
- `resolve_within` root cannot be resolved: deny.
- Symlink resolves outside all allowed roots: deny.
- Invalid regex under `path.matches`: deny through the existing anchored-match behavior.

## Testing Strategy

Use deterministic unit tests in `internal/policy`.

Required test coverage:

- Existing `path.within` happy path remains allowed.
- Missing path now denies for constraint-evaluated `allow: "true"` path rules.
- Relative and non-clean paths deny.
- Prefix-trick paths deny.
- `resolve_within` allows direct files and symlinks that resolve inside the root.
- `resolve_within` denies symlinks that resolve outside the root.
- `resolve_within` denies missing candidate files and missing configured roots.

Do not add timing-dependent race tests. Instead, the docs should state that TOCTOU-safe enforcement requires restricting the child MCP server's own filesystem permissions.

## Documentation Plan

Update operator docs with concise guidance:

- `path.within`: use for pure string containment and planned writes/new paths.
- `path.resolve_within`: use for existing paths when the gateway has filesystem visibility and symlink defense is needed.
- `ask` prompts do not evaluate constraints; approvers must inspect proposed paths manually before allowing.
- Neither option replaces sandboxing the child MCP server.
- For high-risk filesystem tools, combine MCP-GATE policy with a server root, read-only mounts where possible, container isolation, or OS-level permissions.

## Success Criteria

- Constraint-evaluated `allow: "true"` path calls without `path` deny.
- Existing path-policy behavior remains compatible except for the intentional missing-path tightening.
- Tests pass with deterministic coverage for the path boundary cases.
- Docs clearly explain TOCTOU limitations without overselling MCP-GATE's guarantees.
- `ROADMAP.md` reflects the v1.3 item as complete after implementation.
