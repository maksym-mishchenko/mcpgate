# TOCTOU Path Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tighten MCP-GATE path constraints so missing path arguments fail closed, then document the TOCTOU boundary and operator mitigations.

**Architecture:** Keep all behavior changes inside `internal/policy`; the proxy, audit, transport, and web layers stay unchanged. Use deterministic unit tests for policy-time behavior and update operator docs/examples to distinguish string-only path checks from disk-aware symlink checks.

**Tech Stack:** Go 1.21+, standard library `filepath`/`os` testing helpers, YAML policy examples, Markdown docs.

---

## File Structure

- Modify: `internal/policy/engine_test.go`
  - Owns policy engine unit tests. Add focused tests before changing implementation.
- Modify: `internal/policy/engine.go`
  - Owns `Evaluate`, constraint application, and path-check helpers. Change only missing-path behavior and comments.
- Modify: `README.md`
  - Owns user-facing configuration reference. Update constraint semantics and TOCTOU note.
- Modify: `SECURITY.md`
  - Owns threat model and limitation language. Update the path-policy bullets to match the new fail-closed behavior.
- Modify: `examples/simple-policy.yaml`
  - Owns the stdio filesystem example. Show `resolve_within` for existing read/list flows and `within` for ask-gated writes.
- Modify: `examples/http-policy.yaml`
  - Owns the HTTP transport policy example. Add comments that explain why read uses both `within` and `resolve_within`, while write uses `within`.
- Modify: `ROADMAP.md`
  - Owns local backlog state. Mark the v1.3 TOCTOU item done after tests/docs pass.
- Modify: `.agent/STATE.md`
  - Owns agent memory state. Record the completed implementation.
- Modify: `.agent/DECISIONS.md`
  - Owns non-trivial project decisions. Add a short entry for missing path fail-closed behavior.

---

## Task 1: Add failing tests for missing path and string-level path boundaries

**Files:**
- Modify: `internal/policy/engine_test.go`

- [ ] **Step 1: Add failing tests near existing `TestWithinPathComponent` and `TestWithinDotDot`**

Insert this test after `TestWithinDotDot`:

```go
func TestPathConstraintMissingPathDenies(t *testing.T) {
	c := cfg()
	got := policy.Evaluate("fs", "tools/call", "read_file", map[string]string{}, c)
	if got != policy.VerdictDeny {
		t.Errorf("missing path under path constraint: got %v, want deny", got)
	}
}

func TestWithinRelativePathDenies(t *testing.T) {
	c := cfg()
	got := policy.Evaluate("fs", "tools/call", "read_file",
		map[string]string{"path": "home/safe/a.txt"}, c)
	if got != policy.VerdictDeny {
		t.Errorf("relative path: got %v, want deny", got)
	}
}

func TestWithinCleanPathRequired(t *testing.T) {
	c := cfg()
	got := policy.Evaluate("fs", "tools/call", "read_file",
		map[string]string{"path": "/home/safe//a.txt"}, c)
	if got != policy.VerdictDeny {
		t.Errorf("non-clean path: got %v, want deny", got)
	}
}
```

- [ ] **Step 2: Run the new missing-path test and verify it fails**

Run:

```bash
go test -buildvcs=false ./internal/policy -run TestPathConstraintMissingPathDenies -count=1
```

Expected: FAIL with output showing `missing path under path constraint: got ALLOW, want deny`.

- [ ] **Step 3: Run the new path-format tests and verify the existing behavior is already protected**

Run:

```bash
go test -buildvcs=false ./internal/policy -run 'TestWithin(RelativePathDenies|CleanPathRequired)' -count=1
```

Expected: PASS.

- [ ] **Step 4: Keep the failing test uncommitted for the green step**

```bash
git --no-pager status --short
```

Expected: `internal/policy/engine_test.go` is modified and the missing-path test is still failing. Do not commit a red test; Task 2 commits the test and implementation together after the test passes.

---

## Task 2: Make missing path arguments fail closed

**Files:**
- Modify: `internal/policy/engine.go:115-124`

- [ ] **Step 1: Change `checkConstraints` missing-path behavior**

Replace the path block in `checkConstraints` with:

```go
	if c.Path != nil {
		pathVal, ok := args["path"]
		if !ok {
			return VerdictDeny
		}
		if v := checkPathConstraint(c.Path, pathVal); v != VerdictAllow {
			return v
		}
	}
```

- [ ] **Step 2: Run the previously failing test and verify it passes**

Run:

```bash
go test -buildvcs=false ./internal/policy -run TestPathConstraintMissingPathDenies -count=1
```

Expected: PASS.

- [ ] **Step 3: Run the full policy package tests**

Run:

```bash
go test -buildvcs=false ./internal/policy -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit the tests and implementation**

```bash
git add internal/policy/engine.go internal/policy/engine_test.go
git commit -m "fix(policy): deny missing constrained paths" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 3: Expand `resolve_within` fail-closed tests

**Files:**
- Modify: `internal/policy/engine_test.go`

- [ ] **Step 1: Add a missing-root case to `TestResolveWithinPathConstraint`**

Inside `TestResolveWithinPathConstraint`, after the existing `cfg` variable, add:

```go
	cfgMissingRoot := &policy.Config{
		Version: 1,
		Mode:    "enforce",
		Servers: map[string]policy.ServerConfig{
			"fs": {
				Command: []string{"echo"},
				Tools: map[string]policy.TargetRule{
					"read_file": {
						Allow: policy.AllowTrue,
						Constraints: &policy.Constraints{
							Path: &policy.PathConstraint{ResolveWithin: []string{filepath.Join(dir, "missing-root")}},
						},
					},
				},
			},
		},
	}
```

Then after the existing loop in that test, add:

```go
	t.Run("missing root fails closed", func(t *testing.T) {
		got := policy.Evaluate("fs", "tools/call", "read_file", map[string]string{"path": safeTarget}, cfgMissingRoot)
		if got != policy.VerdictDeny {
			t.Fatalf("Evaluate = %v, want %v", got, policy.VerdictDeny)
		}
	})
```

- [ ] **Step 2: Run the expanded resolve-within test**

Run:

```bash
go test -buildvcs=false ./internal/policy -run TestResolveWithinPathConstraint -count=1
```

Expected: PASS.

- [ ] **Step 3: Run all policy tests again**

Run:

```bash
go test -buildvcs=false ./internal/policy -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit the additional test coverage**

```bash
git add internal/policy/engine_test.go
git commit -m "test(policy): cover resolve_within missing roots" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 4: Update operator docs and examples

**Files:**
- Modify: `README.md:145-200`
- Modify: `SECURITY.md:73-91`
- Modify: `examples/simple-policy.yaml`
- Modify: `examples/http-policy.yaml`

- [ ] **Step 1: Update README constraint reference**

In `README.md`, replace the constraints table rows at lines 193-195 with:

```markdown
| `path.within` | `arguments.path` | String-level absolute path containment check; no symlink resolution; useful for planned writes or new paths |
| `path.resolve_within` | `arguments.path` | Opt-in `EvalSymlinks` containment check for existing paths; fails closed if the path or root cannot be resolved |
| `path.equals` / `path.one_of` / `path.matches` | `arguments.path` | Exact, enum, or anchored RE2 checks |
```

Replace the sentence after the table with:

```markdown
Missing constrained fields deny the call. Invalid regexes, unparseable numbers, unparseable booleans, unresolved symlinks, and missing `path` values for path-constrained rules fail closed.

**TOCTOU boundary:** Path checks run before the call is forwarded. The child MCP server performs actual filesystem I/O later, so high-risk deployments should combine mcpgate policy with the MCP server's own root restrictions, read-only mounts where possible, containers, or OS-level permissions.
```

- [ ] **Step 2: Update SECURITY policy model bullets**

In `SECURITY.md`, replace the path-related bullets under `### Policy model` with:

```markdown
- **Path traversal protection:** The `path.within` constraint rejects missing, relative, empty, non-clean, and prefix-trick paths. For example, `/home/safe-evil` will not pass a `/home/safe` constraint. This is a string-level check and does not resolve symlinks.
- **Symlink-aware path checks:** Use `path.resolve_within` when a tool operates on existing filesystem paths and the gateway should resolve symlinks before allowing the call. It fails closed when the path or root cannot be resolved.
- **Constraint coverage:** Missing constrained fields deny the call. For path-constrained tools, a missing `arguments.path` denies instead of falling back to the rule's allow value.
- **TOCTOU boundary:** Path validation occurs at policy-check time, before the child MCP server performs filesystem I/O. Use MCP server root restrictions, read-only mounts, containers, or OS-level permissions when race-free filesystem confinement matters.
```

In `SECURITY.md`, replace the TOCTOU limitation bullet with:

```markdown
- **TOCTOU:** Path validation occurs at policy-check time, not at actual filesystem access time. MCP-GATE reduces risk before forwarding, but race-free enforcement belongs in the child MCP server sandbox or the operating system.
```

- [ ] **Step 3: Update `examples/simple-policy.yaml` read/list constraints**

Change `read_file` to:

```yaml
      # read_file: allowed for existing paths within the safe directory.
      # resolve_within adds symlink defense and fails closed if the path/root
      # cannot be resolved.
      read_file:
        allow: "true"
        constraints:
          path:
            within: ["/home/user/safe"]
            resolve_within: ["/home/user/safe"]
```

Change `write_file` comment to:

```yaml
      # write_file: requires human approval before executing.
      # Use within rather than resolve_within because a newly-created file may
      # not exist at policy-check time.
```

Change `list_directory` to:

```yaml
      # list_directory: allowed for existing directories under safe root.
      list_directory:
        allow: "true"
        constraints:
          path:
            within: ["/home/user/safe"]
            resolve_within: ["/home/user/safe"]
          fields:
            recursive:
              bool: false
```

- [ ] **Step 4: Update `examples/http-policy.yaml` comments**

Change the `read_file` block to:

```yaml
      read_file:
        allow: "true"
        constraints:
          path:
            # within is a string-level containment check.
            within: ["/srv/safe"]
            # resolve_within adds symlink defense for existing paths.
            resolve_within: ["/srv/safe"]
```

Change the `write_file` block to:

```yaml
      write_file:
        allow: ask
        constraints:
          path:
            # Use within for writes because a new target may not exist yet.
            within: ["/srv/safe"]
          fields:
            mode:
              one_of: ["create", "overwrite"]
```

- [ ] **Step 5: Review docs for stale missing-path language**

Run:

```bash
grep -RIn "no path arg\\|constraint is not applicable\\|If no .*path" README.md SECURITY.md docs examples internal/policy || true
```

Expected: no output that claims missing path is allowed or not applicable.

- [ ] **Step 6: Commit docs and examples**

```bash
git add README.md SECURITY.md examples/simple-policy.yaml examples/http-policy.yaml
git commit -m "docs: clarify path TOCTOU boundary" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 5: Update roadmap and agent memory

**Files:**
- Modify: `ROADMAP.md`
- Modify: `.agent/STATE.md`
- Modify: `.agent/DECISIONS.md`

- [ ] **Step 1: Mark the roadmap item done**

In `ROADMAP.md`, replace:

```markdown
| P0 | TOCTOU guidance and tests | Path checks document the boundary between policy-time validation and child-process I/O |
```

with:

```markdown
| Done | TOCTOU guidance and tests | Path checks document the boundary between policy-time validation and child-process I/O, and missing path arguments fail closed |
```

- [ ] **Step 2: Update `.agent/STATE.md`**

Add these bullets under `## Done`:

```markdown
- Tightened path-constrained rules so missing `arguments.path` fails closed.
- Added deterministic TOCTOU/path-boundary tests and updated operator guidance for `path.within` versus `path.resolve_within`.
```

Remove any stale next-step item that says TOCTOU path guidance/tests are still pending.

- [ ] **Step 3: Add a decision entry**

Add this entry near the top of `.agent/DECISIONS.md` under the template:

```markdown
## [2026-06-14] Missing constrained paths fail closed  #auth
**What:** Path-constrained rules now deny calls that omit `arguments.path`.
**Why:** A configured path constraint means the rule is only safe when the target path is available for evaluation. Allowing missing paths contradicted the deny-by-default constraint model and weakened the TOCTOU hardening story.
**Rejected:** Keeping missing path as "constraint not applicable"; this preserved compatibility but allowed path-scoped allow rules to pass calls without the scoped argument.
```

- [ ] **Step 4: Commit roadmap and memory updates**

```bash
git add ROADMAP.md .agent/STATE.md .agent/DECISIONS.md
git commit -m "docs: mark TOCTOU path hardening complete" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 6: Final verification

**Files:**
- Verify all modified files.

- [ ] **Step 1: Run policy tests**

Run:

```bash
go test -buildvcs=false ./internal/policy -count=1
```

Expected: PASS.

- [ ] **Step 2: Run all repository tests**

Run:

```bash
go test -buildvcs=false ./... -count=1
```

Expected: PASS.

- [ ] **Step 3: Run formatting**

Run:

```bash
gofmt -w internal/policy/engine.go internal/policy/engine_test.go
git diff --check
```

Expected: `git diff --check` exits 0 with no whitespace errors.

- [ ] **Step 4: Inspect final diff**

Run:

```bash
git --no-pager diff main...HEAD --stat
git --no-pager diff main...HEAD -- internal/policy/engine.go internal/policy/engine_test.go README.md SECURITY.md examples/simple-policy.yaml examples/http-policy.yaml ROADMAP.md .agent/STATE.md .agent/DECISIONS.md
```

Expected: diff only contains the planned path-hardening code, tests, docs, examples, roadmap, and memory updates.

- [ ] **Step 5: Create final verification commit only if formatting changed files**

If `gofmt` changed files after earlier commits, run:

```bash
git add internal/policy/engine.go internal/policy/engine_test.go
git commit -m "chore: format path hardening changes" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

Expected: commit is created only when `git status --short` shows formatting changes.

---

## Self-Review Notes

- Spec coverage: Tasks cover missing path fail-closed behavior, deterministic path tests, TOCTOU documentation, examples, roadmap, and agent memory.
- Placeholder scan: No task uses placeholder language or incomplete instructions.
- Type consistency: All function names, fields, and config keys match the existing Go code and YAML schema: `policy.Evaluate`, `policy.VerdictDeny`, `constraints.path`, `within`, `resolve_within`, and `arguments.path`.
