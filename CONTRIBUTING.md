# Contributing

Thanks for your interest in mcpgate. This project is a zero-trust gateway for MCP-enabled agents, so changes should preserve the core security invariants: deny by default, audit before forwarding, and fail closed on ambiguous or unsafe states.

## Development setup

Prerequisites:

- Go 1.25+.
- An MCP server binary if you want to run an end-to-end local demo.

Install dependencies and run the test suite:

```bash
go test ./...
```

In generated Copilot worktrees, Go VCS stamping may fail. Use:

```bash
go test -buildvcs=false ./...
```

Run the same quality checks used by CI before opening a pull request:

```bash
go test -race -count=1 ./...
golangci-lint run
goreleaser check
```

## Local demo

1. Create a policy file from `examples/simple-policy.yaml`.
2. Generate a dashboard token:

   ```bash
   openssl rand -hex 32 > .mcpgate-token
   ```

3. Run mcpgate:

   ```bash
   mcpgate --config examples/simple-policy.yaml --token-file .mcpgate-token
   ```

4. Open the dashboard URL printed on startup, replacing the placeholder with your local token:

   ```bash
   open "http://127.0.0.1:18789/#token=$(cat .mcpgate-token)"
   ```

Do not commit `.mcpgate-token`, audit keys, exported production audit logs, or local SQLite runtime databases.

## Pull request expectations

- Keep changes small and focused.
- Add or update tests for behavior changes.
- Update README/docs when CLI flags, policy semantics, APIs, examples, or operator workflows change.
- Preserve fail-closed behavior for policy, audit, auth, transport, and approval paths.
- For security issues, do not open a public issue; follow `SECURITY.md`.

## Useful docs

- `README.md` — setup, configuration, CLI, and API reference.
- `docs/SHOWCASE.md` — safe demo flow and assets.
- `docs/AUDIT_REVIEW.md` — export, verify, and policy-discovery workflow.
- `docs/OPERATIONAL_SECRETS.md` — token/key storage and rotation guidance.
- `docs/RELEASE_CHECKLIST.md` — release steps.
