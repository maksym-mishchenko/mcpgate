# Operational Secrets

mcpgate requires a high-entropy web token for the local dashboard and API. Treat that token like any other operational credential: generate it outside the repository, inject it at runtime, and rotate it if it is exposed in logs, shared instructions, screenshots, chat, or issue text.

## Runtime storage

Use one of these sources, in order of preference:

1. A host secret manager or orchestrator secret store.
2. A local keychain wrapper that exports `MCPGATE_TOKEN` only for the mcpgate process.
3. An environment variable set in the operator's private shell session.

Do not store real token values in policy YAML, README snippets, GitHub issues, agent instruction files, shell profiles committed to a repo, screenshots, or release artifacts.

## Generation

```bash
export MCPGATE_TOKEN="$(openssl rand -hex 32)"
mcpgate --config examples/simple-policy.yaml
```

For repeatable local launches, load `MCPGATE_TOKEN` from your operating system's secret store and pass it only to the mcpgate process environment.

## Rotation workflow

1. Generate a new token in the owning secret-management workflow.
2. Update the runtime secret reference without committing the value.
3. Restart mcpgate so the process reads the new token.
4. Confirm `/health` succeeds with the new token and fails with the old token.
5. Revoke or delete the old token from the secret store.
6. Record the rotation event without including either token value.

If a token appears outside the owning secret boundary, rotate it before relying on the deployment again.

## Showcase assets

Showcase screenshots and recordings must use placeholders such as `<token>` or deterministic demo-only values. Never capture live dashboard URLs containing real query tokens.
