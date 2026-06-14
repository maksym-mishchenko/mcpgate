# Audit Review Handoff

Use this workflow to hand a reproducible mcpgate audit package to a reviewer without giving them the live SQLite database or dashboard token.

## Export and verify evidence

```bash
mcpgate export --db mcpgate.db --out audit-review.jsonl
mcpgate verify --file audit-review.jsonl
```

If rows were signed with an HMAC key, verify with the key file:

```bash
mcpgate verify --file audit-review.jsonl --key audit.key
```

Only share exports after verification succeeds. Do not edit JSON Lines exports by hand; edits break the hash chain.

## Review checklist

1. Confirm `mcpgate verify` reports `OK`.
2. Filter rows by `verdict`, `reason`, `approval_source`, and `warnings`.
3. Inspect `approval_source: human` rows for intentional approvals.
4. Inspect `approval_source: timeout` rows for calls that were auto-denied.
5. Inspect warning rows before using them for policy discovery.

## Draft a policy from observe-mode evidence

After running mcpgate in `mode: observe`, export and verify the audit log, then generate a draft policy:

```bash
mcpgate discover --file audit-review.jsonl --out draft-policy.yaml
```

The generated policy is intentionally conservative:

- `mode` is set to `enforce`.
- `default` is set to `"false"`.
- Only warning-free `ALLOW` rows are included.
- Tool names are allowlisted exactly as observed.
- Path and field constraints are not inferred.
- Server commands are placeholders that must be reviewed and replaced.

Review `draft-policy.yaml` before using it. Observed behavior is not automatically safe behavior.
