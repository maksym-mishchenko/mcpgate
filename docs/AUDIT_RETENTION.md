# Audit Retention and Rotation

mcpgate writes audit entries to SQLite before forwarding gated MCP calls. The database is intentionally append-only from the gateway's perspective: deleting or rewriting rows weakens the audit trail and can break hash-chain verification.

## Retention model

- Treat `mcpgate.db` as the hot audit log for the running gateway.
- Export immutable evidence files before archiving or rotating the database.
- Store exported JSON Lines files in append-only or versioned storage when possible.
- Keep HMAC key files outside the repository and outside the audit export location.

## Safe export workflow

```bash
mcpgate export --db mcpgate.db --out audit-$(date +%Y%m%d-%H%M%S).jsonl
mcpgate verify --file audit-YYYYMMDD-HHMMSS.jsonl
```

If the audit rows were signed with an HMAC key, verify with the key:

```bash
mcpgate verify --file audit-YYYYMMDD-HHMMSS.jsonl --key audit.key
```

Only archive an export after verification succeeds. A failed verification means the chain is incomplete, corrupted, or signed with a different key.

## Rotation options

| Option | Use when | Notes |
|---|---|---|
| Keep one database | Low-volume local use | Simplest; periodically export for review |
| Stop, export, move DB, restart | Local demos or maintenance windows | Preserves a clear boundary between hot and archived logs |
| Filesystem snapshots | Long-running host with backup tooling | Verify exported JSONL after restore tests |

## Stop/move/restart rotation

1. Stop mcpgate cleanly.
2. Export and verify the current database.
3. Move `mcpgate.db` to an archive path.
4. Start mcpgate; it will create a fresh SQLite database.
5. Store the verified JSONL export and archived DB according to your retention policy.

Do not rotate by deleting rows from SQLite. Row deletion can create sequence gaps and defeats the purpose of an append-only audit trail.

## Demo recommendation

For the showcase demo, start from a clean `mcpgate.db`, perform the allow/ask/deny/warn flow, export to JSONL, and run `mcpgate verify` on camera. This makes the audit story visible without needing production log infrastructure.

For review handoff and policy discovery examples, see `docs/AUDIT_REVIEW.md`.
