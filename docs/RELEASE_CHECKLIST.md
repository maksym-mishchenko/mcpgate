# Release Checklist

Use this checklist before tagging a showcase or public release.

## Pre-release

1. Update `CHANGELOG.md` with the release date and notable changes.
2. Confirm `README.md`, `SECURITY.md`, `DESIGN.md`, examples, and `ROADMAP.md` match current behavior.
3. Run tests:

   ```bash
   go test -race -count=1 ./...
   ```

   In generated worktrees where VCS stamping fails, use:

   ```bash
   go test -buildvcs=false -race -count=1 ./...
   ```

4. Run GoReleaser config validation:

   ```bash
   goreleaser check
   ```

5. Confirm the release workflow has `contents: write`, `id-token: write`, and `attestations: write` permissions for artifact publishing and provenance.
6. Confirm no secrets or real tokens appear in docs, examples, or config.
7. If the release changes audit behavior, run an export/verify cycle and update `docs/AUDIT_RETENTION.md`.

## Release

1. Create an annotated tag:

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   ```

2. Push the tag after CI passes:

   ```bash
   git push origin vX.Y.Z
   ```

3. Let the tag-driven `Release` workflow publish archives and `checksums.txt`.
4. Attach demo screenshots/GIFs from `docs/SHOWCASE.md` to the GitHub release when useful.
5. Do not move or rewrite a public release tag. If a tag was cut too early, publish the next patch release instead.

## Post-release

1. Open follow-up issues for deferred roadmap items.
2. Update `.agent/STATE.md` with the release state and next steps.
3. Verify a downloaded archive against `checksums.txt`.
4. Verify at least one artifact attestation with `gh attestation verify`.
5. Verify the install command in a clean checkout.
