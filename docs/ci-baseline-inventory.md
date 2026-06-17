# CI Baseline Inventory

## Repository

- Repo: maksym-mishchenko/mcpgate
- Default branch: main
- Visibility: public
- External fork PRs accepted: yes
- Inventory branch: chore/fleet-ci-baseline-inventory
- Implementation branch: maksym-mishchenko/ci-gate-hardening

## Existing workflows

| Workflow | Path | State |
| --- | --- | --- |
| agent-state-freshness | .github/workflows/agent-state-freshness.yml | active |
| CI | .github/workflows/ci.yml | active |
| gitleaks | .github/workflows/gitleaks.yml | active |
| Release | .github/workflows/release.yml | active |
| Secret Scan | .github/workflows/secret-scan.yml | active |

## Current emitted checks

| Check | Status behavior | Required today |
| --- | --- | --- |
| GoReleaser check | terminal success | no |
| lint | terminal success | yes |
| test | terminal success | yes |
| build | terminal success | yes |
| security | terminal success | yes |
| gitleaks / scan | terminal success on current baseline; advisory | no |
| Secret Scan / Gitleaks | terminal success on current baseline; advisory | no |

## Target normalized gates

| Gate | Source workflow/job | Required in this phase | Reason |
| --- | --- | --- | --- |
| lint | CI / lint | yes | Existing golangci-lint signal was normalized to a stable lower-case job name and proved on PR #32. |
| typecheck | not emitted separately | no | Go build/test perform type checking; a separate typecheck context would duplicate the same compiler signal. |
| test | CI / test | yes | Existing race-enabled Go test command proved on PR #32. |
| build | CI / build | yes | `go build ./...` provides a dedicated build/package compilation gate and proved on PR #32. |
| security | CI / security | yes | Blocking scope is limited to gitleaks' PR commit-range secret detection for pull requests, not full-history scanning; proved on PR #32. |

## Non-required gates

| Check | Source | Reason non-required |
| --- | --- | --- |
| GoReleaser check | CI / GoReleaser check | Release configuration validation is useful but not a core PR correctness gate for this phase. |
| state-freshness | agent-state-freshness / state-freshness | Repository-local agent hygiene gate; not part of the normalized fleet core set. |
| scan | gitleaks / scan | Full-history secret scanning is broad and remains advisory. |
| Gitleaks | Secret Scan / Gitleaks | Full-history secret scanning is broad and remains advisory. |

## Security scan scope

- Blocking dependency scope: none added in this phase; no existing fast runtime dependency vulnerability gate was present.
- Blocking secret scope: gitleaks PR commit-range secret detection through the normalized `security` job.
- Advisory scope: full-history secrets, CodeQL, broad SAST, AI-assisted scans until stable.
- Waiver tracking location: GitHub issue or security advisory reference.

## Deploy or release behavior

- Deploys or publishes artifacts: yes
- Secret-dependent PR checks: yes
- Protected environment required: no
- Smoke check command: not applicable
- Rollback command or drill evidence: no documented rollback command found during inventory

## Transition safety

- Temporary maintainer bypass enabled during rollout: no
- Positive test PR: https://github.com/maksym-mishchenko/mcpgate/pull/32
- Positive test PR evidence head SHA: 6e7f050813d9d948a3a928147c8b093d881fdafe
- Required contexts applied after proof: lint, test, build, security
- Negative test PR: https://github.com/maksym-mishchenko/mcpgate/pull/33
- Negative test PR head SHA: 6b4996a7eb9fa7f1bb556cfed5e020ef4325337c
- Bypass removal PR or API update: not applicable; branch protection reports no restrictions/bypass actors, and repository rulesets remain empty.
- Transition rule applied: no context was required until it emitted a terminal status on the normalization PR.

## Captured governance state

- Branch protection: enabled on `main` after PR #32 proved terminal success for all required contexts.
- Repository rulesets returned: 0
- Active GitHub workflow registry checked during rollout: agent-state-freshness, CI, gitleaks, Release, Secret Scan.
- Current required status checks: lint, test, build, security.
- Required status checks strict mode: enabled.
- Admin enforcement: enabled.
- Force pushes: disabled.
- Branch deletions: disabled.
- Conversation resolution: required.
- Pull request review requirement: not configured in this phase.
- Restrictions/bypass actors: none; branch protection restrictions are null and repository rulesets are empty.

## Evidence log

| Evidence | Result |
| --- | --- |
| Normalization PR URL | https://github.com/maksym-mishchenko/mcpgate/pull/32 |
| Normalization PR evidence head SHA | 6e7f050813d9d948a3a928147c8b093d881fdafe |
| Terminal check statuses on PR #32 | lint SUCCESS, test SUCCESS, build SUCCESS, security SUCCESS; advisory GoReleaser check, Gitleaks, state-freshness, scan, and GitGuardian checks also completed SUCCESS. |
| Required contexts applied | main requires lint, test, build, security with strict status checks enabled. |
| Branch protection/ruleset evidence | branch protection requires strict status checks, enforces admins, disables force pushes/deletions, requires conversation resolution, has null restrictions, and repository rulesets returned `[]`. |
| Negative PR URL | https://github.com/maksym-mishchenko/mcpgate/pull/33 |
| Negative PR blocked evidence | PR #33 head 6b4996a7eb9fa7f1bb556cfed5e020ef4325337c had lint/test/security SUCCESS, required build FAILURE, mergeStateStatus BLOCKED, and was closed unmerged. |
