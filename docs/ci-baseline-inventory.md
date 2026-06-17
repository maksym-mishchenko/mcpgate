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
| Lint / lint | terminal success | no |
| Test / test | terminal success | no |
| gitleaks / scan | terminal success on current baseline; advisory | no |
| Secret Scan / Gitleaks | terminal success on current baseline; advisory | no |

## Target normalized gates

| Gate | Source workflow/job | Required in this phase | Reason |
| --- | --- | --- | --- |
| lint | CI / lint | yes, after live proof | Existing golangci-lint signal can be normalized to a stable lower-case job name. |
| typecheck | not emitted separately | no | Go build/test perform type checking; a separate typecheck context would duplicate the same compiler signal. |
| test | CI / test | yes, after live proof | Existing race-enabled Go test command should be a required core gate once proven on the normalization PR. |
| build | CI / build | yes, after live proof | `go build ./...` provides a dedicated build/package compilation gate. |
| security | CI / security | yes, after live proof | Blocking scope is limited to gitleaks' PR commit-range secret detection for pull requests, not full-history scanning. |

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
- Positive test PR: pending live verification
- Positive test PR head SHA: pending live verification
- Required contexts to apply after proof: lint, test, build, security
- Negative test PR: pending live verification
- Negative test PR head SHA: pending live verification
- Bypass removal PR or API update: not applicable unless the branch protection API reports a bypass actor after protection is applied
- Transition rule: do not require any context until it has emitted a terminal status on the normalization PR.

## Captured governance state

- Branch protection: No branch protection returned by API; add later only after checks are normalized and proven.
- Repository rulesets returned: 0
- Active GitHub workflow registry checked during rollout: agent-state-freshness, CI, gitleaks, Release, Secret Scan.
- Current required status checks: none.
- Current bypass actors: none found because no branch protection or rulesets are configured.

## Evidence log

| Evidence | Result |
| --- | --- |
| Normalization PR URL | pending live verification |
| Normalization PR head SHA | pending live verification |
| Terminal check statuses | pending live verification |
| Required contexts applied | pending live verification |
| Branch protection/ruleset evidence | pending live verification |
| Negative PR URL | pending live verification |
| Negative PR blocked evidence | pending live verification |
