# Secret scanning

This repository uses **GitHub native secret scanning** instead of an in-CI
Gitleaks workflow. Native scanning is maintained by GitHub, runs on every push
and pull request, and also scans the full git history — with no workflow file,
no third-party action, and no license to manage.

## Enabling it

Secret scanning is a repository setting, not a workflow. A maintainer must turn
it on once:

1. Open **Settings → Code security** (or **Settings → Security → Code security
   and analysis**).
2. Under **Secret scanning**, enable:
   - **Secret scanning** — detects supported secret patterns in the repository.
   - **Push protection** — blocks pushes that contain a detected secret before
     it ever lands in history.
3. Optionally enable **Validity checks** and **Non-provider patterns** for
   broader coverage.

For public repositories these features are free. For private repositories they
require GitHub Secret Protection (Advanced Security).

## Customising the scan

[`secret_scanning.yml`](./secret_scanning.yml) excludes paths that are known to
hold non-production data (test fixtures and examples). Keep that list minimal —
each excluded path is a blind spot.

## What replaced what

| Before | After |
| --- | --- |
| `.github/workflows/secret-scan.yml` running `gitleaks/gitleaks-action` | GitHub native secret scanning + push protection |
| PR-gating only, on `master` | Every push, every PR, and full history |
| Third-party action pinned by SHA | Maintained by GitHub, no action to pin |

## Responding to an alert

When a secret is detected, GitHub opens an alert under **Security → Secret
scanning**. Treat it as a real credential until proven otherwise:

1. **Revoke** the exposed credential at the provider.
2. **Rotate** it and update the deployment secret store.
3. **Remove** it from the working tree and, if it is in history, rewrite the
   affected commits (for example with `git filter-repo`) and force-push.
4. **Resolve** the alert, recording the rotation in the commit message.
