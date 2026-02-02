# Security

This repo is the **end-user distribution feed** for MIDI Studio.

The trust model is:
- GitHub Releases host the assets.
- `manifest.json` describes exactly what to download (filenames + sha256).
- `manifest.json.sig` is an Ed25519 detached signature over the exact bytes of `manifest.json`.
- `ms-manager` verifies the signature and then verifies each downloaded asset sha256.

## Where the signing key lives

The private key is **never** committed to git.

Stable/beta releases are signed in GitHub Actions using an **Environment secret**:
- Environment: `release`
- Secret: `MS_DIST_ED25519_SK` (base64, 32-byte Ed25519 signing key seed)

Nightly uses a separate key (recommended):
- Environment: `nightly`
- Secret: `MS_DIST_ED25519_SK_NIGHTLY` (base64, 32-byte Ed25519 signing key seed)

Public keys are embedded in `ms-manager`.

## Why workflows are sensitive

Anyone who can change `.github/workflows/**` can try to exfiltrate secrets.
This repo should treat workflow changes as security-critical.

## Recommended GitHub settings (high ROI)

Branch protection on `main`:
- Require pull request before merging
- (recommended when there are 2+ maintainers) Require Code Owner review + approvals
- Disable force-push and branch deletion
- Require conversation resolution

Actions environments:
- `release` environment requires approval (at least you)
- Put `MS_DIST_ED25519_SK` only in the `release` environment
- `nightly` environment can remain unapproved, but should use a separate key

## Channel selection

`ms-manager` resolves the latest tag for the selected channel using GitHub Releases and verifies:
- `manifest.json.sig` (Ed25519)
- each downloaded asset sha256

Workflow triggers:
- Release publishing should run only via `workflow_dispatch` (manual)
- Avoid running jobs with secrets on PR events (`pull_request`, `pull_request_target`)

Workflow hardening:
- Minimal job permissions (`permissions:` in workflows)
- Prefer pinning third-party actions by commit SHA
