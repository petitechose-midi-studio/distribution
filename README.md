# MIDI Studio Distribution

This repo is the public, end-user distribution feed for MIDI Studio.

It will contain:
- `schemas/`: JSON schemas for the release inputs (`release-spec.json`) and outputs (`manifest.json`).
- GitHub Releases: bundle assets + `manifest.json` + `manifest.json.sig`.

## Release Policy

- `distribution` is the canonical public release surface for the MIDI Studio payload.
- It publishes the exact end-user content consumed by `ms-manager`: bundles, firmware, extension,
  `manifest.json`, and `manifest.json.sig`.
- It does not rebuild producer repos during release publication. Producer artifacts are consumed as
  signed candidates and then assembled into the final distribution release.
- It does not ship `ms-manager`. `ms-manager` is a separate app release that consumes the signed
  distribution feed.

## Signing

- `manifest.json.sig` is an Ed25519 detached signature over the exact bytes of `manifest.json`.
- The signature file is ASCII: base64(signature) + newline.

## Anti-rollback

`ms-manager` must refuse downgrades by default. Downgrades are allowed only via an explicit
advanced UI action.

Optional hard blocks:
- `revoked.json` (signed or pinned) can list tags that should never be installed.

## Tools

`tools/ms-dist-manifest` provides:
- `build`: generate `manifest.json` from a `release-spec.json` and a directory of built assets.
- `sign`: sign `manifest.json` into `manifest.json.sig`.
- `verify`: verify a manifest + signature (for local/CI checks).
