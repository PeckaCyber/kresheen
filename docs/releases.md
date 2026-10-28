# Releases

Every release is built by a GitHub Actions workflow from a tag on `main`. Nothing is built or uploaded by hand.

## What a release contains

For version `X.Y.Z` (tag `vX.Y.Z`):

| Artifact | Where |
|---|---|
| Container image (linux/amd64 and linux/arm64) | `ghcr.io/peckacyber/kresheen:X.Y.Z`, and `:latest` for a stable release |
| Python package | `kresheen` on PyPI |
| Helm chart | `oci://ghcr.io/peckacyber/charts/kresheen`, chart version `X.Y.Z` |
| SBOM (SPDX JSON) | An asset of the GitHub release, and a signed attestation on the image |
| Desktop installers (Windows, macOS, Linux) | Assets of the GitHub release, with `kresheen-X.Y.Z-desktop-SHA256SUMS` and its signature bundle |
| Release notes | The GitHub release: a provenance block, then the section copied from [CHANGELOG.md](../CHANGELOG.md) |

The chart runs the image with the same version by default.

The provenance block at the top of the release notes says who started the release (the maintainer's tag push, the maintainer's release pull request that the project's security App tagged once the required checks passed, or the automatic security patch with the advisories it fixes), the commit, and every commit since the previous release, flagging any that did not come through a pull request.

Releases are immutable: once published, the tag cannot move and the assets cannot change. Only the maintainer and the project's security App may create release tags.

## Verify the image

The image is signed with [cosign](https://docs.sigstore.dev/cosign/overview/) using GitHub's OIDC identity. There is no long-lived key. Use cosign 3 or later: releases are signed with cosign 3, whose signature format cosign 2 does not find (it reports `no signatures found`). Check that the signature came from the release workflow of this repository:

```bash
cosign verify ghcr.io/peckacyber/kresheen:X.Y.Z \
  --certificate-identity-regexp '^https://github\.com/PeckaCyber/kresheen/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For a production install, pin the image by digest (`image.digest` in the Helm chart, or `@sha256:...` in Compose) and verify that digest.

## Verify the desktop installers

The installers are not code-signed with Apple or Microsoft certificates yet. Their checksums file is signed with cosign the same way as the image. Download the installer, `kresheen-X.Y.Z-desktop-SHA256SUMS` and `kresheen-X.Y.Z-desktop-SHA256SUMS.sigstore.json` into one folder, then:

```bash
cosign verify-blob kresheen-X.Y.Z-desktop-SHA256SUMS \
  --bundle kresheen-X.Y.Z-desktop-SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/PeckaCyber/kresheen/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing kresheen-X.Y.Z-desktop-SHA256SUMS
```

On macOS use `shasum -a 256 --check --ignore-missing`; on Windows compare the output of `Get-FileHash <file>` with the line in the checksums file. Each installer also has GitHub build provenance: `gh attestation verify <file> --repo PeckaCyber/kresheen`.

## Verify the build provenance

Each image has a GitHub build provenance attestation. It states which commit and workflow built it.

```bash
gh attestation verify oci://ghcr.io/peckacyber/kresheen:X.Y.Z --repo PeckaCyber/kresheen
```

## Get and verify the SBOM

Download `kresheen-X.Y.Z.sbom.spdx.json` from the GitHub release. The same SBOM is attached to the image as a signed attestation:

```bash
cosign verify-attestation ghcr.io/peckacyber/kresheen:X.Y.Z --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/PeckaCyber/kresheen/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Verify the Helm chart

The chart is signed the same way:

```bash
cosign verify ghcr.io/peckacyber/charts/kresheen:X.Y.Z \
  --certificate-identity-regexp '^https://github\.com/PeckaCyber/kresheen/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Versions and support

Kresheen uses [semantic versioning](https://semver.org/). Only the latest minor release receives security fixes, as described in [SECURITY.md](../SECURITY.md). Upgrade to the latest release before you report a problem that may already be fixed. See [upgrading.md](upgrading.md) before you upgrade.

## Security fixes in dependencies

Dependencies are checked every day. The automatic fix uses only versions published at least three days earlier, so a malicious release has time to be found and pulled first; a vulnerability that is known to be exploited (listed in CISA's Known Exploited Vulnerabilities catalog) is fixed without waiting. When a fix for a known vulnerability in a dependency or in the base image reaches `main`, a patch release is prepared and published automatically, once the tests and code scanning pass. The release notes list the advisories under "Security". A person reviews major version updates of dependencies before they are merged.
