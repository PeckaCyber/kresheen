# Changelog

All notable changes to Kresheen are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] - 2026-10-28

### Added

- Desktop installers for Windows (setup .exe and .zip), macOS (.dmg, Apple silicon and Intel) and Linux (.deb, .rpm, .tar.gz), attached to each release with a signed checksums file. They run Kresheen on your own computer only (127.0.0.1), with SQLite and Grype included, and need no Python, Docker or Kubernetes. Not code-signed yet. See [installation.md](docs/installation.md#desktop-app).
- `kresheen desktop`, the command the installers start: a per-user data folder with a generated secret key, the browser opened for you, and on the first start a one-time setup link to create the owner account.
- Export menu, **Report (Markdown)** (`GET /api/applications/{id}/runs/{run_id}/report.md`): the threat model report as one Markdown file laid out for an AI assistant to read. Text from the model (names, descriptions, notes) is escaped or fenced, and the file says it is data, not instructions. See [user-guide.md](docs/user-guide.md).

### Fixed

- A Terraform plan value marked sensitive is redacted however deeply it is nested. Values more than six levels deep were stored as they were (found by the new fuzz tests).
- A Kubernetes manifest with a field of the wrong type (a list where a mapping belongs, and so on) is refused with a message naming the document, instead of failing the run with an internal error. In a GitHub repository such a file is skipped and counted with the other unreadable files. A malformed Terraform plan is refused the same way.
- Service selectors are compared as text, like pod labels, so a numeric selector value such as `version: 1` matches its pods.
- A Threat Dragon file with a non-text shape or type, or a GitHub archive with a hard link to a missing file, no longer fails the run.
- A GitHub archive with a link that replaces a directory an earlier entry created is refused before extraction. Python's tarfile could recurse on such a link until the run failed with an internal error (found by the new fuzz tests).

### Security

- The web interface builds with npm install scripts turned off (`frontend/.npmrc`), in CI and in the image. None of the Linux dependencies needs one, and install scripts are how most malicious npm packages run.
- GitHub repository scans check hard links in the downloaded archive against the archive root, the way they are extracted. A hard link that pointed outside the extraction folder could pass the pre-check on Python 3.11.0 to 3.11.3, which lack tarfile's `data` filter. Scans now refuse to run on a Python without that filter.
- Release notes start with a provenance block: who started the release, the commit, and every commit since the previous release. Releases are created as drafts with all their assets and then published, so they work as immutable releases.

## [1.1.0] - 2026-10-21

### Added

- Two more sample models, next to the online shop: a Kubernetes app built from bundled manifests and an AWS app built from a bundled Terraform plan. Each has a few weaknesses planted on purpose so the config checks have something to find. Open them from the first-run page or the New threat model menu; they are ordinary models you can edit or delete. `POST /api/applications/sample` takes an optional `{"sample": "online_shop" | "kubernetes" | "aws"}`.

### Fixed

- The diagram draws flows that leave a trust boundary. They were drawn underneath the boundary boxes, so a Terraform diagram could show no connections at all.
- `docker run ghcr.io/peckacyber/kresheen --help` prints `Usage: kresheen` (it printed `Usage: -c`).
- The nightly security job no longer fails when there is nothing to update.
- User-supplied names are quoted in two log lines, so a line break in them cannot start a fake log entry.

## [1.0.1] - 2026-10-20

### Fixed

- The release workflow signs the Helm chart. The 1.0.0 chart was pushed without a cosign signature, and 1.0.0 has no GitHub release; use 1.0.1.

## [1.0.0] - 2026-10-20

First public release of Kresheen, a self-hosted threat-modeling platform.

### Added

- Threat modeling from Kubernetes YAML, Terraform plan and state files, GitHub repositories with an SBOM, and diagram imports.
- Data-flow diagram editing with trust boundaries, properties and multiple diagrams per model.
- STRIDE threats per element, a sample of misconfiguration checks for Kubernetes and AWS, and custom threats. Plugins can add methodologies and checks.
- Threats, risk scoring, an action plan, attack paths and completeness checks.
- Run history, diffs, staleness tracking and per-model trends.
- Reports in HTML, PDF, Word, CSV and SARIF.
- A CI gate and API tokens for automated checks.
- Optional experimental AI assist. It is off by default and uses your own Anthropic API key. Rule-based analysis works without it.
