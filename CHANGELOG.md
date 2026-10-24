# Changelog

All notable changes to Kresheen are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- The web interface builds with npm install scripts turned off (`frontend/.npmrc`), in CI and in the image. None of the Linux dependencies needs one, and install scripts are how most malicious npm packages run.
- GitHub repository scans check hard links in the downloaded archive against the archive root, the way they are extracted. A hard link that pointed outside the extraction folder could pass the pre-check on Python 3.11.0 to 3.11.3, which lack tarfile's `data` filter. Scans now refuse to run on a Python without that filter.

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
