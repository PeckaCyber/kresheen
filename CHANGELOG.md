# Changelog

All notable changes to Kresheen are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
