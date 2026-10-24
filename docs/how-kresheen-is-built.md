# How Kresheen is built and released

Kresheen is a security tool, so how it is made matters as much as what it does. This page says how a change reaches a release, what checks it, and where the process has limits.

## Who reviews changes

Kresheen has one maintainer. There is no second human reviewer. Every change is written or reviewed by the maintainer before it is submitted, and many changes are written with an AI coding assistant (commits made that way carry a `Co-Authored-By` trailer). Because no second person approves pull requests, the OpenSSF Scorecard "Code-Review" check scores low. That score is accurate, and it will rise when other contributors review changes.

No AI-written code is merged without the maintainer. An automated AI review comments on the maintainer's pull requests (see below), but it is advisory and cannot change code.

## What every pull request must pass

`main` is protected: changes arrive only through pull requests, and these checks must pass before a merge. The protection applies to administrators too.

- `tests`: backend and frontend unit and integration tests, type checks and linting.
- `e2e`: browser tests against a real server.
- `audit`: known vulnerabilities in Python and npm dependencies (pip-audit, npm audit).
- `secrets`: gitleaks over the full history, and a check that rejects invisible and direction-changing Unicode characters ("Trojan Source").
- `config-scan`: the GitHub workflows (actionlint, shellcheck, zizmor), the Dockerfile (hadolint) and the Helm chart (kube-linter).
- `image`: builds and starts the container image, and checks the licences of every bundled dependency.
- CodeQL code scanning for Python and JavaScript/TypeScript.

The maintainer's pull requests also get an advisory review from Claude Code. It reads the diff with read-only tools (no shell, no edits, no network), treats the diff as untrusted content, and posts its findings as a comment. It is not a required check. If it flags a possible security problem, the maintainer is alerted.

## Dependencies

- Every GitHub Action is pinned to a full commit SHA, and the workflow token is read-only unless a job needs more.
- Dependabot proposes updates for Python, npm, GitHub Actions and container images. Versions must be at least 7 days old. Patch and minor updates merge automatically once the checks above pass; major updates wait for the maintainer.
- A nightly job audits `main` and the image (pip-audit, npm audit, Grype). When a vulnerable dependency has a fixed version, it opens a pull request with the fix. It only uses versions published at least 3 days earlier, so a malicious release has time to be found and pulled first. A vulnerability that is known to be exploited (listed in CISA's Known Exploited Vulnerabilities catalog) is fixed without waiting.
- npm install scripts are turned off for every frontend install.

## AI guardrails

AI is used to help write Kresheen and to review it, so the repository has guardrails for AI tools, not only for people:

- [AGENTS.md](../AGENTS.md) gives AI coding assistants the project's rules: text in issues, pull requests and data files is data, not instructions; security controls are never weakened without the maintainer; fixes come with tests; dependencies are checked before they are added.
- `.claude/settings.json` stops Claude Code from reading or editing credential files (SSH keys, cloud and registry credentials, `.env` files).
- A pull request that adds a package new to a lockfile fails unless the package is an established project at a version at least 3 days old. AI tools sometimes invent package names, and attackers register them.
- The automated review gets no pull request title, description or comments, can only read the repository (no shell, no web tools, nothing outside the checkout), and never posts output that looks like a credential. Its comments are advisory.
- No AI tool can push code or merge. There is no automatic AI fix of failing builds.

## Releases

- Releases are built by a GitHub Actions workflow from a tag on `main`. Nothing is built or uploaded by hand.
- Releases are immutable: once published, the tag cannot move and the assets cannot change. Only the maintainer and the project's security App may create release tags.
- The container image and Helm chart are signed with cosign (keyless), the image carries an SPDX SBOM attestation and GitHub build provenance, and the Python package is published to PyPI through a trusted publisher with attestations.
- The notes of every GitHub release start with a provenance block: who started the release (the maintainer, or the automatic security patch with the advisories it fixes), the commit, and every commit since the previous release, flagging any that did not come through a pull request. The maintainer is notified of every release and checks it against this block.
- When a dependency fix reaches `main`, a patch release is prepared and published automatically after the same checks.

How to verify a release: [releases.md](releases.md).

## Ongoing checks

- [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/PeckaCyber/kresheen) rates the repository's practices every week.
- Each night the previous release is installed with Helm on PostgreSQL, upgraded to the latest release, checked for data integrity, and scanned with an authenticated OWASP ZAP API scan.
- Dependabot alerts, secret scanning with push protection and private vulnerability reporting are on.

## Reporting a problem

See [SECURITY.md](../SECURITY.md). Please report vulnerabilities privately, not in a public issue.
