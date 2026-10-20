# Security policy

## Reporting a vulnerability

Please report security problems privately, so they can be fixed before they are public. Do not open a public GitHub issue for a vulnerability. Ordinary bugs and feature requests go in [GitHub issues](https://github.com/PeckaCyber/kresheen/issues/new/choose).

Use one of these channels:

- **GitHub private vulnerability reporting:** open the repository's Security tab and choose "Report a vulnerability".
- **Email:** support@peckacyber.com (put "Security" in the subject)

## What to include

- The Kresheen version or commit you tested (`kresheen --version`, or the container image tag).
- How you installed it (Docker Compose, Helm, or from source).
- Steps to reproduce, or a proof of concept.
- The impact you expect, and who could exploit it.
- Any logs or screenshots that help. Remove secrets, keys and personal data first.

## What to expect

- We acknowledge your report within 3 business days.
- We will keep you informed while we investigate and agree on a fix and a disclosure date.
- We cannot promise a fixed time to resolution, but we will work on confirmed issues as quickly as we can.
- We credit reporters in the release notes unless you ask us not to.

## Supported versions

Only the latest minor release receives security fixes. Upgrade to the latest release before you report a problem that may already be fixed.

## Scope

This policy covers the Kresheen code in this repository and the official container image and Helm chart. Problems in third-party dependencies should go to their maintainers, although we are glad to hear about them too.
