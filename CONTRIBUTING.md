# Contributing to Kresheen

Thanks for your interest in improving Kresheen.

**Kresheen does not accept pull requests from outside contributors yet.** You are welcome to report bugs and suggest features in [GitHub issues](https://github.com/PeckaCyber/kresheen/issues/new/choose). Report security problems privately as described in [SECURITY.md](SECURITY.md). This page will say when pull requests open.

The rest of this guide covers building Kresheen and running its checks, which you can do on your own copy at any time.

## Development setup

You need Python 3.13 and Node 24.

Backend:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

To install exactly the versions in `uv.lock` (the project's only lock file, which CI and the Docker image use), install [uv](https://docs.astral.sh/uv/) and run `uv sync --locked --extra dev` instead. After you change dependencies in `pyproject.toml`, run `uv lock` and commit `uv.lock`.

Frontend:

```bash
cd frontend
npm ci
```

## Running the checks

Run these from the repository root.

Backend:

```bash
ruff check src tests
mypy src/kresheen
pytest -q
```

Frontend (from `frontend/`):

```bash
npx tsc -b --noEmit
npm test
```

End-to-end tests use Playwright. Follow the setup steps in [frontend/e2e/README.md](frontend/e2e/README.md) before you run them.

## Database changes

Kresheen uses Alembic for database migrations. Every change to the schema needs a new migration, and migrations are forward-only. Read the "For contributors" section of [docs/upgrading.md](docs/upgrading.md) before you change a model.

## Reporting bugs and requesting features

Open a [GitHub issue](https://github.com/PeckaCyber/kresheen/issues/new/choose) with the bug report or feature request template. For a bug, include your operating system, the Kresheen version (`kresheen --version` or the image tag), how you installed it, the steps to reproduce and the exact error message. Remove secrets, keys and personal data first.

By submitting an issue, you agree that Pecka Cyber LLC may freely use your feedback or feature idea in any open-source or commercial version of the tool without restriction or compensation.

For security problems, follow [SECURITY.md](SECURITY.md) instead. For questions about enterprise use or the upcoming Kresheen Pro, email support@peckacyber.com.

Our [Code of Conduct](CODE_OF_CONDUCT.md) applies to every conversation about the project.
