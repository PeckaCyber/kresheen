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
ruff format .
ruff check .
mypy src/kresheen
pytest -q
```

Frontend (from `frontend/`):

```bash
npm run format
npm run lint
npm run typecheck
npm test
```

### Code style

Formatting is automatic, so style is never a review topic. Python follows PEP 8 as enforced by
[Ruff's formatter](https://docs.astral.sh/ruff/formatter/) (Black-compatible), and the frontend uses
[Prettier](https://prettier.io/) with its defaults; both use a 120-character line, set in `pyproject.toml` and
`frontend/.prettierrc.json`. CI runs `ruff format --check` and `npm run format:check`, so run the formatters before
you push. `.editorconfig` gives editors the same basics (UTF-8, LF, final newline, spaces).

Linting: Python uses Ruff with the explicit rule list in `pyproject.toml`; the frontend uses
[Oxlint](https://oxc.rs/docs/guide/usage/linter) (ESLint-compatible rules, including React hooks and accessibility)
configured in `frontend/.oxlintrc.json`. Lint errors fail CI. A few rules are being phased in as warnings, because
existing code still breaks them; `npm run lint` caps the number of warnings, so new code cannot add any. When you fix
one, lower the `--max-warnings` number in `frontend/package.json`. Silence a finding only with an
`oxlint-disable-next-line <rule> -- <reason>` comment, or `# noqa: <code>` with a reason in Python.

New features and bug fixes come with tests: a fix adds a test that fails without it. Every pull request must pass the full suite, which runs as required checks in CI.

End-to-end tests use Playwright. Follow the setup steps in [frontend/e2e/README.md](frontend/e2e/README.md) before you run them.

## Database changes

Kresheen uses Alembic for database migrations. Every change to the schema needs a new migration, and migrations are forward-only. Read the "For contributors" section of [docs/upgrading.md](docs/upgrading.md) before you change a model.

## Reporting bugs and requesting features

Open a [GitHub issue](https://github.com/PeckaCyber/kresheen/issues/new/choose) with the bug report or feature request template. For a bug, include your operating system, the Kresheen version (`kresheen --version` or the image tag), how you installed it, the steps to reproduce and the exact error message. Remove secrets, keys and personal data first.

By submitting an issue, you agree that Pecka Cyber LLC may freely use your feedback or feature idea in any open-source or commercial version of the tool without restriction or compensation.

For security problems, follow [SECURITY.md](SECURITY.md) instead. For questions about enterprise use or the upcoming Kresheen Pro, email support@peckacyber.com.

Our [Code of Conduct](CODE_OF_CONDUCT.md) applies to every conversation about the project.
