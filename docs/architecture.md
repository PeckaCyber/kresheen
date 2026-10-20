# Architecture

This page is a short map of the code for people who want to read it or contribute. For what the product does, see the [user guide](user-guide.md).

Kresheen is one FastAPI service (`src/kresheen/`) that also serves a React single-page app (`frontend/`). Data lives in SQLite or PostgreSQL through SQLAlchemy. There is no queue and no separate worker: a run executes inside the request that starts it, limited by a small gate (`engine/run_safety.py`).

## The flow of a run

```
data sources --> ingest --> facts graph --> DFD --> threats (derived) --> views and reports
                                              ^
                       your edits and stated facts (stored)
```

1. **Ingest** (`engine/ingest/`). Each data source type has an ingestor with the same three steps: fetch, parse and normalise. The types are `manifest_upload`, `github_repository`, `architecture_diagram` and `documentation`. `engine/orchestrator.py` holds the registry, `SUPPORTED_DATA_SOURCE_TYPES`, which is the single list of what can be ingested. Diagram formats live in `engine/ingest/diagrams/`. Secrets are redacted here, before anything is stored. What each source reads is in [data-sources.md](data-sources.md).
2. **Facts graph** (`engine/facts/`). Every ingestor produces the same shape: fact nodes and fact edges for one run, kept as a plain adjacency graph. Facts are the record of what the inputs said. Nothing downstream looks threats up from a stored table of component types.
3. **DFD** (`engine/dfd/`). A diagram is derived from the facts: only components that make sense on a diagram become boxes, and metadata such as namespaces, services and policies stays as facts that feed the rules. Your manual components, flows, trust-boundary overrides, hidden-on-this-diagram choices and stated properties are stored separately and merged over the derived diagram (`engine/dfd/merge.py`). The merged diagram is the one you see and the one threats are generated from.
4. **Rules and threats** (`engine/threats/`). Threats are **derived, never stored**. A pure function (`generate.py`) takes the merged diagram and the rule catalogs (STRIDE, any methodologies a plugin adds through `Plugin.methodologies`, plus your custom threat entries) and returns threats with stable keys. Configuration rules (`config_rules*.py`) read facts to find specific misconfigurations and cite their evidence. The open-source edition ships a small sample of them; a plugin can add more through `Plugin.config_rules`. `risk.py` scores likelihood from evidence such as exposure, stated weaknesses and findings. What *is* stored is your decisions: the status of each threat key, your custom threats, and action statuses. A small in-process cache (`cache.py`) avoids recomputing, and it is cleared on every write.
5. **Findings** (`engine/reasoning.py`). Scanner results, such as vulnerabilities from Grype, become findings. A finding never creates a threat. It raises the likelihood of a threat it supports.
6. **Everything else is computed on request** from the same inputs: completeness questions (`engine/completeness.py`), the action plan (`engine/action_plan.py`), attack paths (`engine/attack_paths.py`), run-to-run diffs (`engine/diff.py`), the CI gate (`engine/ci_gate.py`) and trend snapshots (`engine/trend.py`). Each run is stamped with the engine version, a hash of the rule catalogs and a digest of each source (`engine/provenance.py`), which is how staleness is detected.
7. **Reports** (`reporting/`). One report model feeds the HTML, Word (`python-docx`) and PDF (`reportlab`) renderers, plus CSV, SARIF, SVG and Threat Dragon JSON exports. They are pure Python, with no native rendering libraries, which keeps the image small.

## The web layer

`dashboard/` holds the app factory (`app.py`), cookie sessions with CSRF tokens, API tokens, the sign-in throttle, security headers, the request size limit, the audit middleware and the route modules (`routes/api_*.py`). Reads and writes of application data go through `storage/repository.py` (an interface) and `storage/sql_repo.py` (the SQLAlchemy implementation). Access to an application is decided in `dashboard/access.py`.

The experimental AI assist is isolated in `engine/llm/`. Every call goes through one policy module (`policy.py`). See [ai.md](ai.md).

## Plugin hooks

The core runs fully with no plugin. An optional Python package can extend it through the entry-point group `kresheen.plugins`. `src/kresheen/plugins.py` defines a `Plugin` base class in which every hook does nothing by default, and a plugin overrides only what it needs. A plugin that fails to load, or a hook that raises, is logged and skipped. It never stops the core.

The hooks cover: mounting routes, deciding access to applications and groups, extra sign-in methods, audit sinks, extra threat rules, action-plan guidance, report sections, dashboard sections, CLI commands, extra tables and migration trees, which API areas are threat-neutral (for the cache), and cleanup when an application, group or user is deleted. The web app has matching extension points (`frontend/src/extensions.ts`) for routes, navigation items, settings sections, model tabs and dashboard panels. Read `plugins.py` for the exact list and contracts.

## Migrations

The schema is built by Alembic migrations, never by `create_all`. Core revisions are in `src/kresheen/storage/migrations/versions/`. A plugin can add its own tree with its own version table, so trees upgrade independently. Migrations are forward-only. On start the app upgrades a single-instance database itself (backing up SQLite first), or only checks when `KRESHEEN_AUTO_MIGRATE=0`, and it refuses to start older code against a newer database. Any change to a table needs a new revision in the same change, and a test compares the models with the migrated schema. See [upgrading.md](upgrading.md).

## Where to start reading

- `src/kresheen/engine/orchestrator.py`: one run end to end.
- `src/kresheen/engine/threats/generate.py` and `catalog.py`: how rules become threats.
- `src/kresheen/dashboard/app.py`: how the web app is assembled.
- `frontend/src/pages/`: the pages of the web interface.
