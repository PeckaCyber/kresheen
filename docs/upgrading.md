# Upgrading Kresheen

Kresheen keeps all of its data in one database (SQLite by default, PostgreSQL for larger or Kubernetes installs).
New releases sometimes change the shape of that database. This page explains how those changes are applied and what
to do before you upgrade.

## Before you upgrade: back up

Always take a backup first. Upgrades only go forward, so a backup is the way back.

- **SQLite:** stop Kresheen and copy the database file (for example `kresheen.db`), or use `sqlite3 kresheen.db ".backup kresheen.bak"`. Kresheen also makes its own copy before applying a change (see below), but your own backup, kept somewhere else, is the one to trust.
- **PostgreSQL:** run `pg_dump` (or take a snapshot with your database service). Kresheen does not back up PostgreSQL for you.

Also keep your `KRESHEEN_SECRET_KEY`. Without it, stored credentials cannot be read.

## What happens when you start a new version

By default Kresheen checks the database when it starts and brings it up to date on its own (`KRESHEEN_AUTO_MIGRATE=1`).

| Situation | What Kresheen does |
|---|---|
| New, empty database | Builds the current schema and starts. |
| Database already current | Starts. Nothing is changed and no backup is made. |
| Database from an older release | Applies the missing changes in order, then starts. |
| Database from a newer release | Refuses to start. It tells you which revision the database is at and which this version knows. Run the newer release again, or restore a backup. The database is not touched. |
| Database from before versioned schemas (see below) | Refuses to start with an explanation. The database is not touched. |

**SQLite backup.** Before applying changes to an existing SQLite database, Kresheen copies it to
`<database>.pre-<revision>.bak` next to the file (owner-only permissions), using SQLite's online backup so the copy is
consistent even while the database is in use. The three newest copies are kept. If the copy cannot be made, the upgrade
does not run.

**PostgreSQL.** Kresheen takes a database-wide lock while it upgrades, so several copies starting together do not
migrate at the same time: one does the work and the rest wait, then find nothing left to do. The log reminds you that
backups are yours.

To see where a database stands, or to run the upgrade yourself:

```
kresheen db current     # the recorded revision of each schema
kresheen db history     # the revisions this version knows
kresheen db upgrade     # apply any missing changes (SQLite is backed up first)
```

All of these accept `--db <url>` and read `KRESHEEN_DB_URL`. If the Pro plugin is installed and licensed, they cover its
tables too. Core and Pro keep separate revision records and upgrade independently.

## Turning automatic upgrades off

Set `KRESHEEN_AUTO_MIGRATE=0` to make startup read-only with respect to the schema. Kresheen then only checks that the
database is current, and refuses to start, saying to run `kresheen db upgrade`, if it is not. Use this when you want to
run upgrades as a separate, deliberate step.

## Kubernetes (Helm)

With an external database (`postgresql.enabled=false`) the chart runs `kresheen db upgrade` in a Job before each
install and upgrade (a `pre-install,pre-upgrade` hook), using the same image as the Deployment. The Deployment itself
runs with `KRESHEEN_AUTO_MIGRATE=0`, so pods never race to migrate and an out-of-date database stops them from
starting. If the Job fails, the release fails and the old pods keep running; read the Job's logs.

With the bundled development PostgreSQL there is no Job (the database does not exist yet when install hooks run) and the
pod upgrades the schema itself on startup. The bundled database is for trials only.

Take a `pg_dump` before running `helm upgrade`.

## Why there are no downgrades

Schema changes can rewrite stored data, and a rewritten record cannot always be turned back into the old one. A downgrade
path that sometimes loses data is worse than none, so Kresheen only goes forward and refuses to run old code against a
newer database. To go back, restore the backup you took before the upgrade and run the older release.

## A database from before v1.0.0

Databases created by pre-release builds have tables but no revision record, and Kresheen will not guess at their shape.
There is no supported upgrade for them. Export what you need and start with a fresh database.

If the database is your own development or demo database, and it was created by the current pre-release code,
`kresheen db stamp-baseline` can adopt it: it compares the live tables, columns and indexes with the v1.0.0 baseline,
stops and lists every difference if there is any, and only if everything matches records the baseline revision. Back up
first. It is meant for that one case, not as a general repair tool.

## For contributors

The schema is built by migrations, never by `create_all`. Revisions live in `src/kresheen/storage/migrations/versions/`.
Kresheen Pro has its own migrations and upgrades with the same command.

- **Any change to a table** (a column, an index, a new table) needs a new revision in the same change. A test compares the models with the migrated schema on SQLite and PostgreSQL and fails if they differ. To draft one: `KRESHEEN_DB_URL=sqlite:////tmp/scratch.db PYTHONPATH=src alembic upgrade head`, then `... alembic revision --autogenerate -m "add x"`. Read and edit the result; autogenerate does not see data changes or renames.
- **Never edit a released revision.** Add a new one.
- **Changing the shape of a field inside a JSON `data` blob** (renaming or removing a field, changing its type, splitting it) needs a data migration that rewrites the stored rows in batches (select a page of rows ordered by `id`, rewrite each blob, update, repeat), so a large database never loads whole into memory. A new field with a default value needs nothing: the model fills it in when old rows are read. Test it by building a database at the previous revision, upgrading, and reading the records back through the repository (see `tests/unit/test_migrations.py`).
- Revisions are forward-only: no `downgrade()`.
- SQLite cannot alter most things in place; `render_as_batch=True` makes Alembic rebuild the table. Check any hand-written change on both SQLite and PostgreSQL.
