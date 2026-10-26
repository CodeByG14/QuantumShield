# QuantumShield database setup (database-only phase)

This setup provisions local PostgreSQL and its schema. It deliberately does **not** add a web backend, Python database integration, API endpoints, or changes to the scanning engine.

## Scope and data model

The first database schema has seven domain tables, plus `schema_migrations`:

- `projects`: durable project identity and archive state.
- `scan_runs`: execution state and non-secret input metadata; it does not store source bytes or temporary workspace paths.
- `assessments`: complete assessment JSONB snapshot plus a small summary and policy/schema versions.
- `assessment_findings`: indexed relational projection for finding searches, retaining complete finding and risk objects in JSONB.
- `migration_plans`: immutable plan snapshots and summary JSONB.
- `compliance_reports`: compliance report snapshots, optionally associated with a migration plan.
- `scan_diffs`: persisted comparison snapshots and summary counts.

The existing `docs/database-schema-week6.md` records a broader normalized design from an earlier planning stage. This migration implements the more recent agreed snapshot-plus-search-projection design; it does not silently rewrite that historical document. The more detailed context/evidence/risk-factor tables can be revisited as a separate schema-design decision before any backend integration.

## Start from a clean local setup

Requirements: Docker Engine and the Docker Compose plugin.

```bash
./scripts/db-init-env.sh
./scripts/db-up.sh
./scripts/db-migrate.sh
./scripts/db-verify.sh
```

`db-init-env.sh` generates a random local password and writes `.env` with file mode `0600`. `.env` is ignored by Git. The expected database is `quantumshielf_db`, user `postgres`, and host port `5433` bound to `127.0.0.1` only.

To inspect the database:

```bash
docker compose exec db psql -U postgres -d quantumshielf_db
```

Inside `psql`, use `\dt` to list tables and `\d+ assessment_findings` to inspect the finding projection. Exit using `\q`.

## Persistence and shutdown

The database uses a named Docker volume (`quantumshield_pgdata`), so ordinary container recreation does not delete data. Stop the service with:

```bash
docker compose down
```

**Do not use `docker compose down -v` unless you intend to permanently delete the local database volume.**

## Migrations

Migrations live in `db/migrations/`. The runner tracks each version and its SHA-256 checksum. Re-running it skips an unchanged applied migration; editing an applied migration causes it to stop. Add a new numbered migration for subsequent schema changes rather than changing an applied file.

## Security boundaries

- The database port is bound to `127.0.0.1`, not all network interfaces.
- Credentials stay in the untracked `.env` file; do not paste them into commits or issue logs.
- No private key material, source archives, or source directory contents are stored by this database setup.
- `input_name`, scan metadata, and report JSONB should still be treated as potentially sensitive application data.
- This setup does not add application credentials or remote database access; that belongs to a later, explicitly approved integration phase.
