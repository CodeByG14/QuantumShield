# Database migrations

- SQL migrations are numbered, for example `001_initial.sql`, `002_add_something.sql`.
- `scripts/db-migrate.sh` creates `schema_migrations`, applies each unapplied migration in a transaction, and records its SHA-256 checksum.
- Re-running the migration command skips migrations already applied with the same checksum.
- If an applied migration file is edited, the runner stops and reports a checksum mismatch. Add a new migration instead.
- Run migrations against a backed-up database before applying changes to any non-disposable environment.
- The database phase is intentionally independent of the Python engine and web backend.
