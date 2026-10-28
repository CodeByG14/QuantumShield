# QuantumShield backend — Phase 1

This phase adds the first FastAPI layer around the existing engine and database contracts. It does **not** rewrite discovery, scoring, compliance, migration planning, or comparison logic.

## Install runtime dependencies

From the QuantumShield repository root:

```bash
uv add 'fastapi>=0.115' 'uvicorn[standard]>=0.30' 'psycopg[binary,pool]>=3.2' 'python-multipart>=0.0.9'
```

The app expects the PostgreSQL settings already in the repository `.env`:

```dotenv
POSTGRES_DB=quantumshield_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your-local-password
POSTGRES_PORT=5433
# Optional; these are the default development frontend origins.
QUANTUMSHIELD_CORS_ORIGINS=http://127.0.0.1:5173,http://localhost:5173
```

`POSTGRES_HOST` defaults to `127.0.0.1`. An optional `DATABASE_URL` can override the individual settings. Do not commit `.env`. CORS only allows the explicitly listed origins; wildcard origins are rejected. Use the same hostname in the browser for frontend and API (both `127.0.0.1`, or both `localhost`) so the strict same-site session cookie is sent as intended. Browser `fetch` calls to the API must use `credentials: "include"`.

## Install files

After extracting this bundle, run its `apply_quantumshield_api.py` from the QuantumShield repository root. The installer checks that the engine/source/storage contracts and migration `002` are already present, then adds new API files without overwriting differing files.

## Start locally

Start PostgreSQL first, then run:

```bash
./scripts/db-verify.sh
uv run uvicorn quantumshield.api.app:app --host 127.0.0.1 --port 8000 --env-file .env
```

Open the interactive API reference at `http://127.0.0.1:8000/docs`. The server command binds to loopback intentionally. Do not expose this initial session model to a LAN or the public internet.

Run the focused backend tests with:

```bash
uv run pytest -q tests/api
```

## Root-level routes

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/health` | API/database check |
| `GET` | `/dashboard/summary` | Session-scoped project/scan totals and latest-assessment risk summary |
| `GET`, `PATCH` | `/session` | Create/read or label the anonymous local workspace session |
| `GET`, `POST` | `/projects` | List or create session-owned projects |
| `GET` | `/projects/{project_id}` | Get one owned project |
| `POST` | `/scan` | Queue one of four supported source types |
| `GET` | `/projects/{project_id}/scans` | List scan history |
| `GET` | `/scans/{scan_run_id}` | Check status/error/summary |
| `GET` | `/scans/{scan_run_id}/assessment` | Get the completed assessment |
| `GET` | `/assessments/{assessment_id}` | Get an assessment snapshot |
| `GET` | `/assessments/{assessment_id}/findings` | Filter/paginate searchable findings |
| `POST`, `GET` | `/plan`, `/plans/{plan_id}` | Generate and retrieve a migration plan |
| `POST`, `GET` | `/compliance`, `/compliance/{report_id}` | Generate and retrieve a compliance report |
| `POST`, `GET` | `/diff`, `/diffs/{diff_id}` | Compare two assessments from the same project and retrieve that comparison |

No `/api/v1/` prefix is used.

## `POST /scan` input contract

The request uses `multipart/form-data`:

- `source_type=github_repository` and `repository_url=https://github.com/owner/repository`, **or**
- `source_type=zip_archive` and a `.zip` upload, **or**
- `source_type=sbom` and a `.json` upload, **or**
- `source_type=cbom` and a `.json` upload.

Optional fields: `project_id` to attach the scan to an existing project, `project_name` and `description` when creating a project, and `context_json` containing a JSON object conforming to QuantumShield `ProjectContext`.

A new project is created when `project_id` is omitted. A fresh `workspace_id` UUID is generated per scan and used for `/tmp/quantumshield-workspaces/<workspace_id>` by default. The persistent `project_id`, scan-run UUID, workspace UUID and engine-generated assessment ID are distinct values. The database stores the workspace UUID, not the absolute path. The workspace is deleted on both successful and failed processing.

Upload limit: 50 MiB. ZIP extraction limits are 10,000 entries, 100 MiB per member and 500 MiB expanded overall. Archive traversal, symlink and special filesystem entries are rejected. GitHub input is limited to public HTTPS URLs on `github.com`; the backend does not accept credentials, query strings, fragments, non-canonical paths, or arbitrary hostnames.

### BOM import behavior

- **SBOM:** JSON in CycloneDX format or SPDX 2.x format. It emits potential inventory findings only for a bounded allowlist of recognizable cryptographic library packages. It does not infer algorithms from arbitrary dependency names. Package presence is not proof of runtime use.
- **CBOM:** CycloneDX JSON; imports components with `type=cryptographic-asset`. QuantumShield properties are preserved where compatible with the engine model. Findings from external BOMs are downgraded to potential unless a confirmed/high-confidence QuantumShield status is present.
- BOM scans preserve provenance limitations to make clear that the source code was not rescanned. They do not claim full SBOM/CBOM schema validation against every vendor extension.

## Session and data isolation

The browser receives an HTTP-only, `SameSite=Strict` opaque cookie. The database stores only its SHA-256 hash in `local_sessions.token_hash`. A session is anonymous and identifies a local browser workspace; it is **not** verified user authentication. New projects always record `session_id`, and all project/assessment/plan/report/diff retrieval routes check session ownership.

Assessment snapshots are produced with `assessment_snapshot_for_storage()`, which replaces the top-level temporary `target` path with `project:<project_id>` and rejects absolute or traversal evidence paths. Full assessment JSON and searchable finding/risk projections are stored in one transaction; a scan is marked completed only after persistence succeeds.

## Known initial limitations

- Scan processing uses FastAPI/Starlette in-process background tasks. It is suitable for the local prototype, but queued work is not durable across a process crash/restart. If this proves insufficient, add a worker queue in a later phase.
- There is no authentication beyond anonymous local session scoping.
- The public API intentionally does not accept arbitrary local paths, perform runtime scanning, or perform network/TLS endpoint scanning.
- SBOM package recognition is conservative and allowlist-based. A “no recognized cryptographic package” result is not proof of an absence of cryptographic usage.
- Database integration tests against your running PostgreSQL instance are still required after installing the code; the included unit/OpenAPI tests do not replace the existing database smoke tests.
