#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

"$ROOT/scripts/db-migrate.sh"
echo "Running database schema and relationship smoke tests..."
cat "$ROOT/db/tests/schema_smoke.sql" | docker compose exec -T db \
  psql -X -v ON_ERROR_STOP=1 -U postgres -d quantumshield_db
