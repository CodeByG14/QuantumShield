#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "No .env found. Run ./scripts/db-init-env.sh first." >&2
  exit 1
fi
if ! docker compose ps --status running --services | grep -Fxq db; then
  echo "The database service is not running. Run ./scripts/db-up.sh first." >&2
  exit 1
fi

psql_base=(docker compose exec -T db psql -X -v ON_ERROR_STOP=1 -U postgres -d quantumshielf_db)
"${psql_base[@]}" -c "CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(20) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    checksum_sha256 VARCHAR(64) NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);"

shopt -s nullglob
migrations=("$ROOT"/db/migrations/[0-9][0-9][0-9]_*.sql)
if (( ${#migrations[@]} == 0 )); then
  echo "No numbered SQL migrations found under db/migrations/." >&2
  exit 1
fi

for migration in "${migrations[@]}"; do
  filename="$(basename "$migration")"
  version="${filename%%_*}"
  name="${filename#*_}"
  name="${name%.sql}"
  checksum="$(sha256sum "$migration" | awk '{print $1}')"
  applied_checksum="$("${psql_base[@]}" -At -c "SELECT checksum_sha256 FROM schema_migrations WHERE version = '${version}';" | tr -d '\r\n')"

  if [[ -n "$applied_checksum" ]]; then
    if [[ "$applied_checksum" != "$checksum" ]]; then
      echo "ERROR: migration $filename was already applied with a different checksum." >&2
      echo "Do not edit applied migrations; create a new numbered migration." >&2
      exit 1
    fi
    echo "Skipping already-applied migration $filename"
    continue
  fi

  echo "Applying migration $filename"
  {
    printf 'BEGIN;\n'
    cat "$migration"
    printf '\nINSERT INTO schema_migrations (version, name, checksum_sha256) VALUES (\047%s\047, \047%s\047, \047%s\047);\n' "$version" "$name" "$checksum"
    printf 'COMMIT;\n'
  } | "${psql_base[@]}"
done

echo "Database migrations are up to date."
"${psql_base[@]}" -c "SELECT version, name, applied_at FROM schema_migrations ORDER BY version;"
