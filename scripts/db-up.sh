#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "No .env found. Run ./scripts/db-init-env.sh first." >&2
  exit 1
fi
if ! grep -Eq '^POSTGRES_PASSWORD=.{2,}$' .env; then
  echo "POSTGRES_PASSWORD is missing or too short in .env." >&2
  exit 1
fi

docker compose up -d --wait db
echo "PostgreSQL is healthy. It is bound to localhost on port configured by POSTGRES_PORT (default 5433)."
echo "Next: ./scripts/db-migrate.sh"
