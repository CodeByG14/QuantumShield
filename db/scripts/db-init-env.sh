#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -e .env ]]; then
  echo ".env already exists; leaving it unchanged."
  exit 0
fi

umask 077
password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
cat > .env <<EOF
POSTGRES_DB=quantumshielf_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=${password}
POSTGRES_PORT=5433
EOF
chmod 600 .env
echo "Created .env with a newly generated local PostgreSQL password (not printed)."
echo "The .env file is ignored by Git; keep it private."
