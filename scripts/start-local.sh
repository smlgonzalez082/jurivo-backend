#!/usr/bin/env bash
# Start the backend against the local docker-compose Postgres.
#
# Waits for the database to be genuinely accepting connections before starting, rather than
# assuming `docker compose up -d` means "ready" — it does not, and the resulting Flyway failure
# looks like a migration bug rather than a race.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f .env.local ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env.local
  set +a
fi

export JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 21 2>/dev/null || echo "$JAVA_HOME")}"

echo "==> Starting PostgreSQL"
docker compose up -d postgres

echo "==> Waiting for PostgreSQL to accept connections"
for _ in $(seq 1 30); do
  if docker compose exec -T postgres pg_isready -U jurivo -d jurivo_dev >/dev/null 2>&1; then
    echo "    ready"
    break
  fi
  sleep 1
done

echo "==> Starting jurivo-backend on :8080"
./gradlew bootRun
