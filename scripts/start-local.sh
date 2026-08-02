#!/usr/bin/env bash
#
# Start jurivo-backend against the local docker-compose PostgreSQL.
#
#   ./scripts/start-local.sh          # dev profile
#   ./scripts/start-local.sh prod     # any other profile
#
# What this does beyond `./gradlew bootRun`:
#   - frees port 8080 if a previous run is still holding it
#   - starts PostgreSQL and waits until it genuinely accepts connections
#   - loads .env.local
#   - prints the URLs once the application reports healthy
#   - cleans up its background watcher on exit
set -euo pipefail

PROFILE="${1:-dev}"
PORT=8080
DB_PORT=5442
DB_USER=jurivo
DB_NAME=jurivo_dev

cd "$(dirname "$0")/.."

# Docker Compose v2 is a docker subcommand; v1 was a separate binary. Detecting both means the
# script fails with a clear message rather than "docker: 'compose' is not a docker command".
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: Docker Compose is not available. Install Docker Desktop, or start PostgreSQL yourself" >&2
  echo "       and point DB_URL at it." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: The Docker daemon is not running. Start Docker Desktop and try again." >&2
  exit 1
fi

# ---------------------------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------------------------

if [ -f .env.local ]; then
  echo "==> Loading .env.local"
  set -a
  # shellcheck disable=SC1091
  . ./.env.local
  set +a
fi

if [ -z "${JAVA_HOME:-}" ] && /usr/libexec/java_home -v 21 >/dev/null 2>&1; then
  JAVA_HOME="$(/usr/libexec/java_home -v 21)"
  export JAVA_HOME
fi

# The dev profile supplies placeholder Cognito values so the application starts without a real
# user pool — token decoding is lazy, so nothing contacts AWS until a token arrives. Any other
# profile has no defaults, deliberately: a wrong issuer does not error, it rejects every token.
if [ "$PROFILE" != "dev" ] && [ -z "${COGNITO_ISSUER_URI:-}" ]; then
  echo "ERROR: profile '$PROFILE' requires COGNITO_ISSUER_URI and COGNITO_CLIENT_IDS." >&2
  echo "       Set them in .env.local (see .env.example), or run with the dev profile." >&2
  exit 1
fi

# ---------------------------------------------------------------------------------------------
# Free the port
#
# Almost always a previous run of this script. Killing whatever holds the port unconditionally
# would be a nasty surprise for anyone running something unrelated there, so this only stops a
# JVM — anything else is reported and left alone.
# ---------------------------------------------------------------------------------------------

PID="$(lsof -ti :"$PORT" 2>/dev/null || true)"
if [ -n "$PID" ]; then
  HOLDER="$(ps -p "$PID" -o comm= 2>/dev/null || echo unknown)"
  case "$HOLDER" in
    *java*)
      echo "==> Stopping the previous backend on :$PORT (pid $PID)"
      kill "$PID" 2>/dev/null || true
      for _ in $(seq 1 10); do
        lsof -ti :"$PORT" >/dev/null 2>&1 || break
        sleep 1
      done
      # Only escalate if it ignored SIGTERM. A graceful shutdown drains in-flight requests.
      if lsof -ti :"$PORT" >/dev/null 2>&1; then
        echo "    it did not stop; forcing"
        kill -9 "$PID" 2>/dev/null || true
        sleep 1
      fi
      ;;
    *)
      echo "ERROR: port $PORT is held by '$HOLDER' (pid $PID), which is not a JVM." >&2
      echo "       Refusing to kill it. Stop it yourself, or free the port." >&2
      exit 1
      ;;
  esac
fi

# ---------------------------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------------------------

if "${COMPOSE[@]}" ps --status running postgres 2>/dev/null | grep -q postgres; then
  echo "==> PostgreSQL already running on :$DB_PORT"
else
  echo "==> Starting PostgreSQL on :$DB_PORT"
  "${COMPOSE[@]}" up -d postgres
fi

# Waiting on pg_isready rather than sleeping: the container reports "up" well before the server
# accepts connections, and the resulting Flyway failure reads like a migration bug rather than
# the race it is.
echo -n "==> Waiting for PostgreSQL"
READY=false
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T postgres pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
    READY=true
    break
  fi
  echo -n "."
  sleep 1
done
echo

if [ "$READY" != true ]; then
  echo "ERROR: PostgreSQL did not become ready. Check: ${COMPOSE[*]} logs postgres" >&2
  exit 1
fi
echo "    ready"

# ---------------------------------------------------------------------------------------------
# Startup summary
#
# Printed by a background watcher once /actuator/health answers, so the URLs appear when they
# actually work rather than scrolled off the top of the Spring banner.
# ---------------------------------------------------------------------------------------------

print_summary() {
  local cognito_note="configured"
  if [ -z "${COGNITO_USER_POOL_ID:-}" ]; then
    # Worth saying plainly: without a pool, sign-in and every user-management operation fails.
    # The rest of the application — schema, RLS, organizations — works fine.
    cognito_note="NOT configured — sign-in and user management will fail (see .env.example)"
  fi

  cat <<SUMMARY

==================================================
  Jurivo backend — local (profile: $PROFILE)
==================================================

  PostgreSQL   localhost:$DB_PORT  ($DB_NAME)
  Cognito      $cognito_note

  GraphQL      http://localhost:$PORT/graphql
  GraphiQL     http://localhost:$PORT/graphiql
  Swagger UI   http://localhost:$PORT/swagger-ui.html
  Health       http://localhost:$PORT/actuator/health
  Version      http://localhost:$PORT/api/version

  Stop with Ctrl-C. PostgreSQL keeps running: ${COMPOSE[*]} down

==================================================

SUMMARY
}

watch_for_startup() {
  for _ in $(seq 1 180); do
    if curl -sf "http://localhost:$PORT/actuator/health" >/dev/null 2>&1; then
      print_summary
      return
    fi
    sleep 1
  done
  # Bounded rather than a `while true`: if startup fails, the watcher must not outlive it and
  # sit there forever waiting for a health check that will never answer.
}

watch_for_startup &
WATCHER_PID=$!

cleanup() {
  kill "$WATCHER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------------------------

echo "==> Starting jurivo-backend on :$PORT (profile: $PROFILE)"
./gradlew bootRun --args="--spring.profiles.active=$PROFILE"
