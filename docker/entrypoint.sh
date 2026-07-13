#!/bin/sh
# Container entrypoint for the local compose stack. Runs the service migrations
# against the compose Postgres, then execs the server. golang-migrate tracks
# applied versions in OMNISURG_MIGRATIONS_TABLE, so a restart re-runs "up" as a
# no-op. OMNISURG_DATABASE_URL and OMNISURG_MIGRATIONS_TABLE come from compose.
set -e

if [ -z "${OMNISURG_DATABASE_URL}" ]; then
  echo "entrypoint: OMNISURG_DATABASE_URL is not set" >&2
  exit 1
fi
if [ -z "${OMNISURG_MIGRATIONS_TABLE}" ]; then
  echo "entrypoint: OMNISURG_MIGRATIONS_TABLE is not set" >&2
  exit 1
fi

echo "entrypoint: applying migrations (table ${OMNISURG_MIGRATIONS_TABLE})"
/app/migrate -path /app/migrations \
  -database "${OMNISURG_DATABASE_URL}&x-migrations-table=${OMNISURG_MIGRATIONS_TABLE}" up
echo "entrypoint: migrations applied, starting server"

exec /app/server
