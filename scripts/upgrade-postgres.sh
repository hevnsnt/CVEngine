#!/usr/bin/env bash
# One-time upgrade of CVEngine's database from PostgreSQL 12 to 18.
#
# PostgreSQL cannot open another major version's data directory, so this dumps the old database and loads it into a
# new volume (postgres18_data). The old volume is NOT touched or deleted, so you can roll back by checking out the
# previous commit. Run it from the repository root after pulling, BEFORE `docker compose up`:
#
#   scripts/upgrade-postgres.sh                # production compose file
#   scripts/upgrade-postgres.sh --dev          # docker-compose.dev.yml
#
# A fresh install (no old volume) needs nothing: the new database is created empty.
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE_FILE_ARG="-f docker-compose.yml"
[ "${1:-}" = "--dev" ] && COMPOSE_FILE_ARG="-f docker-compose.dev.yml"
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
DC="$DC $COMPOSE_FILE_ARG"

# empty (not a failure under pipefail) when .env or the variable is missing, so the defaults below apply
env_value() { grep -E "^$1=" .env 2>/dev/null | head -n1 | cut -d= -f2- || true; }
PROJECT=$(env_value COMPOSE_PROJECT_NAME); PROJECT=${PROJECT:-rengine}
PGUSER=$(env_value POSTGRES_USER); PGUSER=${PGUSER:-rengine}
PGDB=$(env_value POSTGRES_DB); PGDB=${PGDB:-rengine}
OLD_VOLUME="${PROJECT}_postgres_data"
NEW_VOLUME="${PROJECT}_postgres18_data"
OLD_IMAGE="postgres:12.3-alpine"
STAMP=$(date +%Y%m%d-%H%M%S)
DUMP="backups/pg12-${STAMP}.dump"

if ! docker volume inspect "$OLD_VOLUME" >/dev/null 2>&1; then
  echo "No old database volume ($OLD_VOLUME): nothing to upgrade. 'docker compose up' creates a new, empty database."
  exit 0
fi
if docker volume inspect "$NEW_VOLUME" >/dev/null 2>&1; then
  echo "The new volume $NEW_VOLUME already exists, so the upgrade was already done: nothing to do."
  echo "The old volume $OLD_VOLUME is still there; once you are satisfied, reclaim the space:  docker volume rm $OLD_VOLUME"
  echo "(To redo the upgrade from the old volume, remove the new one first, only if it holds no data you need:  docker volume rm $NEW_VOLUME)"
  exit 0
fi

echo "1/5 Stopping the application so nothing writes during the dump"
$DC stop web celery celery-beat 2>/dev/null || true
# also stop the database container (and anything else still using the old volume): two PostgreSQL servers
# must never run on one data directory
$DC stop db 2>/dev/null || true
OLD_USERS=$(docker ps -q --filter "volume=$OLD_VOLUME" 2>/dev/null || true)
[ -z "$OLD_USERS" ] || docker stop $OLD_USERS >/dev/null 2>&1 || true

echo "2/5 Starting the old PostgreSQL 12 on the old volume (read for dumping only)"
docker rm -f cvengine-pg12-dump >/dev/null 2>&1 || true
docker run -d --name cvengine-pg12-dump -v "$OLD_VOLUME":/var/lib/postgresql/data "$OLD_IMAGE" >/dev/null
trap 'docker rm -f cvengine-pg12-dump >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 60); do
  docker exec cvengine-pg12-dump pg_isready -U "$PGUSER" -d "$PGDB" >/dev/null 2>&1 && break
  sleep 2
done
docker exec cvengine-pg12-dump pg_isready -U "$PGUSER" -d "$PGDB" >/dev/null

echo "3/5 Dumping to $DUMP"
mkdir -p backups
docker exec cvengine-pg12-dump pg_dump -U "$PGUSER" -d "$PGDB" -Fc -f /tmp/cvengine.dump
docker cp cvengine-pg12-dump:/tmp/cvengine.dump "$DUMP"
docker rm -f cvengine-pg12-dump >/dev/null
trap - EXIT
[ -s "$DUMP" ] || { echo "The dump is empty; stopping. The old volume is untouched."; exit 1; }

echo "4/5 Starting PostgreSQL 18 on the new volume"
$DC up -d db
for _ in $(seq 1 60); do
  $DC exec -T db pg_isready -U "$PGUSER" -d "$PGDB" >/dev/null 2>&1 && break
  sleep 2
done
$DC exec -T db pg_isready -U "$PGUSER" -d "$PGDB" >/dev/null

echo "5/5 Loading the dump into PostgreSQL 18"
DB_CONTAINER=$($DC ps -q db)
docker cp "$DUMP" "$DB_CONTAINER":/tmp/cvengine.dump
$DC exec -T db pg_restore -U "$PGUSER" -d "$PGDB" --clean --if-exists --no-owner --exit-on-error /tmp/cvengine.dump
$DC exec -T db rm -f /tmp/cvengine.dump
ROWS=$($DC exec -T db psql -U "$PGUSER" -d "$PGDB" -Atc "select count(*) from django_migrations" | tr -d '[:space:]')

echo
echo "Done: PostgreSQL 18 holds the data ($ROWS applied migrations). Start everything with:  $DC up -d --build"
echo "A copy of the old database is in $DUMP and the old volume $OLD_VOLUME is untouched."
echo "When you are satisfied, reclaim the space:  docker volume rm $OLD_VOLUME"
