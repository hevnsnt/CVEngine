#!/usr/bin/env bash
# A compressed dump of the database, taken by the update scripts just before they migrate it. A migration is never rolled back, so this is the
# only way back from a release whose migration goes wrong half way.
#   scripts/db-backup.sh STATE_DIR -- COMPOSE_COMMAND...
# STATE_DIR is the host-private update state directory (scripts/update-state.py directory); the dump goes to STATE_DIR/backups (mode 0700, the file
# 0600) and its path is the last line printed. COMPOSE_COMMAND is `docker compose` with the files, env file and project the install runs with.
# CVENGINE_UPDATE_BACKUPS (environment or .env) is how many dumps to keep: default 3, and 0 takes none (exit 0, prints nothing). Exit status 1 means
# the dump could not be made or did not verify: the caller must not migrate. The Django secret and .env are not in the dump; back them up apart.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# root (cron, systemd) in a checkout owned by whoever cloned it: git refuses it ("dubious ownership") unless this one is named
export GIT_CONFIG_COUNT=$(( ${GIT_CONFIG_COUNT:-0} + 1 ))
export "GIT_CONFIG_KEY_$((GIT_CONFIG_COUNT - 1))=safe.directory" "GIT_CONFIG_VALUE_$((GIT_CONFIG_COUNT - 1))=$PWD"
state=${1:?state directory}
shift
[[ ${1:-} == -- ]] && shift
(( $# )) || set -- docker compose

keep=${CVENGINE_UPDATE_BACKUPS:-}
if [[ -z $keep && -f .env ]]; then
    keep=$(grep -E '^CVENGINE_UPDATE_BACKUPS=' .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || keep=''
    keep=${keep#[\"\']}; keep=${keep%[\"\']}
fi
[[ $keep =~ ^[0-9]+$ ]] || keep=3
(( keep > 0 )) || exit 0

db=$("$@" ps -q --status running db 2>/dev/null | head -n1) || db=''
[[ -n $db ]] || { echo "No running database container to back up." >&2; exit 1; }
for _ in $(seq 1 30); do
    docker exec "$db" sh -c 'pg_isready -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1 && break
    sleep 2
done

mkdir -p "$state/backups"
chmod 700 "$state" "$state/backups"
file="$state/backups/cvengine-$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short=8 HEAD 2>/dev/null || echo unknown).sql.gz"
if ! (umask 077; docker exec "$db" sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > "$file") || ! gzip -t "$file" 2>/dev/null ||
        [[ $(gzip -dc "$file" 2>/dev/null | head -c 64 | wc -c) -lt 64 ]]; then
    rm -f "$file"
    echo "The database backup failed." >&2
    exit 1
fi
ls -1t "$state"/backups/cvengine-*.sql.gz 2>/dev/null | tail -n +"$((keep + 1))" | xargs -r rm -f
echo "$file"
