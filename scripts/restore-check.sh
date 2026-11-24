#!/usr/bin/env bash
# Prove the newest database dump can be restored: load it into a throwaway database in the same PostgreSQL, count a few tables, drop it.
#   scripts/restore-check.sh            the newest dump: the nightly ones (CVENGINE_DB_BACKUP_DIR, default backups/db), else the update's
#                                       (.git/cvengine-update/backups) and automatic deployment's (.git/cvengine-auto-deploy/backups)
#   scripts/restore-check.sh FILE       that dump (.dump in custom format, or .sql.gz)
# The live database is only read (the same counts, for comparison). The throwaway database is named cvengine_restore_check_<pid>, and only a
# database with that exact name is ever dropped, also when the check fails or is interrupted. It needs free disk for one more copy of the
# database for a few minutes, and it loads the database server while it restores: run it in a quiet hour (make restore-check).
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

setting() {
    local value=${!1:-}
    if [[ -z $value && -f .env ]]; then
        value=$(grep -E "^$1=" .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
        value=${value#[\"\']}; value=${value%[\"\']}
    fi
    printf '%s' "${value:-$2}"
}

file=${1:-}
if [[ -z $file ]]; then
    dir=$(setting CVENGINE_DB_BACKUP_DIR backups/db)
    file=$(ls -1t "$dir"/cvengine-*.dump 2>/dev/null | head -n1 || true)
    [[ -n $file ]] || file=$(ls -1t .git/cvengine-update/backups/cvengine-*.sql.gz .git/cvengine-auto-deploy/backups/cvengine-*.sql.gz 2>/dev/null | head -n1 || true)
fi
[[ -n $file && -f $file ]] || { echo "No database dump found (looked in $(setting CVENGINE_DB_BACKUP_DIR backups/db) and the updaters' backup folders). Take one with: make db-backup" >&2; exit 1; }
case $file in
    *.dump) format=custom ;;
    *.sql.gz) format=sql ;;
    *) echo "$file is neither a .dump (custom format) nor a .sql.gz dump." >&2; exit 1 ;;
esac

. scripts/compose-layout.sh
cvengine_compose_layout || exit 1
db=$("${COMPOSE[@]}" ps -q --status running db 2>/dev/null | head -n1) || db=''
[[ -n $db ]] || { echo "No running database container." >&2; exit 1; }

scratch="cvengine_restore_check_$$"
psql_in() {  # psql_in DATABASE SQL: one statement as the owner role, unaligned output
    docker exec "$db" sh -c 'psql -X -q -tA -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$1" -c "$2"' sh "$1" "$2"
}
drop_scratch() {
    docker exec "$db" sh -c 'dropdb --if-exists -U "$POSTGRES_USER" "$1"' sh "$scratch" >/dev/null 2>&1 || \
        echo "Could not drop the throwaway database $scratch: drop it with DROP DATABASE $scratch;" >&2
}
trap drop_scratch EXIT
trap 'exit 130' INT TERM

echo "Restoring $file ($(du -h "$file" | cut -f1)) into the throwaway database $scratch ..."
docker exec "$db" sh -c 'createdb -U "$POSTGRES_USER" "$1"' sh "$scratch"
started=$SECONDS
if [[ $format == custom ]]; then
    docker exec -i "$db" sh -c 'pg_restore -U "$POSTGRES_USER" -d "$1" --no-owner --no-privileges --exit-on-error' sh "$scratch" < "$file"
else
    gzip -dc "$file" | docker exec -i "$db" sh -c 'psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$1"' sh "$scratch" >/dev/null
fi
echo "Restored in $((SECONDS - started)) s. Row counts, restored and (live):"

live=$(docker exec "$db" sh -c 'printf %s "$POSTGRES_DB"')
failed=0
for table in django_migrations auth_user dashboard_project targetApp_domain startScan_subdomain startScan_vulnerability cveFeed_cveentry; do
    sql="SELECT count(*) FROM \"$table\""
    restored=$(psql_in "$scratch" "$sql" 2>/dev/null) || restored='missing'
    now=$(psql_in "$live" "$sql" 2>/dev/null) || now='?'
    printf '  %-26s %10s  (%s)\n' "$table" "$restored" "$now"
    case $table:$restored in
        *:missing) failed=1 ;;
        django_migrations:0|auth_user:0) failed=1 ;;
    esac
done
if (( failed )); then
    echo "Restore check FAILED: a table is missing, or the migrations or users table is empty, in the restored copy." >&2
    exit 1
fi
echo "Restore check passed: $file restores and holds data. The throwaway database is dropped now."
