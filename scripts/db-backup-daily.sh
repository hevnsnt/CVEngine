#!/usr/bin/env bash
# The daily database dump: one pg_dump in PostgreSQL's custom format (compressed, restorable table by table with pg_restore), kept for a number of
# days, in a folder of its own that holds no keys.
#   scripts/db-backup-daily.sh                  take today's dump and remove the ones older than the kept days
#   scripts/db-backup-daily.sh --label NAME     take a dump named after NAME (scripts/rotate-secrets.sh uses before-rotation); prunes nothing
# scripts/install-db-backup.sh puts the first form in root's crontab (03:17 every night); `make db-backup` runs it once.
# Settings (environment or .env):
#   CVENGINE_DB_BACKUP_DIR   where the dumps go (default backups/db in this checkout). The folder is made mode 0700 and each dump 0600.
#   CVENGINE_DB_BACKUP_DAYS  days a dump is kept (default 7). 0 turns the nightly dump off (a --label dump is still taken).
# The dump holds the database only. .env (CVENGINE_FIELD_KEY) and web/secret are never written here: a dump stored beside the key that decrypts
# its stored secrets gives them away (docs/DEPLOYMENT.md, Backups). The path of the new dump is the last line printed. Exit status 1: no dump was
# made or it did not verify; nothing older is removed then.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

label=''
while (( $# )); do
    case $1 in
        --label) label=${2:?--label needs a name}; shift 2 ;;
        -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -z $label || $label =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo "--label takes lowercase letters, digits and hyphens (got '$label')." >&2; exit 2; }

setting() {  # setting NAME DEFAULT: the environment, else .env, else the default
    local value=${!1:-}
    if [[ -z $value && -f .env ]]; then
        value=$(grep -E "^$1=" .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
        value=${value#[\"\']}; value=${value%[\"\']}
    fi
    printf '%s' "${value:-$2}"
}
dir=$(setting CVENGINE_DB_BACKUP_DIR backups/db)
days=$(setting CVENGINE_DB_BACKUP_DAYS 7)
[[ $days =~ ^[0-9]+$ ]] || days=7
if [[ -z $label ]] && (( days == 0 )); then
    echo "CVENGINE_DB_BACKUP_DAYS=0: the nightly dump is off."
    exit 0
fi

. scripts/compose-layout.sh
cvengine_compose_layout || exit 1
db=$("${COMPOSE[@]}" ps -q --status running db 2>/dev/null | head -n1) || db=''
[[ -n $db ]] || { echo "No running database container to back up." >&2; exit 1; }
for _ in $(seq 1 30); do
    docker exec "$db" sh -c 'pg_isready -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1 && break
    sleep 2
done

(umask 077; mkdir -p "$dir")
chmod 700 "$dir"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
file="$dir/cvengine-$stamp${label:+-$label}.dump"
partial="$file.partial"
# As the owner role (pg_dump inside the db container, as the update's dump does): it can read every table. --no-owner and --no-privileges are
# left to the restore, so the dump is complete.
if ! (umask 077; docker exec "$db" sh -c 'pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB"' > "$partial") ||
        [[ ! -s $partial ]] ||
        [[ $(docker exec -i "$db" pg_restore --list < "$partial" 2>/dev/null | grep -c ' TABLE DATA ') -lt 1 ]]; then
    rm -f -- "$partial"
    echo "The database dump failed or did not verify (pg_restore --list found no table data)." >&2
    exit 1
fi
mv -f -- "$partial" "$file"
chmod 600 "$file"
if [[ -z $label ]]; then
    # only after a good dump, and never the dump just made: a run of failed nights must not empty the folder
    find "$dir" -maxdepth 1 -type f -name 'cvengine-*.dump' -mtime +"$((days - 1))" ! -path "$file" -print -delete | sed 's/^/Removed old dump /'
fi
echo "$file"
