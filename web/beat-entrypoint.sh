#!/bin/bash
set -Eeuo pipefail

# The database role Beat runs as (web/db-role.sh): the least privilege app role, which the one-off migrate service created and checked before this
# started; the owner role only when CVENGINE_DB_ALLOW_OWNER_FALLBACK=1 made the migrate service hand it over, said in the log.
. "$(dirname "$0")/db-role.sh" && cvengine_db_role "${CVENGINE_DB_ROLE_WAIT:-60}"

# The migrate service owns migrations; wait until they are applied.
# The check's own output is kept (last lines only, no secrets: Django prints migration names and database error text) so a loop of
# "Waiting for the database migrations" says WHY the check fails (pending migration, database unreachable, settings error)
# instead of hiding it; the check can take 30 s on a busy host, so each attempt is logged with its exit status.
for attempt in {1..60}; do
    # as this container's role: migrate --check only reads django_migrations
    if out=$(python3 manage.py migrate --check 2>&1); then
        exec "$@"
    else
        status=$?
    fi
    echo "Waiting for the database migrations (attempt $attempt/60, migrate --check exit $status; the one-off migrate service applies them)..."
    printf '%s\n' "$out" | grep -v '^weasyprint' | tail -n 5 | sed 's/^/  migrate --check: /'
    sleep 3
done
echo "Celery Beat could not confirm migrations within the wait." >&2
exit 1
