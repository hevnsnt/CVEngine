#!/bin/bash
set -Eeuo pipefail

# web owns migrations; wait until they are applied (avoids concurrent-migrate race)
# The check's own output is kept (last lines only, no secrets: Django prints migration names and database error text) so a loop of
# "Waiting for web to apply migrations" says WHY the check fails (pending migration, database unreachable, settings error)
# instead of hiding it; the check can take 30 s on a busy host, so each attempt is logged with its exit status.
for attempt in {1..60}; do
    if out=$(python3 manage.py migrate --check 2>&1); then
        exec "$@"
    else
        status=$?
    fi
    echo "Waiting for web to apply migrations (attempt $attempt/60, migrate --check exit $status)..."
    printf '%s\n' "$out" | grep -v '^weasyprint' | tail -n 5 | sed 's/^/  migrate --check: /'
    sleep 3
done
echo "Celery Beat could not confirm migrations within the wait." >&2
exit 1
