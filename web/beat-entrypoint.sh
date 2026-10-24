#!/bin/bash
set -Eeuo pipefail

# web owns migrations; wait until they are applied (avoids concurrent-migrate race)
for attempt in {1..60}; do
    if python3 manage.py migrate --check >/dev/null 2>&1; then
        exec "$@"
    fi
    echo "Waiting for web to apply migrations (attempt $attempt/60)..."
    sleep 3
done
echo "Celery Beat could not confirm migrations within three minutes." >&2
exit 1
