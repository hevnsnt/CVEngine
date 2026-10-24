#!/bin/bash
set -Eeuo pipefail

python3 manage.py migrate --noinput

case "${DEBUG:-0}" in
    1|true|True|yes)
        # development (docker-compose.dev.yml): auto-reloading server that also serves static files
        exec python3 manage.py runserver 0.0.0.0:8000
        ;;
    *)
        # production: a real WSGI server sized for the 1 GB web container: two worker processes with 8 threads each. The
        # MFA lockout counters live in the shared Redis cache (CACHES in settings.py), so workers do not multiply the allowed
        # attempts and a worker recycled by --max-requests does not reset them. The timeout matches the proxy's 300 s read timeout so a bulk add that checks many
        # targets is not cut off. Static files come from the nginx proxy (collectstatic runs in the celery
        # container), not from here.
        exec python3 -m gunicorn reNgine.wsgi:application \
            --bind 0.0.0.0:8000 \
            --worker-class gthread \
            --workers "${GUNICORN_WORKERS:-2}" \
            --threads "${GUNICORN_THREADS:-8}" \
            --timeout "${GUNICORN_TIMEOUT:-300}" \
            --graceful-timeout 30 \
            --max-requests 1000 --max-requests-jitter 100 \
            --worker-tmp-dir /dev/shm \
            --access-logfile -
        ;;
esac
