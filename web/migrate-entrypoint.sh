#!/bin/bash
# The one-off migrate service (docker-compose.yml): the ONLY container that gets the database owner's password (POSTGRES_PASSWORD). It runs and
# exits; web, celery and celery-beat start after it (their depends_on, the update scripts, make up) and connect as the least privilege app role.
#
#   docker compose run --rm migrate                                   the migrations, then the app role's grants and login check (the default)
#   docker compose run --rm migrate python3 manage.py COMMAND ...     any other command as the owner: createsuperuser, create_admin,
#                                                                     showmigrations, db_app_role gate, test
#
# The check (manage.py db_app_role gate, cvengine/db_roles.py) exits 1 with the one-line fix when the app role cannot be used, so the application
# is never started with the owner password by accident; CVENGINE_DB_ALLOW_OWNER_FALLBACK=1 in .env is the explicit way to allow that.
set -Eeuo pipefail
export CVENGINE_DB_ROLE=owner
if [ "$#" -gt 0 ]; then
    exec "$@"
fi
python3 manage.py migrate --noinput
exec python3 manage.py db_app_role gate
