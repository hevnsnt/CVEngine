#!/usr/bin/env bash
# Replace the default login of the OpenVAS add-on with a generated one and save it (encrypted) in cvENGINE. Run it once after `make openvas-up`, when gvmd
# is up (the first start also loads the feeds, which takes a long time; this can be done before that ends).
#   ./scripts/openvas-user.sh            (or: make openvas-user)
# Greenbone's community containers create the user admin with the password admin. This signs in once with that default over gvmd's socket, sets a random
# password through GMP (so it never appears on a command line, where every process could read it) and stores it where only cvENGINE reads it. It runs in the
# celery container, the only one that mounts gvmd's socket, and prints nothing but the user name. If the default login no longer works the password was
# already changed: save the one you chose with `printf '%s' "$PASSWORD" | docker compose exec -T web python3 manage.py openvas_credentials --username admin`.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/compose-layout.sh
cvengine_compose_layout || exit 1
"${COMPOSE[@]}" exec -T celery python3 manage.py openvas_bootstrap
