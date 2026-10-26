#!/usr/bin/env bash
# Installs the released version the way a user does: init-env, certificates, up, admin. "overlay" installs it behind a host proxy: an overlay
# compose file that publishes the proxy on 127.0.0.1:18443 instead of 0.0.0.0:443, its own env file, and the layout named in .env.
set -euo pipefail
. "$GITHUB_WORKSPACE/.github/rehearsal/lib.sh"
echo "$1" > "$HOME/mode"
cd "$HOME/cvengine"
./scripts/init-env.sh
make certs
if [ "$1" = overlay ]; then
  cat > docker-compose.vps.yml <<'YML'
services:
  proxy:
    ports: !override
      - "127.0.0.1:18443:443"
YML
  {
    echo 'CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.vps.yml'
    echo 'CVENGINE_COMPOSE_ENV_FILE=.env.vps'
    echo 'CVENGINE_COMPOSE_PROJECT=cvengine'
  } >> .env
  cp .env .env.vps
  python3 scripts/update-state.py commit "$(git rev-parse HEAD)"
  dc up -d --build
else
  make up
fi
wait_for_site 900
dc exec -T web python3 manage.py create_admin >/dev/null
dc ps
