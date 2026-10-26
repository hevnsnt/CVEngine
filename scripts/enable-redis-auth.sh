#!/usr/bin/env bash
# Put a password on the Redis broker of an installation that was set up without one.
#   ./scripts/enable-redis-auth.sh
# It writes REDIS_PASSWORD to .env (a value already there is kept) and, when the installation runs with another Compose env file (an overlay's
# .env.vps), to that file too: Compose reads ${REDIS_PASSWORD} from the env file it is given, not from .env. It recreates Redis and every service that talks to it, so they all
# agree. Running work and queued tasks are lost, as with any restart of the broker: run it when scans are idle or paused. New
# installations get the password from ./scripts/init-env.sh and do not need this.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo ".env not found: run this from the CVEngine directory of a running installation." >&2; exit 1; }

# recreate services with the Compose files, env file and project the installation runs with (an overlay must not be dropped)
. scripts/compose-layout.sh
cvengine_compose_layout || exit 1
compose() { "${COMPOSE[@]}" "$@"; }
random() { head -c 256 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32; }
value_of() { grep -E "^$1=" .env | tail -n 1 | cut -d= -f2- || true; }
set_value() {
  local key=$1 value=$2 file=${3:-.env} tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-env.XXXXXX")
  if grep -q "^${key}=" "$file"; then
    awk -v key="$key" -v value="$value" 'BEGIN { prefix = key "=" } index($0, prefix) == 1 { print prefix value; next } { print }' "$file" > "$tmp"
  else
    { cat "$file"; echo "${key}=${value}"; } > "$tmp"
  fi
  cat "$tmp" > "$file"
  rm -f "$tmp"
}

password=$(value_of REDIS_PASSWORD)
if [ -n "$password" ]; then
  echo "REDIS_PASSWORD is already set in .env; recreating the services so they all use it."
else
  password=$(random)
  set_value REDIS_PASSWORD "$password"
  echo "REDIS_PASSWORD written to .env."
fi
if [ -n "${COMPOSE_ENV_FILE:-}" ] && [ "$COMPOSE_ENV_FILE" != .env ]; then
  set_value REDIS_PASSWORD "$password" "$COMPOSE_ENV_FILE"
  echo "REDIS_PASSWORD written to $COMPOSE_ENV_FILE, the env file this installation's Compose files are read with."
fi
services=(redis web celery celery-beat)
compose config --services | grep -qx proxy && services+=(proxy)
compose up -d --force-recreate "${services[@]}"
echo "Done. Redis now refuses connections without the password."
