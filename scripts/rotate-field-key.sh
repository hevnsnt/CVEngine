#!/usr/bin/env bash
# Rotate the key that encrypts the stored API keys, webhook URLs and two-step sign-in seeds.
#   ./scripts/rotate-field-key.sh
# It puts a new CVENGINE_FIELD_KEY in .env (the old one moves to CVENGINE_FIELD_KEY_PREVIOUS, which only decrypts), recreates the
# services so they all use it, and re-encrypts every stored secret. Keep CVENGINE_FIELD_KEY_PREVIOUS until you have a database backup
# taken after this; then it can be removed. Back up .env together with the database.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo ".env not found: run this from the CVEngine directory of a running installation." >&2; exit 1; }

compose() { if docker compose version >/dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi; }
random() { head -c 256 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }
value_of() { grep -E "^$1=" .env | tail -n 1 | cut -d= -f2- || true; }
set_value() {
  local key=$1 value=$2 tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-env.XXXXXX")
  if grep -q "^${key}=" .env; then
    awk -v key="$key" -v value="$value" 'BEGIN { prefix = key "=" } index($0, prefix) == 1 { print prefix value; next } { print }' .env > "$tmp"
  else
    { cat .env; echo "${key}=${value}"; } > "$tmp"
  fi
  cat "$tmp" > .env
  rm -f "$tmp"
}

old=$(value_of CVENGINE_FIELD_KEY)
previous=$(value_of CVENGINE_FIELD_KEY_PREVIOUS)
new="$(random)$(random)"
if [ -n "$old" ]; then
  previous="${old}${previous:+,$previous}"
  set_value CVENGINE_FIELD_KEY_PREVIOUS "$previous"
fi
set_value CVENGINE_FIELD_KEY "$new"
echo "New key written to .env. Recreating the services so every one of them uses it..."
compose up -d --force-recreate web celery celery-beat
for _ in $(seq 1 60); do
  compose exec -T web python3 -c "print('ready')" >/dev/null 2>&1 && break
  sleep 2
done
compose exec -T web python3 manage.py rotate_field_key
echo "Done. Back up .env and the database now; CVENGINE_FIELD_KEY_PREVIOUS can be removed once that backup exists."
