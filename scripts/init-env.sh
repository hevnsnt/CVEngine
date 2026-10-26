#!/usr/bin/env bash
# Prepare .env for a first start: create it from .env.example when it is missing, then replace the example placeholders of the
# secrets nobody should have to invent (the database and certificate-authority passwords) with random ones. A value that is
# already set is never touched, so this is safe to run again, and an installation that is already running keeps its passwords.
# DOMAIN_NAME, the one setting a person used to have to edit, is detected when it is still the example: the address this machine
# is reached on (or a name given as the first argument or in CVENGINE_DOMAIN). The certificate is made for it, with the loopback
# names added, so https://<that address>/ and https://localhost/ both work.
# The admin password is not here: `make admin` creates the account and prints its password once.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { (umask 077; cp .env.example .env); echo "Created .env from .env.example."; }

# letters and digits only: a `$` or `#` in .env breaks Make and Compose parsing
random() { head -c 256 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

set_value() {
  local key=$1 value=$2 tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-env.XXXXXX")
  if grep -q "^${key}=" .env; then
    awk -v key="$key" -v value="$value" 'BEGIN { prefix = key "=" } index($0, prefix) == 1 { print prefix value; next } { print }' .env > "$tmp"
  else
    { cat .env; echo "${key}=${value}"; } > "$tmp"
  fi
  cat "$tmp" > .env  # keeps the file's own mode and owner, which mv would replace
  rm -f "$tmp"
}

fill() {
  local key=$1
  # an empty value, or the example's "change-me": anything else is the owner's and stays
  if grep -qiE "^${key}=(.*change-me.*)?$" .env; then
    set_value "$key" "$(random)"
    echo "Generated ${key}."
  fi
}

# The key that encrypts the stored API keys, webhook URLs and TOTP seeds, apart from Django's secret. A value already set is
# never changed (that is what rotation is for: manage.py rotate_field_key); values stored before it existed still read.
grep -q '^CVENGINE_FIELD_KEY=' .env || echo 'CVENGINE_FIELD_KEY=' >> .env
fill CVENGINE_FIELD_KEY

# The password of the Redis broker (queues, caches and counters). A first start gets one. An installation that already has containers
# keeps its open broker until ./scripts/enable-redis-auth.sh is run, which also recreates the services: the broker and its clients
# must change together, and the updater never recreates Redis.
grep -q '^REDIS_PASSWORD=' .env || echo 'REDIS_PASSWORD=' >> .env
if ! { command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q 'redis'; }; then
  fill REDIS_PASSWORD
fi

# The address other machines reach this one on: the source of the default route, else the first non-loopback address, else localhost.
detect_host() {
  local ip=''
  if [ -n "${CVENGINE_DETECT_IP+x}" ]; then
    ip=$CVENGINE_DETECT_IP
  else
    if command -v ip >/dev/null 2>&1; then
      ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')
    fi
    if [ -z "$ip" ] && command -v hostname >/dev/null 2>&1; then
      ip=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | head -n 1 || true)
    fi
  fi
  echo "${ip:-localhost}"
}

fill_domain() {
  local wanted=${1:-${CVENGINE_DOMAIN:-}} current
  current=$(grep -E '^DOMAIN_NAME=' .env | tail -n 1 | cut -d= -f2- || true)
  if [ -n "$wanted" ]; then
    case $wanted in *[!A-Za-z0-9.:-]*) echo "'$wanted' is not a hostname or address (letters, digits, dots and dashes only)." >&2; exit 2 ;; esac
    set_value DOMAIN_NAME "$wanted"
    echo "Using ${wanted} as the address."
  elif [ -z "$current" ] || [ "$current" = "cvengine.example.com" ]; then
    set_value DOMAIN_NAME "$(detect_host)"
    echo "Detected the address: $(grep -E '^DOMAIN_NAME=' .env | cut -d= -f2-)  (change DOMAIN_NAME in .env and run make certs up to use a name instead)"
  fi
}

fill POSTGRES_PASSWORD
fill AUTHORITY_PASSWORD
fill_domain "${1:-}"
chmod 600 .env
