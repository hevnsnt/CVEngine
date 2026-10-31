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
    # the value goes in through the environment, not awk's command line, where any local user could read it in `ps`
    CVENGINE_AWK_VALUE="$value" awk -v key="$key" 'BEGIN { prefix = key "=" } index($0, prefix) == 1 { print prefix ENVIRON["CVENGINE_AWK_VALUE"]; next } { print }' .env > "$tmp"
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
# "Already has containers" means this project's own Redis (Compose's project directory and service labels), not any container on the host whose
# name contains "redis": another stack's Redis, or the OpenVAS add-on's, must not leave a brand-new install with an open broker.
existing_redis=''
if command -v docker >/dev/null 2>&1; then
  # by this directory (as given and resolved) or by the project name Compose would use; a password on an installation whose Redis is already
  # running open would lock every client out until the services are recreated, so when in doubt this says "existing"
  project=${COMPOSE_PROJECT_NAME:-}
  if [ -z "$project" ]; then
    project=$(grep -E '^COMPOSE_PROJECT_NAME=' .env 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d '\r') || project=''
    project=${project#[\"\']}; project=${project%[\"\']}
  fi
  project=${project:-$(basename "$(pwd -P)" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')}
  for filter in "label=com.docker.compose.project.working_dir=$(pwd)" "label=com.docker.compose.project.working_dir=$(pwd -P)" "label=com.docker.compose.project=$project"; do
    existing_redis=$(docker ps -a --filter "$filter" --filter "label=com.docker.compose.service=redis" -q 2>/dev/null | head -n 1) || existing_redis=''
    [ -z "$existing_redis" ] || break
  done
fi
[ -n "$existing_redis" ] || fill REDIS_PASSWORD

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

# Opt-in, off unless CVENGINE_ENABLE_BUILTIN_SCANNER=1 (install.sh --builtin-scanner sets it): turn on the built-in scanner service and its
# server side. COMPOSE_PROFILES keeps whatever profiles are already listed. CVENGINE_LOCAL_FALLBACK=none is never written here: it is for
# the owner to set once the scanner shows as live (see .env.example). A default run leaves all of this alone.
enable_builtin_scanner() {
  local profiles
  profiles=$(grep -E '^COMPOSE_PROFILES=' .env | tail -n 1 | cut -d= -f2- | tr -d '\r' || true)
  case ",${profiles}," in
    *,builtin-scanner,*) ;;
    *) set_value COMPOSE_PROFILES "${profiles:+${profiles},}builtin-scanner"; echo "Enabled the builtin-scanner profile (COMPOSE_PROFILES)." ;;
  esac
  grep -qE '^CVENGINE_BUILTIN_SCANNER=1$' .env || { set_value CVENGINE_BUILTIN_SCANNER 1; echo "Set CVENGINE_BUILTIN_SCANNER=1."; }
}

fill POSTGRES_PASSWORD
fill AUTHORITY_PASSWORD
fill_domain "${1:-}"
[ "${CVENGINE_ENABLE_BUILTIN_SCANNER:-}" != 1 ] || enable_builtin_scanner
chmod 600 .env
