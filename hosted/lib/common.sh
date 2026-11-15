# shellcheck shell=bash
# Shared by the scripts in hosted/ (sourced, never run). Hosted-mode helpers: where the files live, logging that never prints a secret, an idempotent
# .env writer and the Compose layout of the installation. Nothing here runs by itself.
#
# Every location can be moved with an environment variable (the tests and a golden-image build do): CVL_ETC (secrets and the generated nginx file,
# default /etc/cvl), CVL_STATE (markers, default /var/lib/cvl), CVL_DATA (the data volume's mount point, default /mnt/cvl-data), CVL_REPO (the
# cvENGINE checkout, default the parent of hosted/).

CVL_ETC=${CVL_ETC:-/etc/cvl}
CVL_STATE=${CVL_STATE:-/var/lib/cvl}
CVL_DATA=${CVL_DATA:-/mnt/cvl-data}
CVL_PUBLIC_DOMAIN=${CVL_PUBLIC_DOMAIN:-cvengine.live}
if [ -z "${CVL_REPO:-}" ]; then
  CVL_REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
fi

# Messages go to stderr: stdout of a script is its contract with the provisioner (JSON, or nothing). Callers never pass a secret to these.
cvl_log() { printf 'cvl: %s\n' "$*" >&2; }
cvl_die() { cvl_log "error: $*"; exit 1; }

cvl_need() {
  local tool
  for tool in "$@"; do command -v "$tool" >/dev/null 2>&1 || cvl_die "$tool is required but not installed"; done
}

cvl_root_or_die() {
  [ "${CVL_ALLOW_NONROOT:-0}" = 1 ] || [ "$(id -u)" -eq 0 ] || cvl_die "run as root"
}

# An edge secret as the Worker makes it: URL-safe base64 of 32 random bytes (43 characters). The same alphabet and length bounds are enforced here
# so a value can never carry a character that means something to nginx or to a shell.
cvl_secret_ok() { [[ ${1:-} =~ ^[A-Za-z0-9_-]{32,128}$ ]]; }

cvl_random_secret() { head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'; }

# Writes $2 to the file $1 keeping its inode (a single file bind-mounted into a container stays the same file only if it is written in place, never
# replaced by a rename), mode 600, owner as the caller.
cvl_write_in_place() {
  local dest=$1 content=$2
  if [ ! -e "$dest" ]; then (umask 077; : >"$dest"); fi
  chmod 600 "$dest"
  printf '%s' "$content" >"$dest"
}

cvl_private_dir() {
  local dir=$1
  mkdir -p "$dir"
  chmod 700 "$dir"
}

# The value of KEY in $CVL_REPO/.env (last assignment wins, quotes and CR removed), or nothing.
cvl_env_get() {
  local key=$1 value
  [ -f "$CVL_REPO/.env" ] || return 0
  value=$(grep -E "^${key}=" "$CVL_REPO/.env" 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d '\r') || value=''
  value=${value#[\"\']}
  value=${value%[\"\']}
  printf '%s' "$value"
}

# Sets KEY=VALUE in $CVL_REPO/.env: replaces the line when there is one, else appends. The value reaches awk through the environment, never its
# command line. Written in place, so the file keeps its mode and owner.
cvl_env_set() {
  local key=$1 value=$2 tmp env_file=$CVL_REPO/.env
  case $value in *$'\n'*|*$'\r'*) cvl_die "refusing a multi-line value for $key" ;; esac
  [ -f "$env_file" ] || (umask 077; : >"$env_file")
  tmp=$(mktemp "${TMPDIR:-/tmp}/cvl-env.XXXXXX")
  if grep -q "^${key}=" "$env_file"; then
    CVL_AWK_VALUE=$value awk -v key="$key" 'BEGIN { prefix = key "=" } index($0, prefix) == 1 { print prefix ENVIRON["CVL_AWK_VALUE"]; next } { print }' "$env_file" >"$tmp"
  else
    { cat "$env_file"; printf '%s=%s\n' "$key" "$value"; } >"$tmp"
  fi
  cat "$tmp" >"$env_file"
  rm -f "$tmp"
  chmod 600 "$env_file"
}

# Whether hosted mode is on in this installation's .env (CVENGINE_HOSTED not empty, 0, false, no or off).
cvl_hosted_on() {
  local value
  value=$(cvl_env_get CVENGINE_HOSTED | tr '[:upper:]' '[:lower:]')
  case $value in ''|0|false|no|off) return 1 ;; esac
  return 0
}

# Sets COMPOSE (an array) to `docker compose` with the files, env file and project this installation runs with (scripts/compose-layout.sh).
cvl_compose_layout() {
  cd "$CVL_REPO" || cvl_die "cannot enter $CVL_REPO"
  # shellcheck source=/dev/null  # scripts/compose-layout.sh, relative to the repository root
  . scripts/compose-layout.sh
  cvengine_compose_layout || cvl_die "cannot work out the Compose layout"
}

# Waits until the web container accepts connections (it does so only after it has migrated the database), up to $1 seconds (default 420;
# CVL_WAIT_SECONDS replaces it, which the tests use).
cvl_wait_web() {
  local deadline=$((SECONDS + ${CVL_WAIT_SECONDS:-${1:-420}}))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if "${COMPOSE[@]}" exec -T web python3 -c 'import socket; socket.create_connection(("127.0.0.1", 8000), 3)' </dev/null >/dev/null 2>&1; then return 0; fi
    sleep "${CVL_POLL_SECONDS:-5}"
  done
  return 1
}
