# shellcheck shell=bash
# Sourced by scripts/update.sh, scripts/update-deploy.sh (the web updater), scripts/apply-update.sh, install.sh and `make up`: the built-in scanner's
# image and container (docs/BUILTIN-SCANNER.md). It never fails what sources it: the scanner is retried at the next update, and until it is back the
# work that needs it waits (nothing is marked failed).
#
#   . scripts/scanner.sh
#   cvengine_scanner_fetch docker compose [ARGS...]   before anything is stopped: make the pinned image present (pull it, or build it from source)
#   cvengine_scanner_start [--no-wait] docker compose [ARGS...]
#                                                     after celery was recreated: recreate the scanner, wait until a heartbeat reaches the server,
#                                                     and put the previous image back when none does (`make up` passes --no-wait: no rollback)
#
# The pinned image is the one scanner.lock.json names (scripts/scanner_lock.py ref), which docker-compose.yml runs by default. CVENGINE_SCANNER_IMAGE
# in the env file is an administrator's own image and is used as it is (never pulled over, never rolled back). A rollback is written as
# CVENGINE_SCANNER_ROLLBACK_IMAGE into the env file Compose reads (and .env), and the next update removes it before it tries its own pin again.
# CVENGINE_BUILTIN_SCANNER=0 turns the scanner off: it is stopped and removed, and nothing is pulled.
# CVENGINE_SCANNER_READY_SECONDS (default 300) is how long the start waits for the first heartbeat.

_cvengine_scanner_log() { if declare -F log >/dev/null 2>&1; then log "$*"; else echo "$*" >&2; fi; }

_cvengine_scanner_env_file() {  # the env file Compose reads ${VARIABLES} from: the --env-file on the command line, else .env
  local prev='' arg
  for arg in "$@"; do
    if [ "$prev" = --env-file ]; then printf '%s\n' "$arg"; return 0; fi
    prev=$arg
  done
  printf '.env\n'
}

_cvengine_scanner_value() {  # KEY: from the environment, else the env file Compose reads, else .env
  local key=$1 file=$2 value=${!1:-} f
  if [ -z "$value" ]; then
    for f in "$file" .env; do
      [ -f "$f" ] || continue
      value=$(grep -E "^${key}=" "$f" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
      value=${value#[\"\']}; value=${value%[\"\']}
      [ -z "$value" ] || break
    done
  fi
  printf '%s' "$value"
}

_cvengine_scanner_set_rollback() {  # FILE VALUE: write (or with an empty VALUE remove) CVENGINE_SCANNER_ROLLBACK_IMAGE, in place
  local file=$1 value=$2 tmp
  [ -f "$file" ] || return 0
  tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-env.XXXXXX") || return 1
  grep -v '^CVENGINE_SCANNER_ROLLBACK_IMAGE=' "$file" > "$tmp" || true
  if [ -n "$value" ]; then
    [ -z "$(tail -c 1 "$tmp")" ] || echo >> "$tmp"
    echo "CVENGINE_SCANNER_ROLLBACK_IMAGE=$value" >> "$tmp"
  fi
  cat "$tmp" > "$file"  # keeps the file's owner and mode
  rm -f -- "$tmp"
}

_cvengine_scanner_rollback() {  # ENV_FILE VALUE (never fails the caller: a pin that cannot be written is said and left)
  _cvengine_scanner_set_rollback "$1" "$2" || _cvengine_scanner_log "could not write CVENGINE_SCANNER_ROLLBACK_IMAGE to $1"
  [ "$1" = .env ] || _cvengine_scanner_set_rollback .env "$2" || _cvengine_scanner_log "could not write CVENGINE_SCANNER_ROLLBACK_IMAGE to .env"
}

cvengine_scanner_enabled() {  # docker compose [ARGS...]: the compose file has the service and the switch is not off
  local file value
  file=$(_cvengine_scanner_env_file "$@")
  value=$(_cvengine_scanner_value CVENGINE_BUILTIN_SCANNER "$file" | tr '[:upper:]' '[:lower:]')
  case "$value" in 0|false|no|off) return 1 ;; esac
  "$@" config --services 2>/dev/null | grep -qx scanner
}

cvengine_scanner_wanted_image() {  # docker compose [ARGS...]: the image this release runs (an administrator's own wins)
  local file own
  file=$(_cvengine_scanner_env_file "$@")
  own=$(_cvengine_scanner_value CVENGINE_SCANNER_IMAGE "$file")
  if [ -n "$own" ]; then printf '%s\n' "$own"; else python3 scripts/scanner_lock.py ref; fi
}

cvengine_scanner_fetch() {
  local file wanted own
  if ! cvengine_scanner_enabled "$@"; then
    if "$@" config --services 2>/dev/null | grep -qx scanner; then
      "$@" rm -sf scanner >/dev/null 2>&1 || true
      _cvengine_scanner_log "the built-in scanner is turned off (CVENGINE_BUILTIN_SCANNER=0); not fetching its image"
    fi
    return 0
  fi
  file=$(_cvengine_scanner_env_file "$@")
  own=$(_cvengine_scanner_value CVENGINE_SCANNER_IMAGE "$file")
  _cvengine_scanner_rollback "$file" ''  # this release tries its own pin again
  wanted=$(cvengine_scanner_wanted_image "$@") || { _cvengine_scanner_log "could not read scanner.lock.json; the built-in scanner keeps the image it has"; return 0; }
  if [ -n "$own" ]; then
    docker image inspect "$wanted" >/dev/null 2>&1 || docker pull -q "$wanted" >/dev/null 2>&1 ||
      _cvengine_scanner_log "CVENGINE_SCANNER_IMAGE=$wanted is not on this host and could not be pulled; the built-in scanner keeps the image it has"
    return 0
  fi
  if python3 scripts/scanner_lock.py published; then
    if docker image inspect "$wanted" >/dev/null 2>&1 || docker pull -q "$wanted" >/dev/null; then
      _cvengine_scanner_log "the built-in scanner image $wanted is on this host"
    else
      _cvengine_scanner_log "could not pull the built-in scanner image $wanted (offline, or the registry refused); the scanner keeps the image it has. Build it from source with: make scanner-build"
    fi
  elif ! docker image inspect "$wanted" >/dev/null 2>&1; then
    _cvengine_scanner_log "building the built-in scanner image $wanted from $(python3 scripts/scanner_lock.py source) (10 to 25 minutes)"
    cvengine_scanner_build >/dev/null || _cvengine_scanner_log "could not build the built-in scanner image; the scanner keeps the image it has (make scanner-build tries again)"
  fi
  return 0
}

cvengine_scanner_build() {  # build the pinned scanner from source, tagged as scanner_lock.py local (and latest)
  local tag context
  tag=$(python3 scripts/scanner_lock.py local) || return 1
  context=$(python3 scripts/scanner_lock.py source) || return 1
  DOCKER_BUILDKIT=1 docker build --build-arg BUILDKIT_CONTEXT_KEEP_GIT_DIR=1 -t "$tag" -t cvengine-sentinel-local:latest "$context" && printf '%s\n' "$tag"
}

_cvengine_scanner_image_of() {  # docker compose [ARGS...]: the image reference the scanner container runs now, or nothing
  local id
  id=$("$@" ps -aq scanner 2>/dev/null | head -n1) || id=''
  [ -n "$id" ] && docker inspect -f '{{.Config.Image}}' "$id" 2>/dev/null || true
}

_cvengine_scanner_ready() {  # docker compose [ARGS...]: wait until a heartbeat of the running scanner reached the server
  local deadline=$((SECONDS + ${CVENGINE_SCANNER_READY_SECONDS:-300}))
  while [ "$SECONDS" -lt "$deadline" ]; do
    "$@" exec -T scanner python3 -m client.control heartbeat >/dev/null 2>&1 && return 0
    sleep "${CVENGINE_SCANNER_POLL:-5}"
  done
  return 1
}

cvengine_scanner_start() {
  local file wanted previous wait=1
  if [ "${1:-}" = --no-wait ]; then wait=0; shift; fi
  cvengine_scanner_enabled "$@" || return 0
  file=$(_cvengine_scanner_env_file "$@")
  wanted=$(cvengine_scanner_wanted_image "$@" 2>/dev/null) || wanted=''
  previous=$(_cvengine_scanner_image_of "$@")
  if [ -n "$wanted" ] && ! docker image inspect "$wanted" >/dev/null 2>&1; then
    if [ -n "$previous" ] && [ "$previous" != "$wanted" ]; then
      _cvengine_scanner_rollback "$file" "$previous"
      _cvengine_scanner_log "the built-in scanner image $wanted is not on this host; keeping $previous"
    else
      _cvengine_scanner_log "the built-in scanner image $wanted is not on this host; the scanner cannot start until it is (make scanner-build, or the next update)"
      return 0
    fi
  fi
  # recreated after celery: it joins celery's network namespace by container id, so it lost its network when celery was recreated
  if ! "$@" up -d --no-deps --force-recreate scanner; then
    _cvengine_scanner_log "could not start the built-in scanner (docker compose up -d scanner); scans that need it wait until it runs"
    return 0
  fi
  [ "$wait" = 1 ] || return 0
  if _cvengine_scanner_ready "$@"; then
    _cvengine_scanner_log "the built-in scanner ($(_cvengine_scanner_image_of "$@")) reaches the server"
    return 0
  fi
  if [ -n "$previous" ] && [ "$previous" != "$(_cvengine_scanner_image_of "$@")" ] && [ -z "$(_cvengine_scanner_value CVENGINE_SCANNER_IMAGE "$file")" ]; then
    _cvengine_scanner_log "the built-in scanner on $wanted sent no heartbeat within ${CVENGINE_SCANNER_READY_SECONDS:-300}s; rolling back to $previous (the next update tries again)"
    _cvengine_scanner_rollback "$file" "$previous"
    "$@" up -d --no-deps --force-recreate scanner || _cvengine_scanner_log "could not start the built-in scanner on $previous either; see docker compose logs scanner"
  else
    _cvengine_scanner_log "the built-in scanner has not reached the server yet (it keeps trying; see docker compose logs scanner and the Sentinels page)"
  fi
  return 0
}
