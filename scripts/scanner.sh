# shellcheck shell=bash
# Sourced by scripts/update.sh, scripts/update-deploy.sh (the web updater), scripts/apply-update.sh, scripts/scanner-update.sh, scripts/auto-deploy.sh,
# install.sh and `make up`: the built-in scanner's image and container (docs/BUILTIN-SCANNER.md). It never fails what sources it: the scanner is retried
# at the next update, and until it is back the work that needs it waits (nothing is marked failed).
#
#   . scripts/scanner.sh
#   cvengine_scanner_fetch docker compose [ARGS...]   before anything is stopped: pull the newest published scanner image (the moving tag, `main`)
#   cvengine_scanner_start [--no-wait] docker compose [ARGS...]
#                                                     after celery was recreated: recreate the scanner, wait until it is healthy AND has checked in with a
#                                                     contract version this server accepts, and put the previous image back when it does not (`make up`
#                                                     passes --no-wait: a first start is not waited for; a changed image is still checked)
#   cvengine_scanner_update docker compose [ARGS...]  the "Scanner update" routine for a running install (scripts/scanner-update.sh runs it): fetch,
#                                                     then, only when the newest image is not the one running, let the scanner finish its work and start
#                                                     the new one as above. Safe to run from cron or a timer.
#
# The scanner FOLLOWS the newest published Sentinel: scanner.lock.json names the moving tag (scripts/scanner_lock.py ref), which docker-compose.yml runs by
# default, and its known-good floor (the commit and contract version the release was tested with, which `make scanner-build` builds from source offline).
# CVENGINE_SCANNER_IMAGE in the env file is an administrator's own image or digest, the way to HOLD a version: it is used as it is and never pulled over, updated
# or rolled back. A rollback tags the image that was running as cvengine-sentinel-rollback:previous (a moving tag cannot name it any more) and writes it as
# CVENGINE_SCANNER_ROLLBACK_IMAGE into the env file Compose reads (and .env); the next update removes it before it pulls the newest image again.
# CVENGINE_BUILTIN_SCANNER=0 turns the scanner off: it is stopped and removed, and nothing is pulled.
# CVENGINE_SCANNER_READY_SECONDS (default 300) is how long the start waits for the first heartbeat; CVENGINE_SCANNER_DRAIN_SECONDS (default 900) how long
# a scheduled update lets the running scanner finish its tasks before it gives up for this time.
# When a new image is refused, the reason is logged and, through the scanner that is running again, reported to the server (the Sentinels page shows it).

_cv_scanner_rollback_tag=cvengine-sentinel-rollback:previous
_cv_scanner_why=''          # why the last new image was refused (set by _cvengine_scanner_ready)
_cv_scanner_result=''       # cvengine_scanner_update: `done` (on the newest image, or held, or off: nothing more to do), `busy` or `no-pull` (try again at the next run)
_cv_scanner_pulled=''       # fetch: `ok`, `failed`, `own` (an administrator's image: nothing pulled), or empty (nothing tried)

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

_cvengine_scanner_image_id() {  # REF: the id of the local image REF names, or nothing
  docker image inspect -f '{{.Id}}' "$1" 2>/dev/null || true
}

cvengine_scanner_fetch() {
  local file wanted own
  _cv_scanner_pulled=''
  if ! cvengine_scanner_enabled "$@"; then
    if "$@" config --services 2>/dev/null | grep -qx scanner; then
      "$@" rm -sf scanner >/dev/null 2>&1 || true
      _cvengine_scanner_log "the built-in scanner is turned off (CVENGINE_BUILTIN_SCANNER=0); not fetching its image"
    fi
    return 0
  fi
  file=$(_cvengine_scanner_env_file "$@")
  own=$(_cvengine_scanner_value CVENGINE_SCANNER_IMAGE "$file")
  _cvengine_scanner_rollback "$file" ''  # the newest image is tried again
  wanted=$(cvengine_scanner_wanted_image "$@") || { _cvengine_scanner_log "could not read scanner.lock.json; the built-in scanner keeps the image it has"; return 0; }
  if [ -n "$own" ]; then
    _cv_scanner_pulled=own
    [ -n "$(_cvengine_scanner_image_id "$wanted")" ] || docker pull -q "$wanted" >/dev/null 2>&1 ||
      _cvengine_scanner_log "CVENGINE_SCANNER_IMAGE=$wanted is not on this host and could not be pulled; the built-in scanner keeps the image it has"
    return 0
  fi
  # the moving tag: pulled every time (that is the update). A failure never stops the update; the image on this host is kept.
  if docker pull -q "$wanted" >/dev/null 2>&1; then
    _cv_scanner_pulled=ok
    _cvengine_scanner_log "the newest published built-in scanner image ($wanted) is on this host"
  else
    _cv_scanner_pulled=failed
    _cvengine_scanner_log "could not pull the built-in scanner image $wanted (offline, or the registry refused); the scanner keeps the image it has. Build the tested floor from source with: make scanner-build"
  fi
  return 0
}

cvengine_scanner_build() {  # build the floor commit of scanner.lock.json from source, tagged as scanner_lock.py local (and latest): the offline fallback
  local tag context
  tag=$(python3 scripts/scanner_lock.py local) || return 1
  context=$(python3 scripts/scanner_lock.py source) || return 1
  DOCKER_BUILDKIT=1 docker build --build-arg BUILDKIT_CONTEXT_KEEP_GIT_DIR=1 -t "$tag" -t cvengine-sentinel-local:latest "$context" && printf '%s\n' "$tag"
}

_cvengine_scanner_container() {  # docker compose [ARGS...]: the id of the scanner container (running or not), or nothing
  "$@" ps -aq scanner 2>/dev/null | head -n1 || true
}

_cvengine_scanner_running_id() {  # docker compose [ARGS...]: the id of the IMAGE the scanner container was created from, or nothing
  local id
  id=$(_cvengine_scanner_container "$@")
  [ -n "$id" ] && docker inspect -f '{{.Image}}' "$id" 2>/dev/null || true
}

_cvengine_scanner_image_of() {  # docker compose [ARGS...]: the image reference the scanner container runs now, or nothing
  local id
  id=$(_cvengine_scanner_container "$@")
  [ -n "$id" ] && docker inspect -f '{{.Config.Image}}' "$id" 2>/dev/null || true
}

_cvengine_scanner_exec() {  # docker compose [ARGS...] -- COMMAND...: run COMMAND in the scanner container
  local -a compose=()
  while [ "$#" -gt 0 ] && [ "$1" != -- ]; do compose+=("$1"); shift; done
  shift
  "${compose[@]}" exec -T scanner "$@"
}

_cvengine_scanner_release() {  # docker compose [ARGS...]: the release (commit) the running scanner reports, or nothing
  _cvengine_scanner_exec "$@" -- python3 -c 'from client import config; print(config.version())' 2>/dev/null | tr -dc 'A-Za-z0-9._+-' || true
}

_cvengine_scanner_ready() {  # docker compose [ARGS...]: wait until the running scanner is healthy and checked in with a contract version this server accepts
  local deadline=$((SECONDS + ${CVENGINE_SCANNER_READY_SECONDS:-300})) declared server sv sm why; local -a server_args
  _cv_scanner_why=''
  while [ "$SECONDS" -lt "$deadline" ]; do
    if _cvengine_scanner_exec "$@" -- python3 -m client.control heartbeat >/dev/null 2>&1; then
      declared=$(_cvengine_scanner_exec "$@" -- python3 -c 'from client import config; print(config.CONTRACT_VERSION)' 2>/dev/null | tr -dc '0-9') || declared=''
      server=$("$@" exec -T web python3 -c 'from cvengine_scanner import contract as c; print(c.version(), c.min_supported())' 2>/dev/null) || server=''
      read -r sv sm <<<"$server" || true
      if [[ ${sv:-} =~ ^[0-9]+$ && ${sm:-} =~ ^[0-9]+$ ]]; then server_args=("$sv" "$sm"); else server_args=(); fi
      if [ -z "$declared" ]; then
        _cv_scanner_why='it checked in but did not report its contract version'
        return 2
      fi
      if why=$(python3 scripts/scanner_lock.py accepts "$declared" ${server_args[@]+"${server_args[@]}"} 2>&1); then return 0; fi
      _cv_scanner_why="it checked in, but $why"
      return 2
    fi
    sleep "${CVENGINE_SCANNER_POLL:-5}"
  done
  _cv_scanner_why="it sent no heartbeat within ${CVENGINE_SCANNER_READY_SECONDS:-300}s"
  return 1
}

cvengine_scanner_start() {
  local file wanted previous_id previous_ref previous_release wanted_id own wait=1 up_args=() now_ref release_now
  if [ "${1:-}" = --no-wait ]; then wait=0; shift; fi
  cvengine_scanner_enabled "$@" || return 0
  file=$(_cvengine_scanner_env_file "$@")
  own=$(_cvengine_scanner_value CVENGINE_SCANNER_IMAGE "$file")
  wanted=$(cvengine_scanner_wanted_image "$@" 2>/dev/null) || wanted=''
  previous_id=$(_cvengine_scanner_running_id "$@")
  previous_ref=$(_cvengine_scanner_image_of "$@")
  wanted_id=''; [ -z "$wanted" ] || wanted_id=$(_cvengine_scanner_image_id "$wanted")
  # --no-wait is for a first start (nothing to go back to). A scanner that was running and is about to change image is always checked: that is the safety net.
  if [ "$wait" = 0 ] && [ -n "$previous_id" ] && [ -z "$own" ] && [ "$previous_id" != "$wanted_id" ]; then wait=1; fi
  if [ -n "$previous_id" ] && [ "$wait" = 1 ]; then previous_release=$(_cvengine_scanner_release "$@"); else previous_release=''; fi
  if [ -n "$wanted" ] && [ -z "$wanted_id" ]; then
    if [ -n "$previous_id" ] && [ -z "$own" ] && docker tag "$previous_id" "$_cv_scanner_rollback_tag" 2>/dev/null; then
      _cvengine_scanner_rollback "$file" "$_cv_scanner_rollback_tag"
      _cvengine_scanner_log "the built-in scanner image $wanted is not on this host; keeping the one that ran (${previous_ref:-$previous_id})"
      up_args=(--pull never)
    else
      _cvengine_scanner_log "the built-in scanner image $wanted is not on this host; the scanner cannot start until it is (make scanner-build, or the next update)"
      return 0
    fi
  elif [ -n "$previous_id" ] && [ "$previous_id" != "$wanted_id" ] && [ -z "$own" ]; then
    # the moving tag will name the new image, so the image that works now gets a name of its own to go back to (and is kept from pruning)
    docker tag "$previous_id" "$_cv_scanner_rollback_tag" >/dev/null 2>&1 || previous_id=''
  fi
  # recreated after celery: it joins celery's network namespace by container id, so it lost its network when celery was recreated
  if ! "$@" up -d --no-deps --force-recreate ${up_args[@]+"${up_args[@]}"} scanner; then
    _cvengine_scanner_log "could not start the built-in scanner (docker compose up -d scanner); scans that need it wait until it runs"
    return 0
  fi
  [ "$wait" = 1 ] || return 0
  if _cvengine_scanner_ready "$@"; then
    release_now=$(_cvengine_scanner_release "$@")
    _cvengine_scanner_log "the built-in scanner (${release_now:-$(_cvengine_scanner_image_of "$@")}) is healthy and has checked in with a contract version this server accepts"
    if [ -n "$previous_release" ] && [ -n "$release_now" ] && [ "$previous_release" != "$release_now" ]; then
      _cvengine_scanner_exec "$@" -- python3 -m client.control report done --phase scanner-update --from "$previous_release" --to "$release_now" >/dev/null 2>&1 || true
    fi
    return 0
  fi
  if [ -n "$previous_id" ] && [ "$previous_id" != "$(_cvengine_scanner_running_id "$@")" ] && [ -z "$own" ] && [ -z "$(_cvengine_scanner_value CVENGINE_SCANNER_ROLLBACK_IMAGE "$file")" ]; then
    _cvengine_scanner_log "the new built-in scanner image ($wanted) was not kept: $_cv_scanner_why. Putting the previous image back (${previous_ref:-$previous_id}); the next update tries the newest again"
    _cvengine_scanner_rollback "$file" "$_cv_scanner_rollback_tag"
    if "$@" up -d --no-deps --force-recreate --pull never scanner; then
      # the restored scanner tells the server why, through its next heartbeat (the Sentinels page shows a failed update with its reason)
      _cvengine_scanner_exec "$@" -- python3 -m client.control report failed --phase scanner-update --detail "kept the previous image: $_cv_scanner_why" --from "${previous_release:-unknown}" --to "${wanted##*/}" >/dev/null 2>&1 || true
    else
      _cvengine_scanner_log "could not start the built-in scanner on the previous image either; see docker compose logs scanner"
    fi
  else
    _cvengine_scanner_log "the built-in scanner is not accepted yet ($_cv_scanner_why); it keeps trying (see docker compose logs scanner and the Sentinels page)"
  fi
  return 0
}

cvengine_scanner_update() {  # docker compose [ARGS...]
  local file own running_id wanted wanted_id
  _cv_scanner_result=done
  if ! cvengine_scanner_enabled "$@"; then
    _cvengine_scanner_log "the built-in scanner is not on this install (or CVENGINE_BUILTIN_SCANNER=0): nothing to update"
    return 0
  fi
  file=$(_cvengine_scanner_env_file "$@")
  own=$(_cvengine_scanner_value CVENGINE_SCANNER_IMAGE "$file")
  if [ -n "$own" ]; then
    _cvengine_scanner_log "the built-in scanner is held at CVENGINE_SCANNER_IMAGE=$own; the scanner update leaves it alone (remove the line to follow the newest published image)"
    return 0
  fi
  running_id=$(_cvengine_scanner_running_id "$@")
  cvengine_scanner_fetch "$@"
  [ "$_cv_scanner_pulled" = ok ] || { _cv_scanner_result=no-pull; _cvengine_scanner_log "no new scanner image was fetched; the running scanner is left as it is"; return 0; }
  wanted=$(cvengine_scanner_wanted_image "$@") || return 0
  wanted_id=$(_cvengine_scanner_image_id "$wanted")
  if [ -n "$running_id" ] && [ "$running_id" = "$wanted_id" ]; then
    _cvengine_scanner_log "the built-in scanner already runs the newest published image"
    return 0
  fi
  if [ -n "$running_id" ]; then
    # a running scanner finishes the tasks it holds first; it is not interrupted for an update that can wait for the next run
    _cvengine_scanner_exec "$@" -- python3 -m client.control drain >/dev/null 2>&1 || true
    if ! _cvengine_scanner_exec "$@" -- python3 -m client.control wait-idle --timeout "${CVENGINE_SCANNER_DRAIN_SECONDS:-900}" >/dev/null 2>&1; then
      _cvengine_scanner_exec "$@" -- python3 -m client.control undrain >/dev/null 2>&1 || true
      _cv_scanner_result=busy
      _cvengine_scanner_log "the built-in scanner is still busy; the newer image is on this host and is started at the next run"
      return 0
    fi
  fi
  cvengine_scanner_start "$@"
}
