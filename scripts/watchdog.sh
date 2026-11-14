#!/usr/bin/env bash
# The host side of the outer watchdog (docs/WATCHDOG.md). scripts/update-watch.sh, which cron keeps running and which already has Docker access,
# calls it:
#   scripts/watchdog.sh tick    one pass of `manage.py watchdog_tick` inside the web container (every 30 seconds)
#   scripts/watchdog.sh act     carry out the one request the watchdog left in web/.watchdog-action, and answer in web/.watchdog-result
# The web container has no Docker access on purpose: it decides, this script acts, and only on three named actions (restart-celery, restart-celery-beat,
# prune-docker), each a non-destructive Docker call (recreating a container never touches a volume; the prune removes dangling images and build cache,
# never a tagged image or a volume).
#
# Safety, in the order it is checked:
#   - CVENGINE_WATCHDOG=0 (environment or .env) switches the host side off too;
#   - STANDING DOWN: nothing is done while an update owns the stack: web/.update-approved, a draining or applying web/.update-phase.json, the update
#     script's lock ($STATE/update.lock) or the web side's (web/.update-lock) held (both tested without waiting), or the maintenance page flag. A refused
#     request is answered "standdown", so the watchdog does not count it as an attempt;
#   - the update lock is then TAKEN (without waiting) for the length of the action, so an approval that arrives meanwhile waits for it (the update
#     watcher asks again every few seconds), and the two never recreate containers at once;
#   - limits of its own, whatever the web side asks: at least 10 minutes between two restarts of one kind (30 for the prune) and 8 restarts a day;
#   - one tick at a time ($STATE/watchdog.lock) and one action at a time ($STATE/watchdog-act.lock), each taken without waiting;
#   - the Compose layout is the one the installation runs with (scripts/compose-layout.sh: CVENGINE_COMPOSE_FILES, CVENGINE_COMPOSE_ENV_FILE,
#     CVENGINE_COMPOSE_PROJECT, else what the running web container was started with), so recreating a service never drops an overlay.
# Everything it does is logged to $STATE/watchdog.log (private to the host, trimmed); nothing it writes into web/ is read back as a path.
set -uo pipefail
cd "$(dirname "$0")/.."
export GIT_CONFIG_COUNT=$(( ${GIT_CONFIG_COUNT:-0} + 1 ))
export "GIT_CONFIG_KEY_$((GIT_CONFIG_COUNT - 1))=safe.directory" "GIT_CONFIG_VALUE_$((GIT_CONFIG_COUNT - 1))=$PWD"
umask 077
mode=${1:-}
case $mode in tick|act) ;; *) echo "usage: scripts/watchdog.sh tick|act" >&2; exit 2;; esac
STATE=$(python3 scripts/update-state.py directory) || exit 1
LOG="$STATE/watchdog.log"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$LOG"; }
if [ -f "$LOG" ] && [ "$(wc -c <"$LOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then tail -c 262144 "$LOG" >"$LOG.tmp" 2>/dev/null && mv -f "$LOG.tmp" "$LOG"; fi
# shellcheck source=compose-layout.sh
. scripts/compose-layout.sh

setting() {
  local name=$1 value=${!1:-}
  if [ -z "$value" ] && [ -f .env ]; then
    value=$(grep -E "^${name}=" .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r') || value=''
    value=${value#[\"\']}; value=${value%[\"\']}
  fi
  printf '%s' "$value"
}
enabled() {
  case "$(setting CVENGINE_WATCHDOG | tr 'A-Z' 'a-z')" in 0|off|false|no) return 1;; esac
  return 0
}

# Whether a lock file is held by someone else: tested without waiting and never kept. A file that cannot be opened (or is a link) is not "held".
lock_held() {
  [ -L "$1" ] && return 1
  ( exec 9>>"$1" 2>/dev/null || exit 2; flock -n 9 )
  [ $? -eq 1 ]
}

# Prints why the watchdog must not act and returns 0 when an update (or maintenance) owns the stack; returns 1 when the stack is free.
# `skip_lock` leaves out $STATE/update.lock, for the caller that is about to take it.
standing_down() {
  local skip_lock=${1:-}
  if [ -e web/.update-approved ] || [ -L web/.update-approved ]; then echo "an update is approved and waiting or running (web/.update-approved)"; return 0; fi
  if [ -f web/.update-phase.json ] && [ ! -L web/.update-phase.json ] && grep -Eq '"phase": *"(draining|applying)"' web/.update-phase.json 2>/dev/null \
     && [ -n "$(find web/.update-phase.json -mmin -120 2>/dev/null)" ]; then
    echo "an update is draining or applying (web/.update-phase.json)"; return 0
  fi
  if [ "$skip_lock" != skip-update-lock ] && lock_held "$STATE/update.lock"; then echo "the update script holds its lock"; return 0; fi
  if lock_held web/.update-lock; then echo "the web side holds the update lock (web/.update-lock)"; return 0; fi
  if [ -e config/nginx/state/maintenance ]; then echo "the maintenance page is on"; return 0; fi
  return 1
}

layout() { cvengine_compose_layout 2>>"$LOG"; }

if [ "$mode" = tick ]; then
  enabled || exit 0
  exec 7>"$STATE/watchdog.lock"
  flock -n 7 || exit 0  # the previous tick is still running
  layout || { log "tick: could not work out the Compose layout"; exit 1; }
  # `timeout` is the hard bound around the tick's own limit (40 seconds) and its own timer (55): the tick ends itself, and this kills it if it does not
  out=$(timeout -k 5 65 "${COMPOSE[@]}" exec -T web timeout -k 3 55 python3 manage.py watchdog_tick 2>&1 </dev/null 7>&- 8>&-)
  rc=$?
  summary=$(printf '%s\n' "$out" | grep '^{' | tail -n 1)  # the command prints one JSON line; Django's start-up chatter around it is not for the log
  if [ $rc -ne 0 ]; then
    log "tick failed (exit $rc): $(printf '%s' "${summary:-$out}" | tail -c 300 | tr '\n' ' ')"
  elif ! grep -q '"ok": true' <<<"$summary" || ! grep -q '"acted": \[\]' <<<"$summary"; then
    log "tick: ${summary:-no answer}"  # only a tick that did something or stopped early is worth a line
  fi
  exit 0
fi

# ---- act ----
[ -e web/.watchdog-action ] || [ -L web/.watchdog-action ] || exit 0
exec 6>"$STATE/watchdog-act.lock"
flock -n 6 || exit 0  # an action is running; the request stays until it ends
line=$(python3 scripts/update-state.py watchdog-request 2>>"$LOG") || line=''
if [ -z "$line" ]; then log "act: ignored a request that was not valid"; exit 0; fi
read -r id action rule <<<"$line"
answer() { python3 scripts/update-state.py watchdog-result "$id" "$action" "$1" "$2" >>"$LOG" 2>&1 || log "act: could not publish the answer to $id"; }
log "act: request $id from $rule: $action"
if ! enabled; then answer failed "switched off on the host (CVENGINE_WATCHDOG)"; exit 0; fi
if reason=$(standing_down skip-update-lock); then log "act: standing down: $reason"; answer standdown "$reason."; exit 0; fi
exec 9>"$STATE/update.lock"
if ! flock -n 9; then log "act: standing down: the update script holds its lock"; answer standdown "the update script holds its lock."; exit 0; fi
if reason=$(standing_down skip-update-lock); then log "act: standing down: $reason"; answer standdown "$reason."; exit 0; fi  # checked again, now that nothing can start

# the host's own limits
ACTIONS_LOG="$STATE/watchdog-actions.log"
now=$(date +%s)
case $action in prune-docker) gap=1800;; *) gap=600;; esac
last=$(awk -v a="$action" '$2 == a { t = $1 } END { print t + 0 }' "$ACTIONS_LOG" 2>/dev/null || echo 0)
today=$(awk -v n="$now" '$2 != "prune-docker" && n - $1 < 86400 { c++ } END { print c + 0 }' "$ACTIONS_LOG" 2>/dev/null || echo 0)
if (( now - last < gap )); then log "act: refused $action: done $(( (now - last) / 60 )) minutes ago"; answer limit-gap "refused by the host: $action was done $(( (now - last) / 60 )) minutes ago (limit: one per $((gap / 60)) minutes)."; exit 0; fi
if [ "$action" != prune-docker ] && (( today >= 24 )); then log "act: refused $action: $today restarts in the last day"; answer limit-day "refused by the host: $today restarts in the last 24 hours (limit 24)."; exit 0; fi
printf '%s %s %s\n' "$now" "$action" "$rule" >>"$ACTIONS_LOG"
if [ "$(wc -l <"$ACTIONS_LOG" 2>/dev/null || echo 0)" -gt 500 ]; then tail -n 200 "$ACTIONS_LOG" >"$ACTIONS_LOG.tmp" && mv -f "$ACTIONS_LOG.tmp" "$ACTIONS_LOG"; fi

if ! layout; then answer failed "could not work out the Compose layout (see the log on the host)"; exit 0; fi
recreate() { timeout -k 10 300 "${COMPOSE[@]}" up -d --no-deps --force-recreate "$@" >>"$LOG" 2>&1 </dev/null 6>&- 9>&-; }
present() { grep -qx "$1" < <("${COMPOSE[@]}" ps -a --services 2>/dev/null </dev/null); }
rc=0
case $action in
  restart-celery)
    recreate celery || rc=$?
    # the scanner and the Tailscale sidecar share celery's network namespace by container id: they follow it (the update does the same)
    if [ $rc -eq 0 ]; then
      for svc in scanner tailscale; do
        if present "$svc"; then recreate "$svc" || log "act: could not recreate $svc after celery"; fi
      done
    fi;;
  restart-celery-beat) recreate celery-beat || rc=$?;;
  prune-docker)
    timeout -k 10 300 docker image prune -f >>"$LOG" 2>&1 </dev/null 6>&- 9>&- || rc=$?
    timeout -k 10 300 docker builder prune -f >>"$LOG" 2>&1 </dev/null 6>&- 9>&- || rc=$?;;
esac
if [ $rc -eq 0 ]; then log "act: $action done"; answer ok "$action done at $(date -u +%H:%M:%SZ)"
else log "act: $action failed (exit $rc)"; answer failed "$action failed (exit $rc); see watchdog.log on the host"; fi
exit 0
