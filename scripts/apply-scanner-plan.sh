#!/usr/bin/env bash
# Carries out "Which scanners run" as chosen in Settings > Sentinels, with no update and no command line.
#   scripts/apply-scanner-plan.sh
# The web container cannot touch Docker or .env, so the page leaves a one-word request (web/.scanner-plan-wanted: internal, both or external) and
# scripts/update-watch.sh starts this within seconds. It writes the choice with the same rules the updater and install.sh use (scripts/host-fit.sh), waits
# until no scan is running (the server's processes are recreated to read the new setting; it exits 3 and the watcher asks again a little later), recreates web,
# the workers and Beat, then removes the built-in scanner (external) or starts it again (internal, both; it waits for the scanner's first heartbeat). The answer is published for the page
# (web/.scanner-plan-applied.json) and the request removed, so it runs once. Safe to run by hand.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
export GIT_CONFIG_COUNT=$(( ${GIT_CONFIG_COUNT:-0} + 1 ))
export "GIT_CONFIG_KEY_$((GIT_CONFIG_COUNT - 1))=safe.directory" "GIT_CONFIG_VALUE_$((GIT_CONFIG_COUNT - 1))=$PWD"
[ -f .env ] || exit 0
plan=$(python3 scripts/update-state.py plan-wanted 2>/dev/null) || plan=''
if [ -z "$plan" ]; then
  # a request that is not one of the three words is dropped, so it does not make the watcher start this every second
  if [ -e web/.scanner-plan-wanted ] || [ -L web/.scanner-plan-wanted ]; then rm -f web/.scanner-plan-wanted; fi
  exit 0
fi
STATE=$(python3 scripts/update-state.py directory) || exit 1
LOG="$STATE/scanner-plan.log"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }
exec 9>"$STATE/update.lock"
flock -n 9 || exit 3  # an update is running: it is the one that applies a choice, and this one asks again afterwards

. scripts/compose-layout.sh
if ! cvengine_compose_layout >>"$LOG" 2>&1; then
  python3 scripts/update-state.py plan-done "$plan" failed "the Compose layout of this install could not be worked out (see $LOG)"
  exit 1
fi
. scripts/scanner.sh
. scripts/host-fit.sh

scans=$("${COMPOSE[@]}" exec -T web python3 manage.py shell -c "from startScan.models import ScanHistory; print(ScanHistory.objects.filter(scan_status=1).count())" 2>/dev/null | tail -n1) || scans=''
if [[ $scans =~ ^[1-9][0-9]*$ ]]; then
  [ "$(cat "$STATE/scanner-plan.waiting" 2>/dev/null)" = "$plan" ] || log "waiting for $scans running scan(s) to finish before applying '$plan'"
  printf '%s' "$plan" > "$STATE/scanner-plan.waiting"
  exit 3
fi
rm -f "$STATE/scanner-plan.waiting"

if cvengine_scanner_enabled "${COMPOSE[@]}"; then was=on; else was=off; fi
log "applying the scanner choice '$plan'"
cvengine_fit_run "$plan" "${COMPOSE[@]}" | tee -a "$LOG" >/dev/null
if cvengine_scanner_enabled "${COMPOSE[@]}"; then now=on; else now=off; fi
note="$(cvengine_fit_plan_words "$plan")"
if [ "$was" != "$now" ]; then
  # the setting is read by the server's processes when they start
  if ! "${COMPOSE[@]}" up -d --no-deps web celery-beat celery >>"$LOG" 2>&1; then
    python3 scripts/update-state.py plan-done "$plan" failed "the choice is saved but the services could not be restarted (see $LOG)"
    exit 1
  fi
  for _ in $(seq 1 60); do "${COMPOSE[@]}" exec -T web python3 manage.py check >/dev/null 2>&1 && break; sleep 2; done
  # Not run by hand here: Beat, just recreated, runs ensure_builtin_scanner at once (it revokes the built-in scanner's token when off, writes its enrollment when on), and a
  # second run beside it can delete the enrollment the first one wrote, leaving the scanner a blob the server no longer knows. The scanner waits for the file;
  # cvengine_scanner_start below waits for its first heartbeat.
  cvengine_scanner_fetch "${COMPOSE[@]}" >>"$LOG" 2>&1 || true
  [ "$now" = off ] || cvengine_scanner_start "${COMPOSE[@]}" >>"$LOG" 2>&1 || true
  [ "$now" = on ] || note="$note; the built-in scanner was removed"
fi
cvengine_fit_budget "${COMPOSE[@]}" >>"$LOG" 2>&1 || true
python3 scripts/update-state.py plan-done "$plan" ok "$note"
log "done: $note"
