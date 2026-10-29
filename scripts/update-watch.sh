#!/usr/bin/env bash
# Picks up an update approved in Settings > Updates within seconds instead of at the next cron run.
#   scripts/update-watch.sh [SECONDS]      (default 55)
# Cron starts it every minute (scripts/install-updater.sh). Each start watches web/.update-approved for SECONDS (a little less than a
# minute), so an approval is acted on within about two seconds: scans are paused, running ones drain, the files are updated and the
# containers restart (all of that is scripts/apply-update.sh). It also tells the app it is alive every 15 seconds (web/.updater-heartbeat),
# so Settings > Updates can say when nothing on the host is listening; the heartbeat goes on while an update runs, which takes minutes.
# The web container has no Docker or git access on purpose; this script is the only thing that acts on the approval.
set -uo pipefail
cd "$(dirname "$0")/.."
# root (cron, systemd) in a checkout owned by whoever cloned it: git refuses it ("dubious ownership") unless this one is named
export GIT_CONFIG_COUNT=$(( ${GIT_CONFIG_COUNT:-0} + 1 ))
export "GIT_CONFIG_KEY_$((GIT_CONFIG_COUNT - 1))=safe.directory" "GIT_CONFIG_VALUE_$((GIT_CONFIG_COUNT - 1))=$PWD"
span=${1:-55}
[[ $span =~ ^[0-9]+$ ]] || span=55
STATE=$(python3 scripts/update-state.py directory) || exit 1
exec 8>"$STATE/watch.lock"
flock -n 8 || exit 0  # the previous minute's watcher is still on, or an update is running under it

# The web interface certificate is renewed before it expires (scripts/renew-certs.sh: nothing until its next check is due, twice a day, then
# a new certificate only when fewer than 30 days remain; the proxy reloads it with no restart). In the background so it never delays the
# heartbeat, with its own lock and log; the watcher's lock is not handed on.
if [ -f scripts/renew-certs.sh ]; then
  setsid nohup scripts/renew-certs.sh --if-due >>"$STATE/cert.log" 2>&1 8>&- </dev/null &
fi

end=$((SECONDS + span))
next_beat=0
heartbeat() {
  if (( SECONDS >= next_beat )); then
    python3 scripts/update-state.py heartbeat >/dev/null 2>&1 || true
    next_beat=$((SECONDS + ${CVENGINE_HEARTBEAT_SECONDS:-15}))  # the setting is for the tests
  fi
}
while :; do
  heartbeat
  # an OpenVAS switch flipped in the app (web/.openvas-wanted newer than the answer): carry it out in the background, so a first start that pulls
  # several GB neither delays an update nor stops the heartbeat. The script takes its own lock. Its output goes to a host-private log (it
  # publishes the tail as web/.openvas-log): this runs as root, and a path inside the web mount could be a link to a host file.
  if [ -f web/.openvas-wanted ] && [ web/.openvas-wanted -nt web/.openvas-applied ]; then
    setsid nohup scripts/openvas-sync.sh >>"$STATE/openvas.log" 2>&1 </dev/null &
  fi
  pause=2
  if [ -e web/.update-approved ] || [ -L web/.update-approved ]; then
    # In the background, so the heartbeat goes on for the minutes an update takes: the app says "nothing is listening" after three silent ones.
    scripts/apply-update.sh &
    update_pid=$!
    while kill -0 "$update_pid" 2>/dev/null; do
      heartbeat
      sleep 1
    done
    wait "$update_pid"
    case $? in
      0) ;;
      3) pause=15 ;;  # waiting for scans to finish: do not ask the database every two seconds
      *) pause=30 ;;  # refused or failed with the approval kept: it retries, but not in a tight loop
    esac
  fi
  (( SECONDS + pause >= end )) && break
  sleep "$pause"
done
exit 0
