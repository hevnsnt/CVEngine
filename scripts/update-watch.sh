#!/usr/bin/env bash
# Picks up an update approved in Settings > Updates within seconds instead of at the next cron run.
#   scripts/update-watch.sh [SECONDS]      (default 55)
# Cron starts it every minute (scripts/install-updater.sh). Each start watches web/.update-approved for SECONDS (a little less than a
# minute), so an approval is acted on within about two seconds: scans are paused, running ones drain, the files are updated and the
# containers restart (all of that is scripts/apply-update.sh). It also tells the app it is alive every 15 seconds (web/.updater-heartbeat),
# so Settings > Updates can say when nothing on the host is listening.
# The web container has no Docker or git access on purpose; this script is the only thing that acts on the approval.
set -uo pipefail
cd "$(dirname "$0")/.."
span=${1:-55}
[[ $span =~ ^[0-9]+$ ]] || span=55
STATE=$(python3 scripts/update-state.py directory) || exit 1
exec 8>"$STATE/watch.lock"
flock -n 8 || exit 0  # the previous minute's watcher is still on, or an update is running under it

end=$((SECONDS + span))
next_beat=0
while :; do
  if (( SECONDS >= next_beat )); then
    python3 scripts/update-state.py heartbeat >/dev/null 2>&1 || true
    next_beat=$((SECONDS + 15))
  fi
  pause=2
  if [ -e web/.update-approved ] || [ -L web/.update-approved ]; then
    scripts/apply-update.sh
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
