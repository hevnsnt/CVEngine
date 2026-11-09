#!/usr/bin/env bash
# The watchdog beside a real update (runs in the plain job and in the overlay job) (docs/WATCHDOG.md): the host watcher (started the way cron starts it, a bare environment) runs the watchdog's tick every
# 10 seconds while it applies a further update. What is checked:
#   1. the watchdog ticks before the update (the tick runs in the web container, driven by the watcher through the install's own Compose layout);
#   2. the watcher still applies the update with the watchdog running (the approval is cleared, the new commit is running, the site and the workers answer);
#   3. during the update the watchdog stood down: at least one tick saw "an update is in progress", and it asked the host for nothing (no request file, no
#      action in the host's log, no action event) between the approval and the end of the update;
#   4. afterwards it ticks again and every rule is green or watching, none red.
set -euo pipefail
. "$GITHUB_WORKSPACE/.github/rehearsal/lib.sh"
cd "$HOME/cvengine"
bad() { echo "::error::$*"; exit 1; }
[ -f scripts/watchdog.sh ] || bad "scripts/watchdog.sh is not in the updated checkout"
state=$(python3 scripts/update-state.py directory)

tick_age() {
  dc exec -T web python3 manage.py shell -c "
from django.utils import timezone
from cveFeed.models import WatchdogState
t = WatchdogState.objects.get(rule='_all').last_tick_at
print('AGE', int((timezone.now() - t).total_seconds()) if t else 99999)" 2>/dev/null | sed -n 's/^AGE //p' | tail -n1
}
wait_for_ticks() {
  local deadline=$((SECONDS + ${1:-300})) age=99999
  while (( SECONDS < deadline )); do
    age=$(tick_age || echo 99999); age=${age:-99999}
    if (( age < 45 )); then echo "The watchdog ticks (last pass $age s ago)."; return 0; fi
    sleep 5
  done
  return 1
}

nohup env -i PATH=/usr/bin:/bin HOME="$HOME" CVENGINE_WATCHDOG_SECONDS=10 scripts/update-watch.sh 3000 >"$HOME/watcher3.log" 2>&1 &
watcher=$!
trap 'kill "$watcher" 2>/dev/null || true' EXIT
# A real install already has a watcher: the update that installed the host updater (scripts/update.sh) started one, and it holds the watcher's lock, so a
# second one exits at once. Then the installed watcher is the one under test (it runs the watchdog at its own interval); only a stopped one is a failure.
sleep 3
if ! kill -0 "$watcher" 2>/dev/null; then
  if flock -n 9 9>"$state/watch.lock"; then cat "$HOME/watcher3.log" || true; bad "the host watcher exited and nobody else holds its lock"; fi
  echo "The host watcher the install already runs is the one under test."
  sleep 7200 &  # stands in for the installed watcher in the checks below; the trap ends it
  watcher=$!
fi
wait_for_ticks 300 || { cat "$state/watchdog.log" 2>/dev/null || true; cat "$HOME/watcher3.log" || true; bad "the watchdog does not tick beside the host watcher"; }

# a third commit, approved the way the app approves one
third="$HOME/third"
rm -rf "$third"
git clone -q "$HOME/origin.git" "$third"
git -C "$third" config user.name rehearsal
git -C "$third" config user.email rehearsal@example.invalid
echo "rehearsal: a further update, with the watchdog running" > "$third/docs/.rehearsal-third-update"
git -C "$third" add -A
git -C "$third" commit -q -m "A change that only a further update brings"
git -C "$third" push -q origin HEAD:master
git -C "$third" rev-parse HEAD > "$HOME/candidate.sha"
# the scans the conductor started would only make the drain wait: stop them, as the second update does
dc exec -T web python3 manage.py shell -c "from cveFeed.scan_control import abort_running_scans; print(abort_running_scans(None), 'scans stopped')"
approved_at=$(date +%s)
cp "$HOME/candidate.sha" web/.update-approved
printf 'master\n' > web/.update-branch

# while the update runs, note what the watchdog says (the web container is briefly down while it is recreated: those polls fail and are skipped)
: > "$HOME/wd-poll.log"
for _ in $(seq 1 540); do
  [ -e web/.update-approved ] || break
  kill -0 "$watcher" 2>/dev/null || break
  dc exec -T web python3 manage.py shell -c "
from cveFeed.models import WatchdogState
d = WatchdogState.objects.get(rule='_all').data.get('snapshot', {})
print('STAND', d.get('stand_down') or '-')" 2>/dev/null | sed -n 's/^STAND //p' >>"$HOME/wd-poll.log" || true
  sleep 4
done
if [ -e web/.update-approved ]; then
  cat "$HOME/watcher3.log" || true
  bad "the approval is still waiting: the host watcher did not apply the update with the watchdog running"
fi
[ "$(git rev-parse HEAD)" = "$(cat "$HOME/candidate.sha")" ] || bad "the checkout is not at the third commit"
wait_for_site 300
wait_for_workers 600
ended_at=$(date +%s)

echo "::group::what the watchdog said while the update ran"
sort "$HOME/wd-poll.log" | uniq -c | sort -rn || true
echo "::endgroup::"
grep -q "update is in progress" "$HOME/wd-poll.log" || bad "no tick during the update saw it: the watchdog did not stand down (or did not tick)"

# it asked the host for nothing, and the host did nothing for it, between the approval and the end
if [ -f "$state/watchdog-actions.log" ]; then
  while read -r at action rule; do
    [ -n "${at:-}" ] || continue
    if (( at >= approved_at && at <= ended_at )); then bad "the watchdog acted during the update: $action for $rule at $at"; fi
  done <"$state/watchdog-actions.log"
fi
[ ! -e web/.watchdog-action ] || bad "a watchdog request was left in web/.watchdog-action after the update"
n=$(dc exec -T web python3 manage.py shell -c "
from datetime import datetime, timezone
from cveFeed.models import WatchdogEvent
since = datetime.fromtimestamp($approved_at, tz=timezone.utc)
print('ACTIONS', WatchdogEvent.objects.filter(at__gte=since, level='action').count())" 2>/dev/null | sed -n 's/^ACTIONS //p' | tail -n1)
[ "${n:-x}" = 0 ] || bad "the watchdog recorded ${n:-an unknown number of} actions after the approval"

# and it is back to work afterwards
wait_for_ticks 300 || bad "the watchdog does not tick after the update"
dc exec -T web python3 manage.py shell -c "
from cveFeed.models import WatchdogState
rows = list(WatchdogState.objects.exclude(rule='_all').order_by('rule'))
for r in rows: print(r.rule, r.status, '|', r.status_text[:100])
red = [r.rule for r in rows if r.status == 'problem']
assert not red, f'rules in trouble after the update: {red}'
print('WATCHDOG OK')"
echo "The host watcher applied the update with the watchdog running; the watchdog stood down, asked for nothing, and ticks again."
