#!/usr/bin/env bash
# Starts or stops the OpenVAS (Greenbone) containers when someone switches the add-on on or off in the app. The web container has no Docker access on
# purpose, so it writes web/.openvas-wanted ("on" or "off") and scripts/update-watch.sh runs this when that file is newer than web/.openvas-applied,
# the answer this script leaves (JSON, read by Settings > OpenVAS and Administration > OpenVAS). It never runs anything the file does not name: the
# only words it accepts are on and off, and the services are the ones listed here (keep the list equal to OPENVAS_SERVICES in the Makefile).
#   scripts/openvas-sync.sh        (also: make openvas-up / make openvas-down do the same by hand)
set -uo pipefail
cd "$(dirname "$0")/.."
# root (cron, systemd) in a checkout owned by whoever cloned it: git refuses it ("dubious ownership") unless this one is named
export GIT_CONFIG_COUNT=$(( ${GIT_CONFIG_COUNT:-0} + 1 ))
export "GIT_CONFIG_KEY_$((GIT_CONFIG_COUNT - 1))=safe.directory" "GIT_CONFIG_VALUE_$((GIT_CONFIG_COUNT - 1))=$PWD"
SERVICES=(openvas-gvmd openvas-ospd openvas-openvasd openvas-redis openvas-pg-gvm openvas-pg-gvm-migrator openvas-configure openvas-gpg-data openvas-vulnerability-tests openvas-notus-data openvas-scap-data openvas-cert-bund-data openvas-dfn-cert-data openvas-data-objects openvas-report-formats)

# This runs as root, and ./web is writable by the web container: everything read from or written to it goes through scripts/update-state.py, which
# never follows a link planted there.
want=$(python3 scripts/update-state.py openvas-wanted) || exit 0
case $want in on | off) ;; *) exit 0 ;; esac

STATE=$(python3 scripts/update-state.py directory) || exit 1
exec 9>"$STATE/openvas.lock"
flock -n 9 || exit 0  # the previous request is still being carried out

# The watcher sends this script's output to $STATE/openvas.log (host-private); the end of it is published as web/.openvas-log.
LOG=$STATE/openvas.log
publish_log() {
  [ -f "$LOG" ] && [ ! -L "$LOG" ] || return 0
  python3 scripts/update-state.py openvas-log "$LOG" || true
  if [ "$(stat -c %s "$LOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then tail -c 262144 "$LOG" >"$LOG.tmp" && cat "$LOG.tmp" >"$LOG"; rm -f "$LOG.tmp"; fi
}
trap publish_log EXIT

report() {  # report applying|ok|failed [message]: one line of JSON, published whole so the app never reads half of it
  local ok=false message
  [ "$1" = ok ] && ok=true
  message=$(printf '%s' "${2:-}" | tr -cd 'A-Za-z0-9 .,:;()_/-' | head -c 200)
  python3 scripts/update-state.py openvas-applied "$(printf '{"want":"%s","state":"%s","ok":%s,"error":"%s","at":%s}' "$want" "$1" "$ok" "$message" "$(date +%s)")" || true
}

. scripts/compose-layout.sh
cvengine_compose_layout || { report failed "the Compose layout could not be worked out"; exit 1; }

if [ "$want" = off ]; then
  report applying
  if "${COMPOSE[@]}" --profile openvas stop "${SERVICES[@]}"; then report ok; else report failed "stopping the containers failed"; fi
  exit 0
fi

# the first start loads the feeds and the scanner holds several GB: say so instead of starting something the host would kill
floor=$(_cvengine_setting CVENGINE_OPENVAS_MIN_AVAILABLE_MB)  # the environment or .env, as the app's own scan guard reads it
[[ $floor =~ ^[0-9]+$ ]] || floor=3072
free=$(awk '/^MemAvailable:/ { printf "%d", $2 / 1024 }' /proc/meminfo 2>/dev/null || echo 0)
if [ "${free:-0}" -lt "$floor" ]; then
  report failed "only $free MB of memory is free and OpenVAS needs $floor MB; free some and switch it on again"
  exit 1
fi
report applying
if "${COMPOSE[@]}" --profile openvas up -d "${SERVICES[@]}"; then report ok; else report failed "starting the containers failed, see web/.openvas-log"; fi
