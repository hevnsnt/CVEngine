#!/usr/bin/env bash
# Starts or stops the OpenVAS (Greenbone) containers when someone switches the add-on on or off in the app. The web container has no Docker access on
# purpose, so it writes web/.openvas-wanted ("on" or "off") and scripts/update-watch.sh runs this when that file is newer than web/.openvas-applied,
# the answer this script leaves (JSON, read by Settings > OpenVAS and Administration > OpenVAS). It never runs anything the file does not name: the
# only words it accepts are on and off, and the services are the ones listed here (keep the list equal to OPENVAS_SERVICES in the Makefile).
#   scripts/openvas-sync.sh        (also: make openvas-up / make openvas-down do the same by hand)
set -uo pipefail
cd "$(dirname "$0")/.."
WANTED=web/.openvas-wanted
APPLIED=web/.openvas-applied
SERVICES=(openvas-gvmd openvas-ospd openvas-openvasd openvas-redis openvas-pg-gvm openvas-pg-gvm-migrator openvas-configure openvas-gpg-data openvas-vulnerability-tests openvas-notus-data openvas-scap-data openvas-cert-bund-data openvas-dfn-cert-data openvas-data-objects openvas-report-formats)

[ -f "$WANTED" ] && [ ! -L "$WANTED" ] || exit 0
want=$(head -c 8 "$WANTED" | tr -d '[:space:]')
case $want in on | off) ;; *) exit 0 ;; esac

STATE=$(python3 scripts/update-state.py directory) || exit 1
exec 9>"$STATE/openvas.lock"
flock -n 9 || exit 0  # the previous request is still being carried out

report() {  # report ok|failed [message]: one line of JSON, written whole so the app never reads half of it
  local ok=false message
  [ "$1" = ok ] && ok=true
  message=$(printf '%s' "${2:-}" | tr -cd 'A-Za-z0-9 .,:;()_/-' | head -c 200)
  printf '{"want":"%s","ok":%s,"error":"%s","at":%s}\n' "$want" "$ok" "$message" "$(date +%s)" >"$APPLIED.tmp" && mv -f "$APPLIED.tmp" "$APPLIED"
}

. scripts/compose-layout.sh
cvengine_compose_layout || { report failed "the Compose layout could not be worked out"; exit 1; }

if [ "$want" = off ]; then
  if "${COMPOSE[@]}" --profile openvas stop "${SERVICES[@]}"; then report ok; else report failed "stopping the containers failed"; fi
  exit 0
fi

# the first start loads the feeds and the scanner holds several GB: say so instead of starting something the host would kill
floor=${CVENGINE_OPENVAS_MIN_AVAILABLE_MB:-3072}
free=$(awk '/^MemAvailable:/ { printf "%d", $2 / 1024 }' /proc/meminfo 2>/dev/null || echo 0)
if [ "${free:-0}" -lt "$floor" ]; then
  report failed "only $free MB of memory is free and OpenVAS needs $floor MB; free some and switch it on again"
  exit 1
fi
if "${COMPOSE[@]}" --profile openvas up -d "${SERVICES[@]}"; then report ok; else report failed "starting the containers failed, see web/.openvas-log"; fi
