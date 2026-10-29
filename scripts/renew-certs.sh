#!/usr/bin/env bash
# Renews the web interface certificate before it expires, with no manual step and no downtime.
#   scripts/renew-certs.sh [--if-due] [--no-reload]
# The certificate is made by the certs service (certs/entrypoint.sh, `make certs`): signed by the local authority the installer created, valid
# for 397 days. That script decides: it issues a new certificate (same key, same authority, same names) only when fewer than 30 days remain,
# the names changed or the certificate is not the one it would make today (a 10-year certificate from an older install is replaced once). This
# script runs it, tells the running proxy to reload when a certificate was issued (nginx `reload`: no restart, no dropped connection; the
# certificate files are rewritten in place so the proxy's mounts see them; a certificate some other authority issued, such as a Let's Encrypt one
# (docs/HOSTING-ONLINE.md), is never replaced), and publishes the outcome for the app (web/.cert-status.json,
# read by Settings > Updates and get_system_status, which warn under 30 days or when a renewal failed).
#
# Started by scripts/update-watch.sh (cron, every minute: --if-due makes this a no-op until the next check is due, twice a day), by
# scripts/auto-deploy.sh, and before the services are recreated by an update. --if-due: do nothing unless the next check is due. --no-reload:
# do not touch the running proxy (the caller recreates it). CVENGINE_CERT_CHECK_SECONDS (default 43200) is the time between checks and
# CVENGINE_CERT_RETRY_SECONDS (default 3600) the wait after a failure. Nothing happens on an install that does not use the bundled
# authority (no secrets/certs/rengine.pem: a host proxy owns the certificate).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
# root (cron, systemd) in a checkout owned by whoever cloned it: git refuses it ("dubious ownership") unless this one is named
export GIT_CONFIG_COUNT=$(( ${GIT_CONFIG_COUNT:-0} + 1 ))
export "GIT_CONFIG_KEY_$((GIT_CONFIG_COUNT - 1))=safe.directory" "GIT_CONFIG_VALUE_$((GIT_CONFIG_COUNT - 1))=$PWD"

if_due=0
reload=1
for arg in "$@"; do
  case $arg in
    --if-due) if_due=1 ;;
    --no-reload) reload=0 ;;
    *) echo "usage: $0 [--if-due] [--no-reload]" >&2; exit 2 ;;
  esac
done
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
number() { [[ ${!1:-} =~ ^[0-9]+$ ]] && printf '%s' "${!1}" || printf '%s' "$2"; }

[ -s secrets/certs/rengine.pem ] || exit 0
interval=$(number CVENGINE_CERT_CHECK_SECONDS 43200)
retry=$(number CVENGINE_CERT_RETRY_SECONDS 3600)
STATE=$(python3 scripts/update-state.py directory) || exit 1
exec 9>"$STATE/cert.lock"
flock -n 9 || exit 0  # another check is running

due_file=$STATE/cert-next-check
if [ "$if_due" -eq 1 ] && [ -f "$due_file" ]; then
  next=$(cat "$due_file" 2>/dev/null)
  [[ $next =~ ^[0-9]+$ ]] && [ "$(date +%s)" -lt "$next" ] && exit 0
fi
schedule() { printf '%s' "$(( $(date +%s) + $1 ))" > "$due_file.tmp" && mv -f "$due_file.tmp" "$due_file"; }

publish() {  # result, the certificate's notAfter date, an error line
  python3 scripts/update-state.py cert-status "$1" "${2:-}" "${3:-}" >/dev/null 2>&1 || log "could not publish the certificate status"
}
fail() {
  local error=${1:0:200}
  log "certificate renewal failed: $error"
  publish failed "$(openssl x509 -in secrets/certs/rengine.pem -noout -enddate 2>/dev/null | cut -d= -f2)" "$error"
  schedule "$retry"
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker is not available to the certificate check"
# shellcheck source=compose-layout.sh
. scripts/compose-layout.sh
cvengine_compose_layout || fail "the Compose layout of this install could not be worked out (see the log)"

# The certs service lives in its own Compose file; it needs the same project and env file as the running stack, but not its files
certs_compose=()
skip=0
for arg in "${COMPOSE[@]}"; do
  if [ "$skip" -eq 1 ]; then skip=0; continue; fi
  if [ "$arg" = -f ]; then skip=1; continue; fi
  certs_compose+=("$arg")
done
certs_compose+=(-f docker-compose.setup.yml)

output=$("${certs_compose[@]}" run --rm -T --no-deps -e CERT_ONLY_OURS=1 certs 2>&1)
status=$?
printf '%s\n' "$output" | sed 's/^/certs: /'
result=$(printf '%s\n' "$output" | sed -n 's/^cert-result: //p' | tail -n1)
not_after=$(printf '%s\n' "$output" | sed -n 's/^cert-not-after: //p' | tail -n1)
if [ "$status" -ne 0 ] || [[ $result != @(issued|kept|external) ]]; then
  fail "the certs service failed: $(printf '%s\n' "$output" | grep -v '^[[:space:]]*$' | tail -n1)"
fi

if [ "$result" = issued ]; then
  log "issued a new web interface certificate (valid until $not_after)"
  if [ "$reload" -eq 1 ] && "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx proxy; then
    if "${COMPOSE[@]}" exec -T proxy nginx -s reload >/dev/null 2>&1; then
      log "the proxy reloaded the new certificate"
    elif "${COMPOSE[@]}" up -d --no-deps --force-recreate proxy >/dev/null 2>&1; then
      log "the proxy could not reload, so it was recreated to load the new certificate"
    else
      fail "a new certificate was issued but the proxy could neither reload nor restart; run: docker compose up -d --force-recreate proxy"
    fi
  fi
fi
publish "$result" "$not_after" ""
schedule "$interval"
exit 0
