#!/usr/bin/env bash
# First boot of a hosted cvENGINE server built from the golden image (hosted/README.md). Run once as root by cloud-init, safe to run again: a step
# already done is skipped, and the marker /var/lib/cvl/ready is written only when everything below succeeded.
#
#   1. the data volume is mounted at /mnt/cvl-data (formatted only when it holds no filesystem) with the directories the overlay binds;
#   2. scripts/init-env.sh makes .env: its own passwords and field key, DOMAIN_NAME=s-<8 random characters>.cvengine.live (the server's internal origin
#      name; written to /var/lib/cvl/origin-host for the provisioner, which makes the DNS record and the certificate for it), then the hosted settings:
#      CVENGINE_HOSTED=1, CVENGINE_CSRF_TRUSTED_ORIGINS=https://scanner.cvengine.live, HSTS, and CVENGINE_COMPOSE_FILES naming the hosted overlay so
#      the updater, the watchdog and the certificate renewal keep it;
#   3. the edge secret placeholder: a random value nobody knows, so the proxy refuses everything until the provisioner sets the real one
#      (hosted/cvl-set-edge-secret.sh); /etc/cvl/edge-secret, mode 600;
#   4. the stack starts, migrations run, the CVE catalog is seeded, and /var/lib/cvl/ready is written.
#
# Settings (environment): CVL_ORIGIN_HOST (default: s-<random>.cvengine.live), CVL_PUBLIC_URL (default https://scanner.cvengine.live),
# CVL_VOLUME_DEVICE (default: the first /dev/disk/by-id/scsi-0DO_Volume_*), CVL_ALLOW_NO_VOLUME=1 (development only: keep the data on the root disk),
# CVL_SERVICES (the Compose services to start; default "db redis web celery celery-beat proxy": no built-in scanner and no AI reviewer, a hosted server
# is scanned by the external fleet), CVL_SKIP_SEED=1 (development only). Prints progress on stderr, nothing on stdout.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
umask 077
cvl_root_or_die
cvl_need openssl python3 base64

volume_mount() {
  local device=${CVL_VOLUME_DEVICE:-} candidate
  if mountpoint -q "$CVL_DATA" 2>/dev/null; then cvl_log "the data volume is already mounted at $CVL_DATA"; return 0; fi
  if [ -z "$device" ]; then
    for candidate in /dev/disk/by-id/scsi-0DO_Volume_*; do
      if [ -e "$candidate" ]; then device=$candidate; break; fi
    done
  fi
  if [ -z "$device" ]; then
    [ "${CVL_ALLOW_NO_VOLUME:-0}" = 1 ] || cvl_die "no data volume found (set CVL_VOLUME_DEVICE); refusing to keep customer data on the root disk"
    cvl_log "warning: no data volume: the data stays on the root disk (CVL_ALLOW_NO_VOLUME=1)"
    return 0
  fi
  [ -b "$device" ] || [ -e "$device" ] || cvl_die "the data volume device $device does not exist"
  if ! blkid "$device" >/dev/null 2>&1; then
    cvl_log "the data volume holds no filesystem: creating ext4"
    mkfs.ext4 -q -L cvl-data "$device"
  fi
  mkdir -p "$CVL_DATA"
  mount -o defaults,nofail,noatime "$device" "$CVL_DATA"
  local uuid fstab=${CVL_FSTAB:-/etc/fstab}
  uuid=$(blkid -s UUID -o value "$device" 2>/dev/null || true)
  if [ -n "$uuid" ] && ! grep -q "UUID=$uuid" "$fstab" 2>/dev/null; then
    printf 'UUID=%s %s ext4 defaults,nofail,noatime 0 2\n' "$uuid" "$CVL_DATA" >>"$fstab"
  fi
  cvl_log "mounted the data volume at $CVL_DATA"
}

userland_proxy_note() {
  local file=${CVL_DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}
  if [ -f "$file" ] && python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("userland-proxy") is False else 1)' "$file" 2>/dev/null; then return 0; fi
  cvl_log "warning: Docker's userland proxy is on ($file lacks \"userland-proxy\": false): the proxy container then sees outside clients as the bridge gateway"
}

cvl_private_dir "$CVL_ETC"
cvl_private_dir "$CVL_STATE"
cd "$CVL_REPO"

volume_mount
mkdir -p "$CVL_DATA/postgres" "$CVL_DATA/scan_results"
userland_proxy_note

# --- .env ------------------------------------------------------------------------------------------------------------------------------------
origin=${CVL_ORIGIN_HOST:-}
if [ -z "$origin" ] && [ -s "$CVL_STATE/origin-host" ]; then
  IFS= read -r origin <"$CVL_STATE/origin-host" || true
fi
if [ -z "$origin" ]; then
  origin="s-$(head -c 64 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 8).$CVL_PUBLIC_DOMAIN"
fi
[[ $origin =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || cvl_die "the origin host name '$origin' is not a plain host name"
public_url=${CVL_PUBLIC_URL:-https://scanner.$CVL_PUBLIC_DOMAIN}
[[ $public_url =~ ^https://[a-z0-9.-]+(:[0-9]+)?$ ]] || cvl_die "CVL_PUBLIC_URL must be https://<host>"
printf '%s\n' "$origin" >"$CVL_STATE/origin-host"

# a hosted server is scanned by the external fleet only: the built-in scanner is switched off (CVENGINE_BUILTIN_SCANNER=0) and its image is never needed
CVENGINE_DOMAIN=$origin CVENGINE_INSTALL_SENTINELS=external ./scripts/init-env.sh >&2

cvl_env_set CVENGINE_HOSTED 1
cvl_env_set CVENGINE_CSRF_TRUSTED_ORIGINS "$public_url"
cvl_env_set CVENGINE_HSTS_SECONDS 31536000
cvl_env_set CVENGINE_COMPOSE_FILES docker-compose.yml,docker-compose.hosted.yml

# --- the edge secret placeholder ---------------------------------------------------------------------------------------------------------------
if [ ! -s "$CVL_ETC/edge-secret" ]; then
  cvl_write_in_place "$CVL_ETC/edge-secret" "$(cvl_random_secret)"$'\n'
  cvl_log "wrote a random placeholder edge secret (nobody knows it): the proxy refuses everything until cvl-set-edge-secret.sh sets the real one"
fi
"$(dirname "${BASH_SOURCE[0]}")/gen-edge-auth.sh"

# --- start -------------------------------------------------------------------------------------------------------------------------------------
cvl_compose_layout
[ -s secrets/certs/rengine.pem ] || docker compose -f docker-compose.setup.yml run --rm certs >&2  # the private certificate, until the provisioner installs the real one
rm -f config/nginx/state/maintenance config/nginx/state/maintenance-failed
python3 scripts/update-state.py commit "$(git rev-parse HEAD)" >&2 || cvl_log "warning: could not record the commit for the updater"
read -r -a services <<<"${CVL_SERVICES:-db redis web celery celery-beat proxy}"
"${COMPOSE[@]}" up -d "${services[@]}" >&2
cvl_wait_web 600 || cvl_die "the web service did not come up within 10 minutes"
"${COMPOSE[@]}" exec -T web python3 manage.py migrate --noinput </dev/null >&2
if [ "${CVL_SKIP_SEED:-0}" != 1 ]; then
  "${COMPOSE[@]}" exec -T web python3 manage.py import_cve_seed </dev/null >&2
fi
date -u +%Y-%m-%dT%H:%M:%SZ >"$CVL_STATE/ready"
cvl_log "ready: origin host $origin"
