# shellcheck shell=bash
# Sourced by scripts/update-deploy.sh, scripts/update.sh, scripts/apply-update.sh and `make up`: the one-off ownership service (docker-compose.yml,
# web/ownership.sh), which hands the paths the application writes to its unprivileged account (uid 10002) before the migrate service and the
# application containers start. An install from before the non-root image has its volumes and the Django secret as root's; the first run
# changes them, every later run finds nothing to change. It is run after the image is built (the script is in the image) and once more right
# before the application containers are recreated, for what the old containers, which ran as root, wrote in between.
#
#   . scripts/app-ownership.sh
#   cvengine_app_ownership docker compose [ARGS...]     prints one line (what changed, or that nothing did); exit 1 when the service failed
#
# A Compose layout without the service (an install's own file that replaces docker-compose.yml) is left alone: its containers run as its file says.
# ROLLBACK: the previous release runs these containers as root, which can read and write whatever the ownership service changed, so an update
# that is put back needs no step for it (docs/UPGRADE.md).
cvengine_app_ownership() {
  local listed out status=0
  listed=$("$@" config --services 2>/dev/null) || listed=''
  if [ -n "$listed" ] && ! grep -qx ownership <<<"$listed"; then
    echo "ownership: this Compose layout has no ownership service; the application containers run as its file says"
    return 0
  fi
  out=$("$@" run --rm --no-deps -T ownership 2>&1) || status=$?
  if [ "$status" = 0 ]; then
    out=$(printf '%s\n' "$out" | grep '^ownership:' | tail -n 1)
    printf '%s\n' "${out:-ownership: done}"
    return 0
  fi
  printf 'ownership: the ownership service failed (status %s): %s\n' "$status" "$(printf '%s\n' "$out" | tail -n 3 | tr '\n' ' ')"
  return 1
}
