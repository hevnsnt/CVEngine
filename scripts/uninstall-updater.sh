#!/usr/bin/env bash
# Removes the host-side update watcher that install.sh and scripts/install-updater.sh put in the crontab: the line that starts
# scripts/update-watch.sh every minute (marked "# cvengine-auto-update"). Nothing else in the crontab is touched, and running it when the
# line is not there is not an error. Settings > Updates then shows "no updater on this host" and Approve does nothing until
# scripts/install-updater.sh is run again. It does not touch the containers, volumes or .env (scripts/uninstall.sh does that) or the
# automatic-deployment timer (scripts/install-auto-deploy.sh --remove).
# Run as the user whose crontab holds the line (install.sh runs as root, so:  sudo scripts/uninstall-updater.sh   or   sudo make uninstall-updater)
set -euo pipefail

MARK="# cvengine-auto-update"
if ! command -v crontab >/dev/null 2>&1; then
  echo "crontab is not available on this host: there is no update cron entry to remove."
  exit 0
fi
if ! crontab -l 2>/dev/null | grep -qF "$MARK"; then
  echo "No CVEngine update cron entry in $(id -un)'s crontab: nothing to remove."
  echo "(The installer puts it in root's crontab: run this with sudo if it was installed that way.)"
  exit 0
fi
REMAINING=$(crontab -l 2>/dev/null | grep -vF "$MARK" || true)
if [ -n "$REMAINING" ]; then
  printf '%s\n' "$REMAINING" | crontab -
else
  crontab -r 2>/dev/null || true  # the entry was the only line: leave no empty crontab behind
fi
echo "Removed the CVEngine update cron entry from $(id -un)'s crontab."
