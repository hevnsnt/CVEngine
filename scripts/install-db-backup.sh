#!/usr/bin/env bash
# Schedule the daily database dump (scripts/db-backup-daily.sh): one line in the crontab of the user that runs this, every night at 03:17
# (host time), its output appended to the log in the dump folder.
#   scripts/install-db-backup.sh            install or replace the line (make db-backup-schedule)
#   scripts/install-db-backup.sh --remove   remove it; the dumps already taken stay
# Run it as a user that may run Docker (root on most hosts). Only the line marked "# cvengine-db-backup" is ever touched.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
MARK="# cvengine-db-backup"
CURRENT=$(crontab -l 2>/dev/null | grep -vF "$MARK" || true)

if [ "${1:-}" = "--remove" ]; then
  printf '%s\n' "$CURRENT" | sed '/^$/d' | crontab -
  echo "Removed the nightly database dump from the crontab. The dumps already taken stay where they are."
  exit 0
fi

dir=${CVENGINE_DB_BACKUP_DIR:-}
if [ -z "$dir" ] && [ -f "$ROOT/.env" ]; then
  dir=$(grep -E '^CVENGINE_DB_BACKUP_DIR=' "$ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d '\r\"'"'" || true)
fi
dir=${dir:-backups/db}
case $dir in /*) ;; *) dir="$ROOT/$dir" ;; esac
case $ROOT$dir in *[!A-Za-z0-9._/-]*) echo "The checkout path and CVENGINE_DB_BACKUP_DIR may hold only letters, digits, dots, dashes, underscores and slashes for a cron line (got $ROOT and $dir)." >&2; exit 1 ;; esac
(umask 077; mkdir -p "$dir")
chmod 700 "$dir"
chmod +x "$ROOT/scripts/db-backup-daily.sh"
printf '%s\n17 3 * * * cd %s && scripts/db-backup-daily.sh >> %s/backup.log 2>&1 %s\n' "$CURRENT" "$ROOT" "$dir" "$MARK" | sed '/^$/d' | crontab -
echo "Installed: a database dump every night at 03:17 into $dir (log: $dir/backup.log). Run it now with: make db-backup"
