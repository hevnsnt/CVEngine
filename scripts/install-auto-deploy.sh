#!/usr/bin/env bash
# Installs automatic deployment of new master commits as a systemd timer. Run once, as root, on the server:
#   scripts/install-auto-deploy.sh            install (checks master every 3 minutes)
#   scripts/install-auto-deploy.sh --remove   remove
# Status: systemctl list-timers cvengine-auto-deploy.timer    Logs: journalctl -u cvengine-auto-deploy
# CVENGINE_AUTO_DEPLOY_INTERVAL sets the check interval, for example 5min (default 3min).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
unit=/etc/systemd/system/cvengine-auto-deploy
[[ $EUID -eq 0 ]] || { echo 'Run as root: it installs systemd units and runs Docker.' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemd is required.' >&2; exit 1; }

if [[ ${1:-} == --remove ]]; then
    systemctl disable --now cvengine-auto-deploy.timer 2>/dev/null || true
    rm -f "$unit.service" "$unit.timer"
    systemctl daemon-reload
    echo 'Removed automatic deployment.'
    exit 0
fi

interval=${CVENGINE_AUTO_DEPLOY_INTERVAL:-3min}
[[ $interval =~ ^[0-9]+(s|min|h)$ ]] || { echo 'CVENGINE_AUTO_DEPLOY_INTERVAL must look like 90s, 3min or 1h.' >&2; exit 1; }

echo 'Checking that this install can update cleanly...'
env -u SUDO_UID "$root/scripts/update.sh" --check || { echo 'Fix the items above, then run this again.' >&2; exit 1; }

chmod +x "$root/scripts/auto-deploy.sh"
cat > "$unit.service" <<UNIT
[Unit]
Description=CVEngine: deploy new master commits
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$root
ExecStart=$root/scripts/auto-deploy.sh
TimeoutStartSec=infinity
Nice=5
UNIT
cat > "$unit.timer" <<UNIT
[Unit]
Description=CVEngine: check for new master commits every $interval

[Timer]
OnBootSec=5min
OnUnitInactiveSec=$interval
Unit=cvengine-auto-deploy.service

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now cvengine-auto-deploy.timer >/dev/null
echo "Installed: new master commits deploy automatically (checked every $interval)."
echo 'Logs: journalctl -u cvengine-auto-deploy    Remove: scripts/install-auto-deploy.sh --remove'
if crontab -l 2>/dev/null | grep -qF '# cvengine-auto-update'; then
    echo 'Note: the approval-based updater (scripts/install-updater.sh) is also installed; remove it with scripts/install-updater.sh --remove so only one updater runs.'
fi
echo 'The timer deploys new master commits only while Settings > Updates is set to Automatic; with the default, Manual, it does nothing.'
