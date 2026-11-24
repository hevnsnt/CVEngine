#!/bin/sh
# The one-off ownership service (docker-compose.yml, `ownership`): hands the paths the application writes to its unprivileged account, once, and
# idempotently. It is the only container of this image that runs as root, with CHOWN, FOWNER and DAC_OVERRIDE and no other capability, no network
# and no environment file; the update scripts and `make up` run it after the image is built and before the migrate service and the application
# start (`docker compose up` does the same through depends_on). Run by hand with `docker compose run --rm ownership`.
#
# Before this release web, celery, celery-beat and the migrate service ran as root, so the volumes and the files they wrote in the host's web/ folder
# are root's. This changes only what is not already right, says how many paths it changed in one line, and changes nothing on a second run:
#   scan results          every entry to uid 10002 (groups kept); the folder itself 10002:101 (the proxy's nginx group), mode 0750
#   static files, generated templates, ~/.config (the CVE seed folder), the owner fallback, the AI reviewer's token folder: every entry to 10002:10002
#   the built-in scanner's enrollment folder: the folder only (the blob in it stays the scanner's until the server writes the next one)
#   the host's web/ folder (mounted at /var/lib/cvengine/web): group 10002 and mode 1775, so the application can create its update requests there
#   but cannot change, rename or remove any file it does not own (the sticky bit); the Django secret (web/secret, mode 0600) and the request
#   files the containers wrote as root before (.update-approved and the rest) become 10002's. Nothing else in web/ changes owner: the source stays
#   the checkout's, and the image is built from an allow list (web/.dockerignore), so a file the application creates there never reaches an image.
# ROLLBACK: the previous release runs these containers as root, which reads and writes every path above whatever its owner, so going back needs
# no step; `chmod 0755 web` restores the folder mode if wanted.
set -eu
APP_UID=${CVENGINE_APP_UID:-10002}
APP_GID=${CVENGINE_APP_GID:-10002}
PROXY_GID=${CVENGINE_PROXY_GID:-101}
# CVENGINE_OWNERSHIP_ROOT puts every path below another folder: the tests run this script on a scratch tree (tests/test_image_user.py)
R=${CVENGINE_OWNERSHIP_ROOT:-}
HOST_WEB=$R${CVENGINE_HOST_DIR:-/var/lib/cvengine/web}
INIT=$(dirname "$0")/reNgine/init.py
# what the web and celery containers write in web/ (cveFeed/updater.py, cveFeed/scanner_plan.py, cveFeed/watchdog.py, agentapi/sentinel_autoupdate.py)
REQUESTS='.update-approved .update-branch .update-sentinels .update-mode .update-wait-scans .update-source .scanner-update-requested .scanner-plan-wanted .watchdog-action .update-lock'
changed=0
report=''

count() {  # the entries below $1 (not crossing into another mount) that are not owned as $2 says: find tests
    find "$1" -xdev $2 -print 2>/dev/null | wc -l | tr -d ' '
}

tree() {  # DIR USER[:GROUP] FIND-TEST: every entry below DIR that fails the test is given USER[:GROUP]
    [ -d "$1" ] || return 0
    n=$(count "$1" "$3")
    if [ "$n" -gt 0 ]; then
        find "$1" -xdev $3 -exec chown -h "$2" {} +
        changed=$((changed + n))
        report="$report $(basename "$1")=$n"
    fi
}

top() {  # DIR USER:GROUP MODE: the folder itself
    [ -d "$1" ] || return 0
    if [ "$(stat -c '%u:%g %a' "$1")" != "$2 $3" ]; then
        chown "$2" "$1"
        chmod "$3" "$1"
        changed=$((changed + 1))
        report="$report $(basename "$1")/"
    fi
}

tree "$R/usr/src/scan_results" "$APP_UID" "! -user $APP_UID"
top "$R/usr/src/scan_results" "$APP_UID:$PROXY_GID" 750
for dir in /usr/src/app/staticfiles /root/cvengine-generated-templates /home/cvengine/.config /var/lib/cvengine-db-owner /var/lib/cvengine-reviewer; do
    tree "$R$dir" "$APP_UID:$APP_GID" "( ! -user $APP_UID -o ! -group $APP_GID )"
done
if [ -d "$R/var/lib/cvengine-scanner" ] && [ "$(stat -c '%u' "$R/var/lib/cvengine-scanner")" != "$APP_UID" ]; then
    chown "$APP_UID:$APP_GID" "$R/var/lib/cvengine-scanner"
    changed=$((changed + 1))
    report="$report cvengine-scanner/"
fi

if [ -d "$HOST_WEB" ]; then
    owner=$(stat -c '%u' "$HOST_WEB")
    top "$HOST_WEB" "$owner:$APP_GID" 1775
    # A first start: the Django secret is created here, with the application's own code (reNgine/init.py first_run: 64 random characters, written
    # atomically, mode 0600), and handed over below. The migrate service and Beat mount web/ read-only and could not create it.
    if [ ! -e "$HOST_WEB/secret" ] && [ ! -L "$HOST_WEB/secret" ]; then
        python3 -c "import importlib.util, sys; s = importlib.util.spec_from_file_location('cvengine_init', sys.argv[2]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); m.first_run(sys.argv[1], '')" "$HOST_WEB/secret" "$INIT"
        echo "ownership: created the Django secret (web/secret)"
    fi
    for name in secret $REQUESTS; do
        for path in "$HOST_WEB/$name" "$HOST_WEB/$name.tmp"; do
            # a regular file only (never through a link a container may have planted)
            if [ -f "$path" ] && [ ! -L "$path" ] && [ "$(stat -c '%u:%g' "$path")" != "$APP_UID:$APP_GID" ]; then
                chown -h "$APP_UID:$APP_GID" "$path"
                changed=$((changed + 1))
                report="$report web/$name"
            fi
        done
    done
    if [ -f "$HOST_WEB/secret" ] && [ ! -L "$HOST_WEB/secret" ] && [ "$(stat -c '%a' "$HOST_WEB/secret")" != 600 ]; then
        chmod 0600 "$HOST_WEB/secret"
    fi
fi

if [ "$changed" -gt 0 ]; then
    echo "ownership: handed $changed path(s) to the application account (uid $APP_UID):$report"
else
    echo "ownership: every application path already belongs to uid $APP_UID; nothing changed"
fi
