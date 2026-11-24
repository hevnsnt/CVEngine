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
#   the built-in scanner's enrollment folder: the folder only, 10002:10002 mode 2751 (setgid: the blob the server writes there is 0640, group 10002,
#   which the scanner service is given with group_add); a blob left readable by others is made group 10002 and 0640
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
INIT=$(dirname "$0")/cvengine/init.py
# what the web and celery containers write in web/ (cveFeed/updater.py, cveFeed/scanner_plan.py, cveFeed/watchdog.py, agentapi/sentinel_autoupdate.py)
REQUESTS='.update-approved .update-branch .update-sentinels .update-mode .update-wait-scans .update-source .scanner-update-requested .scanner-plan-wanted .watchdog-action'
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
# The built-in scanner's enrollment folder: 10002's, group 10002 (the scanner service has it through group_add), setgid so a blob created in it
# takes that group, and closed to others. A blob left readable by others (the 0644 an earlier writer fell back to) is closed to group 10002 and 0640.
# The setgid bit is set while the folder's group is still root's: this root has no FSETID capability and is not in group 10002, and the kernel
# drops the bit from a chmod by such a process; a later change of a folder's group keeps it.
scanner_dir="$R/var/lib/cvengine-scanner"
# Others may pass through the folder (the 1 of 2751) but not list it: the previous release's scanner, which has no group 10002, still reaches the
# 0600 blob of its own that the previous release writes there, so an update that is put back does not leave its scanner unable to enroll.
if [ -d "$scanner_dir" ] && [ "$(stat -c '%u:%g %a' "$scanner_dir")" != "$APP_UID:$APP_GID 2751" ]; then
    chown "$APP_UID:$(id -g)" "$scanner_dir"
    chmod 2751 "$scanner_dir"
    chgrp "$APP_GID" "$scanner_dir"
    changed=$((changed + 1))
    report="$report cvengine-scanner/"
fi
blob="$R/var/lib/cvengine-scanner/blob"
if [ -f "$blob" ] && [ ! -L "$blob" ] && [ -n "$(find "$blob" -perm /0007 -print)" ]; then
    chgrp -h "$APP_GID" "$blob"
    chmod 0640 "$blob"
    changed=$((changed + 1))
    report="$report cvengine-scanner/blob"
fi

if [ -d "$HOST_WEB" ]; then
    owner=$(stat -c '%u' "$HOST_WEB")
    top "$HOST_WEB" "$owner:$APP_GID" 1775
    # A first start: the Django secret is created here, with the application's own code (cvengine/init.py first_run: 64 random characters, written
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
    # The update lock (web/.update-lock) is opened in place, with O_CREAT, by three parties: the application (uid 10002, cveFeed/scan_control.py
    # updater_idle), the host (scripts/watchdog.sh, as root or the checkout's owner) and, after an update that failed and put the previous release
    # back, that release's root containers. In this folder (group writable, sticky) the kernel's fs.protected_regular (2 on Ubuntu) refuses such an
    # open of a file that belongs to neither the opener nor the folder's owner, root included: with the lock as 10002's the host's watchdog read it
    # as free and the previous release could not release the update's scan pause. So it belongs to the folder's owner, group 10002, mode 0660,
    # which every one of them may open. An existing file is only given away and chmodded here, never opened (that open would be refused too).
    lock="$HOST_WEB/.update-lock"
    if [ ! -L "$lock" ] && { [ ! -e "$lock" ] || [ -f "$lock" ]; }; then
        [ -e "$lock" ] || : > "$lock"
        if [ "$(stat -c '%u:%g %a' "$lock")" != "$owner:$APP_GID 660" ]; then
            chown -h "$owner:$APP_GID" "$lock"
            chmod 0660 "$lock"
            changed=$((changed + 1))
            report="$report web/.update-lock"
        fi
    fi
fi

if [ "$changed" -gt 0 ]; then
    echo "ownership: handed $changed path(s) to the application account (uid $APP_UID):$report"
else
    echo "ownership: every application path already belongs to uid $APP_UID; nothing changed"
fi
