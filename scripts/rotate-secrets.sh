#!/usr/bin/env bash
# Rotate every secret this host holds for cvENGINE, in the order that keeps the site up, and prove it worked.
#   ./scripts/rotate-secrets.sh --dry-run               print the plan and change nothing (make rotate-secrets ARGS=--dry-run)
#   ./scripts/rotate-secrets.sh                         rotate; asks you to type yes first (make rotate-secrets)
#   ./scripts/rotate-secrets.sh --yes                   rotate without asking (no terminal, for example from a runbook)
#   ./scripts/rotate-secrets.sh --keep-django-secret    leave web/secret as it is, so nobody is signed out
# What it rotates: the database owner's password (POSTGRES_PASSWORD), the password of the role the server runs as (CVENGINE_DB_APP_PASSWORD,
# when the installation has that role), the Redis password (REDIS_PASSWORD), the key that encrypts stored secrets (CVENGINE_FIELD_KEY) and the
# Django secret (web/secret, or CVENGINE_SECRET_KEY when the env file sets it). In order:
#   1. backs up .env, the Compose env file and web/secret into backups/keys-<time> (mode 0700) and dumps the database into the dump folder
#      (scripts/db-backup-daily.sh, backups/db by default): two folders, so the old keys and the dump they decrypt are never in one place;
#   2. writes the new values to .env and the Compose env file (the old field key goes to CVENGINE_FIELD_KEY_PREVIOUS, which only decrypts);
#   3. sets the new passwords in PostgreSQL (ALTER ROLE, through psql's standard input, never on a command line);
#   4. recreates redis, web, celery and celery-beat (and the scanner and the AI reviewer when they run) from a clean environment (env -i), so a
#      value exported in this shell can never win over the env file;
#   5. re-encrypts every stored secret under the new field key (manage.py rotate_field_key) and checks that none still needs the old one;
#   6. removes CVENGINE_FIELD_KEY_PREVIOUS, writes a new 64 character Django secret, recreates web, celery, celery-beat (and the reviewer);
#   7. restarts the proxy, which otherwise keeps the old address of web and answers 502;
#   8. checks that the site answers, that both database roles log in with the new passwords, that Redis takes the new password and refuses
#      none, that no stored secret is unreadable, and that the server still runs as its own role.
# It refuses to start while this shell exports one of the variables it rotates. A new Django secret signs everyone out and voids the
# two-step recovery codes made so far. It ends with what it cannot rotate and where to change each. See docs/CONFIGURATION.md, Rotating secrets.
# CVENGINE_ROTATE_WAIT (seconds, default 300) is how long it waits for the web service after each recreate.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

ROTATED=(POSTGRES_PASSWORD REDIS_PASSWORD CVENGINE_DB_APP_PASSWORD CVENGINE_FIELD_KEY CVENGINE_FIELD_KEY_PREVIOUS CVENGINE_SECRET_KEY)
dry_run=0 assume_yes=0 keep_secret=0
args=("$@")
while (( $# )); do
    case $1 in
        --dry-run) dry_run=1 ;;
        --yes) assume_yes=1 ;;
        --keep-django-secret) keep_secret=1 ;;
        -h|--help) sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done
wait_seconds=${CVENGINE_ROTATE_WAIT:-300}
[[ $wait_seconds =~ ^[0-9]+$ ]] || wait_seconds=300

die() { echo "rotate-secrets: $*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

[[ -f .env ]] || die ".env not found: run this from the CVEngine directory of a running installation."

# Compose takes ${VARIABLE} from the shell before the env file, so a stale export recreates the containers with the old password.
exported=()
for name in "${ROTATED[@]}"; do
    [[ -n ${!name+x} ]] && exported+=("$name")
done
if (( ${#exported[@]} )); then
    echo "Refusing to run: this shell exports ${exported[*]}. Docker Compose would take the old value from the shell instead of the new one in" >&2
    echo "the env file, and the containers would start with a password the database no longer accepts. Run: unset ${exported[*]}" >&2
    echo "then run this again (and remove the export from your shell profile if it is there)." >&2
    exit 2
fi

# Every docker and Compose call runs with a clean environment: the path, the home directory and Docker's own connection settings only.
CLEAN_ENV=(env -i "PATH=$PATH" "HOME=${HOME:-/root}")
for name in DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY COMPOSE_PROJECT_NAME TMPDIR \
            CVENGINE_COMPOSE_FILES CVENGINE_COMPOSE_FILE CVENGINE_COMPOSE_ENV_FILE CVENGINE_COMPOSE_PROJECT; do
    [[ -n ${!name:-} ]] && CLEAN_ENV+=("$name=${!name}")
done
# The script itself then starts again with that environment only, so nothing it runs (docker, Compose, python3, curl) sees anything else.
if [[ -z ${ROTATE_SECRETS_CLEAN_ENV:-} ]]; then
    exec "${CLEAN_ENV[@]}" ROTATE_SECRETS_CLEAN_ENV=1 "TERM=${TERM:-dumb}" "CVENGINE_ROTATE_WAIT=$wait_seconds" bash "${BASH_SOURCE[0]}" ${args[@]+"${args[@]}"}
fi

. scripts/compose-layout.sh
cvengine_compose_layout || exit 1
compose() { "${CLEAN_ENV[@]}" "${COMPOSE[@]}" "$@"; }
dockerc() { "${CLEAN_ENV[@]}" docker "$@"; }
ENV_FILES=(.env)
[[ -n ${COMPOSE_ENV_FILE:-} && $COMPOSE_ENV_FILE != .env ]] && ENV_FILES+=("$COMPOSE_ENV_FILE")
EFFECTIVE=${ENV_FILES[${#ENV_FILES[@]}-1]}  # the file Compose reads ${VARIABLES} from

value_of() {  # value_of KEY FILE
    local value
    value=$(grep -E "^$1=" "$2" 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d '\r') || value=''
    value=${value#[\"\']}; value=${value%[\"\']}
    printf '%s' "$value"
}
has_line() { grep -qE "^$1=" "$2" 2>/dev/null; }
set_value() {  # set_value KEY VALUE FILE: replace or append, in place (keeps owner and mode), the value never on a command line
    local key=$1 value=$2 file=$3 tmp
    tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-env.XXXXXX")
    chmod 600 "$tmp"
    if has_line "$key" "$file"; then
        CVENGINE_AWK_VALUE="$value" awk -v key="$key" 'BEGIN { prefix = key "=" } index($0, prefix) == 1 { print prefix ENVIRON["CVENGINE_AWK_VALUE"]; next } { print }' "$file" > "$tmp"
    else
        { cat "$file"; [[ -z $(tail -c 1 "$file") ]] || echo; echo "${key}=${value}"; } > "$tmp"
    fi
    cat "$tmp" > "$file"
    rm -f -- "$tmp"
}
drop_line() {  # drop_line KEY FILE
    local tmp
    has_line "$1" "$2" || return 0
    tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-env.XXXXXX")
    chmod 600 "$tmp"
    grep -vE "^$1=" "$2" > "$tmp" || true
    cat "$tmp" > "$2"
    rm -f -- "$tmp"
}
random() { local out=''; while (( ${#out} < $1 )); do out+=$(head -c 512 /dev/urandom | base64 | tr -dc 'A-Za-z0-9'); done; printf '%s' "${out:0:$1}"; }

# What this installation has
for file in "${ENV_FILES[@]}"; do
    if [[ -n $(value_of CVENGINE_FIELD_KEY_FILE "$file") ]]; then
        die "$file sets CVENGINE_FIELD_KEY_FILE: the field key lives in a file this script does not manage. Rotate it by hand (docs/CONFIGURATION.md, Rotating secrets)."
    fi
done
owner=$(value_of POSTGRES_USER "$EFFECTIVE")
[[ -n $owner ]] || owner=$(value_of POSTGRES_USER .env)
[[ $owner =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "POSTGRES_USER '$owner' is not a plain role name; rotate its password by hand."
app_user=''
if ! grep -qE '^CVENGINE_DB_APP_USER=[[:space:]]*$' "$EFFECTIVE" && [[ -n $(value_of CVENGINE_DB_APP_PASSWORD "$EFFECTIVE") ]]; then
    app_user=$(value_of CVENGINE_DB_APP_USER "$EFFECTIVE")
    app_user=${app_user:-cvengine_app}
    [[ $app_user =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "CVENGINE_DB_APP_USER '$app_user' is not a plain role name."
fi
secret_in_env=''
for file in "${ENV_FILES[@]}"; do has_line CVENGINE_SECRET_KEY "$file" && secret_in_env="${secret_in_env:+$secret_in_env }$file"; done
running=$(compose ps --status running --services 2>/dev/null || true)
is_running() { grep -qx "$1" <<<"$running"; }
first=(redis web celery celery-beat)
second=(web celery celery-beat)
for service in scanner reviewer; do is_running "$service" && first+=("$service"); done
is_running reviewer && second+=(reviewer)
has_proxy=0
dump_dir=${CVENGINE_DB_BACKUP_DIR:-$(value_of CVENGINE_DB_BACKUP_DIR .env)}
dump_dir=${dump_dir:-backups/db}
grep -qx proxy < <(compose config --services 2>/dev/null) && has_proxy=1

checklist() {
    cat <<'EOF'

What this script cannot rotate, and where to change each:
  - Third party API keys stored in the app (the AI provider key, Chaos, Netlas, HackerOne, WordPress data, runZero, webhook URLs, the
    Telegram bot token): they were re-encrypted, not changed. Make a new key at each provider, enter it under Settings, API keys (per
    organization or project), Settings, AI model, or Settings, Notifications, then revoke the old one at the provider.
  - The admin login password: change it on your account page, or run make admin-password for a new random one.
    DJANGO_SUPERUSER_PASSWORD in .env is read only when the first account is made; changing it changes no account.
  - MCP and agent API tokens: Settings, API keys. Make a new token, put it in each MCP client or agent, then revoke the old one.
  - Sentinel tokens: API keys, Agents in your organizations, Manage. Enroll each Sentinel again with a new token, then revoke the old one.
  - The host's root password and SSH keys: on the host (passwd, ~/.ssh/authorized_keys).
  - The hosting provider's control panel password: in the provider's panel (and turn on its two step sign-in).
  - The HTTPS certificate key (secrets/certs) and a Tailscale auth key: make certs, and the Tailscale admin console.
EOF
}
plan() {
    say "Plan (nothing is changed by --dry-run):"
    say "  Compose: ${COMPOSE[*]}"
    say "  Env files written: ${ENV_FILES[*]}"
    say "  1. Back up ${ENV_FILES[*]} and web/secret into backups/keys-<time> (mode 0700); dump the database into $dump_dir (a separate folder)."
    say "  2. New POSTGRES_PASSWORD, REDIS_PASSWORD${app_user:+, CVENGINE_DB_APP_PASSWORD}, CVENGINE_FIELD_KEY (the old one kept as CVENGINE_FIELD_KEY_PREVIOUS)."
    say "  3. ALTER ROLE $owner${app_user:+ and $app_user} WITH PASSWORD (through psql's standard input)."
    say "  4. Recreate ${first[*]} from a clean environment (env -i)."
    say "  5. manage.py rotate_field_key, then rotate_field_key --check --strict (every secret under the new key)."
    if (( keep_secret )); then
        say "  6. Remove CVENGINE_FIELD_KEY_PREVIOUS; keep the Django secret (--keep-django-secret); recreate ${second[*]}."
    else
        say "  6. Remove CVENGINE_FIELD_KEY_PREVIOUS; new 64 character Django secret in ${secret_in_env:-web/secret}; recreate ${second[*]}."
    fi
    (( has_proxy )) && say "  7. Restart the proxy." || say "  7. No proxy service in this layout: nothing to restart."
    say "  8. Verify: the site answers, $owner${app_user:+ and $app_user} log in with the new passwords, Redis takes the new password and refuses none,"
    say "     no stored secret is unreadable${app_user:+, and web, celery and celery-beat run as $app_user}."
}
logout_warning() {
    if (( keep_secret )); then
        say "The Django secret is kept: nobody is signed out."
    else
        say "WARNING: the new Django secret signs EVERYONE out (every session ends) and voids the two-step sign-in recovery codes made so far:"
        say "each user with two-step sign-in should make new recovery codes after signing in (the authenticator apps keep working)."
    fi
    say "Running scans keep running; tasks queued in Redis at the moment Redis restarts are lost, as with any restart of the broker."
}

if (( dry_run )); then
    plan
    echo
    logout_warning
    checklist
    exit 0
fi

plan
echo
logout_warning
if (( ! assume_yes )); then
    [[ -t 0 ]] || die "not run from a terminal: pass --yes to rotate without the question, or --dry-run to see the plan."
    printf '\nType yes to rotate now: '
    read -r answer
    [[ $answer == yes ]] || { echo "Aborted: nothing changed."; exit 1; }
fi

phase=preflight
trap 'echo "rotate-secrets: stopped during $phase (line $LINENO). Backups: ${keydir:-none yet} and ${dump:-no dump yet}. See docs/CONFIGURATION.md, Rotating secrets." >&2' ERR

step "Checking the running installation"
db=$(compose ps -q --status running db 2>/dev/null | head -n1) || db=''
[[ -n $db ]] || die "the database container is not running: start the stack first (make up)."
is_running web || die "the web container is not running: start the stack first (make up)."
dockerc exec "$db" sh -c 'pg_isready -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"' || die "the database does not answer."
app_exists=0
if [[ -n $app_user ]]; then
    [[ $(dockerc exec "$db" sh -c 'psql -X -tA -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT 1 FROM pg_roles WHERE rolname = '"'"'$1'"'"'"' sh "$app_user" 2>/dev/null) == 1 ]] && app_exists=1
    (( app_exists )) || say "The role $app_user does not exist yet: its password is written to the env files and the next migrate creates it with it."
fi
# rotate_field_key saves every row: a value no key reads now would be saved as empty, losing the ciphertext an old key might still open
if ! before=$(compose exec -T web python3 manage.py rotate_field_key --check 2>&1); then
    say "$before"
    die "some stored secrets cannot be read with the keys this installation has now (listed above). Enter them again in Settings (they show as empty), or put the key that reads them in CVENGINE_FIELD_KEY_PREVIOUS, then run this again."
fi
say "${before%%$'\n'*}"

step "Backing up the keys and the database"
phase=backup
stamp=$(date -u +%Y%m%dT%H%M%SZ)
keydir="backups/keys-$stamp"
(umask 077; mkdir -p backups "$keydir")
chmod 700 "$keydir"
for file in "${ENV_FILES[@]}"; do (umask 077; cp -p -- "$file" "$keydir/$(basename "$file")"); done
[[ -f web/secret ]] && (umask 077; cp -p -- web/secret "$keydir/secret")
chmod 600 "$keydir"/* 2>/dev/null || true
say "Keys backed up in $keydir."
dump=$("${CLEAN_ENV[@]}" bash scripts/db-backup-daily.sh --label before-rotation | tail -n 1) || die "the database dump failed: nothing was changed."
[[ -f $dump ]] || die "the database dump failed: nothing was changed."
say "Database dumped to $dump."

restore_files() { for file in "${ENV_FILES[@]}"; do cat "$keydir/$(basename "$file")" > "$file"; done; }

step "Writing the new values"
phase='writing the env files'
old_field=$(value_of CVENGINE_FIELD_KEY .env)
old_previous=$(value_of CVENGINE_FIELD_KEY_PREVIOUS .env)
new_pg=$(random 32)
new_redis=$(random 32)
new_app=$(random 32)
new_field=$(random 48)
new_secret=$(random 64)
previous="${old_field}${old_previous:+${old_field:+,}$old_previous}"
for file in "${ENV_FILES[@]}"; do
    set_value POSTGRES_PASSWORD "$new_pg" "$file"
    set_value REDIS_PASSWORD "$new_redis" "$file"
    [[ -n $app_user ]] && set_value CVENGINE_DB_APP_PASSWORD "$new_app" "$file"
    if [[ $file == .env ]] || has_line CVENGINE_FIELD_KEY "$file"; then
        set_value CVENGINE_FIELD_KEY "$new_field" "$file"
        if [[ -n $previous ]]; then set_value CVENGINE_FIELD_KEY_PREVIOUS "$previous" "$file"; else drop_line CVENGINE_FIELD_KEY_PREVIOUS "$file"; fi
    fi
done
say "New values written to ${ENV_FILES[*]}."

step "Setting the new database passwords"
phase='ALTER ROLE'
sql="SET log_statement = 'none';
SET log_min_duration_statement = -1;
\\set ON_ERROR_STOP 1
BEGIN;
ALTER ROLE \"$owner\" WITH PASSWORD '$new_pg';"
(( app_exists )) && sql+="
ALTER ROLE \"$app_user\" WITH PASSWORD '$new_app';"
sql+="
COMMIT;"
# The two SET lines keep the statement out of the server log (they need a superuser, the owner of a stock install; without one psql says so and
# goes on). From \set ON_ERROR_STOP on, an error stops psql with a failure, and the transaction leaves both passwords as they were.
if ! printf '%s\n' "$sql" | dockerc exec -i "$db" sh -c 'psql -X -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"'; then
    restore_files
    die "setting the passwords failed: the env files are put back and nothing else changed."
fi
if (( app_exists )); then say "Passwords set for $owner and $app_user."; else say "Password set for $owner."; fi

step "Recreating ${first[*]} from a clean environment"
phase='the first recreate'
compose up -d --force-recreate "${first[@]}"

wait_web() {
    local deadline=$((SECONDS + wait_seconds))
    while (( SECONDS < deadline )); do
        compose exec -T web python3 -c "import http.client, sys; c = http.client.HTTPConnection('127.0.0.1', 8000, timeout=5); c.request('GET', '/', headers={'Host': 'localhost'}); sys.exit(0 if c.getresponse().status < 500 else 1)" >/dev/null 2>&1 && return 0
        sleep 3
    done
    return 1
}
wait_web || die "the web service did not answer within ${wait_seconds}s after the recreate. Its log: docker compose logs web. The new values are in the env files and the database; CVENGINE_FIELD_KEY_PREVIOUS still holds the old key."

step "Re-encrypting the stored secrets under the new field key"
phase=rotate_field_key
compose exec -T web python3 manage.py rotate_field_key
if ! compose exec -T web python3 manage.py rotate_field_key --check --strict; then
    die "some stored secrets still need the old key, so CVENGINE_FIELD_KEY_PREVIOUS and the Django secret are left as they are. Run docker compose exec web python3 manage.py rotate_field_key again, then this script's last steps by hand (docs/CONFIGURATION.md, Rotating secrets)."
fi

if (( keep_secret )); then step "Removing the old field key"; else step "Removing the old field key and replacing the Django secret"; fi
phase='the second recreate'
for file in "${ENV_FILES[@]}"; do drop_line CVENGINE_FIELD_KEY_PREVIOUS "$file"; done
if (( ! keep_secret )); then
    if [[ -n $secret_in_env ]]; then
        for file in $secret_in_env; do set_value CVENGINE_SECRET_KEY "$new_secret" "$file"; done
    else
        (umask 077; printf '%s\n' "$new_secret" > web/secret.rotating)
        chmod 600 web/secret.rotating
        # the application reads it as its own account (uid 10002, docs/DEPLOYMENT.md): the new file must be that account's, as the old one was
        chown --reference=web/secret web/secret.rotating 2>/dev/null || chown 10002:10002 web/secret.rotating 2>/dev/null || true
        mv -f -- web/secret.rotating web/secret
    fi
fi
compose up -d --force-recreate "${second[@]}"
wait_web || die "the web service did not answer within ${wait_seconds}s after the second recreate. Its log: docker compose logs web. The old keys are in $keydir."

if (( has_proxy )); then
    step "Restarting the proxy"
    phase='the proxy restart'
    compose restart proxy
fi

step "Verifying"
phase=verify
trap - ERR
failed=()
ok() { say "  ok: $*"; }
bad() { say "  FAILED: $*"; failed+=("$1"); }

# the site, through the proxy when it publishes a port here, else web's own port
ready_url=$(compose config --format json 2>/dev/null | python3 -c '
import json, sys
try:
    services = json.load(sys.stdin).get("services") or {}
except ValueError:
    sys.exit(0)
def host(mapping):
    ip = str(mapping.get("host_ip") or "")
    return "127.0.0.1" if ip in ("", "0.0.0.0", "::") else ip
for target in (443, 8443):
    for mapping in (services.get("proxy") or {}).get("ports") or []:
        if int(mapping.get("target") or 0) == target and mapping.get("published"):
            print("https://" + host(mapping) + ":" + str(mapping["published"]) + "/"); sys.exit(0)
for mapping in (services.get("web") or {}).get("ports") or []:
    if int(mapping.get("target") or 0) == 8000 and mapping.get("published"):
        print("http://" + host(mapping) + ":" + str(mapping["published"]) + "/"); sys.exit(0)
' 2>/dev/null || true)
if [[ -n $ready_url ]] && command -v curl >/dev/null 2>&1; then
    status=000
    deadline=$((SECONDS + 60))
    while (( SECONDS < deadline )); do
        status=$(curl -k -s --max-time 5 -o /dev/null -w '%{http_code}' "$ready_url" || true)
        [[ $status =~ ^[23][0-9][0-9]$ ]] && break
        sleep 3
    done
    [[ $status =~ ^[23][0-9][0-9]$ ]] && ok "the site answers at $ready_url ($status)" || bad "site: $ready_url answered $status"
elif wait_web; then
    ok "the web service answers"
else
    bad "site: the web service does not answer"
fi

login() {  # login ROLE PASSWORD: a real password login over the network, from the web container
    printf '%s\n' "$2" | compose exec -T web python3 -c "import os, sys, psycopg2
password = sys.stdin.readline().rstrip('\n')
psycopg2.connect(host=os.environ.get('POSTGRES_HOST') or 'db', port=os.environ.get('POSTGRES_PORT') or 5432, dbname=os.environ['POSTGRES_DB'],
                 user=sys.argv[1], password=password, connect_timeout=5).close()" "$1" >/dev/null 2>&1
}
login "$owner" "$new_pg" && ok "the database owner $owner logs in with the new password" || bad "database login as $owner"
old_pg=$(value_of POSTGRES_PASSWORD "$keydir/$(basename "$EFFECTIVE")")
if [[ -n $old_pg ]]; then
    login "$owner" "$old_pg" && bad "the old password of $owner still works" || ok "the old password of $owner is refused"
fi
if (( app_exists )); then
    login "$app_user" "$new_app" && ok "the app role $app_user logs in with the new password" || bad "database login as $app_user"
fi

redis=$(compose ps -q --status running redis 2>/dev/null | head -n1) || redis=''
if [[ -z $redis ]]; then
    bad "redis: the container is not running"
else
    pong=$(printf '%s\n' "$new_redis" | dockerc exec -i "$redis" sh -c 'IFS= read -r REDISCLI_AUTH; export REDISCLI_AUTH; redis-cli --no-auth-warning ping' 2>/dev/null || true)
    [[ $pong == PONG ]] && ok "Redis takes the new password" || bad "Redis did not answer PONG to the new password"
    open=$(dockerc exec "$redis" redis-cli ping 2>&1 || true)
    [[ $open != PONG ]] && ok "Redis refuses a client without the password" || bad "Redis answers without a password"
fi

check=$(compose exec -T web python3 manage.py rotate_field_key --check 2>&1) && ok "${check%%$'\n'*}" || bad "stored secrets: ${check//$'\n'/ }"

if [[ -n $app_user ]]; then
    report=$(. scripts/db-app-role.sh && cvengine_db_role_report compose)
    [[ -n $report ]] && say "$report" | sed 's/^/  /'
    grep -q '^Warning:' <<<"$report" && bad "a service connects as the owner role, not $app_user"
fi

echo
if (( ${#failed[@]} )); then
    say "Rotation finished with ${#failed[@]} failed check(s). The old keys are in $keydir and the database as it was in $dump."
else
    say "Rotation done and verified."
fi
say "Backups: the old keys in $keydir, the database dump in $dump. Keep them apart: move $keydir to a password manager or another store"
say "with different access, and delete both once you are sure the site works (they hold the OLD keys and the data they decrypt)."
echo
logout_warning
checklist
(( ${#failed[@]} == 0 ))
