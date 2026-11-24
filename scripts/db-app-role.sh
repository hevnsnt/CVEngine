# Sourced by the update scripts and `make up`: the least privilege database role the server runs as (web/cvengine/db_roles.py,
# docs/CONFIGURATION.md "Database roles").
#
#   . scripts/db-app-role.sh && cvengine_ensure_db_app_password [ENV_FILE]
#   . scripts/db-app-role.sh && cvengine_db_role_report docker compose [ARGS...]
#   . scripts/db-app-role.sh && cvengine_owner_password_check docker compose [ARGS...]
#   . scripts/db-app-role.sh && cvengine_db_gate docker compose [ARGS...]
#   . scripts/db-app-role.sh && cvengine_db_owner_fallback [ENV_FILE]
#
# cvengine_ensure_db_app_password gives the app role a password when the installation has none (CVENGINE_DB_APP_PASSWORD, 32 letters and digits),
# exactly as scripts/redis-password.sh does for Redis: written to .env and, when the installation runs with another Compose env file (ENV_FILE, an
# overlay's .env.vps), to that file too, because Compose reads ${CVENGINE_DB_APP_PASSWORD} from the env file it is given. The next migrate (which
# runs as the owner role) creates the role with it and grants it; the web, celery and celery-beat containers started after that run as it.
# Returns 0 when it wrote a password, 1 when there already is one, when there is no .env, or when CVENGINE_DB_APP_USER is set empty in the env
# file Compose reads (then no password is made, and cvengine_db_gate refuses to start the application unless CVENGINE_DB_ALLOW_OWNER_FALLBACK=1).
#
# The owner role's password (POSTGRES_PASSWORD) is in ONE container only, the one-off migrate service of docker-compose.yml (web/migrate-entrypoint.sh).
# cvengine_owner_password_check fails, naming the services (never a value), when the effective Compose configuration (docker compose config,
# overlays and env files included) would still hand it to any other service than db and migrate: an overlay such as docker-compose.vps.yml that
# lists POSTGRES_PASSWORD under a service's environment. cvengine_db_gate runs `manage.py db_app_role gate` in the migrate service: it creates and
# grants the app role, checks that it logs in, and exits 1 with the one-line fix when it does not, so the caller stops before the application is
# recreated. CVENGINE_DB_ALLOW_OWNER_FALLBACK=1 (read by cvengine_db_owner_fallback from the environment, the Compose env file or .env) is the
# explicit permission to run the application on the owner role instead.
#
# cvengine_db_role_report prints one line per application service saying which role it connects as (manage.py db_app_role status in each
# container), and a warning line when any still runs as the owner role. Never fails the caller.
if ! declare -F cvengine_redis_set >/dev/null; then
  # shellcheck source=scripts/redis-password.sh
  . "$(dirname "${BASH_SOURCE[0]}")/redis-password.sh"
fi

cvengine_ensure_db_app_password() {
  local env_file=${1:-} effective password
  [ -f .env ] || return 1
  if [ -z "$env_file" ] || [ "$env_file" = .env ] || [ ! -f "$env_file" ]; then env_file=''; fi
  effective=${env_file:-.env}
  # CVENGINE_DB_APP_USER= (set, and empty) is the rollback to the owner role: leave it so
  if grep -qE '^CVENGINE_DB_APP_USER=[[:space:]]*$' "$effective"; then return 1; fi
  [ -z "$(cvengine_redis_value CVENGINE_DB_APP_PASSWORD "$effective")" ] || return 1
  password=$(cvengine_redis_value CVENGINE_DB_APP_PASSWORD .env)
  if [ -z "$password" ]; then
    password=$(head -c 256 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
    [ ${#password} -eq 32 ] || return 1
    cvengine_redis_set CVENGINE_DB_APP_PASSWORD "$password" .env || return 1
  fi
  if [ -n "$env_file" ]; then cvengine_redis_set CVENGINE_DB_APP_PASSWORD "$password" "$env_file" || return 1; fi
  return 0
}

cvengine_db_role_report() {  # cvengine_db_role_report docker compose [ARGS...]
  local service line owner_services=''
  for service in web celery celery-beat; do
    line=$("$@" exec -T "$service" python3 manage.py db_app_role status 2>/dev/null | tail -n 1) || line=''
    [ -n "$line" ] || continue
    echo "Database role of $service: $line"
    case $line in owner*) owner_services="$owner_services $service" ;; esac
  done
  if [ -n "$owner_services" ]; then
    echo "Warning:$owner_services still connect$( [ "$(wc -w <<<"$owner_services")" -gt 1 ] || echo s) to the database as the owner role, which can do anything on the database server. See docs/UPGRADE.md, Database roles."
  fi
  return 0
}

cvengine_db_owner_fallback() {  # cvengine_db_owner_fallback [ENV_FILE]: prints 1 when CVENGINE_DB_ALLOW_OWNER_FALLBACK=1, else 0
  local value=${CVENGINE_DB_ALLOW_OWNER_FALLBACK:-} file
  if [ -z "$value" ]; then
    for file in "${1:-}" .env; do
      [ -n "$file" ] && [ -f "$file" ] || continue
      value=$(cvengine_redis_value CVENGINE_DB_ALLOW_OWNER_FALLBACK "$file")
      value=${value#[\"\']}; value=${value%[\"\']}
      [ -z "$value" ] || break
    done
  fi
  if [ "$value" = 1 ]; then echo 1; else echo 0; fi
}

cvengine_owner_password_check() {  # cvengine_owner_password_check docker compose [ARGS...]
  local json services
  json=$("$@" config --format json 2>/dev/null) || return 0  # an older Compose: nothing to check with, never a failed update for it
  services=$(printf '%s' "$json" | python3 -c '
import json, sys
try:
    services = json.load(sys.stdin).get("services") or {}
except ValueError:
    sys.exit(0)
for name, spec in sorted(services.items()):
    if name in ("db", "migrate"):
        continue
    env = (spec or {}).get("environment") or {}
    if isinstance(env, list):
        env = dict(item.split("=", 1) if "=" in item else (item, "") for item in env)
    if any((env.get(key) or "").strip() for key in ("POSTGRES_PASSWORD", "POSTGRES_PASSWORD_FILE")):
        print(name)
' 2>/dev/null) || return 0
  [ -n "$services" ] || return 0
  services=$(tr '\n' ' ' <<<"$services"); services=${services% }
  echo "Refusing to start the application: the Compose configuration gives the database owner password to: $services. Only the one-off migrate service may have it."
  echo "Fix: remove POSTGRES_PASSWORD from the environment of $services in your overlay (for example docker-compose.vps.yml), then run the update again."
  return 1
}

cvengine_db_gate() {  # cvengine_db_gate docker compose [ARGS...]: the app role's check, as the owner, in the one-off migrate service
  local flag
  flag=$(cvengine_db_owner_fallback "$(cvengine_compose_env_file "$@" 2>/dev/null || true)")
  "$@" run --rm --no-deps -T -e CVENGINE_DB_ALLOW_OWNER_FALLBACK="$flag" migrate python3 manage.py db_app_role gate
}
