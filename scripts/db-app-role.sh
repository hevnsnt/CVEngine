# Sourced by the update scripts and `make up`: the least privilege database role the server runs as (web/reNgine/db_roles.py,
# docs/CONFIGURATION.md "Database roles").
#
#   . scripts/db-app-role.sh && cvengine_ensure_db_app_password [ENV_FILE]
#   . scripts/db-app-role.sh && cvengine_db_role_report docker compose [ARGS...]
#
# cvengine_ensure_db_app_password gives the app role a password when the installation has none (CVENGINE_DB_APP_PASSWORD, 32 letters and digits),
# exactly as scripts/redis-password.sh does for Redis: written to .env and, when the installation runs with another Compose env file (ENV_FILE, an
# overlay's .env.vps), to that file too, because Compose reads ${CVENGINE_DB_APP_PASSWORD} from the env file it is given. The next migrate (which
# runs as the owner role) creates the role with it and grants it; the web, celery and celery-beat containers started after that run as it.
# Returns 0 when it wrote a password, 1 when there already is one, when there is no .env, or when CVENGINE_DB_APP_USER is set empty in the env
# file Compose reads (the way back to the owner role: then no password is made).
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
