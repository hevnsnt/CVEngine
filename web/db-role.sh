# Sourced by the entrypoints (entrypoint.sh, celery-entrypoint.sh, beat-entrypoint.sh): which database role this container runs as.
#
#   . ./db-role.sh && cvengine_db_role [WAIT_SECONDS]
#
# The least privilege app role (CVENGINE_DB_APP_USER, default cvengine_app), which the one-off migrate service created and checked before this
# container started. These containers have no owner password: the owner role (POSTGRES_USER, exported as CVENGINE_DB_ROLE=owner) is used only
# when CVENGINE_DB_ALLOW_OWNER_FALLBACK=1 made the migrate service hand its password over (the db_owner_fallback volume) and the app role does
# not log in within WAIT_SECONDS (reNgine/db_roles.py, choose). The choice is written to /tmp/cvengine-db-role, which every later process of
# the container reads (docker compose exec, the watchdog), and `manage.py db_app_role status` prints it (the update scripts report it).
cvengine_db_role() {
  local role
  role=$(python3 manage.py db_app_role choose --wait "${1:-0}" | tail -n 1) || role=''
  [ "$role" = app ] && return 0
  if [ "$role" != owner ]; then
    # no silent switch to the owner role: the container keeps the configured one, and its connections say what is wrong
    echo "Could not check which database role to use; this container keeps the configured one." >&2
    rm -f "${CVENGINE_DB_ROLE_STATE:-/tmp/cvengine-db-role}" 2>/dev/null || true
    return 0
  fi
  export CVENGINE_DB_ROLE=owner
  return 0
}
