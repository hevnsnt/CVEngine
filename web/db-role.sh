# Sourced by the entrypoints (entrypoint.sh, celery-entrypoint.sh, beat-entrypoint.sh): which database role this container runs as.
#
#   . ./db-role.sh && cvengine_db_role [WAIT_SECONDS]
#
# The least privilege app role (CVENGINE_DB_APP_USER, default cvengine_app) when it is configured and logs in; else the owner role
# (POSTGRES_USER), exported as CVENGINE_DB_ROLE=owner, so an update never locks the server out of its database (reNgine/db_roles.py, choose).
# WAIT_SECONDS gives the web service time to create the role first (its migrate does that): the workers wait, the web service does not.
# The choice is written to /tmp/cvengine-db-role, which every later process of the container reads (docker compose exec, the watchdog),
# and `manage.py db_app_role status` prints it (the update scripts report it).
cvengine_db_role() {
  local role
  role=$(python3 manage.py db_app_role choose --wait "${1:-0}" | tail -n 1) || role=''
  [ "$role" = app ] && return 0
  if [ "$role" != owner ]; then
    echo "Could not check which database role to use; this container keeps the owner role." >&2
    echo "owner the database role check could not run" > "${CVENGINE_DB_ROLE_STATE:-/tmp/cvengine-db-role}" 2>/dev/null || true
  fi
  export CVENGINE_DB_ROLE=owner
  return 0
}
