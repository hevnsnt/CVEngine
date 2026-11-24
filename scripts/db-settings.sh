# shellcheck shell=bash
# The database's settings have one source: the db service's command line in the compose files (`-c name=${POSTGRES_...}`, values in .env).
# A value set by hand with ALTER SYSTEM lives in postgresql.auto.conf inside the data volume. A command line option wins over it, so it is
# hidden while the compose files pass the same setting, and it comes back the day they stop passing it (or someone runs the server without
# them), which nobody would expect. The update removes such a leftover for every setting the compose files pass (synchronous_commit, set by
# hand on a production host before POSTGRES_SYNCHRONOUS_COMMIT existed, and log_connections and log_disconnections likewise).
#
#   cvengine_db_settings_one_source COMPOSE...
#       Reads the names postgresql.auto.conf holds (pg_file_settings lists file entries even when the command line hides them; pg_settings then
#       says source 'command line'). For each one the db service's command passes as `name=...` in the compose configuration, runs ALTER SYSTEM
#       RESET, then reloads the configuration once. A name the compose files do not pass is the only place that setting is made, and stays.
#       psql runs inside the db container as the owner (POSTGRES_USER, the image's superuser, over the local socket: no password on any command
#       line). Idempotent: nothing to remove is a no-op. Prints one line per change or problem and ALWAYS returns 0: a leftover is harmless while
#       the command line wins, so it never fails an update.
#
# Sourced by scripts/update-deploy.sh (the Update button) and scripts/update.sh after the db container is up with its new command line.

cvengine_db_settings_one_source() {
  local config names name removed=() failed=()
  config=$("$@" config 2>/dev/null) || { echo "could not read the compose configuration, so no ALTER SYSTEM value was looked at"; return 0; }
  if ! names=$(cvengine_db_psql "$@" "SELECT DISTINCT name FROM pg_file_settings WHERE sourcefile LIKE '%/postgresql.auto.conf' ORDER BY name"); then
    echo "could not read the database's ALTER SYSTEM values; left as they are"
    return 0
  fi
  for name in $names; do
    [[ $name =~ ^[a-z_]+$ ]] || continue
    # only a setting the db service's command passes (`- name=value` in the configuration Compose prints)
    grep -Eq -- "^[[:space:]]*- \"?$name=" <<<"$config" || continue
    if cvengine_db_psql "$@" "ALTER SYSTEM RESET $name" >/dev/null; then removed+=("$name"); else failed+=("$name"); fi
  done
  if [ ${#removed[@]} -gt 0 ]; then
    cvengine_db_psql "$@" "SELECT pg_reload_conf()" >/dev/null || true
    echo "removed the ALTER SYSTEM value of ${removed[*]} (postgresql.auto.conf): the compose files set it (POSTGRES_* in .env), one source"
  fi
  if [ ${#failed[@]} -gt 0 ]; then
    echo "could not remove the ALTER SYSTEM value of ${failed[*]}; the compose files' value still wins (ALTER SYSTEM RESET <name> as the database owner removes it)"
  fi
  return 0
}

# cvengine_db_psql COMPOSE... SQL: one statement, as the owner, inside the db container; prints the bare result
cvengine_db_psql() {
  local sql=${*: -1}
  "${@:1:$#-1}" exec -T db sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$1"' sh "$sql" 2>/dev/null
}
