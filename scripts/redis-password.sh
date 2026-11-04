# Sourced by the update scripts and `make up`: give the Redis broker a password when the installation has none.
#
#   . scripts/redis-password.sh && cvengine_ensure_redis_password [ENV_FILE]
#
# Returns 0 when it wrote a password (the caller recreates Redis together with its clients, which an update does anyway), 1 when the
# installation already has one or there is no .env. The password is written to .env and, when the installation runs with another Compose
# env file (ENV_FILE, an overlay's .env.vps), to that file too: Compose reads ${REDIS_PASSWORD} from the env file it is given. An open broker
# lets anything that reaches it queue work the workers run as root, and the host network overlay publishes it on the host's loopback, so a
# headless installation gets one by itself instead of waiting for someone to run `make redis-auth`.
cvengine_redis_value() { [ -f "$2" ] && grep -E "^$1=" "$2" | tail -n 1 | cut -d= -f2- | tr -d '\r' || true; }

cvengine_redis_set() {  # cvengine_redis_set KEY VALUE FILE: replace or append, without the value on a command line (`ps` shows those)
  local key=$1 value=$2 file=$3 tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-env.XXXXXX") || return 1
  chmod 600 "$tmp"
  if grep -q "^${key}=" "$file"; then
    CVENGINE_AWK_VALUE="$value" awk -v key="$key" 'BEGIN { prefix = key "=" } index($0, prefix) == 1 { print prefix ENVIRON["CVENGINE_AWK_VALUE"]; next } { print }' "$file" > "$tmp"
  else
    { cat "$file"; [ -z "$(tail -c 1 "$file")" ] || echo; echo "${key}=${value}"; } > "$tmp"
  fi
  cat "$tmp" > "$file"  # in place: keeps the file's owner and mode
  rm -f -- "$tmp"
}

cvengine_ensure_redis_password() {
  local env_file=${1:-} effective password
  [ -f .env ] || return 1
  if [ -z "$env_file" ] || [ "$env_file" = .env ] || [ ! -f "$env_file" ]; then env_file=''; fi
  effective=${env_file:-.env}
  [ -z "$(cvengine_redis_value REDIS_PASSWORD "$effective")" ] || return 1
  password=$(cvengine_redis_value REDIS_PASSWORD .env)
  if [ -z "$password" ]; then
    password=$(head -c 256 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
    [ ${#password} -eq 32 ] || return 1
    cvengine_redis_set REDIS_PASSWORD "$password" .env || return 1
  fi
  if [ -n "$env_file" ]; then cvengine_redis_set REDIS_PASSWORD "$password" "$env_file" || return 1; fi
  return 0
}
