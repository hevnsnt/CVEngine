# Shared by the upgrade rehearsal scripts. The mode (plain or overlay) is remembered in $HOME/mode.
mode() { cat "$HOME/mode"; }
port() { if [ "$(mode)" = overlay ]; then echo 18443; else echo 443; fi; }
# docker compose with the layout the rehearsal install runs with
dc() {
  ( cd "$HOME/cvengine"
    if [ "$(mode)" = overlay ]; then docker compose --env-file .env.vps -p cvengine -f docker-compose.yml -f docker-compose.vps.yml "$@"
    else docker compose "$@"; fi )
}
wait_for_site() {
  local deadline=$((SECONDS + ${1:-600})) code=000
  while (( SECONDS < deadline )); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$(port)/" || true)
    case $code in 200|301|302) echo "The site answers ($code) on port $(port)."; return 0;; esac
    sleep 5
  done
  echo "::error::The site does not answer on port $(port) (last status $code)"
  return 1
}
