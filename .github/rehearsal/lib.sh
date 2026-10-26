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
# A freshly installed stack is not ready when the site first answers: the Celery entrypoint can spend minutes before its workers reply. An
# installed system that is being updated has had that time, so wait for it here, as a real install would have.
wait_for_workers() {
  local deadline=$((SECONDS + ${1:-900})) count=0
  while (( SECONDS < deadline )); do
    count=$(dc exec -T celery celery -A reNgine.tasks inspect ping -t 10 2>/dev/null | grep -c pong || true)
    if (( count >= 3 )); then echo "$count Celery workers answer."; return 0; fi
    sleep 10
  done
  echo "::error::Only $count Celery workers answer"
  return 1
}
