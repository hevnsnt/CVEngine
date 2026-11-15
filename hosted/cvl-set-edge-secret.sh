#!/usr/bin/env bash
# Sets or rotates this server's edge secret (the value the Cloudflare Worker sends in X-CVL-Edge-Auth), with an overlap so a rotation drops no request.
#
#   cvl-set-edge-secret.sh [--no-reload]                  the new secret on stdin: it becomes the current one and the old current one is kept as the
#                                                         previous (both accepted) until --drop-previous
#   cvl-set-edge-secret.sh --no-previous [--no-reload]    the new secret on stdin: first-time set; any previous secret is removed at once
#   cvl-set-edge-secret.sh --drop-previous [--no-reload]  nothing on stdin: remove the previous secret (the provisioner does this ten minutes
#                                                         after a rotation, once the Worker has the new one)
#
# The secret is read from stdin, never from the command line (a command line is visible to every user in `ps`), is 32 to 128 characters of
# A-Z a-z 0-9 _ - (the Worker's own tokens are 43), and is never printed or logged. Files: /etc/cvl/edge-secret, edge-secret.previous (600), then
# hosted/gen-edge-auth.sh regenerates edge-auth.conf and edge-header and the proxy is told to reload (nginx -t first; an invalid file is not applied
# and the command fails). With the proxy container not running, or with --no-reload, nothing is reloaded: the next start reads the file.
# Stdout: one JSON line {"ok":true,"previous":<true|false>,"reloaded":<true|false>}. Errors: stderr and a non-zero exit.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
umask 077

mode=rotate
reload=1
for arg in "$@"; do
  case $arg in
    --no-previous) mode=first ;;
    --drop-previous) mode=drop ;;
    --no-reload) reload=0 ;;
    *) cvl_die "usage: $0 [--no-previous | --drop-previous] [--no-reload]   (the new secret on stdin)" ;;
  esac
done
cvl_root_or_die
cvl_private_dir "$CVL_ETC"
current_file=$CVL_ETC/edge-secret
previous_file=$CVL_ETC/edge-secret.previous

if [ "$mode" != drop ]; then
  new=''
  IFS= read -r new || true
  new=${new%$'\r'}
  cvl_secret_ok "$new" || cvl_die "the new secret on stdin is not 32 to 128 characters of A-Z a-z 0-9 _ -"
  old=''
  [ ! -f "$current_file" ] || { IFS= read -r old <"$current_file" || true; old=${old%$'\r'}; }
  if [ "$mode" = rotate ] && [ -n "$old" ] && [ "$old" != "$new" ]; then
    cvl_write_in_place "$previous_file" "$old"$'\n'
  elif [ "$mode" = first ]; then
    rm -f "$previous_file"
  fi
  cvl_write_in_place "$current_file" "$new"$'\n'
  unset new old
else
  rm -f "$previous_file"
fi

"$(dirname "${BASH_SOURCE[0]}")/gen-edge-auth.sh"

reloaded=false
if [ "$reload" = 1 ]; then
  cvl_compose_layout
  if "${COMPOSE[@]}" ps -q --status running proxy 2>/dev/null </dev/null | grep -q .; then
    if ! "${COMPOSE[@]}" exec -T proxy nginx -t >/dev/null 2>&1 </dev/null; then
      cvl_die "nginx rejected the new configuration: it was not reloaded"
    fi
    "${COMPOSE[@]}" exec -T proxy nginx -s reload >/dev/null 2>&1 </dev/null || cvl_die "nginx could not be reloaded"
    reloaded=true
  else
    cvl_log "the proxy is not running: nothing to reload"
  fi
fi
had_previous=false
[ ! -f "$previous_file" ] || had_previous=true
printf '{"ok":true,"previous":%s,"reloaded":%s}\n' "$had_previous" "$reloaded"
