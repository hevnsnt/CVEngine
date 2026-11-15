#!/usr/bin/env bash
# Flips this server's single sign-on mode (hosted/README.md, "Single sign-on"). The provisioner runs it over SSH; at least one option is required:
#
#   cvl-sso-mode.sh --sso on|off              CVENGINE_SSO: accept assertions from the site (needs the SSO key set, see cvl-set-sso-keys.sh, to be useful)
#   cvl-sso-mode.sh --enforce on|off          CVENGINE_SSO_ENFORCE: refuse the local password login (phase B). Refused unless SSO is on (after this
#                                             command's own --sso) and the installed key set holds at least one key
#   cvl-sso-mode.sh --breakglass <minutes>|off   CVENGINE_SSO_BREAKGLASS_UNTIL = now + <minutes> (1 to 60), as Unix seconds: the time-boxed window in
#                                             which the local login works again under enforcement (it still needs the edge secret, the local password
#                                             and the local TOTP). Needs SSO on. "off" removes the setting
#
# --sso off also switches enforcement and break-glass off (enforcement without SSO would lock everybody out). Everything is validated first: a refusal
# changes nothing. .env is edited in place (same file, mode 600) and only the web container is recreated (--no-deps), and only when a value changed;
# the command returns once the web service answers again. Stdout: one JSON line
#
#   {"ok":true,"sso":<bool>,"enforce":<bool>,"breakglass_until":<unix seconds or null>}
#
# Errors: stderr and a non-zero exit, nothing on stdout. Needs hosted mode on and the server ready. CVL_NOW (Unix seconds) replaces the clock (tests).
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
umask 077

usage() { cvl_die "usage: $0 [--sso on|off] [--enforce on|off] [--breakglass <minutes 1-60>|off]   (at least one)"; }

want_sso='' want_enforce='' want_breakglass=''
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case $1 in
    --sso) want_sso=$2 ;;
    --enforce) want_enforce=$2 ;;
    --breakglass) want_breakglass=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$want_sso$want_enforce$want_breakglass" ] || usage
case $want_sso in ''|on|off) ;; *) usage ;; esac
case $want_enforce in ''|on|off) ;; *) usage ;; esac
if [ -n "$want_breakglass" ] && [ "$want_breakglass" != off ]; then
  [[ $want_breakglass =~ ^[0-9]{1,2}$ ]] && [ "$((10#$want_breakglass))" -ge 1 ] && [ "$((10#$want_breakglass))" -le 60 ] \
    || cvl_die "--breakglass takes a number of minutes from 1 to 60, or off"
fi

cvl_root_or_die
cd "$CVL_REPO"
[ -f "$CVL_STATE/ready" ] || cvl_die "this server is not ready: $CVL_STATE/ready is missing (cvl-firstboot.sh has not finished)"
cvl_hosted_on || cvl_die "hosted mode is off in .env (CVENGINE_HOSTED): this is not a hosted server"

now=${CVL_NOW:-$(date +%s)}
[[ $now =~ ^[0-9]+$ ]] || cvl_die "CVL_NOW is not a number"

# the state after this command, starting from what .env says now
sso=0 enforce=0 bg_until=''
if cvl_env_truthy CVENGINE_SSO; then sso=1; fi
if cvl_env_truthy CVENGINE_SSO_ENFORCE; then enforce=1; fi
bg_until=$(cvl_env_get CVENGINE_SSO_BREAKGLASS_UNTIL)
[[ $bg_until =~ ^[0-9]+$ ]] || bg_until=''
[ "$want_sso" != on ] || sso=1
if [ "$want_sso" = off ]; then
  [ "$want_enforce" != on ] || cvl_die "enforcement cannot be turned on while turning SSO off"
  [ -z "$want_breakglass" ] || [ "$want_breakglass" = off ] || cvl_die "break-glass cannot be opened while turning SSO off"
  sso=0 enforce=0 bg_until=''
fi
[ "$want_enforce" != on ] || enforce=1
[ "$want_enforce" != off ] || enforce=0
if [ "$want_breakglass" = off ]; then bg_until=''
elif [ -n "$want_breakglass" ]; then
  [ "$sso" = 1 ] || cvl_die "break-glass needs SSO on: it is the exception to enforcement, and there is no enforcement without SSO"
  bg_until=$((now + 10#$want_breakglass * 60))
fi

if [ "$want_enforce" = on ]; then
  [ "$sso" = 1 ] || cvl_die "enforcement needs SSO on (turn it on first, or in the same command)"
  keys_out=$("$(dirname "${BASH_SOURCE[0]}")/cvl-set-sso-keys.sh" --check) || cvl_die "the installed SSO key set cannot be read: enforcement refused"
  CVL_KEYS_OUT=$keys_out python3 -I -c '
import json, os, sys
sys.exit(0 if json.loads(os.environ["CVL_KEYS_OUT"]).get("kids") else 1)
' || cvl_die "the installed SSO key set is empty: enforcement would lock everybody out, refused"
fi

changed=0
set_env() {  # key, new value ('' = remove): only a real change counts
  local old
  old=$(cvl_env_get "$1")
  [ "$old" != "$2" ] || return 0
  if [ -n "$2" ]; then cvl_env_set "$1" "$2"; else cvl_env_unset "$1"; fi
  changed=1
}
set_env CVENGINE_SSO "$sso"
set_env CVENGINE_SSO_ENFORCE "$enforce"
set_env CVENGINE_SSO_BREAKGLASS_UNTIL "$bg_until"

if [ "$changed" = 1 ]; then
  cvl_compose_layout
  "${COMPOSE[@]}" up -d --no-deps --force-recreate web </dev/null >&2 || cvl_die "could not restart the web service"
  cvl_wait_web 420 || cvl_die "the web service did not come back within 7 minutes"
fi

b_sso=false b_enforce=false b_until=null
[ "$sso" = 0 ] || b_sso=true
[ "$enforce" = 0 ] || b_enforce=true
[ -z "$bg_until" ] || [ "$bg_until" -le "$now" ] || b_until=$bg_until  # a window that has passed is reported as closed
printf '{"ok":true,"sso":%s,"enforce":%s,"breakglass_until":%s}\n' "$b_sso" "$b_enforce" "$b_until"
