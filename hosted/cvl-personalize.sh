#!/usr/bin/env bash
# Hands a booted hosted server (cvl-firstboot.sh done) to one customer. The provisioner runs it over SSH with a JSON object on stdin:
#
#   {"customer_slug": "acme", "email": "owner@acme.example", "username": "admin"}      (username is optional, default "admin"; other keys are ignored)
#
# It sets CVENGINE_PUBLIC_API_URL=https://api-<slug>.cvengine.live (the address the fleet's Sentinels reach this server on; recreates the web service
# when it changed), creates the first App Admin with a generated one-time password (manage.py create_admin; the account must change it at first sign-in)
# and issues the scanner fleet's token (manage.py ensure_fleet_token). Stdout is exactly one JSON line and nothing else:
#
#   {"username": "...", "password": "...", "fleet_token": "...", "api_base": "https://api-<slug>.cvengine.live"}
#
# Errors: one line on stderr and a non-zero exit, with nothing on stdout. The password and the token are never written to a log, a file or a command
# line: they travel in pipes and variables, and appear once, in that JSON line. Run again with the same slug (a retry) and the admin gets a NEW password
# and the fleet a NEW token (the earlier ones stop working); run with another slug and it refuses (a server belongs to one customer).
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
umask 077
cvl_root_or_die
cvl_need python3

# The JSON on stdin is validated by Python (no shell parsing of it), which prints "slug<TAB>email<TAB>username" for the three checked values.
input=$(cat)
fields=$(printf '%s' "$input" | python3 -I -c '
import json, re, sys
try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit("stdin is not valid JSON")
if not isinstance(data, dict):
    sys.exit("stdin must be a JSON object")
slug, email, user = data.get("customer_slug"), data.get("email"), data.get("username", "admin")
if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,56}[a-z0-9])?", slug):
    sys.exit("customer_slug must be a DNS label: lowercase letters, digits and dashes, 1 to 58 characters, starting and ending with a letter or digit")
if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r"[^@\s,;<>\"\x00-\x1f]+@[^@\s,;<>\"\x00-\x1f]+", email):
    sys.exit("email must be one address")
if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,149}", user):
    sys.exit("username must be letters, digits, dots, dashes and underscores")
print("\t".join((slug, email, user)))
') || cvl_die "the JSON on stdin was refused (the reason is above)"
unset input
IFS=$'\t' read -r slug email username <<<"$fields"

cd "$CVL_REPO"
[ -f "$CVL_STATE/ready" ] || cvl_die "this server is not ready: $CVL_STATE/ready is missing (cvl-firstboot.sh has not finished)"
cvl_hosted_on || cvl_die "hosted mode is off in .env (CVENGINE_HOSTED): this is not a hosted server"
if [ -s "$CVL_STATE/personalized" ]; then
  IFS= read -r owner <"$CVL_STATE/personalized" || true
  [ "$owner" = "$slug" ] || cvl_die "this server already belongs to another customer"
fi

api_base="https://api-$slug.$CVL_PUBLIC_DOMAIN"
cvl_compose_layout

if [ "$(cvl_env_get CVENGINE_PUBLIC_API_URL)" != "$api_base" ]; then
  cvl_env_set CVENGINE_PUBLIC_API_URL "$api_base"
  "${COMPOSE[@]}" up -d --no-deps --force-recreate web </dev/null >&2 || cvl_die "could not restart the web service"
  cvl_wait_web 420 || cvl_die "the web service did not come back within 7 minutes"
fi

# create_admin prints a banner with the generated password. Its output is captured, searched for that one line and never printed.
manage() { "${COMPOSE[@]}" exec -T web python3 manage.py "$@" </dev/null; }
created=$(manage create_admin --username "$username" --email "$email") || cvl_die "create_admin failed"
if printf '%s\n' "$created" | grep -q '^The account .* already exists'; then
  created=$(manage create_admin --username "$username" --email "$email" --reset) || cvl_die "create_admin --reset failed"
fi
password=$(printf '%s\n' "$created" | sed -n 's/^ *Password *: //p' | head -n 1)
unset created
[ -n "$password" ] || cvl_die "create_admin did not produce a password"

fleet=$(manage ensure_fleet_token --user "$username" | grep -E '^\{' | tail -n 1) || cvl_die "ensure_fleet_token failed"
[ -n "$fleet" ] || cvl_die "ensure_fleet_token printed nothing"

printf '%s\n' "$slug" >"$CVL_STATE/personalized"

# The JSON is made by Python from values handed over in the environment (so quoting is never ours to get wrong, and nothing is on a command line).
CVL_OUT_USERNAME=$username CVL_OUT_PASSWORD=$password CVL_OUT_FLEET=$fleet CVL_OUT_API=$api_base python3 -I -c '
import json, os
fleet = json.loads(os.environ["CVL_OUT_FLEET"])
print(json.dumps({"username": os.environ["CVL_OUT_USERNAME"], "password": os.environ["CVL_OUT_PASSWORD"],
                  "fleet_token": fleet["token"], "api_base": os.environ["CVL_OUT_API"]}, separators=(",", ":")))
' || cvl_die "could not build the result"
