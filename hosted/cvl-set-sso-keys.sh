#!/usr/bin/env bash
# Installs the PUBLIC keys this server trusts for single sign-on assertions (hosted/README.md, "Single sign-on"). The provisioner runs it over SSH with
# the site's JWKS on stdin, at personalise time and for every `sso_keys` job (rotation, emergency revoke):
#
#   cvl-set-sso-keys.sh            JWKS JSON on stdin: validated, written to /etc/cvl/sso-keys.json (mode 600), the complete replacement of what was there
#   cvl-set-sso-keys.sh --check    nothing on stdin: validates and lists what is installed; changes nothing
#
# Accepted input: {"keys":[{"kid":"...","kty":"OKP","crv":"Ed25519","x":"<base64url, 32 bytes>","status":"current|next|retiring"}, ...]}
# with at most 8 keys (zero is fine: it makes every assertion fail closed). Strict: a key of any other type or curve, an unknown status (a revoked key
# is simply left out of the set), a duplicate kid, an x that is not exactly the unpadded base64url of 32 bytes, or a kid outside A-Z a-z 0-9 . _ : -
# (1 to 128 characters) refuses the WHOLE input and changes nothing. Members other than kid, kty, crv, x and status (and top-level members other than
# "keys") are accepted and dropped, so the file holds only what the verifier reads.
#
# The target is a single file bind-mounted into the web container (docker-compose.hosted.yml), so it is written IN PLACE (same inode, never renamed
# over), mode 600; an identical file is not touched. The file is re-read by the application on every verification, so no restart is needed.
# Settings (environment): CVL_SSO_KEYS_FILE (default $CVL_ETC/sso-keys.json, the same name the Compose overlay uses for the mount's source).
# Stdout: one JSON line {"ok":true,"kids":["..."]}. Errors: stderr and a non-zero exit, nothing on stdout. Only kids are ever printed or logged.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
umask 077

check=0
for arg in "$@"; do
  case $arg in
    --check) check=1 ;;
    *) cvl_die "usage: $0 [--check]   (the JWKS JSON on stdin unless --check)" ;;
  esac
done
cvl_root_or_die
cvl_need python3

target=${CVL_SSO_KEYS_FILE:-$CVL_ETC/sso-keys.json}

# Python does all the parsing (no shell parsing of the JSON). "normalize" reads JSON on stdin and prints the canonical file text; "kids" reads that and
# prints the result line. Error messages name the position of a problem, never a value.
helper() {
  python3 -I -c '
import base64, json, re, sys

MAX_KEYS = 8
STATUSES = ("current", "next", "retiring")

def fail(message):
    sys.exit("sso keys: " + message)

def normalize(raw):
    if len(raw) > 65536:
        fail("input is larger than 64 KiB")
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=lambda name: fail("not valid JSON"))
    except (ValueError, UnicodeDecodeError):
        fail("input is not valid JSON")
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        fail("input must be a JSON object with a \"keys\" array")
    keys = data["keys"]
    if len(keys) > MAX_KEYS:
        fail("at most %d keys are accepted" % MAX_KEYS)
    out, seen = [], set()
    for index, key in enumerate(keys):
        where = "key %d: " % index
        if not isinstance(key, dict):
            fail(where + "not an object")
        kid, kty, crv, x, status = (key.get(name) for name in ("kid", "kty", "crv", "x", "status"))
        if not isinstance(kid, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", kid):
            fail(where + "kid must be 1 to 128 characters of A-Z a-z 0-9 . _ : -")
        if kid in seen:
            fail(where + "duplicate kid")
        seen.add(kid)
        if kty != "OKP":
            fail(where + "kty must be OKP")
        if crv != "Ed25519":
            fail(where + "crv must be Ed25519")
        if not isinstance(x, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", x):
            fail(where + "x must be the unpadded base64url of 32 bytes")
        try:
            raw_x = base64.urlsafe_b64decode(x + "=")
        except ValueError:
            fail(where + "x is not base64url")
        if len(raw_x) != 32 or base64.urlsafe_b64encode(raw_x).decode().rstrip("=") != x:
            fail(where + "x must be the canonical base64url of 32 bytes")
        if status == "revoked":
            fail(where + "a revoked key is removed from the set, not listed")
        if status not in STATUSES:
            fail(where + "status must be current, next or retiring")
        out.append({"kid": kid, "kty": kty, "crv": crv, "x": x, "status": status})
    return json.dumps({"keys": out}, separators=(",", ":"), ensure_ascii=True) + "\n"

mode = sys.argv[1]
raw = sys.stdin.buffer.read()
text = normalize(raw)
if mode == "normalize":
    sys.stdout.write(text)
else:
    kids = [key["kid"] for key in json.loads(text)["keys"]]
    sys.stdout.write(json.dumps({"ok": True, "kids": kids}, separators=(",", ":")) + "\n")
' "$1"
}

if [ "$check" = 1 ]; then
  [ -f "$target" ] || cvl_die "no key file is installed at $target"
  helper normalize <"$target" >/dev/null || cvl_die "the installed key file is not a valid key set"
  helper kids <"$target" || cvl_die "could not read the installed key file"
  exit 0
fi

canonical=$(helper normalize) || cvl_die "the key set on stdin was refused (the reason is above); nothing was changed"

if [ -d "$target" ]; then cvl_die "$target is a directory (a bind mount created it before the file existed); remove it and run cvl-firstboot.sh again"; fi
cvl_private_dir "$(dirname "$target")"
current=''
if [ -f "$target" ]; then current=$(cat "$target"); fi  # command substitution drops the final newline of both sides of the comparison
if [ "$current" != "$canonical" ]; then
  # temp file first (a failure before this point never touches the live file), then copied over the existing file in place: same inode, mode 600
  tmp=$(mktemp "${TMPDIR:-/tmp}/cvl-sso.XXXXXX")
  trap 'rm -f "$tmp"' EXIT
  printf '%s\n' "$canonical" >"$tmp"
  [ -e "$target" ] || : >"$target"
  chmod 600 "$target"
  cat "$tmp" >"$target"
fi
printf '%s\n' "$canonical" | helper kids
