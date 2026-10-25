#!/usr/bin/env bash
# Prepare .env for a first start: create it from .env.example when it is missing, then replace the example placeholders of the
# secrets nobody should have to invent (the database and certificate-authority passwords) with random ones. A value that is
# already set is never touched, so this is safe to run again, and an installation that is already running keeps its passwords.
# The admin password is not here: `make admin` creates the account and prints its password once.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { cp .env.example .env; echo "Created .env from .env.example."; }

# letters and digits only: a `$` or `#` in .env breaks Make and Compose parsing
random() { head -c 256 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

fill() {
  local key=$1
  # an empty value, or the example's "change-me": anything else is the owner's and stays
  if grep -qiE "^${key}=(.*change-me.*)?$" .env; then
    local value tmp
    value=$(random)
    tmp=$(mktemp "${TMPDIR:-/tmp}/cvengine-env.XXXXXX")
    awk -v key="$key" -v value="$value" 'BEGIN { prefix = key "=" } index($0, prefix) == 1 { print prefix value; next } { print }' .env > "$tmp"
    cat "$tmp" > .env  # keeps the file's own mode and owner, which mv would replace
    rm -f "$tmp"
    echo "Generated ${key}."
  fi
}

fill POSTGRES_PASSWORD
fill AUTHORITY_PASSWORD
chmod 600 .env
