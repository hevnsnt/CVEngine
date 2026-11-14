#!/usr/bin/env bash
# The Sentinel commit the server image installs its scanner library from, resolved NOW (at build time).
#   scripts/sentinel-ref.sh            prints a 40 character sha, or nothing when it cannot be read (then the Dockerfile resolves it itself)
# SENTINEL_REF (environment, or the same key in .env) is a branch, a tag or a full sha; the default is main: the newest Sentinel build. The result is passed to
# the image build as the SENTINEL_SHA build argument (docker-compose.yml): the build argument is what makes Docker rebuild the layer when main moved, and it is the
# commit the image records. docs/UPDATES.md ("The Sentinel library in the server image").
set -u
cd "$(dirname "$0")/.." || exit 0
ref=${SENTINEL_REF:-}
if [ -z "$ref" ] && [ -f .env ]; then
  ref=$(sed -n 's/^SENTINEL_REF=//p' .env | tail -n 1 | tr -d "\"' \r")
fi
ref=${ref:-main}
repo=${SENTINEL_REPO:-https://github.com/hevnsnt/cvENGINE-sentinel}
if [[ $ref =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' "$ref"
  exit 0
fi
[[ $ref =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$ ]] || exit 0
command -v git >/dev/null 2>&1 || exit 0
sha=$(git ls-remote "$repo" "refs/heads/$ref" "refs/tags/$ref^{}" "refs/tags/$ref" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9a-f]{40}$' | head -n 1) || sha=''
[ -n "$sha" ] && printf '%s\n' "$sha"
exit 0
