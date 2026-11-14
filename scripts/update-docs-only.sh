#!/usr/bin/env bash
# Decides whether an update between two commits changes documentation only, so the host can move to the new commit without a maintenance
# page, a scan pause or any container recreate (scripts/apply-update.sh uses it; nothing here touches Docker, a flag or any state).
#
#   scripts/update-docs-only.sh [--explain] FROM TO      prints "skip" (exit 0) or "deploy" (exit 1); --explain adds the reason on stderr
#   . scripts/update-docs-only.sh; cvengine_docs_only_update FROM TO
#
# THE ALLOWLIST. A range is docs-only only when EVERY path it changes matches one of these, and nothing else (any other path, in any
# amount, means a full deploy):
#   README.md  CHANGELOG.md  CONTRIBUTORS.md          (the repository root)
#   docs/**/*.md  docs/**/*.png|jpg|jpeg|gif|svg|webp   (the documentation folder, any depth)
# Nothing under web/ (the code, templates and static files, bind-mounted into the containers), reviewer/, config/, scripts/, .github/,
# a compose file, a Dockerfile, requirements, scanner.lock.json, .env or Makefile is ever on the list. Neither is anything unlisted: the
# default is the full deploy. A path in the list that is not a plain file (a symlink, a submodule, an executable) is not docs either.
# Why safe: ./web is the only part of the checkout the running containers read, plus config/ and the compose files, and the image is built
# from ./web (and ./reviewer) alone, so a change confined to the list above is not seen by any container.
#
# Any doubt is "deploy": an unreadable range, a commit that is not known here, FROM not an ancestor of TO, no changed path at all (an
# empty range is for the caller to decide, and it deploys), a path with an odd name (newline, control character, "..", a leading slash).
cvengine_docs_only_reason=''

cvengine_docs_only_path_ok() {
  case $1 in
    README.md|CHANGELOG.md|CONTRIBUTORS.md) return 0 ;;
    docs/*) ;;
    *) return 1 ;;
  esac
  case $1 in
    *..*|*//*) return 1 ;;
  esac
  case $1 in
    *.md|*.png|*.jpg|*.jpeg|*.gif|*.svg|*.webp) return 0 ;;
  esac
  return 1
}

# 0 when every path changed from $1 to $2 is on the allowlist; 1 otherwise, with the reason in cvengine_docs_only_reason.
cvengine_docs_only_update() {
  local from=$1 to=$2 meta path line mode n=0 raw
  cvengine_docs_only_reason=''
  if ! [[ $from =~ ^[0-9a-f]{40}$ && $to =~ ^[0-9a-f]{40}$ ]]; then
    cvengine_docs_only_reason='a commit is not a full 40 character id'; return 1
  fi
  if ! git cat-file -e "$from^{commit}" 2>/dev/null || ! git cat-file -e "$to^{commit}" 2>/dev/null; then
    cvengine_docs_only_reason='a commit is not in this checkout'; return 1
  fi
  if ! git merge-base --is-ancestor "$from" "$to" 2>/dev/null; then
    cvengine_docs_only_reason='the deployed commit is not an ancestor of the new one'; return 1
  fi
  # --no-renames: a rename lists both the old and the new path, so each is judged. A path with a quote, tab, newline or other odd
  # character comes out quoted by git (core.quotepath on), starts with a double quote, and so matches nothing on the list.
  # (read into a variable first: a failing git must not look like an empty list)
  if ! raw=$(git -c core.quotepath=true diff --raw --no-renames --no-abbrev "$from" "$to" 2>/dev/null); then
    cvengine_docs_only_reason='the diff could not be read'; return 1
  fi
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    n=$((n + 1))
    # line: ":<oldmode> <newmode> <oldsha> <newsha> <status><TAB><path>"
    meta=${line%%$'\t'*}; path=${line#*$'\t'}
    if [[ $meta != :* || $path == "$line" || $path == /* || $path == \"* || $path == *[[:cntrl:]]* ]] || ! cvengine_docs_only_path_ok "$path"; then
      cvengine_docs_only_reason="${path:-an unreadable diff line} is not on the documentation allowlist"; return 1
    fi
    set -- $meta
    for mode in "${1#:}" "$2"; do
      case $mode in 100644|000000) ;; *) cvengine_docs_only_reason="$path is not a plain file (mode $mode)"; return 1 ;; esac
    done
  done <<<"$raw"
  if (( n == 0 )); then cvengine_docs_only_reason='no path changed'; return 1; fi
  cvengine_docs_only_reason="$n path(s), all on the documentation allowlist"
  return 0
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  set -uo pipefail
  explain=0
  if [[ ${1:-} == --explain ]]; then explain=1; shift; fi
  if [[ $# -ne 2 ]]; then echo "usage: $0 [--explain] FROM TO" >&2; exit 2; fi
  # full ids only (the function insists), so a name or a short id is resolved here, by git, in this checkout
  from=$(git rev-parse --verify --quiet "$1^{commit}") || from=$1
  to=$(git rev-parse --verify --quiet "$2^{commit}") || to=$2
  if cvengine_docs_only_update "$from" "$to"; then verdict=skip; code=0; else verdict=deploy; code=1; fi
  echo "$verdict"
  [[ $explain = 1 ]] && echo "$cvengine_docs_only_reason" >&2
  exit $code
fi
