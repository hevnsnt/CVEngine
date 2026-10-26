#!/usr/bin/env bash
# Works out the installed version (BASE_REF) and the release candidate (the installed version with CANDIDATE_REF merged in, as the
# release itself will be), and sets up a local "origin" that holds the installed version as master.
set -euo pipefail
cd "$GITHUB_WORKSPACE"
git config user.name rehearsal
git config user.email rehearsal@example.invalid

sha_of() {
  if [[ $1 =~ ^[0-9a-f]{40}$ ]]; then echo "$1"; return; fi
  git rev-parse --verify --quiet "origin/$1^{commit}" || git rev-parse --verify "$1^{commit}"
}
base=$(sha_of "$BASE_REF")
head=$(sha_of "$CANDIDATE_REF")
echo "Installed version:  $base ($BASE_REF)"
echo "Update goes to:     $head ($CANDIDATE_REF)"

git checkout -q --detach "$base"
if git merge-base --is-ancestor "$head" "$base"; then
  echo "Nothing is being released: the candidate is already in the installed version."
  candidate=$base
elif ! git merge --no-ff -q -m "Release candidate" "$head"; then
  echo "::error::Merging $CANDIDATE_REF into $BASE_REF conflicts. A release would have to resolve:"
  git diff --name-only --diff-filter=U | sed 's/^/  /'
  exit 1
else
  candidate=$(git rev-parse HEAD)
fi
git branch -f rehearsal-candidate "$candidate"
echo "$candidate" > "$HOME/candidate.sha"
echo "$base" > "$HOME/base.sha"

rm -rf "$HOME/origin.git" "$HOME/cvengine"
git clone -q --bare "$GITHUB_WORKSPACE" "$HOME/origin.git"
git --git-dir="$HOME/origin.git" update-ref refs/heads/master "$base"
git --git-dir="$HOME/origin.git" symbolic-ref HEAD refs/heads/master
git clone -q --branch master "$HOME/origin.git" "$HOME/cvengine"
git -C "$HOME/cvengine" config user.name rehearsal
git -C "$HOME/cvengine" config user.email rehearsal@example.invalid
echo "Release candidate: $candidate"
