#!/usr/bin/env bash
. "$GITHUB_WORKSPACE/.github/rehearsal/lib.sh"
cd "$HOME/cvengine" 2>/dev/null || exit 0
echo '== compose ps'; dc ps -a || true
echo '== update log (docker build progress left out)'
cat .git/cvengine-update/update.log 2>/dev/null | grep -vE '^#[0-9]+ |^ *(Container|Image) |weasyprint|^ *_|^ *\\_|^\| |^$' | head -n 400 || true
for service in web celery celery-beat proxy redis db; do echo "== $service"; dc logs --tail 60 "$service" 2>&1 || true; done
