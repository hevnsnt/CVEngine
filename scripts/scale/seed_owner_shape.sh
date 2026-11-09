#!/bin/bash
# Seed a 15-project, about 3,000-host database shaped like a busy production instance (synthetic data only), then ANALYZE.
#   SCALE_DB=cv_scale_owner RENGINE_HOME=$PWD/web bash scripts/scale/seed_owner_shape.sh
# Needs the CI-style environment (POSTGRES_*, CELERY_BROKER) and a database name containing "scale" that is already migrated.
# project:hosts:targets (one project holds ~1,000 targets, several hold one, hosts per project run from 5 to 600).
set -euo pipefail
cd "$(dirname "$0")/../../web"
spec=${OWNER_SHAPE:-"scale-fixture:600:12 big-estate:520:1000 acme:420:6 globex:300:4 initech:250:3 umbrella:200:2 hooli:150:1 stark:120:2 wayne:100:1 wonka:80:1 cyberdyne:60:1 soylent:60:1 tyrell:50:1 oscorp:30:1 pied:10:1"}
first=1
for p in $spec; do
  IFS=: read -r slug hosts targets <<<"$p"
  extra=(--sentinels 0 --tasks 0)
  [ $first = 1 ] && extra=(--sentinels 2 --tasks 400)
  first=0
  python manage.py seed_scale_fixture --slug "$slug" --hosts "$hosts" --targets "$targets" --matches-per-host "${MATCHES_PER_HOST:-8}" --findings-per-host "${FINDINGS_PER_HOST:-0.8}" --ip-ratio "${IP_RATIO:-0.9}" --history-scans "${HISTORY_SCANS:-2}" --queued 2 --seed 7 "${extra[@]}" 2>&1 | tail -1
done
