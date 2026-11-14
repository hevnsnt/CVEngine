#!/bin/bash
# Measure the slow paths at several fixture sizes on a throwaway Postgres.
#
#   scripts/scale/run_matrix.sh [outdir] [sizes...]        (default sizes: 500 1000 2000 3000)
#
# Needs a Postgres and a Redis the caller may write to (the CI test environment works: POSTGRES_HOST/PORT/USER/PASSWORD and CELERY_BROKER
# exported). The database SCALE_DB (default cv_scale) is dropped and rebuilt for each size from SCALE_TPL (default cv_scale_tpl, migrated once
# here), then filled by `manage.py seed_scale_fixture --hosts N` and measured by scripts/scale/measure.py. DB_EXEC runs psql, e.g.
# DB_EXEC="docker exec -i cvt-pg psql -U cvengine_ci -d postgres" when the Postgres is a container; by default psql is used directly.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-/tmp/scale-results}; shift || true
sizes=${*:-500 1000 2000 3000}
mkdir -p "$out"
export RENGINE_HOME=${RENGINE_HOME:-$here/../../web}
DB_EXEC=${DB_EXEC:-psql -h ${POSTGRES_HOST:-127.0.0.1} -p ${POSTGRES_PORT:-5432} -U ${POSTGRES_USER} -d postgres}
tpl=${SCALE_TPL:-cv_scale_tpl}; db=${SCALE_DB:-cv_scale}
cd "$here/../../web"
if ! echo "select 1 from pg_database where datname='$tpl'" | $DB_EXEC -tA | grep -q 1; then
  echo "create database $tpl" | $DB_EXEC
  POSTGRES_DB=$tpl python manage.py migrate -v0
fi
for n in $sizes; do
  echo "drop database if exists $db" | $DB_EXEC
  echo "create database $db template $tpl" | $DB_EXEC
  export POSTGRES_DB=$db
  python manage.py seed_scale_fixture --hosts "$n" > "$out/seed-$n.full" 2>&1 || { tail -30 "$out/seed-$n.full"; exit 1; }
  tail -1 "$out/seed-$n.full" | tee "$out/seed-$n.txt"
  python ../scripts/scale/measure.py --label "$n" --out "$out/scale-$n.json" ${EXPLAIN:+--explain} 2>&1 | grep -v '^weasyprint\|^reNgine\.' | tee "$out/scale-$n.log"
done
