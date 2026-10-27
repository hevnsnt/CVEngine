#!/usr/bin/env bash
# The database schema before and after an update, to catch a column the new version adds that the OLD code cannot live with.
# Between the migration and the restart (and for as long as a failed restart is retried) the old containers run on the new schema. A new
# NOT NULL column with no database-level default makes every insert the old code does into that table fail. Give the field db_default.
#   schema.sh snapshot FILE     write the columns of the install's database to FILE
#   schema.sh check FILE        compare with the snapshot: fail on a new NOT NULL column without a default on a table that already existed
set -euo pipefail
. "$GITHUB_WORKSPACE/.github/rehearsal/lib.sh"
columns() {
  dc exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atq' <<'SQL' | sed 's/\r$//'
select table_name || '.' || column_name || ' | nullable=' || is_nullable || ' | default=' || coalesce(column_default, 'NONE')
from information_schema.columns where table_schema = 'public' order by 1;
SQL
}
case "${1:-}" in
  snapshot) columns > "$2"; echo "Schema snapshot: $(wc -l < "$2") columns." ;;
  check)
    columns > "$HOME/schema-after.txt"
    python3 - "$2" "$HOME/schema-after.txt" <<'PY'
import sys
before = open(sys.argv[1]).read().splitlines()
after = open(sys.argv[2]).read().splitlines()
known = {line.split(' | ')[0] for line in before}
tables = {key.split('.')[0] for key in known}
risky = [line for line in after if line.split(' | ')[0] not in known and line.split('.')[0] in tables
         and 'nullable=NO' in line and 'default=NONE' in line]
for line in risky:
    print(f'::error::new NOT NULL column without a database default on an existing table: {line.split(" | ")[0]} (add db_default to the field)')
print(f'{len(after) - len(known)} columns added; {len(risky)} that the old code cannot insert around.')
sys.exit(1 if risky else 0)
PY
    ;;
  *) echo "usage: schema.sh snapshot|check FILE" >&2; exit 2 ;;
esac
