"""Merging duplicate rows before a unique constraint is added (the migrations that add ``uniq_sub_scan_dom_name`` and the name constraints
of the finding vocabulary and technologies use it). Plain SQL over the database's own foreign keys, so a table of any app that points at
the merged table is covered, whatever the migration state knows of it. Migrations call this: keep its behaviour stable."""
from django.db import IntegrityError, transaction


def referencing(cursor, table):
    """``(table, column)`` of every single column foreign key that points at ``table`` (a quoted table name)."""
    cursor.execute(
        "SELECT c.conrelid::regclass::text, a.attname FROM pg_constraint c "
        "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] "
        "WHERE c.contype = 'f' AND c.confrelid = %s::regclass AND array_length(c.conkey, 1) = 1 ORDER BY 1, 2", [table])
    return cursor.fetchall()


def primary_key(cursor, table):
    cursor.execute(
        "SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
        "WHERE i.indrelid = %s::regclass AND i.indisprimary", [table])
    rows = cursor.fetchall()
    if len(rows) != 1:
        raise RuntimeError(f'{table} has no single column primary key; merge its rows by hand')
    return rows[0][0]


def merge_rows(connection, table, keep, extras):
    """Point every row that references one of ``extras`` at ``keep``, then delete ``extras``. A row whose move would break a unique
    constraint of its own table (the kept row already has the same link) is deleted instead, but only when nothing points at its table
    (a link table); otherwise a RuntimeError names it and the caller's transaction rolls back, so no row with children is ever deleted.
    Must run inside a transaction (each move is a savepoint)."""
    if not extras:
        return
    alias = connection.alias
    with connection.cursor() as cursor:
        for child, column in referencing(cursor, table):
            if child == table:
                raise RuntimeError(f'{table} points at itself; merge its rows by hand')
            try:
                with transaction.atomic(using=alias):
                    cursor.execute(f'UPDATE {child} SET "{column}" = %s WHERE "{column}" = ANY(%s)', [keep, list(extras)])
                continue
            except IntegrityError:
                pass  # some row collides with one the kept row already has: move them one by one
            pk = primary_key(cursor, child)
            cursor.execute(f'SELECT "{pk}" FROM {child} WHERE "{column}" = ANY(%s) ORDER BY "{pk}"', [list(extras)])
            for (row,) in cursor.fetchall():
                try:
                    with transaction.atomic(using=alias):
                        cursor.execute(f'UPDATE {child} SET "{column}" = %s WHERE "{pk}" = %s', [keep, row])
                except IntegrityError:
                    if referencing(cursor, child):
                        raise RuntimeError(f'{child} row {row} duplicates one of {table} row {keep} and has rows pointing at it; '
                                           f'merge {table} rows {[keep, *extras]} by hand, then run migrate again')
                    cursor.execute(f'DELETE FROM {child} WHERE "{pk}" = %s', [row])
        cursor.execute(f'DELETE FROM {table} WHERE id = ANY(%s)', [list(extras)])


def merge_groups(connection, table, columns):
    """Merge the rows of ``table`` that share ``columns`` (none NULL) onto the oldest of each group. Returns the number of rows removed."""
    cols = ', '.join(f'"{c}"' for c in columns)
    present = ' AND '.join(f'"{c}" IS NOT NULL' for c in columns)
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT array_agg(id ORDER BY id) FROM {table} WHERE {present} GROUP BY {cols} HAVING count(*) > 1')
        groups = [row[0] for row in cursor.fetchall()]
    for ids in groups:
        merge_rows(connection, table, ids[0], ids[1:])
    return sum(len(ids) - 1 for ids in groups)


def unique_operations(model_name, table, name, columns, fields):
    """The operations that add the unique constraint ``name`` on ``columns`` without blocking writers for the build: the unique index is
    built CONCURRENTLY (the migration must be ``atomic = False``), then the constraint is attached to it, a short metadata change.
    ``fields`` are the model's names of ``columns``. Reversing drops the constraint and its index."""
    from django.db import migrations, models
    cols = ', '.join(f'"{c}"' for c in columns)
    return migrations.SeparateDatabaseAndState(
        database_operations=[
            migrations.RunSQL(f'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {table} ({cols})',
                              reverse_sql=f'DROP INDEX CONCURRENTLY IF EXISTS {name}'),
            migrations.RunSQL(f'ALTER TABLE {table} ADD CONSTRAINT {name} UNIQUE USING INDEX {name}',
                              reverse_sql=f'ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}'),
        ],
        state_operations=[
            migrations.AddConstraint(model_name=model_name, constraint=models.UniqueConstraint(
                fields=tuple(fields), name=name)),
        ],
    )
