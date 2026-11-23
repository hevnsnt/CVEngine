from django.db import migrations, models

from startScan.dedupe import merge_rows

CONSTRAINT = 'uniq_sub_scan_dom_name'
TABLE = '"startScan_subdomain"'
# facts a kept host lacks are taken from the newest of its duplicates that has them
FACTS = ('http_url', 'screenshot_path', 'screenshot_hash', 'http_header_path', 'cname', 'cdn_name', 'content_type', 'response_time',
         'webserver', 'content_length', 'page_title', 'attack_surface', 'http_status')


def merge_duplicate_hosts(apps, schema_editor):
    """One host row per (scan, target, name). A discovery copied into a scan twice (``discovery.seed_from_scan`` run again by a resumed
    stage) or two writers creating the same host at the same moment left two rows; every reader already used the oldest
    (``startScan.ip_rows.get_or_create_first``). The oldest row stays. Every row that points at a newer duplicate (findings, endpoints,
    CVE matches, subscans, address, technology and WAF links) is moved onto it; a link the kept row already has is dropped instead.
    A moved row that would break a unique constraint of its own table and has rows pointing at it stops the migration (nothing is
    lost, the transaction rolls back) with the ids to merge by hand. Safe to run again."""
    Subdomain = apps.get_model('startScan', 'Subdomain')
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT array_agg(id ORDER BY id) FROM {TABLE} WHERE scan_history_id IS NOT NULL AND target_domain_id IS NOT NULL '
                       'GROUP BY scan_history_id, target_domain_id, name HAVING count(*) > 1')
        groups = [row[0] for row in cursor.fetchall()]
    for ids in groups:
        keep, extras = ids[0], ids[1:]
        keeper = Subdomain.objects.get(pk=keep)
        changed = []
        for extra in Subdomain.objects.filter(pk__in=extras).order_by('-id'):
            for field in FACTS:
                if getattr(keeper, field) in (None, '', 0) and getattr(extra, field) not in (None, '', 0):
                    setattr(keeper, field, getattr(extra, field))
                    changed.append(field)
            for flag in ('is_important', 'is_cdn', 'is_imported_subdomain'):
                if getattr(extra, flag) and not getattr(keeper, flag):
                    setattr(keeper, flag, True)
                    changed.append(flag)
            if extra.discovered_date and (keeper.discovered_date is None or extra.discovered_date < keeper.discovered_date):
                keeper.discovered_date = extra.discovered_date
                changed.append('discovered_date')
        if changed:
            keeper.save(update_fields=sorted(set(changed)))
        merge_rows(connection, TABLE, keep, extras)


class Migration(migrations.Migration):
    """The database refuses a second host row for the same name in the same scan and target. The duplicates are merged first (above,
    in its own transaction), then the unique index is built CONCURRENTLY, so writers of the host table are not blocked while it builds,
    and the constraint is attached to the built index (a short metadata change). Reversing drops the constraint and its index; the
    merged rows stay merged. If the build is interrupted, ``migrate`` stops: run
    ``DROP INDEX CONCURRENTLY IF EXISTS uniq_sub_scan_dom_name;`` and ``migrate`` again."""

    atomic = False
    dependencies = [('startScan', '0030_subdomain_upper_name_idx')]

    operations = [
        migrations.RunPython(merge_duplicate_hosts, migrations.RunPython.noop, atomic=True),
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    f'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS {CONSTRAINT} ON {TABLE} (scan_history_id, target_domain_id, name)',
                    reverse_sql=f'DROP INDEX CONCURRENTLY IF EXISTS {CONSTRAINT}'),
                migrations.RunSQL(
                    f'ALTER TABLE {TABLE} ADD CONSTRAINT {CONSTRAINT} UNIQUE USING INDEX {CONSTRAINT}',
                    reverse_sql=f'ALTER TABLE {TABLE} DROP CONSTRAINT IF EXISTS {CONSTRAINT}'),
            ],
            state_operations=[
                migrations.AddConstraint(
                    model_name='subdomain',
                    constraint=models.UniqueConstraint(fields=('scan_history', 'target_domain', 'name'), name=CONSTRAINT)),
            ],
        ),
    ]
