"""Trigram indexes for the host search's product names (``tech:``, ``product:``, ``banner:``, ``component:``; agentapi.services._tech_q and
``_banner_q``): a substring or pattern match over every port's product and banner, every technology name and every version source reading
is a sequential scan without them. Django writes ``icontains`` as ``UPPER(col::text) LIKE UPPER(...)`` and ``iregex`` as ``col ~* ...``, so
each column gets the index of the form its lookups take (pg_trgm serves both LIKE and regular expressions). pg_trgm is the extension
migration 0149 enables; a database user that may not create it skips the indexes and search still works, only slower on a large project."""
from django.db import migrations

INDEXES = (
    ('search_port_product_up_trgm', '"startScan_port"', '(upper(product::text)) gin_trgm_ops'),
    ('search_port_product_trgm', '"startScan_port"', 'product gin_trgm_ops'),
    ('search_port_banner_up_trgm', '"startScan_port"', '(upper(banner::text)) gin_trgm_ops'),
    ('search_tech_name_up_trgm', '"startScan_technology"', '(upper(name::text)) gin_trgm_ops'),
    ('search_tech_name_trgm', '"startScan_technology"', 'name gin_trgm_ops'),
    ('search_probeobs_product_up_trgm', '"cveFeed_probeobservation"', '(upper(product::text)) gin_trgm_ops'),
    ('search_probeobs_product_trgm', '"cveFeed_probeobservation"', 'product gin_trgm_ops'),
)


def add_indexes(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'")
        if not cur.fetchone():
            cur.execute("SELECT 1 FROM pg_available_extensions WHERE name = 'pg_trgm'")
            if not cur.fetchone():
                return
            cur.execute('SAVEPOINT search_trgm')
            try:
                cur.execute('CREATE EXTENSION IF NOT EXISTS pg_trgm')
            except Exception:  # noqa: BLE001 - no privilege to create it: search works without the indexes
                cur.execute('ROLLBACK TO SAVEPOINT search_trgm')
                return
            cur.execute('RELEASE SAVEPOINT search_trgm')
        for name, table, expression in INDEXES:
            cur.execute(f'CREATE INDEX IF NOT EXISTS {name} ON {table} USING gin ({expression})')


def drop_indexes(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cur:
        for name, _table, _expression in INDEXES:
            cur.execute(f'DROP INDEX IF EXISTS {name}')


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0171_retry_record_rereads'),
        ('startScan', '0025_scanhistory_discovery_mode'),
    ]

    operations = [
        migrations.RunPython(add_indexes, drop_indexes),
    ]
