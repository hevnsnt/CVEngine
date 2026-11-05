"""Trigram indexes for the CVE explorer (cveFeed.cve_explorer): a substring search ("ssh", "php") over the affected product names and the
title of every CVE is a sequential scan without them. The expressions are the explorer's own, character for character, or the planner
cannot use them. pg_trgm ships with PostgreSQL and is a trusted extension; a database user that may not create it skips the indexes and
the explorer still works, only slower on a large catalog."""
from django.db import migrations

PRODUCTS_INDEX = ('CREATE INDEX IF NOT EXISTS cvefeed_cve_products_trgm ON "cveFeed_cveentry" USING gin ('
                  "(upper((jsonb_path_query_array(affected, '$[*].vendor') || jsonb_path_query_array(affected, '$[*].product')"
                  " || jsonb_path_query_array(affected, '$[*].package'))::text)) gin_trgm_ops)")
TITLE_INDEX = 'CREATE INDEX IF NOT EXISTS cvefeed_cve_title_trgm ON "cveFeed_cveentry" USING gin ((upper(title)) gin_trgm_ops)'
ID_INDEX = 'CREATE INDEX IF NOT EXISTS cvefeed_cve_id_trgm ON "cveFeed_cveentry" USING gin ((upper(cve_id)) gin_trgm_ops)'


def add_indexes(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'")
        if not cur.fetchone():
            cur.execute("SELECT 1 FROM pg_available_extensions WHERE name = 'pg_trgm'")
            if not cur.fetchone():
                return
            cur.execute('SAVEPOINT cve_trgm')
            try:
                cur.execute('CREATE EXTENSION IF NOT EXISTS pg_trgm')
            except Exception:  # noqa: BLE001 - no privilege to create it: the explorer works without the indexes
                cur.execute('ROLLBACK TO SAVEPOINT cve_trgm')
                return
            cur.execute('RELEASE SAVEPOINT cve_trgm')
        for sql in (PRODUCTS_INDEX, TITLE_INDEX, ID_INDEX):
            cur.execute(sql)


def drop_indexes(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cur:
        for name in ('cvefeed_cve_products_trgm', 'cvefeed_cve_title_trgm', 'cvefeed_cve_id_trgm'):
            cur.execute(f'DROP INDEX IF EXISTS {name}')


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0146_ai_job'),
    ]

    operations = [
        migrations.RunPython(add_indexes, drop_indexes),
    ]
