from django.db import migrations

# The Sentinel task table churns the most: on a production host it held 9.4k dead of 116k rows (1.7 GB, mostly the stored result) because autovacuum's
# default scale factor (0.2) lets a fifth of a table go dead before it is vacuumed. 0.05 vacuums and analyzes it at a twentieth. The other five
# tables are in cveFeed 0190, so neither app's migrations wait on the other.
TABLES = (
    ('agentapi', 'SentinelTask'),
)
OPTIONS = {'autovacuum_vacuum_scale_factor': '0.05', 'autovacuum_analyze_scale_factor': '0.05'}


def _tables(apps):
    return [apps.get_model(app, name)._meta.db_table for app, name in TABLES]


def set_options(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    settings = ', '.join(f'{key} = {value}' for key, value in OPTIONS.items())
    for table in _tables(apps):
        schema_editor.execute(f'ALTER TABLE {schema_editor.quote_name(table)} SET ({settings})')


def reset_options(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    for table in _tables(apps):
        schema_editor.execute(f'ALTER TABLE {schema_editor.quote_name(table)} RESET ({", ".join(OPTIONS)})')


class Migration(migrations.Migration):
    """Per table autovacuum settings for the Sentinel task table (the other five tables are in cveFeed 0190) that churn the most. ``ALTER TABLE ... SET (...)`` only changes the table's storage
    options: it takes a short SHARE UPDATE EXCLUSIVE lock (reads and writes go on; it waits only behind a running VACUUM, ANALYZE or index
    build on that table) and rewrites nothing, so it takes a moment on any size of table. Reversed with ``RESET``, which puts the server wide
    defaults back. Data is not touched."""

    dependencies = [
        ('agentapi', '0026_sentineltask_unscrubbed_img_idx'),
    ]

    operations = [
        migrations.RunPython(set_options, reset_options, elidable=False),
    ]
