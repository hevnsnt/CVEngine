from django.db import migrations

# The tables that churn the most: autovacuum's default scale factor (0.2) lets a fifth of a table go dead before it is vacuumed, so a
# 500,000 row table carries 100,000 dead rows. On a production host they held 49.8k of 494k (agent activity), 9.4k of 116k (Sentinel tasks,
# 1.7 GB, mostly the stored result), 21.8k of 447k (service runs), 11k of 57k (CVE detections), 6k of 30k (triage) and 3k of 106k (asset
# changes). 0.05 vacuums and analyzes them at a twentieth instead.
TABLES = (
    ('cveFeed', 'AgentActivity'),
    ('agentapi', 'SentinelTask'),
    ('cveFeed', 'ServiceRun'),
    ('cveFeed', 'CVEDetection'),
    ('cveFeed', 'Triage'),
    ('cveFeed', 'AssetChange'),
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
    """Per table autovacuum settings for the six tables that churn the most. ``ALTER TABLE ... SET (...)`` only changes the table's storage
    options: it takes a short SHARE UPDATE EXCLUSIVE lock (reads and writes go on; it waits only behind a running VACUUM, ANALYZE or index
    build on that table) and rewrites nothing, so it takes a moment on any size of table. Reversed with ``RESET``, which puts the server wide
    defaults back. Data is not touched."""

    dependencies = [
        ('cveFeed', '0189_hostinv_proj_reported_idx'),
        ('agentapi', '0026_sentineltask_unscrubbed_img_idx'),
    ]

    operations = [
        migrations.RunPython(set_options, reset_options, elidable=False),
    ]
