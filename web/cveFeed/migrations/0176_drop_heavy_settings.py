"""The per-tool scanner limits (``heavy.<kind>`` on Settings, configMaxxing) are gone with the memory gate: no scanner runs on the server any
more. Drop what a person saved for them and what the auto-tuner chose, so neither the page nor the published copies carry dead keys. The
tuning history (``TuningDecision`` rows that name a ``heavy.*`` setting) is kept as the record it is. Reverse: nothing to restore."""
from django.db import migrations


def _strip(row):
    values = {k: v for k, v in (row.values or {}).items() if not str(k).startswith('heavy.')}
    meta = {k: v for k, v in (row.meta or {}).items() if not str(k).startswith('heavy.')}
    if values != (row.values or {}) or meta != (row.meta or {}):
        row.values, row.meta = values, meta
        row.save(update_fields=['values', 'meta'])


def drop_heavy(apps, schema_editor):
    for name in ('ScanConcurrency', 'AutoTuneSettings'):
        for row in apps.get_model('cveFeed', name).objects.all():
            _strip(row)


class Migration(migrations.Migration):

    dependencies = [('cveFeed', '0175_drop_nuclei_template_refresh')]

    operations = [migrations.RunPython(drop_heavy, migrations.RunPython.noop)]
