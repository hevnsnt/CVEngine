from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """``auditlog_action_id_idx`` (action, id) on the audit log, built CONCURRENTLY outside a transaction like ``cveFeed`` 0174, so an update never
    blocks the Sentinel claims and reports that write this table. The weekly maintenance reads and deletes the routine Sentinel rows one action at a
    time in id order through it, and the lookups of one action (``host.archive`` in the archive backfill, a task's claim or late report) use it too.
    Index only: no column, no data."""

    atomic = False

    dependencies = [('dashboard', '0037_drop_unused_legacy_models')]

    operations = [
        AddIndexConcurrently(model_name='auditlog', index=models.Index(fields=['action', 'id'], name='auditlog_action_id_idx')),
    ]
