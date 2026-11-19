from django.db import migrations, models


class Migration(migrations.Migration):
    """Two nullable columns on ``agentapi_sentineltask`` (no default, so no table rewrite): ``last_holder``, the Sentinel that held a task last (kept when an
    expiry or a cancel clears ``agent``), and ``late_reported_at``, when a late report of it was recorded. ``sentinel_broker._held_before`` and
    ``_record_late`` asked the audit log for both, with a JSON key lookup inside the task's row lock (54 to 89 ms at a million audit rows, and growing).
    A task claimed before this migration has no ``last_holder``; for those the audit log is still asked."""

    dependencies = [
        ('agentapi', '0022_sentineltask_unscrubbed_idx'),
    ]

    operations = [
        migrations.AddField(model_name='sentineltask', name='last_holder', field=models.IntegerField(blank=True, null=True)),
        migrations.AddField(model_name='sentineltask', name='late_reported_at', field=models.DateTimeField(blank=True, null=True)),
    ]
