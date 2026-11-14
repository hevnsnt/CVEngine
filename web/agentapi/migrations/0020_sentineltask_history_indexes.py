from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """Indexes for the Sentinels page's polls on ``agentapi_sentineltask``, which holds 30 days of work (about a million rows at 3000 targets). Built
    CONCURRENTLY, so an upgrade does not lock the table that Sentinels are claiming tasks from; that needs a migration outside a transaction. Indexes
    only: no column, no data."""

    atomic = False

    dependencies = [
        ('agentapi', '0019_drop_scanner_fallback'),
    ]

    operations = [
        AddIndexConcurrently(
            model_name='sentineltask',
            index=models.Index(fields=['agent', '-finished_at', '-id'], name='sentineltask_agent_done_idx', include=['status', 'accepted_at', 'claimed_at', 'kind'],
                               condition=models.Q(status__in=['done', 'failed'])),
        ),
        AddIndexConcurrently(
            model_name='sentineltask',
            index=models.Index(fields=['finished_at'], name='sentineltask_finished_idx', condition=models.Q(finished_at__isnull=False)),
        ),
        AddIndexConcurrently(
            model_name='sentineltask',
            index=models.Index(fields=['claimed_at'], name='sentineltask_claimed_idx', condition=models.Q(claimed_at__isnull=False)),
        ),
    ]
