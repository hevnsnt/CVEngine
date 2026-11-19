from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """A partial index over the queued rows of ``agentapi_sentineltask`` for the reaper's select of the tasks that waited in the queue too long
    (``created_at``), which runs from every broker call: with nothing to reap it read the whole table (53 ms at 155,000 rows). Built CONCURRENTLY, like 0020 and 0022,
    so an upgrade does not lock the table Sentinels claim from (a migration outside a transaction). Index only: no column, no data."""

    atomic = False

    dependencies = [
        ('agentapi', '0023_sentineltask_last_holder'),
    ]

    operations = [
        AddIndexConcurrently(
            model_name='sentineltask',
            index=models.Index(condition=models.Q(('status', 'queued')), fields=['created_at'], name='sentineltask_queued_age_idx'),
        ),
    ]
