from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """One index, built CONCURRENTLY outside a transaction like 0174, so an update never blocks the writes to ``AIUsage`` (a row per model call).
    The AI and your data page counts each job's calls of the last 30 days (``started_at >= cutoff`` grouped by ``stage``); the only index
    carried ``provider`` and ``model`` after ``started_at``, not ``stage``, so every page view read the rows. Index only: no column, no data."""

    atomic = False

    dependencies = [('cveFeed', '0185_mcpcall')]

    operations = [
        AddIndexConcurrently(model_name='aiusage', index=models.Index(fields=['started_at', 'stage'], name='aiusage_time_stage_idx')),
    ]
