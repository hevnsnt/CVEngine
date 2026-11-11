from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """The partial index behind ``detection_author.progress``: ``GROUP BY source`` over the CVE detections that have checks (``strategy`` is not ``{}``) took up
    to 6.4 s on a production instance because it read the ``strategy`` JSON of all 38,000 rows. The index holds the rows that have checks, with their source and
    id, so the count is an index-only scan. Built CONCURRENTLY in a migration outside a transaction, like agentapi 0022, so an upgrade never blocks the feed or
    the AI author that write this table. Index only: no column, no data."""

    atomic = False

    dependencies = [('cveFeed', '0158_scancontrol_update_window')]

    operations = [
        AddIndexConcurrently(
            model_name='cvedetection',
            index=models.Index(fields=['source', 'id'], name='cvedetection_source_filled_idx', condition=models.Q(('strategy', {}), _negated=True)),
        ),
    ]
