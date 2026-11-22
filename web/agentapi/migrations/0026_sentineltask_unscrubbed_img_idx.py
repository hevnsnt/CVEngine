from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """A partial index over the finished ``web_screenshot`` tasks whose pictures are still in the result, for ``sentinel_broker.scrub_stale_images``
    (once a minute). Without it the select would read the result column of every finished screenshot task, which is the column that is large. Built
    CONCURRENTLY, like 0020, 0022 and 0024, so an upgrade does not lock the table Sentinels claim from. Index only: no column, no data."""

    atomic = False

    dependencies = [
        ('agentapi', '0025_dns_readings'),
    ]

    operations = [
        AddIndexConcurrently(
            model_name='sentineltask',
            index=models.Index(condition=models.Q(('kind', 'web_screenshot'), ('status', 'done'), models.Q(('result__has_key', 'images_scrubbed'), _negated=True)),
                               fields=['id'], name='sentineltask_unscrubbed_img_idx'),
        ),
    ]
