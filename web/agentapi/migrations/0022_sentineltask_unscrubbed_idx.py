from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """The partial index behind ``sentinel_broker.scrub_stale_values``, which runs once a minute and took up to 8.7 s on a production instance: it asks for the
    finished secrets and route-probe tasks whose values are not scrubbed yet, ``ORDER BY id LIMIT 200``, and with no index that serves it Postgres read the result
    column of every finished task (the table holds 30 days of work). The index holds only the unscrubbed rows. Built CONCURRENTLY, like 0020, so an upgrade
    does not lock the table Sentinels claim tasks from (a migration outside a transaction). Index only: no column, no data."""

    atomic = False

    dependencies = [
        ('agentapi', '0021_sentineldefaults_keep_newest'),
    ]

    operations = [
        AddIndexConcurrently(
            model_name='sentineltask',
            index=models.Index(condition=models.Q(('kind__in', ['secrets_scan', 'route_probe']), ('status', 'done'), models.Q(('result__has_key', 'values_scrubbed'), _negated=True)),
                               fields=['id'], name='sentineltask_unscrubbed_idx'),
        ),
    ]
