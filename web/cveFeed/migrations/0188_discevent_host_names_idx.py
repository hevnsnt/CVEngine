from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """One partial index, built CONCURRENTLY outside a transaction like 0174, so an update never blocks the writes to ``DiscoveryEvent``. The
    Hosts page reads the names each IP host answers to (reverse DNS and certificate names) by target and host; the only index was
    ``(domain, id)``, so each read walked every discovery event of the target (34,000 rows on the largest one). Only the ``ptr`` and ``tls-san``
    events are indexed, a few hundred rows. Index only: no column, no data."""

    atomic = False

    dependencies = [('cveFeed', '0187_hostassess_proj_host_idx')]

    operations = [
        AddIndexConcurrently(model_name='discoveryevent', index=models.Index(
            fields=['domain', 'host'], name='discevent_dom_host_names_idx', condition=models.Q(module__in=['ptr', 'tls-san']))),
    ]
