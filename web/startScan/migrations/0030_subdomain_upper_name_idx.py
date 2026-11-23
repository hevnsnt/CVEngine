from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models
from django.db.models.functions import Upper


class Migration(migrations.Migration):
    """An index of the host names in upper case, for the lookups that match a name without case (``name__iexact`` compiles to ``UPPER(name)``):
    the archive and gone closures (cveFeed.archive_closure), the names archived with a host and a host's group of names (agentapi.host_manage).
    Each of them read every host row of the table: on 31,000 rows that is 47 ms a lookup, and a closure's read of its CVE matches went from 29 ms
    to about 1 ms once the host rows came from an index. Built CONCURRENTLY, outside a transaction like 0026, so an update does not lock the
    table scans write their hosts to. Index only: no column, no data."""

    atomic = False

    dependencies = [
        ('startScan', '0029_scan_done_indexes'),
    ]

    operations = [
        AddIndexConcurrently(
            model_name='subdomain',
            index=models.Index(Upper('name'), name='sub_upper_name_idx'),
        ),
    ]
