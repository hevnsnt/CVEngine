from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models
from django.db.models.functions import Lower


class Migration(migrations.Migration):
    """An index of the host names in lower case, for the lookups that match ``LOWER(name)`` within a project: ``cveFeed.manual_only``
    (``other_holder`` and ``only_manual_hosts``, asked for every host a sweep considers, about 29,000 times in two hours on a live install) and the
    network detection and nuclei service lookups. Without it the planner walked the host table by id from the newest row until it found the name,
    or read it to the end when the name was not there: 29,500 buffers and 40 ms on 32,000 hosts for a name the project does not hold, 13.8 ms on
    average. With the name reached by an expression index it is a few buffers and under 0.2 ms (measured on the live table with the equivalent
    ``sub_upper_name_idx`` of 0030). Built CONCURRENTLY, outside a transaction like 0030, so an update does not lock the table scans write their
    hosts to. Index only: no column, no data."""

    atomic = False

    dependencies = [
        ('startScan', '0035_uniq_cweid_name'),
    ]

    operations = [
        AddIndexConcurrently(
            model_name='subdomain',
            index=models.Index(Lower('name'), name='sub_lower_name_idx'),
        ),
    ]
