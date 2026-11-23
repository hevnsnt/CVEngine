from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """Two small partial indexes on the scans, for the current inventory (cveFeed.current_scans, read by correlation.latest_scan_q in every host,
    match, finding and count statement): the finished full scans and the finished host-pipeline scans, each by domain and id. Reading the scan ids
    the inventory needs takes an index only scan of each (about 35 buffers) instead of a seq scan of the scan table. Built CONCURRENTLY, outside a
    transaction like 0026, so an update does not lock the table scans write. Index only: no column, no data."""

    atomic = False

    dependencies = [
        ('startScan', '0028_subdomain_technology_source'),
    ]

    operations = [
        AddIndexConcurrently(
            model_name='scanhistory',
            index=models.Index(fields=['domain', 'id'], name='scan_done_full_idx',
                               condition=models.Q(('scan_status', 2), models.Q(('tasks__contains', ['host_pipeline']), _negated=True))),
        ),
        AddIndexConcurrently(
            model_name='scanhistory',
            index=models.Index(fields=['domain', 'id'], name='scan_done_pipe_idx',
                               condition=models.Q(('scan_status', 2), ('tasks__contains', ['host_pipeline']))),
        ),
    ]
