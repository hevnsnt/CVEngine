from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """One index, built CONCURRENTLY outside a transaction like 0174, so an update never blocks the writes to ``HostAssessment``. The first pass
    backlog (``coverage_topup.host_coverage_due``, every minute for each project a Sentinel covers) asks, per host, for an assessment of it in the
    last day, and ``HostAssessment.host`` had no index, so each host read the project's assessment history through a bitmap scan. Index only: no
    column, no data."""

    atomic = False

    dependencies = [('cveFeed', '0186_aiusage_time_stage_idx')]

    operations = [
        AddIndexConcurrently(model_name='hostassessment', index=models.Index(fields=['project', 'host', 'created_at'], name='hostassess_proj_host_idx')),
    ]
