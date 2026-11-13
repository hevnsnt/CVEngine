from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """The index behind ``reviewer.same_evidence_prior``: the AI reviewer asks, before it closes a finding, how the same evidence (kind and evidence key) was
    judged on other hosts of the project. Without it the question reads every triage row of the project. Built CONCURRENTLY outside a transaction, like 0159,
    so an upgrade never blocks the scans that write this table. Index only: no column, no data."""

    atomic = False

    dependencies = [('cveFeed', '0164_host_review')]

    operations = [
        AddIndexConcurrently(
            model_name='triage',
            index=models.Index(fields=['project', 'kind', 'evidence_key'], name='triage_proj_kind_evkey_idx'),
        ),
    ]
