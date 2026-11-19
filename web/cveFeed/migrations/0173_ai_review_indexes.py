from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """Four indexes, built CONCURRENTLY outside a transaction like 0165, so an update never blocks the scans and validations that write these
    tables. Index only: no column, no data.

    * ``triage_status_updated_idx``: the hourly triage sweep reads the waiting rows oldest first, and the triage backlog signal reads the oldest one;
    * ``triage_proj_status_seen_idx``: ``list_triage?status=pending`` reads a project's rows of one status newest first, a page at a time, in index
      order (it joined and sorted every row of the status before: on a project with 8,000 pending rows the call timed out);
    * ``ondemand_ai_job_idx`` and ``autoval_ai_job_idx``: the validation records a triage answer updates (``triage.settle_validations``)."""

    atomic = False

    dependencies = [('cveFeed', '0172_ai_review_coverage')]

    operations = [
        AddIndexConcurrently(model_name='triage', index=models.Index(fields=['status', 'updated_at'], name='triage_status_updated_idx')),
        AddIndexConcurrently(model_name='triage',
                             index=models.Index(fields=['project', 'status', 'last_seen', 'id'], name='triage_proj_status_seen_idx')),
        AddIndexConcurrently(model_name='ondemandvalidation', index=models.Index(fields=['ai_job_id'], name='ondemand_ai_job_idx')),
        AddIndexConcurrently(model_name='automaticvalidation', index=models.Index(fields=['ai_job_id'], name='autoval_ai_job_idx')),
    ]
