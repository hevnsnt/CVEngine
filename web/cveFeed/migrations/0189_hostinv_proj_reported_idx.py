from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """One index, built CONCURRENTLY outside a transaction like 0174, so an update never blocks the host reports agents send. The list of a
    project's host reports is ordered newest first (``reported_at`` then ``id``, both descending); the only index was ``(project, host)``, so
    every page sorted all of the project's reports. Index only: no column, no data."""

    atomic = False

    dependencies = [('cveFeed', '0188_discevent_host_names_idx')]

    operations = [
        AddIndexConcurrently(model_name='hostinventory', index=models.Index(fields=['project', '-reported_at', '-id'], name='hostinv_proj_reported_idx')),
    ]
