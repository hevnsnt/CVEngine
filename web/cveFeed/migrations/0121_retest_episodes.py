from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("cveFeed", "0120_hostmove")]

    operations = [
        migrations.RemoveConstraint(model_name="deferredretest", name="uniq_retest_evidence"),
        migrations.AddConstraint(
            model_name="deferredretest",
            constraint=models.UniqueConstraint(
                fields=("project", "host", "signature"),
                condition=models.Q(status__in=["pending", "dispatching", "queued", "running"]),
                name="uniq_retest_active_evidence",
            ),
        ),
        migrations.AddConstraint(
            model_name="deferredretest",
            constraint=models.UniqueConstraint(
                fields=("project", "host", "signature", "scan"), name="uniq_retest_scan_evidence",
            ),
        ),
    ]
