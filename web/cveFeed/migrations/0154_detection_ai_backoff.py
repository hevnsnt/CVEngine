from django.db import migrations, models


class Migration(migrations.Migration):
    """A failed model ask for a CVE's detection record is retried with a growing wait and then stops (cveFeed.detection_author.AI_BACKOFF)."""

    dependencies = [('cveFeed', '0153_excluded_address')]

    operations = [
        migrations.AddField(model_name='cvedetection', name='ai_failures', field=models.PositiveSmallIntegerField(default=0, db_default=0)),
        migrations.AddField(model_name='cvedetection', name='ai_retry_at', field=models.DateTimeField(blank=True, null=True)),
    ]
