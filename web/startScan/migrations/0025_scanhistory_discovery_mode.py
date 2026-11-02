from django.db import migrations, models


# Records the bbot mode a discovery scan was queued in. Empty for every scan that exists already (and for any that is not a bbot discovery), which
# is read as "the target's own mode" when a lost queued scan is sent again. Reverse drops the column.
class Migration(migrations.Migration):

    dependencies = [
        ("startScan", "0024_ip_is_private_backfill"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanhistory",
            name="discovery_mode",
            field=models.CharField(blank=True, db_default="", default="", max_length=16),
        ),
    ]
