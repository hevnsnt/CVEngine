from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('startScan', '0011_shorten_bbot_names')]
    operations = [
        migrations.AddField(
            model_name='ipaddress',
            name='full_scan_started_at',
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
    ]
