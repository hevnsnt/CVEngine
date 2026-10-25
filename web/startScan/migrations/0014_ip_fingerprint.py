from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('startScan', '0013_ip_full_scan_backoff')]
    operations = [
        migrations.AddField(model_name='ipaddress', name='fingerprint', field=models.JSONField(blank=True, default=dict)),
    ]
