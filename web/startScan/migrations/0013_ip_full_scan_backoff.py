from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('startScan', '0012_ip_full_scan_started')]
    operations = [
        migrations.AddField(model_name='ipaddress', name='full_scan_failures', field=models.PositiveSmallIntegerField(default=0)),
        migrations.AddField(model_name='ipaddress', name='full_scan_retry_at',
                            field=models.DateTimeField(blank=True, db_index=True, null=True)),
    ]
