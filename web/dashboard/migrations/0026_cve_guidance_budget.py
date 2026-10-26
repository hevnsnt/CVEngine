from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0025_scan_policy')]
    operations = [
        migrations.AddField(model_name='aiprovidersettings', name='cve_guidance_daily', field=models.PositiveIntegerField(default=25)),
    ]
