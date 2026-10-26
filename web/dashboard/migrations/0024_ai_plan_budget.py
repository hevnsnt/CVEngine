from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0023_end_plaintext_sessions')]
    operations = [
        migrations.AddField(model_name='aiprovidersettings', name='plan_daily_total', field=models.PositiveIntegerField(default=200)),
        migrations.AddField(model_name='aiprovidersettings', name='plan_daily_per_project', field=models.PositiveIntegerField(default=20)),
    ]
