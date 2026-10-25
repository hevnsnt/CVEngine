from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0071_rdpscreenshot')]
    operations = [
        migrations.AddField('triage', 'local_checks', models.JSONField(default=dict, blank=True)),
    ]
