from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("agentapi", "0002_sentinels")]
    operations = [
        migrations.AddField("agent", "managed_settings", models.JSONField(blank=True, default=dict)),
        migrations.AddField("agent", "reported_settings", models.JSONField(blank=True, default=dict)),
    ]
