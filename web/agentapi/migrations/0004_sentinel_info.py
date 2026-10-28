from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("agentapi", "0003_sentinel_settings")]
    operations = [
        migrations.AddField("agent", "info", models.JSONField(blank=True, default=dict)),
        migrations.AddField("agent", "update_requested_at", models.DateTimeField(blank=True, null=True)),
    ]
