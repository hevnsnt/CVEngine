from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("agentapi", "0004_sentinel_info")]
    operations = [
        migrations.CreateModel(
            name="SentinelDefaults",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("self_update", models.CharField(blank=True, default="", max_length=10)),
                ("changed_by", models.CharField(blank=True, default="", max_length=150)),
                ("changed_at", models.DateTimeField(blank=True, null=True)),
            ],
        ),
    ]
