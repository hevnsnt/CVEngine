from django.db import migrations, models


class Migration(migrations.Migration):
    """The first-run wizard's server-side state (one row): which steps are done or skipped, and when it was completed."""

    dependencies = [
        ("dashboard", "0031_ai_provider_request_settings"),
    ]

    operations = [
        migrations.CreateModel(
            name="SetupWizard",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("completed_by", models.CharField(blank=True, default="", max_length=150)),
                ("data", models.JSONField(blank=True, default=dict)),
            ],
        ),
    ]
