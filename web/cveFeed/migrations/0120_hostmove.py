import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0119_smtp_settings"),
        ("dashboard", "0030_nuclei_all_templates_on_by_default"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="HostMove",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("host", models.CharField(max_length=500)),
                ("moved_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("moved_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
                ("moved_to", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to="dashboard.project")),
                ("project", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+", to="dashboard.project")),
            ],
            options={
                "constraints": [models.UniqueConstraint(fields=("project", "host"), name="uniq_hostmove_project_host")],
            },
        ),
    ]
