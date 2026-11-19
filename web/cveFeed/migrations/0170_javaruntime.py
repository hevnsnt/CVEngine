"""The Java runtime readings of a host (cveFeed.java_runtime): one new table, nothing backfilled here. The readings that need no request (a JDWP
port the fingerprint pass identified, a header the scans stored, the bundled runtime of a product version) are made by the upgrade backfill
``backfill_java_runtimes`` after the update, and the active reads are planned for the existing Java hosts by the work planner."""

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0169_generated_template_review"),
        ("dashboard", "0036_scan_policy_credential_checks"),
        ("targetApp", "0008_domain_expect_private_ca"),
    ]

    operations = [
        migrations.CreateModel(
            name="JavaRuntime",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("host", models.CharField(max_length=500)),
                ("key", models.CharField(max_length=200)),
                ("version", models.CharField(blank=True, default="", max_length=40)),
                ("major", models.IntegerField(default=0)),
                ("vendor", models.CharField(blank=True, default="unknown", max_length=40)),
                ("runtime", models.CharField(blank=True, default="", max_length=200)),
                ("build", models.CharField(blank=True, default="", max_length=60)),
                ("line_only", models.BooleanField(default=False)),
                ("source", models.CharField(max_length=24)),
                ("confidence", models.CharField(default="exact", max_length=12)),
                ("port", models.IntegerField(default=0)),
                ("url", models.CharField(blank=True, default="", max_length=300)),
                ("evidence", models.TextField(blank=True, default="")),
                ("detail", models.JSONField(blank=True, default=dict)),
                ("first_seen", models.DateTimeField(default=django.utils.timezone.now)),
                ("last_seen", models.DateTimeField(default=django.utils.timezone.now)),
                ("domain", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+", to="targetApp.domain")),
                ("project", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+", to="dashboard.project")),
            ],
            options={
                "indexes": [models.Index(fields=["project", "host"], name="javaruntime_proj_host_idx"),
                            models.Index(fields=["project", "major"], name="javaruntime_proj_major_idx")],
                "constraints": [models.UniqueConstraint(fields=("project", "host", "key"), name="uniq_javaruntime_project_host_key")],
            },
        ),
    ]
