import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0001_initial"),
        ("startScan", "0002_auto_20240911_0145"),
    ]

    operations = [
        migrations.CreateModel(
            name="CVEMatch",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("matched_product", models.CharField(blank=True, default="", max_length=255)),
                ("matched_version", models.CharField(blank=True, default="", max_length=100)),
                ("version_in_range", models.BooleanField(blank=True, null=True)),
                ("confidence", models.FloatField(default=0.0)),
                ("source", models.CharField(default="tech", max_length=16)),
                ("ai_verdict", models.CharField(blank=True, default="", max_length=16)),
                ("ai_reason", models.TextField(blank=True, default="")),
                ("ai_model", models.CharField(blank=True, default="", max_length=128)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("cve_entry", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="matches", to="cveFeed.cveentry")),
                ("scan_history", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="cve_matches", to="startScan.scanhistory")),
                ("subdomain", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="cve_matches", to="startScan.subdomain")),
            ],
            options={
                "verbose_name": "CVE match",
                "verbose_name_plural": "CVE matches",
                "ordering": ["-confidence", "-created_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="cvematch",
            constraint=models.UniqueConstraint(
                fields=("cve_entry", "subdomain", "source", "matched_product"),
                name="uniq_cvematch_asset_source_product",
            ),
        ),
    ]
