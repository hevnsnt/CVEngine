from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="CVEEntry",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("cve_id", models.CharField(db_index=True, max_length=64, unique=True)),
                ("title", models.TextField(blank=True, default="")),
                ("summary", models.TextField(blank=True, default="")),
                ("summary_model", models.CharField(blank=True, default="", max_length=128)),
                ("original_description", models.TextField(blank=True, default="")),
                ("cvss", models.FloatField(blank=True, null=True)),
                ("cvss_vector", models.CharField(blank=True, default="", max_length=128)),
                ("severity_source", models.CharField(blank=True, default="", max_length=32)),
                ("stated_severity", models.CharField(blank=True, default="", max_length=32)),
                ("kev", models.BooleanField(blank=True, null=True)),
                ("epss_reached", models.BooleanField(blank=True, null=True)),
                ("exploit_db", models.BooleanField(blank=True, null=True)),
                ("affected", models.JSONField(blank=True, default=list)),
                ("references", models.JSONField(blank=True, default=list)),
                ("sources", models.JSONField(blank=True, default=list)),
                ("status", models.CharField(blank=True, default="", max_length=32)),
                ("published_at", models.DateTimeField(blank=True, null=True)),
                ("first_seen_at", models.DateTimeField(blank=True, null=True)),
                ("raw", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("synced_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "CVE entry",
                "verbose_name_plural": "CVE entries",
                "ordering": ["-published_at", "-first_seen_at"],
            },
        ),
        migrations.AddIndex(
            model_name="cveentry",
            index=models.Index(fields=["kev"], name="cvefeed_kev_idx"),
        ),
        migrations.AddIndex(
            model_name="cveentry",
            index=models.Index(fields=["cvss"], name="cvefeed_cvss_idx"),
        ),
        migrations.AddIndex(
            model_name="cveentry",
            index=models.Index(fields=["published_at"], name="cvefeed_pub_idx"),
        ),
    ]
