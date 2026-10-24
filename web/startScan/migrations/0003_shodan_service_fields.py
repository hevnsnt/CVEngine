from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("startScan", "0002_auto_20240911_0145"),
    ]

    operations = [
        # IpAddress: host-level OS fingerprint (nmap -O)
        migrations.AddField("ipaddress", "os_guess", models.CharField(blank=True, default="", max_length=255)),
        migrations.AddField("ipaddress", "os_accuracy", models.IntegerField(blank=True, null=True)),
        migrations.AddField("ipaddress", "last_seen", models.DateTimeField(blank=True, null=True)),
        # Port: Shodan-style service enrichment + raw capture
        migrations.AddField("port", "protocol", models.CharField(blank=True, default="tcp", max_length=8)),
        migrations.AddField("port", "state", models.CharField(blank=True, default="open", max_length=16)),
        migrations.AddField("port", "product", models.CharField(blank=True, default="", max_length=255)),
        migrations.AddField("port", "version", models.CharField(blank=True, default="", max_length=100)),
        migrations.AddField("port", "service_extra", models.CharField(blank=True, default="", max_length=255)),
        migrations.AddField("port", "cpe", models.CharField(blank=True, default="", max_length=255)),
        migrations.AddField("port", "os_guess", models.CharField(blank=True, default="", max_length=255)),
        migrations.AddField("port", "banner", models.TextField(blank=True, default="")),
        migrations.AddField("port", "http", models.JSONField(blank=True, default=dict)),
        migrations.AddField("port", "tls", models.JSONField(blank=True, default=dict)),
        migrations.AddField("port", "extra", models.JSONField(blank=True, default=dict)),
        migrations.AddField("port", "source", models.CharField(blank=True, default="", max_length=32)),
        migrations.AddField("port", "last_seen", models.DateTimeField(blank=True, null=True)),
    ]
