from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("targetApp", "0008_domain_expect_private_ca"),
    ]

    operations = [
        migrations.AddField(
            model_name="domain",
            name="display_name",
            field=models.CharField(blank=True, db_default="", default="", max_length=253),
        ),
        migrations.AddField(
            model_name="domain",
            name="display_name_source",
            field=models.CharField(blank=True, db_default="", default="", max_length=10),
        ),
        migrations.AddField(
            model_name="domain",
            name="display_name_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="domain",
            name="printer",
            field=models.BooleanField(db_default=False, default=False),
        ),
        migrations.AddField(
            model_name="domain",
            name="printer_evidence",
            field=models.CharField(blank=True, db_default="", default="", max_length=300),
        ),
    ]
