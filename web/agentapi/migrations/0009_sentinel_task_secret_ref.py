from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agentapi", "0008_sentinel_enrollment_builtin"),
    ]

    operations = [
        migrations.AddField(
            model_name="sentineltask",
            name="secret_read_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="sentineltask",
            name="secret_ref",
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
    ]
