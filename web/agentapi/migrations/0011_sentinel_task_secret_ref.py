from django.db import migrations, models


class Migration(migrations.Migration):

    # Numbered 0009 on 1.4-develop before develop's 0008 and 0009 (released in 1.3.x) were merged in: renumbered past them, and
    # ``replaces`` keeps a database that already applied it under the old name from applying it twice (see 0010_sentinel_enrollment_builtin).
    replaces = [("agentapi", "0009_sentinel_task_secret_ref")]

    dependencies = [
        ("agentapi", "0010_sentinel_enrollment_builtin"),
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
