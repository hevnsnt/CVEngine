import agentapi.models
from django.db import migrations, models


class Migration(migrations.Migration):

    # Numbered 0010 on 1.4-develop before develop's 0008 and 0009 (released in 1.3.x) were merged in: renumbered past them, and
    # ``replaces`` keeps a database that already applied it under the old name from applying it twice (see 0010_sentinel_enrollment_builtin).
    replaces = [("agentapi", "0010_sentinel_task_trace_id")]

    dependencies = [
        ("agentapi", "0011_sentinel_task_secret_ref"),
    ]

    operations = [
        migrations.AddField(
            model_name="sentineltask",
            name="trace_id",
            field=models.CharField(
                db_default="", default=agentapi.models.new_trace_id, max_length=32
            ),
        ),
    ]
