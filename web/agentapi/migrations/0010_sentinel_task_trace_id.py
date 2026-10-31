import agentapi.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agentapi", "0009_sentinel_task_secret_ref"),
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
