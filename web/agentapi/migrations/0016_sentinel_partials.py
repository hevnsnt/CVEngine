import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    """The streamed task kind (bbot_discovery, contract version 3): the seq of the last partial batch a task's Sentinel posted, and the batches
    waiting for the stage that persists them. The new column has a database default, so code from before it keeps writing tasks during an update."""

    dependencies = [
        ("agentapi", "0015_merge_agent_hold"),
    ]

    operations = [
        migrations.AddField(
            model_name="sentineltask",
            name="partial_seq",
            field=models.PositiveIntegerField(db_default=0, default=0),
        ),
        migrations.CreateModel(
            name="SentinelPartial",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("seq", models.PositiveIntegerField()),
                ("body", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "task",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="partials", to="agentapi.sentineltask"
                    ),
                ),
            ],
            options={
                "ordering": ["task", "seq"],
                "constraints": [models.UniqueConstraint(fields=("task", "seq"), name="sentinelpartial_task_seq_uniq")],
            },
        ),
    ]
