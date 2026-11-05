from django.db import migrations, models


class Migration(migrations.Migration):
    """``SentinelDefaults.external_kinds`` (0014) was added NOT NULL with no database default, so the code still running between the migration and
    the restart could not create the row. The upgrade rehearsal refuses that. Catalog-only in PostgreSQL: no rewrite, nothing backfilled."""

    dependencies = [
        ("agentapi", "0015_merge_agent_hold"),
    ]

    operations = [
        migrations.AlterField(
            model_name="sentineldefaults",
            name="external_kinds",
            field=models.JSONField(blank=True, db_default={}, default=dict),
        ),
    ]
