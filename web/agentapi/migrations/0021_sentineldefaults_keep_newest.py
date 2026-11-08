from django.db import migrations, models


class Migration(migrations.Migration):
    """``SentinelDefaults.keep_newest``: the instance switch \"Keep Sentinels on the newest version\" (on by default). A db_default, so the code still running
    during an update inserts rows without it."""

    dependencies = [
        ('agentapi', '0020_sentineltask_history_indexes'),
    ]

    operations = [
        migrations.AddField(
            model_name='sentineldefaults',
            name='keep_newest',
            field=models.BooleanField(default=True, db_default=True),
        ),
    ]
