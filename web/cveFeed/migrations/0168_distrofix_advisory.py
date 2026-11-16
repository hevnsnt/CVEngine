"""Red Hat distribution data: the advisory that shipped a fix (RHSA-2024:4720), kept on ``DistroFix`` so a match can name it. One column
with a database default (the code of the previous release keeps working during an update); nothing is backfilled."""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0167_autotunesettings_agent_policy'),
    ]

    operations = [
        migrations.AddField(model_name='distrofix', name='advisory',
                            field=models.CharField(blank=True, db_default='', default='', max_length=32)),
    ]
