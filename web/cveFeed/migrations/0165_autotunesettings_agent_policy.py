"""1.4.0 maintainer: what an agent may do to a throughput setting (``cveFeed.autotune.agent_change``): off, suggest (the default) or auto. One column on
``AutoTuneSettings`` with a database default (the code of the previous release keeps working during an update); catalog-only, nothing is backfilled."""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0164_host_review'),
    ]

    operations = [
        migrations.AddField(model_name='autotunesettings', name='agent_policy',
                            field=models.CharField(db_default='suggest', default='suggest', max_length=10)),
    ]
