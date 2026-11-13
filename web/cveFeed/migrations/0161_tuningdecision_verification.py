"""1.4.0 maintainer: a tuning decision records what it expected to improve, the measurements before it and, after a settling time, how it turned
out (``cveFeed.autotune`` ``verify_pending``). Six columns on ``TuningDecision``, each with a database default (the code of the previous release keeps
inserting rows during an update); catalog-only on PostgreSQL 11 and later, nothing is backfilled (an older decision reads as not judged)."""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0160_fix_retest'),
    ]

    operations = [
        migrations.AddField(model_name='tuningdecision', name='expected',
                            field=models.CharField(blank=True, db_default='', default='', max_length=32)),
        migrations.AddField(model_name='tuningdecision', name='baseline',
                            field=models.JSONField(blank=True, db_default=models.Value({}, output_field=models.JSONField()), default=dict)),
        migrations.AddField(model_name='tuningdecision', name='verify_at', field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name='tuningdecision', name='verified_at', field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name='tuningdecision', name='outcome',
                            field=models.CharField(blank=True, db_default='', default='', max_length=12)),
        migrations.AddField(model_name='tuningdecision', name='outcome_detail',
                            field=models.CharField(blank=True, db_default='', default='', max_length=300)),
    ]
