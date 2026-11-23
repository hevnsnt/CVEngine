from django.db import migrations, models


class Migration(migrations.Migration):
    """The daily rollup of the certificate transparency watch's lookups per source (``CtLookupDay``): one new, empty table of at most two
    rows a day, kept 30 days (cveFeed.ct_health)."""

    dependencies = [('cveFeed', '0190_autovacuum_busy_tables')]

    operations = [
        migrations.CreateModel(
            name='CtLookupDay',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('day', models.DateField()),
                ('source', models.CharField(max_length=20)),
                ('ok', models.PositiveIntegerField(db_default=0, default=0)),
                ('failed', models.PositiveIntegerField(db_default=0, default=0)),
                ('busy', models.PositiveIntegerField(db_default=0, default=0)),
                ('names', models.PositiveIntegerField(db_default=0, default=0)),
                ('new_hosts', models.PositiveIntegerField(db_default=0, default=0)),
                ('last_ok_at', models.DateTimeField(blank=True, null=True)),
                ('last_attempt_at', models.DateTimeField(blank=True, null=True)),
                ('last_failed_at', models.DateTimeField(blank=True, null=True)),
                ('last_error', models.CharField(blank=True, db_default='', default='', max_length=300)),
            ],
            options={
                'constraints': [models.UniqueConstraint(fields=('day', 'source'), name='ctlookupday_day_source_uniq')],
            },
        ),
    ]
