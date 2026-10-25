from django.db import migrations, models


def schedule(apps, schema_editor):
    """Hourly: refresh the due threat-intelligence sources, reconcile, import missing CVEs (tasks.sync_threat_intel)."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=1, period='hours')
    PeriodicTask.objects.get_or_create(
        name='cvengine-threat-intel',
        defaults={'task': 'sync_threat_intel', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-threat-intel').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0067_hoststate_archived_by_user'), ('django_celery_beat', '0001_initial')]
    operations = [
        migrations.AddField(model_name='cveentry', name='intel', field=models.JSONField(blank=True, default=dict)),
        migrations.CreateModel(
            name='IntelSource',
            fields=[
                ('name', models.CharField(max_length=32, primary_key=True, serialize=False)),
                ('etag', models.CharField(blank=True, default='', max_length=200)),
                ('last_modified', models.CharField(blank=True, default='', max_length=100)),
                ('last_checked', models.DateTimeField(blank=True, null=True)),
                ('last_changed', models.DateTimeField(blank=True, null=True)),
                ('last_error', models.CharField(blank=True, default='', max_length=300)),
                ('cves', models.PositiveIntegerField(default=0)),
            ],
        ),
        migrations.RunPython(schedule, unschedule),
    ]
