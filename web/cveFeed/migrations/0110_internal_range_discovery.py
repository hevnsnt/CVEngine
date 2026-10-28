from django.db import migrations, models


def schedule_internal_discovery_sweep(apps, schema_editor):
    """Once a day, queue a host discovery of every declared internal range not swept inside the cadence (cveFeed.internal_discovery)."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='41', hour='2', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-internal-discovery-sweep',
        defaults={'task': 'internal_discovery_sweep', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-internal-discovery-sweep').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0109_internal_scan_schedule'), ('django_celery_beat', '0001_initial')]
    operations = [
        migrations.AddField('internalrange', 'last_discovery_at', models.DateTimeField(blank=True, null=True)),
        migrations.AddField('internalrange', 'last_discovery_hosts', models.PositiveIntegerField(blank=True, null=True)),
        migrations.AddField('internalrange', 'last_discovery_error', models.CharField(blank=True, default='', max_length=200)),
        migrations.AddField('internalrange', 'discovery_cursor', models.PositiveIntegerField(default=0)),
        migrations.RunPython(schedule_internal_discovery_sweep, unschedule),
    ]
