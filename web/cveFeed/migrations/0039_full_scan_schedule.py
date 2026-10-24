import os

from django.db import migrations

NAME = 'cvengine-background-full-scan'


def schedule(apps, schema_editor):
    """Every CVENGINE_FULLSCAN_INTERVAL_MIN minutes (default 10): one firing of the background full port scan, which sweeps one IP."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    try:
        every = max(1, int(os.environ.get('CVENGINE_FULLSCAN_INTERVAL_MIN', '10')))
    except ValueError:
        every = 10
    interval, _ = Interval.objects.get_or_create(every=every, period='minutes')
    PeriodicTask.objects.get_or_create(
        name=NAME, defaults={'task': 'background_full_scan', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name=NAME).delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0038_triage_schedule'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
