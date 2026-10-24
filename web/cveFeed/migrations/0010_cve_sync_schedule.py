from django.db import migrations


def schedule_cve_sync(apps, schema_editor):
    """The cve.now feed is read on a schedule (the App Admin can change the interval under Timings)."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=30, period='minutes')
    PeriodicTask.objects.get_or_create(
        name='cvengine-cve-sync',
        defaults={'task': 'sync_cve_now_feed', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-cve-sync').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0009_hygiene_schedule'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_cve_sync, unschedule)]
