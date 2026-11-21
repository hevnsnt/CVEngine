from django.db import migrations


def schedule_sync(apps, schema_editor):
    """Every 6 hours: read Cloudflare Radar's Zero Wire feed (cveFeed.tasks.sync_zero_wire). It does nothing while an App Admin has the switch off."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=6, period='hours')
    PeriodicTask.objects.get_or_create(
        name='cvengine-zero-wire', defaults={'task': 'sync_zero_wire', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-zero-wire').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0182_zero_wire'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_sync, unschedule)]
