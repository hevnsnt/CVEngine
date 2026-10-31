from django.db import migrations


def schedule(apps, schema_editor):
    """Keep the built-in scanner's enrollment ready (ensure_builtin_scanner, every 5 minutes). The task does nothing unless CVENGINE_BUILTIN_SCANNER is on."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    every_five, _ = Interval.objects.get_or_create(every=5, period='minutes')
    PeriodicTask.objects.get_or_create(
        name='cvengine-ensure-builtin-scanner',
        defaults={'task': 'ensure_builtin_scanner', 'interval': every_five, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-ensure-builtin-scanner').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0128_updatesettings_reference_unknown_db_default'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
