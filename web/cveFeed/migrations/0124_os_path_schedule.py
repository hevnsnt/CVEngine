from django.db import migrations


def schedule(apps, schema_editor):
    """Measure the scanning path once a day (tasks.check_os_path): does it lose nmap's malformed OS-detection probes (issue 214)?"""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=24, period='hours')
    PeriodicTask.objects.get_or_create(
        name='cvengine-os-path-check',
        defaults={'task': 'check_os_path', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-os-path-check').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0123_recheck_routes'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
