from django.db import migrations


def schedule_internal_scan_sweep(apps, schema_editor):
    """Once a day, queue a scan of every declared-internal target not scanned inside the cadence (cveFeed.internal_scan)."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='17', hour='3', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-internal-scan-sweep',
        defaults={'task': 'internal_scan_sweep', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-internal-scan-sweep').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0108_internal_range'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_internal_scan_sweep, unschedule)]
