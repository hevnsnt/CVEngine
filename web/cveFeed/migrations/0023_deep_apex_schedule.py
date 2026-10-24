from django.db import migrations


def schedule_deep_apex_sweep(apps, schema_editor):
    """Once a day, queue a deep discovery of every apex domain that has not had one in the last week."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='43', hour='2', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-deep-apex-sweep',
        defaults={'task': 'deep_scan_apexes', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-deep-apex-sweep').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0022_autofire_host_cap'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_deep_apex_sweep, unschedule)]
