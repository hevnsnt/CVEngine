from django.db import migrations


def schedule_retention(apps, schema_editor):
    """Daily 04:17 UTC: delete the scans past their retention that no longer back a current inventory (tasks.prune_scan_history)."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='17', hour='4', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-scan-history-retention',
        defaults={'task': 'prune_scan_history', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-scan-history-retention').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0126_retest_episodes'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_retention, unschedule)]
