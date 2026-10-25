from django.db import migrations


def schedule_snapshot(apps, schema_editor):
    """Daily 02:11 UTC: store a point-in-time stats snapshot per project (cveFeed.tasks.snapshot_daily_stats)."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='11', hour='2', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-snapshot-daily-stats',
        defaults={'task': 'snapshot_daily_stats', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-snapshot-daily-stats').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0075_statssnapshot'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_snapshot, unschedule)]
