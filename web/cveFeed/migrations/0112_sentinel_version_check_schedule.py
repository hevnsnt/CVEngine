from django.db import migrations


def schedule(apps, schema_editor):
    """Ask GitHub for the latest Sentinel client version every six hours (the Sentinels page shows whether each Sentinel is current), and keep the
    Sentinels fed (feed_sentinels, every minute)."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='41', hour='*/6', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-sentinel-version-check',
        defaults={'task': 'refresh_sentinel_version', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    every_minute, _ = Interval.objects.get_or_create(every=1, period='minutes')
    PeriodicTask.objects.get_or_create(
        name='cvengine-feed-sentinels',
        defaults={'task': 'feed_sentinels', 'interval': every_minute, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name__in=('cvengine-sentinel-version-check', 'cvengine-feed-sentinels')).delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0111_openvas_forced_hosts'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
