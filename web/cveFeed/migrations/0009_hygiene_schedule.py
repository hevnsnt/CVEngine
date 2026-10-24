from django.db import migrations


def schedule_daily_hygiene(apps, schema_editor):
    """Sweep every target for expiring certificates and weak TLS or email authentication once a day."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='17', hour='3', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-hygiene-daily',
        defaults={'task': 'run_hygiene_all', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-hygiene-daily').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0008_hygiene'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_daily_hygiene, unschedule)]
