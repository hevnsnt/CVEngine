from django.db import migrations


def schedule(apps, schema_editor):
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='41', hour='*', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(name='cvengine-screenshot-backfill', defaults={
        'task': 'screenshot_backfill', 'crontab': crontab, 'enabled': True, 'queue': 'screenshot_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-screenshot-backfill').delete()


class Migration(migrations.Migration):
    dependencies = [("cveFeed", "0132_hostscreenshot"), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
