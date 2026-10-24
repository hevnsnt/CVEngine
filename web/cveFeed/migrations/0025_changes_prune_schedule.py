from django.db import migrations


def schedule_prune(apps, schema_editor):
    """Once a day, drop asset changes older than the retention period."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='11', hour='4', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-changes-prune',
        defaults={'task': 'prune_asset_changes', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-changes-prune').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0024_asset_changes'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_prune, unschedule)]
