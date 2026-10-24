from django.db import migrations


def schedule(apps, schema_editor):
    """Refresh the nuclei templates every day (04:41 UTC)."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='41', hour='4', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-nuclei-templates',
        defaults={'task': 'update_nuclei_templates', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-nuclei-templates').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0015_hygiene_check_name'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
