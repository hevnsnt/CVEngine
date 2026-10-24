from django.db import migrations


def schedule_rescore(apps, schema_editor):
    """Once a day, rescore every host so "new this week" decays and CVE feed updates land."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='29', hour='5', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-rescore-daily',
        defaults={'task': 'rescore_all_hosts', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-rescore-daily').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0028_hoststate_score'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_rescore, unschedule)]
