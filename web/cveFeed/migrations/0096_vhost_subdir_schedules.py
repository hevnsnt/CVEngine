from django.db import migrations

TASKS = (('cvengine-vhost-sweep', 'vhost_sweep', {'minute': '27', 'hour': '*'}),
         ('cvengine-subdir-apps-sweep', 'subdir_apps_sweep', {'minute': '13,43', 'hour': '*'}))


def schedule(apps, schema_editor):
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    for name, task, when in TASKS:
        crontab, _ = Crontab.objects.get_or_create(day_of_week='*', day_of_month='*', month_of_year='*', **when)
        PeriodicTask.objects.get_or_create(name=name, defaults={'task': task, 'crontab': crontab, 'enabled': True, 'queue': 'vhost_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name__in=[name for name, _task, _when in TASKS]).delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0095_bucket_sweep_schedule'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
