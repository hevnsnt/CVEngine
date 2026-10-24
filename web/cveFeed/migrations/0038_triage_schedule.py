from django.db import migrations

TASKS = (
    # name, task, hour, minute: the daily triage sweep (findings queued over a cap, provider errors) and the validation sweep after it
    ('cvengine-triage-sweep', 'triage_sweep', '4', '41'),
    ('cvengine-validate-sweep', 'validate_sweep', '5', '17'),
)


def schedule(apps, schema_editor):
    """Once a day: triage what still waits and queue the validation checks that are due."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    for name, task, hour, minute in TASKS:
        crontab, _ = Crontab.objects.get_or_create(minute=minute, hour=hour, day_of_week='*', day_of_month='*', month_of_year='*')
        PeriodicTask.objects.get_or_create(name=name, defaults={'task': task, 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name__in=[t[0] for t in TASKS]).delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0037_triage'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
