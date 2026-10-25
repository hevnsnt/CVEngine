from django.db import migrations


def schedule_reaper(apps, schema_editor):
    """Every 15 minutes: expire host assessments and validation jobs a lost worker left queued or running."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=15, period='minutes')
    PeriodicTask.objects.get_or_create(
        name='cvengine-reap-stuck-jobs',
        defaults={'task': 'reap_stuck_jobs', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-reap-stuck-jobs').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0063_weekly_maintenance'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_reaper, unschedule)]
