from django.db import migrations


def schedule(apps, schema_editor):
    """Publish the worker container's memory picture every 30 seconds."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=30, period='seconds')
    PeriodicTask.objects.get_or_create(
        name='cvengine-report-resources',
        defaults={'task': 'report_resources', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-report-resources').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0016_nuclei_template_update_schedule'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
