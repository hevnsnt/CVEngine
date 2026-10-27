from django.db import migrations


def schedule(apps, schema_editor):
    """Every 5 minutes: top up host-assessment coverage directly, no model call (see cveFeed.coverage_topup)."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=5, period='minutes')
    PeriodicTask.objects.get_or_create(name='cvengine-host-assessment-topup', defaults={
        'task': 'top_up_host_assessments', 'interval': interval, 'enabled': True, 'queue': 'discovery_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-host-assessment-topup').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0103_supplier_schedule'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
