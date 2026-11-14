from django.db import migrations


def schedule(apps, schema_editor):
    """The AI reviewer's two server-side schedules (docs/AI-REVIEWER.md): keep its token written (every 5 minutes) and run the operations
    checks that raise and resolve the admin alerts (every 30 minutes). Neither calls an AI."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    every_five, _ = Interval.objects.get_or_create(every=5, period='minutes')
    every_thirty, _ = Interval.objects.get_or_create(every=30, period='minutes')
    PeriodicTask.objects.get_or_create(
        name='cvengine-ensure-reviewer-token',
        defaults={'task': 'ensure_reviewer_token', 'interval': every_five, 'enabled': True, 'queue': 'cve_feed_queue'})
    PeriodicTask.objects.get_or_create(
        name='cvengine-reviewer-ops-checks',
        defaults={'task': 'reviewer_ops_checks', 'interval': every_thirty, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(
        name__in=('cvengine-ensure-reviewer-token', 'cvengine-reviewer-ops-checks')).delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0144_reviewer'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
