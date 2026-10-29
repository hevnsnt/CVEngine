from django.db import migrations


def schedule_evaluation(apps, schema_editor):
    """Every 10 minutes: evaluate the saved searches that are due (cveFeed.tasks.evaluate_saved_searches); each search has its own
    frequency, so this is only how often beat looks."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=10, period='minutes')
    PeriodicTask.objects.get_or_create(
        name='cvengine-saved-searches',
        defaults={'task': 'evaluate_saved_searches', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-saved-searches').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0085_saved_search'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_evaluation, unschedule)]
