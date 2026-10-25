from django.db import migrations


def schedule(apps, schema_editor):
    """Keep the bug bounty catalogue current, hourly. The task does nothing until the catalogue has been loaded once from the page
    (see tasks.sync_bounty_catalogue), and costs one conditional request per platform when nothing changed."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=1, period='hours')
    PeriodicTask.objects.get_or_create(
        name='cvengine-bounty-catalogue',
        defaults={'task': 'sync_bounty_catalogue', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-bounty-catalogue').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0062_bug_bounty'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
