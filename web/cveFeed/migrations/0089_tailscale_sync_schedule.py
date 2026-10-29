from django.db import migrations


def schedule(apps, schema_editor):
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=15, period='minutes')
    PeriodicTask.objects.get_or_create(name='cvengine-tailscale-sync', defaults={
        'task': 'sync_tailscale', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-tailscale-sync').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0088_tailscale'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
