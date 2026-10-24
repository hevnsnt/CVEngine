from django.db import migrations


def schedule_ct_watch(apps, schema_editor):
    """Every target is "subscribed" to certificate-transparency monitoring: re-check all of them on an interval."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=20, period='minutes')
    PeriodicTask.objects.get_or_create(
        name='cvengine-ct-watch',
        defaults={'task': 'watch_certificates_all', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-ct-watch').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0012_discoveryevent_cvefeed_dis_domain__343778_idx'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_ct_watch, unschedule)]
