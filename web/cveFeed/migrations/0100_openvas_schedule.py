from django.db import migrations


def schedule(apps, schema_editor):
    """The sweep is created switched OFF: the OpenVAS add-on is optional, and the App Admin's switch (Settings > OpenVAS) is what turns this
    beat entry on (cveFeed.openvas_admin). A fresh install therefore has no OpenVAS work scheduled."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=15, period='minutes')
    PeriodicTask.objects.get_or_create(name='cvengine-openvas-sweep', defaults={
        'task': 'openvas_sweep', 'interval': interval, 'enabled': False, 'queue': 'openvas_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-openvas-sweep').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0099_openvas'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
