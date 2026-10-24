from django.db import migrations


def schedule(apps, schema_editor):
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=5, period='minutes')
    PeriodicTask.objects.get_or_create(
        name='cvengine-retest-sweep',
        defaults={'task': 'retest_sweep', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'},
    )


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-retest-sweep').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0046_hot_validation'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
