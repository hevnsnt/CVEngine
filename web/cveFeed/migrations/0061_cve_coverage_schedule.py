from django.db import migrations


def schedule_coverage(apps, schema_editor):
    """Read the cve.now entries the incremental sync never reached (see tasks.backfill_cve_now_feed). Hourly, and it does nothing
    without a single request once the stored feed reaches back CVENGINE_CVE_COVERAGE_DAYS days (set it to 0 to turn it off)."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=1, period='hours')
    PeriodicTask.objects.get_or_create(
        name='cvengine-cve-coverage',
        defaults={'task': 'backfill_cve_now_feed', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-cve-coverage').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0060_validation_request_authority'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_coverage, unschedule)]
