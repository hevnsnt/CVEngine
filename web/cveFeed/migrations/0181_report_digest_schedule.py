from django.db import migrations


def schedule_digests(apps, schema_editor):
    """Every 15 minutes: send the email reports whose time has come (cveFeed.tasks.send_report_digests); each report has its own weekday and time,
    so this is only how often beat looks. It sends nothing until someone creates an email report and outgoing mail is set up."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=15, period='minutes')
    PeriodicTask.objects.get_or_create(
        name='cvengine-report-digests',
        defaults={'task': 'send_report_digests', 'interval': interval, 'enabled': True, 'queue': 'report_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-report-digests').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0180_report_subscription'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_digests, unschedule)]
