from django.db import migrations


def schedule(apps, schema_editor):
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='38', hour='1', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(name='cvengine-bucket-sweep', defaults={
        'task': 'bucket_sweep', 'crontab': crontab, 'enabled': True, 'queue': 'bucketscan_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-bucket-sweep').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0094_testssl_schedule'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule, unschedule)]
