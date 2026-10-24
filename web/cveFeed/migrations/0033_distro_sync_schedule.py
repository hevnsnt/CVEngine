from django.db import migrations


def schedule_distro_sync(apps, schema_editor):
    """Once a day, refresh what Ubuntu and Debian say fixes the CVEs matched on their hosts (see cveFeed.distro_sync)."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='17', hour='3', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-distro-fix-sync',
        defaults={'task': 'sync_distro_fixes', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-distro-fix-sync').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0032_distro_backports'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(schedule_distro_sync, unschedule)]
