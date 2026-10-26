from django.db import migrations


def every_six_hours(apps, schema_editor):
    """New nuclei templates for new CVEs land several times a day: refresh at 04:41, 10:41, 16:41 and 22:41 UTC instead of once.
    Only the schedule this app created (04:41 daily) is changed; one an administrator edited is left alone."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    task = PeriodicTask.objects.filter(name='cvengine-nuclei-templates').select_related('crontab').first()
    if task is None or task.crontab is None:
        return
    original = task.crontab
    if (original.minute, original.hour, original.day_of_week, original.day_of_month, original.month_of_year) != ('41', '4', '*', '*', '*'):
        return
    crontab, _ = Crontab.objects.get_or_create(minute='41', hour='4,10,16,22', day_of_week='*', day_of_month='*', month_of_year='*')
    task.crontab = crontab
    task.save(update_fields=['crontab'])


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0078_projectsettings'), ('django_celery_beat', '0001_initial')]
    # no reverse: a daily refresh is not worth restoring
    operations = [migrations.RunPython(every_six_hours, migrations.RunPython.noop)]
