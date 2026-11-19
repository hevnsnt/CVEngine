"""The AI review gaps (CHANGELOG, docs/AI-REVIEWER.md):

* the triage sweep runs every hour instead of once a day at 04:41 UTC, so a finding a correlation, a backfill or a provider error left
  pending waits at most an hour, not a day (``cvengine-triage-sweep``, the same task and queue; its own 30-minute claim keeps two runs apart);
* each validation record names the ``AIJob`` of the triage question it queued (``ai_job_id``, empty for every existing row), so the answer
  can update the record's ``ai_state`` when it lands (its index is built concurrently by 0173).
"""
from django.db import migrations, models

TASK = 'cvengine-triage-sweep'


def hourly(apps, schema_editor):
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='41', hour='*', day_of_week='*', day_of_month='*', month_of_year='*')
    if not PeriodicTask.objects.filter(name=TASK).update(crontab=crontab, interval=None):
        PeriodicTask.objects.create(name=TASK, task='triage_sweep', crontab=crontab, enabled=True, queue='cve_feed_queue')


def daily(apps, schema_editor):
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='41', hour='4', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.filter(name=TASK).update(crontab=crontab, interval=None)


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0172_search_trigram_indexes'), ('django_celery_beat', '0001_initial')]
    operations = [
        migrations.AddField(model_name='automaticvalidation', name='ai_job_id', field=models.PositiveBigIntegerField(blank=True, null=True)),
        migrations.AddField(model_name='ondemandvalidation', name='ai_job_id', field=models.PositiveBigIntegerField(blank=True, null=True)),
        migrations.RunPython(hourly, daily),
    ]
