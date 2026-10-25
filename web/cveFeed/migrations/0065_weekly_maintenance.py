from django.db import migrations, models


def schedule_maintenance(apps, schema_editor):
    """Sundays 03:23 UTC: archive and delete log rows past their retention (tasks.weekly_maintenance)."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='23', hour='3', day_of_week='0', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-weekly-maintenance',
        defaults={'task': 'weekly_maintenance', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-weekly-maintenance').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0064_triage_evidence_key'), ('django_celery_beat', '0001_initial')]
    operations = [
        migrations.AddIndex(model_name='agentactivity', index=models.Index(fields=['project', 'id'], name='agentact_project_id_idx')),
        migrations.AddIndex(model_name='agentactivity', index=models.Index(fields=['status', 'id'], name='agentact_status_id_idx')),
        migrations.AddIndex(model_name='agentactivity', index=models.Index(fields=['created_at'], name='agentact_created_idx')),
        migrations.RunPython(schedule_maintenance, unschedule),
    ]
