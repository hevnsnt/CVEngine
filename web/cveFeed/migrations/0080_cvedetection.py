import django.db.models.deletion
from django.db import migrations, models


def schedule(apps, schema_editor):
    """Author detection records for new CVEs (and backfill the old ones) every 30 minutes."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='17,47', hour='*', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-cve-detections',
        defaults={'task': 'author_cve_detections', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-cve-detections').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0079_nuclei_templates_every_six_hours'), ('django_celery_beat', '0001_initial')]
    operations = [
        migrations.CreateModel(
            name='CVEDetection',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('schema_version', models.PositiveSmallIntegerField(default=1)),
                ('source', models.CharField(default='rules', max_length=8)),
                ('strategy', models.JSONField(blank=True, default=dict)),
                ('rules_at', models.DateTimeField(blank=True, null=True)),
                ('ai_model', models.CharField(blank=True, default='', max_length=128)),
                ('ai_attempted_at', models.DateTimeField(blank=True, null=True)),
                ('ai_problems', models.JSONField(blank=True, default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('cve_entry', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='detection', to='cveFeed.cveentry')),
            ],
            options={'verbose_name': 'CVE detection', 'verbose_name_plural': 'CVE detections',
                     'indexes': [models.Index(fields=['ai_attempted_at'], name='cvedetect_ai_idx')]},
        ),
        migrations.RunPython(schedule, unschedule),
    ]
