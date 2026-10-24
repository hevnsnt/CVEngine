from django.db import migrations, models


def schedule_update_check(apps, schema_editor):
    """Check GitHub for a newer version twice a day."""
    Crontab = apps.get_model('django_celery_beat', 'CrontabSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    crontab, _ = Crontab.objects.get_or_create(minute='23', hour='5,17', day_of_week='*', day_of_month='*', month_of_year='*')
    PeriodicTask.objects.get_or_create(
        name='cvengine-update-check',
        defaults={'task': 'check_for_updates', 'crontab': crontab, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-update-check').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0013_ct_watch_schedule'), ('django_celery_beat', '0001_initial')]
    operations = [
        migrations.CreateModel(
            name='UpdateSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=True)),
                ('repo', models.CharField(default='hevnsnt/CVEngine', max_length=200)),
                ('branch', models.CharField(default='master', max_length=100)),
                ('token', models.CharField(blank=True, default='', max_length=500)),
                ('latest_sha', models.CharField(blank=True, default='', max_length=40)),
                ('latest_message', models.CharField(blank=True, default='', max_length=300)),
                ('latest_url', models.CharField(blank=True, default='', max_length=300)),
                ('latest_date', models.DateTimeField(blank=True, null=True)),
                ('behind_by', models.IntegerField(blank=True, null=True)),
                ('commits', models.JSONField(blank=True, default=list)),
                ('last_checked_at', models.DateTimeField(blank=True, null=True)),
                ('last_error', models.CharField(blank=True, default='', max_length=300)),
                ('dismissed_sha', models.CharField(blank=True, default='', max_length=40)),
                ('approved_sha', models.CharField(blank=True, default='', max_length=40)),
                ('approved_by', models.CharField(blank=True, default='', max_length=150)),
                ('approved_at', models.DateTimeField(blank=True, null=True)),
            ],
        ),
        migrations.RunPython(schedule_update_check, unschedule),
    ]
