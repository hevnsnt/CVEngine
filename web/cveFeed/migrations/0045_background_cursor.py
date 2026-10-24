from django.db import migrations, models


def schedule(apps, schema_editor):
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=5, period='minutes')
    PeriodicTask.objects.get_or_create(name='cvengine-reconcile-invalid-correlations', defaults={
        'task': 'reconcile_invalid_correlations', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-reconcile-invalid-correlations').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0044_triage_review_nonce_deferredretest_triagecall'),
                    ('django_celery_beat', '0001_initial')]
    operations = [
        migrations.CreateModel(name='BackgroundCursor', fields=[
            ('lane', models.CharField(max_length=32, primary_key=True, serialize=False)),
            ('last_pk', models.PositiveBigIntegerField(default=0)),
            ('updated_at', models.DateTimeField(auto_now=True)),
        ]),
        migrations.RunPython(schedule, unschedule),
    ]
