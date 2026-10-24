from django.db import migrations, models
import django.db.models.deletion


def schedule(apps, schema_editor):
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=5, period='minutes')
    PeriodicTask.objects.get_or_create(name='cvengine-hot-validation-sweep', defaults={
        'task': 'queue_hot_validations', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-hot-validation-sweep').delete()


class Migration(migrations.Migration):
    dependencies = [
        ('cveFeed', '0045_background_cursor'),
        ('django_celery_beat', '0001_initial'),
    ]
    operations = [
        migrations.AddField(model_name='ondemandvalidation', name='evidence_signature',
                            field=models.CharField(blank=True, default='', max_length=40)),
        migrations.AddField(model_name='ondemandvalidation', name='priority',
                            field=models.PositiveSmallIntegerField(default=3)),
        migrations.CreateModel(name='HotValidationCursor', fields=[
            ('lane', models.CharField(max_length=24, primary_key=True, serialize=False)),
            ('last_pk', models.PositiveBigIntegerField(default=0)),
            ('updated_at', models.DateTimeField(auto_now=True)),
        ]),
        migrations.CreateModel(name='AutomaticValidation', fields=[
            ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ('signature', models.CharField(max_length=64)),
            ('priority', models.PositiveSmallIntegerField(default=6)),
            ('status', models.CharField(default='queued', max_length=12)),
            ('attempts', models.PositiveSmallIntegerField(default=0)),
            ('next_attempt_at', models.DateTimeField(blank=True, null=True)),
            ('result', models.JSONField(blank=True, default=dict)),
            ('error', models.CharField(blank=True, default='', max_length=300)),
            ('created_at', models.DateTimeField(auto_now_add=True)),
            ('started_at', models.DateTimeField(blank=True, null=True)),
            ('finished_at', models.DateTimeField(blank=True, null=True)),
            ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='dashboard.project')),
            ('triage', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='automatic_validations', to='cveFeed.triage')),
        ], options={
            'indexes': [models.Index(fields=['project', 'status', 'created_at'], name='autoval_project_status_idx')],
            'constraints': [models.UniqueConstraint(condition=models.Q(status__in=['queued', 'running']), fields=('triage',), name='one_active_autoval_per_finding')],
        }),
        migrations.RunPython(schedule, unschedule),
    ]
