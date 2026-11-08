import django.db.models.deletion
import django.db.models.functions.datetime
import django.utils.timezone
from django.db import migrations, models


def schedule(apps, schema_editor):
    """The work planner (docs/PIPELINE.md, \"The work planner\"): a tick every minute that keeps the Sentinels busy with due checks, and a census every
    five minutes that counts what is due. Neither calls an AI."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    every_minute, _ = Interval.objects.get_or_create(every=1, period='minutes')
    every_five, _ = Interval.objects.get_or_create(every=5, period='minutes')
    PeriodicTask.objects.get_or_create(
        name='cvengine-work-planner', defaults={'task': 'work_planner_tick', 'interval': every_minute, 'enabled': True, 'queue': 'cve_feed_queue'})
    PeriodicTask.objects.get_or_create(
        name='cvengine-work-planner-census', defaults={'task': 'work_planner_census', 'interval': every_five, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name__in=('cvengine-work-planner', 'cvengine-work-planner-census')).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0153_excluded_address'),
        ('dashboard', '0032_setup_wizard'),
        ('targetApp', '0008_domain_expect_private_ca'),
        ('django_celery_beat', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='PlannerBatch',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('kind', models.CharField(max_length=32)),
                ('units', models.JSONField(default=list)),
                ('status', models.CharField(default='queued', max_length=10)),
                ('detail', models.CharField(blank=True, default='', max_length=300)),
                ('created_at', models.DateTimeField(db_default=django.db.models.functions.datetime.Now(), default=django.utils.timezone.now)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='+', to='targetApp.domain')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='dashboard.project')),
            ],
            options={
                'indexes': [models.Index(fields=['status', 'kind'], name='plannerbatch_status_kind_idx'),
                            models.Index(fields=['kind', 'finished_at'], name='plannerbatch_kind_fin_idx')],
            },
        ),
        migrations.RunPython(schedule, unschedule),
    ]
