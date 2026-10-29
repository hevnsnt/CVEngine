import django.db.models.deletion
from django.db import migrations, models


def schedule(apps, schema_editor):
    """Look for runZero projects due a sync every hour; how often each one really syncs is CVENGINE_RUNZERO_SYNC_HOURS (default 6)."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=1, period='hours')
    PeriodicTask.objects.get_or_create(name='cvengine-runzero-sync', defaults={
        'task': 'runzero_sync_due', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name='cvengine-runzero-sync').delete()


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0086_saved_search_schedule"),
        ("dashboard", "0026_cve_guidance_budget"),
        ("django_celery_beat", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="RunZeroSync",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("import_enabled", models.BooleanField(default=False)),
                ("search", models.CharField(default="alive:true", max_length=300)),
                ("status", models.CharField(blank=True, default="", max_length=10)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("last_sync_at", models.DateTimeField(blank=True, null=True)),
                ("last_ok_at", models.DateTimeField(blank=True, null=True)),
                (
                    "last_error",
                    models.CharField(blank=True, default="", max_length=300),
                ),
                ("counts", models.JSONField(blank=True, default=dict)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "project",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="runzero_sync",
                        to="dashboard.project",
                    ),
                ),
            ],
        ),
        migrations.RunPython(schedule, unschedule),
    ]
