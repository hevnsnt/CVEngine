"""1.4.0 host review: the AI reads every open result of a host together and chooses one next step (``cveFeed.host_review``).

A new table (HostReview) and a few columns on existing ones: FindingReview points back to the host review that gave a verdict,
ProjectSettings has the review mode and ReviewerSettings the daily limits. Every NOT NULL column added to a table that
exists has a database default, so the previous release's code, which keeps running until the workers restart and inserts rows without them, can
still insert. Catalog-only on PostgreSQL 11 and later: no rewrite, nothing backfilled (a project reads as mode recommend, the default, and the review itself is off until a person turns it on).
"""
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


TASK_NAME = 'cvengine-host-review-sweep'


def schedule_sweep(apps, schema_editor):
    """The host review sweep runs every ten minutes from here on (cveFeed.host_review.sweep). It queues AI jobs and nothing else, and does nothing
    with no AI provider, while scanning is paused or past the day's cap."""
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    every_ten, _ = Interval.objects.get_or_create(every=10, period='minutes')
    PeriodicTask.objects.get_or_create(name=TASK_NAME, defaults={'task': 'host_review_sweep', 'interval': every_ten, 'enabled': True, 'queue': 'cve_feed_queue'})


def unschedule_sweep(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name=TASK_NAME).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0163_reviewer_off_until_asked"),
        ("dashboard", "0035_apitoken_suffix_db_default"),
        ("targetApp", "0008_domain_expect_private_ca"),
        ("django_celery_beat", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="projectsettings",
            name="host_review_mode",
            field=models.CharField(db_default="recommend", default="recommend", max_length=10),
        ),
        migrations.AddField(
            model_name="reviewersettings",
            name="host_review_auto_per_project_day",
            field=models.PositiveIntegerField(db_default=50, default=50),
        ),
        migrations.AddField(
            model_name="reviewersettings",
            name="host_review_daily_max",
            field=models.PositiveIntegerField(db_default=100, default=100),
        ),
        migrations.AddField(
            model_name="reviewersettings",
            name="host_review_enabled",
            field=models.BooleanField(db_default=False, default=False),
        ),
        migrations.CreateModel(
            name="HostReview",
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
                ("host", models.CharField(max_length=500)),
                ("state_key", models.CharField(max_length=40)),
                (
                    "status",
                    models.CharField(
                        db_default="queued", default="queued", max_length=10
                    ),
                ),
                ("refs", models.JSONField(blank=True, default=dict)),
                (
                    "step_action",
                    models.CharField(
                        blank=True, db_default="", default="", max_length=24
                    ),
                ),
                (
                    "step_target",
                    models.CharField(
                        blank=True, db_default="", default="", max_length=12
                    ),
                ),
                (
                    "step_reason_code",
                    models.CharField(
                        blank=True, db_default="", default="", max_length=24
                    ),
                ),
                ("step_note", models.TextField(blank=True, db_default="", default="")),
                (
                    "step_mode",
                    models.CharField(
                        blank=True, db_default="", default="", max_length=10
                    ),
                ),
                (
                    "step_state",
                    models.CharField(
                        blank=True, db_default="", default="", max_length=10
                    ),
                ),
                (
                    "step_detail",
                    models.CharField(
                        blank=True, db_default="", default="", max_length=300
                    ),
                ),
                ("host_note", models.TextField(blank=True, db_default="", default="")),
                ("injection", models.JSONField(blank=True, default=list)),
                (
                    "model",
                    models.CharField(
                        blank=True, db_default="", default="", max_length=100
                    ),
                ),
                ("input_tokens", models.PositiveIntegerField(db_default=0, default=0)),
                ("output_tokens", models.PositiveIntegerField(db_default=0, default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("decided_at", models.DateTimeField(blank=True, null=True)),
                ("dismissed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "ai_job",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="cveFeed.aijob",
                    ),
                ),
                (
                    "dismissed_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "domain",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to="targetApp.domain",
                    ),
                ),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to="dashboard.project",
                    ),
                ),
            ],
        ),
        migrations.AddField(
            model_name="findingreview",
            name="host_review",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="finding_reviews",
                to="cveFeed.hostreview",
            ),
        ),
        migrations.AddIndex(
            model_name="hostreview",
            index=models.Index(
                fields=["project", "host", "-created_at"], name="hostreview_host_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="hostreview",
            index=models.Index(fields=["created_at"], name="hostreview_created_idx"),
        ),
        migrations.AddIndex(
            model_name="hostreview",
            index=models.Index(fields=["step_state"], name="hostreview_step_idx"),
        ),
        migrations.AddConstraint(
            model_name="hostreview",
            constraint=models.UniqueConstraint(
                condition=models.Q(("status__in", ["queued", "answered"])),
                fields=("project", "host"),
                name="one_open_hostreview_per_host",
            ),
        ),
        migrations.RunPython(schedule_sweep, unschedule_sweep),
    ]
