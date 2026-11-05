"""Retire the three-hour AI assessment review (docs/AI-REVIEWER.md): the AI reviewer's operations check replaces it.

Its schedule goes first, so beat stops dispatching it, then its two tables. The coverage query it shared with the top-up lives on in
cveFeed.coverage_topup; nothing else read the tables. Reversing restores the schedule row and empty tables."""
from django.db import migrations

NAME = 'cvengine-three-hour-assessment-review'


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name=NAME).delete()


def reschedule(apps, schema_editor):
    Interval = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    interval, _ = Interval.objects.get_or_create(every=3, period='hours')
    PeriodicTask.objects.get_or_create(name=NAME, defaults={
        'task': 'assessment_review', 'interval': interval, 'enabled': True, 'queue': 'cve_feed_queue'})


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0146_ai_job"),
        ("django_celery_beat", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(unschedule, reschedule),
        migrations.RemoveField(
            model_name="assessmentreviewdecision",
            name="review",
        ),
        migrations.RemoveField(
            model_name="assessmentreviewdecision",
            name="project",
        ),
        migrations.DeleteModel(
            name="AssessmentReview",
        ),
        migrations.DeleteModel(
            name="AssessmentReviewDecision",
        ),
    ]
