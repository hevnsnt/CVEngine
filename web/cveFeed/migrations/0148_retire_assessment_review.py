"""Retire the three-hour AI assessment review (docs/AI-REVIEWER.md): the AI reviewer's operations check replaces it.

Its schedule goes first, so beat stops dispatching it, then its two tables. The coverage query it shared with the top-up lives on in
cveFeed.coverage_topup; nothing else read the tables. Reversing restores empty tables and no schedule (the task no longer exists)."""
from django.db import migrations

NAME = 'cvengine-three-hour-assessment-review'


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(name=NAME).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0147_secrets_inventory"),
        ("django_celery_beat", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(unschedule, migrations.RunPython.noop),  # the task is gone: reversing does not schedule it again
        migrations.DeleteModel(name="AssessmentReviewDecision"),  # first: it points at AssessmentReview
        migrations.DeleteModel(name="AssessmentReview"),
    ]
