"""The review of AI-written templates (cveFeed.template_review): a revision is a new GeneratedTemplate row that supersedes the old one
(``supersedes``, ``revised_by``, ``revision_reason``, ``submitted_fixture``; nullable columns or a database default, so the code of the
previous release keeps working during an update), and one new table of reviews (who, when, verdict, reason, outcome). Nothing is backfilled."""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0168_distrofix_advisory"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="generatedtemplate",
            name="revised_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="generatedtemplate",
            name="revision_reason",
            field=models.TextField(blank=True, db_default="", default=""),
        ),
        migrations.AddField(
            model_name="generatedtemplate",
            name="submitted_fixture",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="generatedtemplate",
            name="supersedes",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="revisions",
                to="cveFeed.generatedtemplate",
            ),
        ),
        migrations.CreateModel(
            name="GeneratedTemplateReview",
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
                (
                    "reviewer_name",
                    models.CharField(blank=True, default="", max_length=150),
                ),
                ("verdict", models.CharField(max_length=16)),
                ("reason", models.TextField(blank=True, default="")),
                ("outcome", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "reviewer",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "template",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="reviews",
                        to="cveFeed.generatedtemplate",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at", "-id"],
            },
        ),
    ]
