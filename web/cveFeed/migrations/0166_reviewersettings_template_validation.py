from django.db import migrations, models


class Migration(migrations.Migration):
    """The switch of the automatic validation of AI-written checks (FA-5): off. No data is written: an install that already has validated checks keeps
    them (they are rows with status ``valid``), and nothing new is validated until a person switches it on or answers the AI question."""

    dependencies = [('cveFeed', '0165_triage_kind_evidence_idx')]

    operations = [
        migrations.AddField(
            model_name='reviewersettings',
            name='template_validation_enabled',
            field=models.BooleanField(db_default=False, default=False),
        ),
    ]
