"""Give the two CVE List re-read update steps their attempts back.

``backfill_exact_builds`` and ``backfill_bare_versions`` read about a thousand CVE List records from GitHub eight at a time, with no second
try, and one rate-limited answer failed the whole step (seen on the first install that ran them: "Update step backfill_bare_versions failed
(CommandError)"). After three such failures an update step is recorded as given up and never runs again. They now ask again after a rate
limit and leave a record that will never read as stored, so this clears their done and attempt marks: both run once more at the next worker
start. Both are idempotent and only read the records still missing their ranges, so a second run on an install where they had finished
reads a few hundred records and changes nothing.
"""
from django.db import migrations

LANES = ('bf:backfill_exact_builds', 'bfa:backfill_exact_builds', 'bf:backfill_bare_versions', 'bfa:backfill_bare_versions')


def clear(apps, schema_editor):
    apps.get_model('cveFeed', 'BackgroundCursor').objects.filter(lane__in=LANES).delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0170_javaruntime')]
    operations = [migrations.RunPython(clear, migrations.RunPython.noop)]
