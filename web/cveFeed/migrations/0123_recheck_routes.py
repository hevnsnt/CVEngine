from datetime import timedelta

from django.db import migrations
from django.utils import timezone


# Route checks before the shared soft-404 comparison (issue 213) judged a catch-all server's routes open, and an open route is only read
# again when its ledger entry expires (a week). Mark them all as last checked long ago, so the next scan of each host reads them again with
# the new comparison. Only the ledger moves; no route row is touched.
def recheck(apps, schema_editor):
    ServiceRun = apps.get_model('cveFeed', 'ServiceRun')
    ServiceRun.objects.filter(service='route-auth').update(finished_at=timezone.now() - timedelta(days=60))


class Migration(migrations.Migration):
    dependencies = [
        ('cveFeed', '0122_triage_carried_from'),
    ]

    operations = [
        migrations.RunPython(recheck, migrations.RunPython.noop),
    ]
