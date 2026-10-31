from datetime import timedelta

from django.db import migrations
from django.utils import timezone


# Route checks before the shared soft-404 comparison (issue 213) judged a catch-all server's routes open, and an open route is only read
# again when its ledger entry expires (a week). Mark them all as last checked long ago, so the next scan of each host reads them again with
# the new comparison. Only the ledger moves; no route row is touched or deleted.
#
# What that means for a row already stored: a false ``open`` row stays ``open`` (and a candidate for scoring and hot validation) until its
# host is probed again. It is corrected by that probe, which stores ``catch_all`` over it (no change event), not by this migration. The probe
# comes with the host's next discovery scan: the work conductor (cveFeed.conductor) starts the stalest targets first, a scan's route stage plans
# the routes of the hosts that scan found, and none of them is fresh in the ledger any more. How soon that is depends on how many targets the
# install has and on the conductor being on (CVENGINE_WORK_DEPTH above 0); a manual scan or a re-test of the host does it at once.
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
