"""Resolve the Direct Send findings that were never tested.

Sentinels before the tested check raised ``mx_direct_send`` for every domain whose MX is Microsoft 365, read from DNS alone. A tested finding
carries ``evidence.tested``; every other one is a guess and is resolved here. A later tested acceptance opens a new one. A supplier is never
tested, so every supplier ``mx_direct_send`` that is still open or accepted is resolved; one an admin marked a false positive is left as it is.
"""
from django.db import migrations
from django.utils import timezone

NOTE = 'Resolved by 1.5.0: this was read from the MX record alone, never tested. Direct Send is now reported only when a test shows it is open.'


def resolve_untested(apps, schema_editor):
    now = timezone.now()
    hygiene = apps.get_model('cveFeed', 'HygieneFinding')
    supplier = apps.get_model('cveFeed', 'SupplierFinding')
    # Judged in Python: a JSON key test in SQL treats a missing key as NULL, and NOT NULL then keeps the very rows to resolve.
    rows = hygiene.objects.filter(check_name='mx_direct_send', status='open').values_list('pk', 'evidence')
    guesses = [pk for pk, evidence in rows if not (isinstance(evidence, dict) and evidence.get('tested') is True)]
    for i in range(0, len(guesses), 1000):
        hygiene.objects.filter(pk__in=guesses[i:i + 1000]).update(status='resolved', resolved_at=now)
    supplier.objects.filter(check_name='mx_direct_send', status__in=('open', 'accepted')).update(status='resolved', resolved_at=now, status_note=NOTE)


class Migration(migrations.Migration):
    dependencies = [
        ('cveFeed', '0194_finding_and_host_notes'),
    ]

    operations = [
        migrations.RunPython(resolve_untested, migrations.RunPython.noop, elidable=True),
    ]
