from django.db import migrations

BATCH = 2000


# IpAddress.is_private was never set for an address a scan found (issue 212), so every stored row says False. Set it from the address
# alone (targetApp.target_types.is_public_address: no network, no setting), in batches, only where it changes. The next daily rescore
# drops the "public IP" points a private address was given.
def backfill(apps, schema_editor):
    from targetApp.target_types import is_public_address
    IpAddress = apps.get_model('startScan', 'IpAddress')
    last = 0
    while True:
        rows = list(IpAddress.objects.filter(pk__gt=last).order_by('pk').values_list('pk', 'address', 'is_private')[:BATCH])
        if not rows:
            return
        last = rows[-1][0]
        for private in (True, False):
            ids = [pk for pk, address, flag in rows if flag is not private and (not is_public_address(address)) is private]
            if ids:
                IpAddress.objects.filter(pk__in=ids).update(is_private=private)


class Migration(migrations.Migration):
    dependencies = [
        ('startScan', '0023_drop_legacy_models'),
    ]

    operations = [
        migrations.RunPython(backfill, migrations.RunPython.noop),
    ]
