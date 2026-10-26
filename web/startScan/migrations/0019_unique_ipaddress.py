from django.db import migrations, models
from django.db.models import Count, Min


def merge_duplicates(apps, schema_editor):
    """One IpAddress row per address. Two scans that first saw the same IP at the same moment each inserted one, and every later
    get_or_create for it then failed. The oldest row stays; the others' subdomain links, ports and facts move onto it."""
    IpAddress = apps.get_model('startScan', 'IpAddress')
    Port = apps.get_model('startScan', 'Port')
    SubIp = apps.get_model('startScan', 'Subdomain').ip_addresses.through
    IpPort = IpAddress.ports.through
    duplicated = (IpAddress.objects.exclude(address__isnull=True).exclude(address='').values('address')
                  .annotate(n=Count('id'), keep=Min('id')).filter(n__gt=1))
    for group in duplicated.iterator():
        keeper = IpAddress.objects.get(pk=group['keep'])
        extras = list(IpAddress.objects.filter(address=group['address']).exclude(pk=keeper.pk).order_by('id'))
        extra_ids = [e.pk for e in extras]
        linked = set(SubIp.objects.filter(ipaddress_id=keeper.pk).values_list('subdomain_id', flat=True))
        for link in SubIp.objects.filter(ipaddress_id__in=extra_ids):
            if link.subdomain_id in linked:
                link.delete()
            else:
                link.ipaddress_id = keeper.pk
                link.save(update_fields=['ipaddress'])
                linked.add(link.subdomain_id)
        have = set(Port.objects.filter(ports=keeper.pk).values_list('number', 'protocol'))
        for link in IpPort.objects.filter(ipaddress_id__in=extra_ids).select_related('port'):
            key = (link.port.number, link.port.protocol)
            if key in have:
                link.delete()
            else:
                link.ipaddress_id = keeper.pk
                link.save(update_fields=['ipaddress'])
                have.add(key)
        for extra in extras:  # facts the keeper lacks
            for field in ('os_guess', 'reverse_pointer', 'geo_iso_id', 'version'):
                if not getattr(keeper, field) and getattr(extra, field):
                    setattr(keeper, field, getattr(extra, field))
            if keeper.os_accuracy is None and extra.os_accuracy is not None:
                keeper.os_accuracy = extra.os_accuracy
            if not keeper.fingerprint and extra.fingerprint:
                keeper.fingerprint = extra.fingerprint
            seen = [t for t in (keeper.last_seen, extra.last_seen) if t]
            keeper.last_seen = max(seen) if seen else None
            keeper.is_cdn = keeper.is_cdn or extra.is_cdn
        keeper.save()
        IpAddress.objects.filter(pk__in=extra_ids).delete()


class Migration(migrations.Migration):
    dependencies = [('startScan', '0018_vulnerability_assignee')]
    operations = [
        migrations.RunPython(merge_duplicates, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name='ipaddress',
            constraint=models.UniqueConstraint(condition=models.Q(('address__isnull', False), models.Q(('address', ''), _negated=True)),
                                               fields=('address',), name='uniq_ipaddress_address')),
    ]
