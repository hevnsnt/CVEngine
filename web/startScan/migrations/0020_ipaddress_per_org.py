import django.db.models.deletion
from django.db import migrations, models
from django.db.models import Count, F, Min


def split_by_org(apps, schema_editor):
    """Give every IP row to one organization. An address that hosts of several organizations reached used to be one shared row, so
    one organization's banners and service data were readable through another's hosts. Each organization now gets its own copy (and
    its own copies of the ports), and its subdomains point at it."""
    IpAddress = apps.get_model('startScan', 'IpAddress')
    Port = apps.get_model('startScan', 'Port')
    Subdomain = apps.get_model('startScan', 'Subdomain')
    SubIp = Subdomain.ip_addresses.through
    IpPort = IpAddress.ports.through
    # (ip id, the organization of each linked subdomain's project; None when a project has none)
    pairs = (SubIp.objects.values('ipaddress_id', org=F('subdomain__target_domain__project__org_id')).annotate(n=Count('id')))
    orgs_of = {}
    for row in pairs.iterator():
        orgs_of.setdefault(row['ipaddress_id'], set()).add(row['org'])
    single = {}
    multi = {}
    for ip_id, orgs in orgs_of.items():
        if len(orgs) == 1:
            single.setdefault(next(iter(orgs)), []).append(ip_id)
        else:
            multi[ip_id] = sorted(orgs, key=lambda o: (o is None, o))
    for org, ids in single.items():
        if org is None:
            continue
        for start in range(0, len(ids), 5000):
            IpAddress.objects.filter(pk__in=ids[start:start + 5000]).update(org_id=org)
    scalar = [f.attname for f in IpAddress._meta.concrete_fields if f.name not in ('id', 'org', 'ports')]
    for ip_id, orgs in multi.items():
        original = IpAddress.objects.get(pk=ip_id)
        port_rows = list(Port.objects.filter(ports=ip_id))
        first, rest = orgs[0], orgs[1:]
        if first is not None:
            IpAddress.objects.filter(pk=ip_id).update(org_id=first)
        for org in rest:
            clone = IpAddress.objects.create(org_id=org, **{name: getattr(original, name) for name in scalar})
            moved = list(SubIp.objects.filter(ipaddress_id=ip_id, subdomain__target_domain__project__org_id=org)) if org is not None else \
                list(SubIp.objects.filter(ipaddress_id=ip_id, subdomain__target_domain__project__org_id__isnull=True))
            for link in moved:
                link.ipaddress_id = clone.pk
                link.save(update_fields=['ipaddress'])
            for port in port_rows:
                copy = Port.objects.create(**{f.attname: getattr(port, f.attname) for f in Port._meta.concrete_fields if f.name != 'id'})
                IpPort.objects.create(ipaddress_id=clone.pk, port_id=copy.pk)


class Migration(migrations.Migration):
    dependencies = [('startScan', '0019_unique_ipaddress'), ('dashboard', '0022_mfa_secret_encrypted'), ('targetApp', '0004_domain_org_unique')]
    operations = [
        migrations.AddField(model_name='ipaddress', name='org',
                            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.CASCADE,
                                                    related_name='+', to='dashboard.org')),
        migrations.RunPython(split_by_org, migrations.RunPython.noop),
        migrations.RemoveConstraint(model_name='ipaddress', name='uniq_ipaddress_address'),
        migrations.AddConstraint(model_name='ipaddress', constraint=models.UniqueConstraint(
            condition=models.Q(('org__isnull', False), ('address__isnull', False), models.Q(('address', ''), _negated=True)),
            fields=('org', 'address'), name='uniq_ipaddress_org_address')),
        migrations.AddConstraint(model_name='ipaddress', constraint=models.UniqueConstraint(
            condition=models.Q(('org__isnull', True), ('address__isnull', False), models.Q(('address', ''), _negated=True)),
            fields=('address',), name='uniq_ipaddress_noorg_address')),
    ]
