from django.db import migrations
from django.db.models import Count


def deshare_ports(apps, schema_editor):
    """Give every IP its own Port row. bbot persistence used to attach one Port row per port number to every IP, so one
    host's nmap product and version (nginx 1.18.0 on 443) showed up on every other host with 443 open. The first IP
    (lowest id) keeps the row; each other IP gets a copy of it. Idempotent: a row linked to one IP is left alone."""
    Port = apps.get_model("startScan", "Port")
    IpAddress = apps.get_model("startScan", "IpAddress")
    Through = IpAddress.ports.through
    field_names = [f.name for f in Port._meta.concrete_fields if f.name != "id"]
    shared = (Through.objects.values("port_id").annotate(n=Count("ipaddress_id", distinct=True))
              .filter(n__gt=1).values_list("port_id", flat=True))
    for port_id in list(shared):
        port = Port.objects.get(pk=port_id)
        links = list(Through.objects.filter(port_id=port_id).order_by("ipaddress_id"))
        seen = set()
        for link in links:
            if link.ipaddress_id in seen:  # a duplicated link row of the same pair: drop it
                link.delete()
                continue
            seen.add(link.ipaddress_id)
            if len(seen) == 1:
                continue
            copy = Port.objects.create(**{name: getattr(port, name) for name in field_names})
            link.port_id = copy.pk
            link.save(update_fields=["port"])


class Migration(migrations.Migration):

    dependencies = [
        ("startScan", "0006_screenshot_hash"),
    ]

    operations = [
        migrations.RunPython(deshare_ports, migrations.RunPython.noop),
    ]
