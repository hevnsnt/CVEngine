"""Split the Server-header tokens stored as names ("nginx/1.28.3", "awselb/2.0") into product and version, and correlate again the hosts
whose names now read differently.

The port scanner's http-server-header script fills an unidentified service's product with the whole Server header, so a port stored "nginx/1.28.3
(Ubuntu)" as its product: the version sat in the name, and the name matched nothing. The port scan's ingest now splits it
(cveFeed.port_inventory.split_header_product), as the technology ingest does a "product/version" technology name
(cveFeed.correlation.stored_technology_name); this rewrites the rows stored before, the same way. It also correlates again the hosts
carrying a name the new name data reads differently: a detector's name read as another product (``renames`` in
cveFeed/data/product_aliases.json: "AspNet Version Disclosure") and a name whose version is a protocol's (``protocol_versions``:
Microsoft HTTPAPI's 2.0 is never a version of the product).

A dry run by default: it counts the rows and hosts. With --apply it rewrites the rows and correlates the current hosts that carry them (the
same correlation a scan runs, so a match no longer found is closed and one newly found is opened). Safe to run again: a split row is not
split twice, and correlating a host twice changes nothing the second time.

    python3 manage.py backfill_name_versions
    python3 manage.py backfill_name_versions --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import correlation


def split_ports():
    """``[(port, new fields)]`` of the stored ports whose product is a ``product/version`` header token."""
    from cveFeed.port_inventory import split_header_product
    from startScan.models import Port
    out = []
    for port in Port.objects.filter(product__contains="/").order_by("id").iterator(chunk_size=500):
        rec = {"product": port.product, "version": port.version or "", "service_extra": port.service_extra or ""}
        new = split_header_product(rec)
        if new is not rec:
            out.append((port, new))
    return out


def split_technologies():
    """``[(technology, stored name)]`` of the technologies named by a ``product/version`` header token."""
    from startScan.models import Technology
    out = []
    for tech in Technology.objects.filter(name__contains="/").order_by("id").iterator(chunk_size=500):
        name = correlation.stored_technology_name(tech.name or "")
        if name != tech.name:
            out.append((tech, name[:500]))
    return out


def _read_differently(name):
    token = correlation._norm(correlation.split_name_version(name or "")[0])
    return token in correlation.TECH_RENAMES or token in correlation.PROTOCOL_VERSION_NAMES


def hosts_for(tech_ids, port_ids):
    """The current hosts (each domain's latest inventory) carrying one of the technologies or ports, plus those carrying a name the
    ``renames`` and ``protocol_versions`` data read differently: a queryset."""
    from django.db.models import Q

    from startScan.models import OPEN_PORT_STATES, IpAddress, Port, Subdomain, Technology
    tech_ids = set(tech_ids) | {pk for pk, name in Technology.objects.values_list("id", "name").iterator() if _read_differently(name)}
    port_ids = set(port_ids) | {pk for pk, product, version in Port.objects.filter(state__in=OPEN_PORT_STATES).exclude(version="")
                                .values_list("id", "product", "version").iterator()
                                if correlation.stated_version(product or "", version) != version}
    by_tech = Subdomain.technologies.through.objects.filter(technology_id__in=tech_ids).values("subdomain_id")
    ips = IpAddress.ports.through.objects.filter(port_id__in=port_ids).values("ipaddress_id")
    by_port = Subdomain.ip_addresses.through.objects.filter(ipaddress_id__in=ips).values("subdomain_id")
    return (Subdomain.objects.filter(Q(id__in=by_tech) | Q(id__in=by_port)).filter(correlation.latest_scan_q())
            .prefetch_related("technologies", "ip_addresses__ports").order_by("id"))


def apply_ports(rows):
    from cveFeed import distro as distro_lib
    from cveFeed.port_inventory import fit_columns, store_distro
    for port, new in rows:
        port.product, port.version, port.service_extra = new["product"], new["version"], new["service_extra"]
        cpes = ((port.extra or {}).get("cpes") if isinstance(port.extra, dict) else None) or [port.cpe or ""]
        store_distro(port, distro_lib.parse_distro(port.product, port.version, port.service_extra, cpes, port.banner or ""))
        fit_columns(port)
        port.save(update_fields=["product", "version", "service_extra", "distro", "distro_release", "package_release", "upstream_version",
                                 "extra"])


class Command(BaseCommand):
    help = ("Split the Server-header tokens stored as port products and technology names (nginx/1.28.3) into product and version, and "
            "correlate the current hosts that carry them again (a dry run unless --apply).")

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Rewrite the rows and correlate the hosts. Without it the command only counts them.")

    def handle(self, *args, **opts):
        ports, techs = split_ports(), split_technologies()
        hosts = hosts_for([t.id for t, _n in techs], [p.id for p, _n in ports])
        if not opts["apply"]:
            self.stdout.write(self.style.SUCCESS(
                f"dry run: {len(ports)} port products and {len(techs)} technology names would be split into product and version, and "
                f"{hosts.count()} current hosts correlated again (run again with --apply)"))
            return
        apply_ports(ports)
        for tech, name in techs:
            tech.name = name
            tech.save(update_fields=["name"])  # save() keeps the version and category columns in step
        cve_by_id, index = correlation.cve_pool()
        walked = matches = 0
        if index:
            walked, matches = correlation.correlate_subdomains(hosts.iterator(chunk_size=500), index, cve_by_id)
        self.stdout.write(self.style.SUCCESS(
            f"name versions: {len(ports)} port products and {len(techs)} technology names split; {walked} hosts correlated again, "
            f"{matches} CVE matches recorded"))
