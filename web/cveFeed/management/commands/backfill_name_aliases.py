"""Correlate again the hosts whose technology names the name rules now connect differently (cveFeed.correlation.names_rules_touch).

The alias data (cveFeed/data/product_aliases.json) and the name rules decide which CVE records a detected name reaches: "Cisco ASA" now reaches
Cisco's ASA records, "Ivanti Connect Secure" the Pulse Connect Secure ones, the port scan's nginx CPE (igor_sysoev) the F5 records, and "Express" no
longer reaches Ubiquiti's UniFi Express. A host is correlated again by the next scan of it; this does it now, once, for the current hosts
(each domain's latest inventory) carrying such a name, so a match appears (or a wrong one closes) without waiting for a rescan.

A dry run by default: it counts the hosts. With --apply it correlates them in batches (the same correlation a scan runs, so a match no
longer found is closed and one newly found is opened). Safe to run again: correlating a host twice changes nothing the second time.

    python3 manage.py backfill_name_aliases
    python3 manage.py backfill_name_aliases --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import correlation


def touched_hosts(product_index):
    """The current hosts carrying a technology or an open port product the name rules touch: a queryset."""
    from django.db.models import Q

    from startScan.models import OPEN_PORT_STATES, Port, Subdomain, Technology
    tech_ids = [pk for pk, name in Technology.objects.values_list("id", "name").iterator()
                if correlation.names_rules_touch(correlation.split_name_version(name)[0], product_index)]
    port_ids = [pk for pk, product, cpe in Port.objects.filter(state__in=OPEN_PORT_STATES).exclude(product="").exclude(product__isnull=True)
                .values_list("id", "product", "cpe").iterator()
                if correlation.names_rules_touch(product.strip(), product_index, cpe or "", source="port")]
    by_tech = Subdomain.technologies.through.objects.filter(technology_id__in=tech_ids).values("subdomain_id")
    from startScan.models import IpAddress
    ips = IpAddress.ports.through.objects.filter(port_id__in=port_ids).values("ipaddress_id")
    by_port = Subdomain.ip_addresses.through.objects.filter(ipaddress_id__in=ips).values("subdomain_id")
    return (Subdomain.objects.filter(Q(id__in=by_tech) | Q(id__in=by_port)).filter(correlation.latest_scan_q())
            .prefetch_related("technologies", "ip_addresses__ports").order_by("id"))


class Command(BaseCommand):
    help = ("Correlate again the current hosts whose technology names the name rules (cveFeed/data/product_aliases.json) connect differently "
            "(a dry run unless --apply).")

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Correlate the hosts. Without it the command only counts them.")

    def handle(self, *args, **opts):
        cve_by_id, index = correlation.cve_pool()
        if not index:
            self.stdout.write(self.style.SUCCESS("name aliases: no CVE is stored yet, nothing to correlate"))
            return
        hosts = touched_hosts(index)
        if not opts["apply"]:
            self.stdout.write(self.style.SUCCESS(f"dry run: {hosts.count()} current hosts carry a name the name rules connect differently "
                                                 "and would be correlated again (run again with --apply)"))
            return
        walked, matches = correlation.correlate_subdomains(hosts.iterator(chunk_size=500), index, cve_by_id)
        self.stdout.write(self.style.SUCCESS(f"name aliases: {walked} hosts correlated again, {matches} CVE matches recorded"))
