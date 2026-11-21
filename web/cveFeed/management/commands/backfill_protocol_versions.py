"""Correlate again the current hosts carrying a name whose stated version is a protocol's or a connector's, never the product's
(``protocol_versions`` in cveFeed/data/product_aliases.json, read by cveFeed.correlation.stated_version).

The port scan names Tomcat's HTTP connector "Apache Tomcat/Coyote JSP engine 1.1" (the Server header says "Apache-Coyote/1.1"): 1.1 is the
connector's HTTP/1.1, the same on every Tomcat release. Read as Tomcat's version, it sat below every branch a Tomcat advisory fixes and was
taken as an end-of-life release affected by each of them. Correlation now drops that version, so the product is an unversioned lead; this
correlates the hosts that carry such a name once, so the matches the version made close now (the normal closure of a match the host no longer
supports) instead of at the host's next scan. Microsoft HTTPAPI's 2.0 is read the same way.

A dry run by default: it counts the hosts. With --apply it correlates them (the same correlation a scan runs). Safe to run again: correlating a
host twice changes nothing the second time.

    python3 manage.py backfill_protocol_versions
    python3 manage.py backfill_protocol_versions --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import correlation


def touched_hosts():
    """The current hosts (each domain's latest inventory) with an open port or a technology named by ``protocol_versions``: a queryset."""
    from django.db.models import Q

    from startScan.models import OPEN_PORT_STATES, IpAddress, Port, Subdomain, Technology
    named = correlation.PROTOCOL_VERSION_NAMES
    tech_ids = [pk for pk, name in Technology.objects.values_list("id", "name").iterator()
                if correlation._norm(correlation.split_name_version(name or "")[0]) in named]
    port_ids = [pk for pk, product in Port.objects.filter(state__in=OPEN_PORT_STATES).exclude(product="").exclude(product__isnull=True)
                .values_list("id", "product").iterator()
                if correlation._norm(correlation.split_port_product(product)[0]) in named]
    by_tech = Subdomain.technologies.through.objects.filter(technology_id__in=tech_ids).values("subdomain_id")
    ips = IpAddress.ports.through.objects.filter(port_id__in=port_ids).values("ipaddress_id")
    by_port = Subdomain.ip_addresses.through.objects.filter(ipaddress_id__in=ips).values("subdomain_id")
    return (Subdomain.objects.filter(Q(id__in=by_tech) | Q(id__in=by_port)).filter(correlation.latest_scan_q())
            .prefetch_related("technologies", "ip_addresses__ports").order_by("id"))


class Command(BaseCommand):
    help = ("Correlate again the current hosts carrying a name whose version is a protocol's or a connector's (Apache Tomcat/Coyote JSP "
            "engine 1.1, Microsoft-HTTPAPI/2.0), so the matches that version made close (a dry run unless --apply).")

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Correlate the hosts. Without it the command only counts them.")

    def handle(self, *args, **opts):
        hosts = touched_hosts()
        if not opts["apply"]:
            self.stdout.write(self.style.SUCCESS(f"dry run: {hosts.count()} current hosts carry a name whose version is a protocol's and "
                                                 "would be correlated again (run again with --apply)"))
            return
        cve_by_id, index = correlation.cve_pool()
        if not index:
            self.stdout.write(self.style.SUCCESS("protocol versions: no CVE is stored yet, nothing to correlate"))
            return
        walked, matches = correlation.correlate_subdomains(hosts.iterator(chunk_size=500), index, cve_by_id)
        self.stdout.write(self.style.SUCCESS(f"protocol versions: {walked} hosts correlated again, {matches} CVE matches recorded"))
