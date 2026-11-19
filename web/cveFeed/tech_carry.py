"""Carrying a skipped source's technologies onto this scan's host rows.

Hosts are stored once per scan, so a fresh row starts with only what this scan's own passes attached. A source the service ledger says
covered a host inside its window (the light technology pass, the WAF fingerprint, the WordPress scan) is not run on it again, so what it
found last time has to be carried onto the new row, or it drops out of the current inventory and the next correlation closes its matches.

``carry`` copies, per source, the technologies the row of the scan that last ran that source on the host carries and the new row lacks: a set
difference, so a row another source already filled (discovery's "cloudflare", "hsts") still gets the technology pass's (WordPress:7.1.4,
jQuery ...). A product the new row already names, at any version, is never carried (what this scan read is fresher). The row it reads is the
one of the scan the ledger recorded for the source's run on the host; a run recorded without a scan (its scan was deleted) falls back to the
host's newest other row. No request is made here.
"""
import logging

logger = logging.getLogger(__name__)


def _key(name):
    from cveFeed.correlation import _norm, read_technology
    return _norm(read_technology(name or '')[0]) or (name or '').strip().lower()


def carry(scan, project_id, assets, service):
    """For the hosts of ``assets`` (``{ledger asset: host name}``: what ``service`` records a run against, a host or a ``host:port``), copy onto
    this scan's rows the technologies the row of the scan that last ran ``service`` on the host carries and this row lacks, less any product
    this row already names. Returns ``{host: [technology names carried]}``."""
    from cveFeed import ledger
    from cveFeed.models import ServiceRun
    from startScan.models import Subdomain
    hosts = {str(h) for h in assets.values() if h}
    if not hosts:
        return {}
    mine = {s.name: s for s in Subdomain.objects.filter(scan_history=scan, name__in=hosts).prefetch_related('technologies')}
    if not mine:
        return {}
    norm = {ledger._norm(a): h for a, h in assets.items()}
    last = {}  # host -> the newest scan id another run of the source was recorded under
    for asset, scan_id in ServiceRun.objects.filter(service=service, project_id=project_id, asset__in=list(norm), status='done') \
            .exclude(scan_id=scan.pk).values_list('asset', 'scan_id'):
        host = norm.get(asset)
        if host in mine and scan_id and scan_id > last.get(host, 0):
            last[host] = scan_id
    source = {}
    if last:
        for other in Subdomain.objects.filter(target_domain__project_id=project_id, scan_history_id__in=set(last.values()), name__in=list(last)) \
                .prefetch_related('technologies').order_by('-id'):
            if last.get(other.name) == other.scan_history_id and other.name not in source:
                source[other.name] = list(other.technologies.all())
    rest = [h for h in mine if h not in source]
    if rest:  # no scan recorded for the run (deleted since): the host's newest other row, as before
        for other in Subdomain.objects.filter(target_domain__project_id=project_id, name__in=rest).exclude(scan_history=scan) \
                .prefetch_related('technologies').order_by('-id').iterator(chunk_size=500):
            if other.name not in source and other.technologies.all():
                source[other.name] = list(other.technologies.all())
    through = Subdomain.technologies.through
    links, out = [], {}
    for host, techs in source.items():
        row = mine[host]
        have = {t.pk for t in row.technologies.all()}
        named = {_key(t.name) for t in row.technologies.all()}
        for tech in techs:
            if tech.pk in have or _key(tech.name) in named:
                continue
            links.append(through(subdomain_id=row.pk, technology_id=tech.pk))
            out.setdefault(host, []).append(tech.name)
    if links:
        through.objects.bulk_create(links, ignore_conflicts=True)
    return out
