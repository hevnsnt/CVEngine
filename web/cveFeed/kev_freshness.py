"""A KEV match is raised only on a version read in the last day.

A CVE that joins the KEV, or a feed refresh that gives it a range, is correlated against every host's current inventory at once. That inventory
is what the host's last scan read: a technology fingerprint that can be days old, while the site may have upgraded since (a WordPress
fingerprint read at 7.1.3 two days before a KEV entry for "through 7.1.3", on a site already on 7.1.4). A KEV match is what pages people, so
before a NEW one is raised from a technology fingerprint (``source`` tech) the version it stands on must have been read within FRESH_HOURS:
by the scan that recorded it, or since by a probe (``ProbeObservation``) or the route check (the front page's fingerprints) that read the same
product at the same version. Otherwise the match is held (not created) and the host's version is read again (``reread``: the same version and
identity probes a scan runs, which re-correlate the host); the next correlation after a fresh reading raises it, or, when the host moved past
the range, never does. A match that already exists is updated as usual: only raising one is gated. A host whose reading time is unknown (a
row with no scan and no discovery date) is not held: nothing says it is stale."""
import logging
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

FRESH_HOURS = 24
REREAD_LOCK_SECONDS = 6 * 3600  # one re-read of a host per this many seconds, however many correlations hold its matches
MAX_REREAD_HOSTS = 50           # hosts one call asks to be read again


def _key(name):
    from cvengine_scanner import cms
    return cms.key(name)


def _read_times(subdomain_ids):
    """``{subdomain id: (project id, host, when the scan that holds the row read it)}``."""
    from startScan.models import Subdomain
    out = {}
    for pk, project, host, started, stopped, discovered in Subdomain.objects.filter(pk__in=subdomain_ids).values_list(
            'id', 'target_domain__project_id', 'name', 'scan_history__start_scan_date', 'scan_history__stop_scan_date', 'discovered_date'):
        out[pk] = (project, (host or '').lower(), stopped or started or discovered)
    return out


def _fresh_readings(hosts, since):
    """``{(project id, host): {(product key, version)}}`` read by a probe or the route check since ``since``."""
    from cveFeed.correlation import split_name_version
    from cveFeed.models import ProbeObservation, RouteAuth
    projects = {p for p, _h in hosts if p}
    names = {h for _p, h in hosts}
    out = {}
    if not projects or not names:
        return out
    for project, host, product, version in ProbeObservation.objects.filter(
            project_id__in=projects, host__in=names, outcome='found', observed_at__gte=since).exclude(version='').values_list(
            'project_id', 'host', 'product', 'version'):
        out.setdefault((project, host), set()).add((_key(product), version))
    for project, host, evidence in RouteAuth.objects.filter(project_id__in=projects, host__in=names, path='/', checked_at__gte=since).values_list(
            'project_id', 'host', 'evidence'):
        for name in (evidence or {}).get('fingerprint_names') or [] if isinstance(evidence, dict) else []:
            product, version = split_name_version(str(name))
            if version:
                out.setdefault((project, host), set()).add((_key(product), version))
    return out


def hold(rows, now=None):
    """``(kept, held)``: the new match ``rows`` (CVEMatch field dicts, not saved yet) split into those that may be raised and those held
    because they are KEV matches made from a technology fingerprint older than FRESH_HOURS that nothing has read again since."""
    from cveFeed.models import CVEEntry
    from startScan.models import Technology
    candidates = [r for r in rows if r.get('source') == 'tech' and r.get('matched_version')]
    if not candidates:
        return list(rows), []
    now = now or timezone.now()
    since = now - timedelta(hours=FRESH_HOURS)
    # the reading times first (one query): after a scan every row is fresh and nothing more is asked
    times = _read_times({r['subdomain_id'] for r in candidates})
    stale = [r for r in candidates if r['subdomain_id'] in times and times[r['subdomain_id']][2] is not None
             and times[r['subdomain_id']][2] < since]
    if not stale:
        return list(rows), []
    kev = set(CVEEntry.objects.filter(pk__in={r['cve_entry_id'] for r in stale}, kev=True).values_list('pk', flat=True))
    stale = [r for r in stale if r['cve_entry_id'] in kev]
    if not stale:
        return list(rows), []
    readings = _fresh_readings({times[r['subdomain_id']][:2] for r in stale}, since)
    tech_ids = {(r.get('evidence') or {}).get('source_id') for r in stale}
    tech_names = dict(Technology.objects.filter(pk__in={t for t in tech_ids if isinstance(t, int)}).values_list('id', 'name'))
    from cveFeed.correlation import split_name_version
    held_ids = set()
    for r in stale:
        project, host, _when = times[r['subdomain_id']]
        product = split_name_version(tech_names.get((r.get('evidence') or {}).get('source_id')) or '')[0] or r.get('matched_product') or ''
        if (_key(product), r['matched_version']) in readings.get((project, host), set()):
            continue  # read again since, at the same version: the fingerprint stands
        held_ids.add(id(r))
    kept = [r for r in rows if id(r) not in held_ids]
    held = [r for r in rows if id(r) in held_ids]
    return kept, held


def request_reread(subdomain_ids):
    """Ask for the version of these hosts to be read again (at most MAX_REREAD_HOSTS, each at most once per REREAD_LOCK_SECONDS). Never
    raises: a held match waits for the next scan when the request cannot be queued."""
    from django.core.cache import cache
    due = []
    for pk in sorted(set(subdomain_ids)):
        try:
            if cache.add(f'cvengine:kev-reread:{pk}', 1, REREAD_LOCK_SECONDS):
                due.append(pk)
        except Exception:  # noqa: BLE001 - no cache: ask anyway, the task itself is cheap and bounded
            due.append(pk)
        if len(due) >= MAX_REREAD_HOSTS:
            break
    if not due:
        return 0
    try:
        from django.db import transaction

        from cveFeed.tasks import reread_stale_fingerprints
        transaction.on_commit(lambda: reread_stale_fingerprints.delay(due))
    except Exception:  # noqa: BLE001
        logger.warning('could not queue a version re-read for %d host(s); their KEV matches wait for the next scan', len(due), exc_info=True)
        return 0
    return len(due)


def reread(subdomain_ids):
    """Read the version of each host again, through a Sentinel, with the web probes a scan runs for its products (the front page's headers and generator, the
    WordPress probe and the like), then correlate it again whatever they found, so a held KEV match is raised on a fresh reading or not at
    all. A host of a passive or manual only target, an excluded or archived host, or one whose project is paused is left for its next scan.
    Returns the number of hosts read."""
    from cveFeed import probes
    from cveFeed.archive_rediscovery import archived_names
    from cveFeed.exclusions import is_excluded
    from cveFeed.match_policy import unversioned_products
    from reNgine import resources
    from startScan.models import Subdomain
    from targetApp.models import Domain
    read = 0
    subs = Subdomain.objects.filter(pk__in=list(subdomain_ids)[:MAX_REREAD_HOSTS]).select_related('target_domain').prefetch_related(
        'technologies', 'ip_addresses__ports')
    for sub in subs:
        target = sub.target_domain
        if target is None or getattr(target, 'discovery_mode', '') in (Domain.DISCOVERY_PASSIVE, Domain.DISCOVERY_MANUAL):
            continue
        project = target.project_id
        if resources.global_pause_requested(fail_closed=True):
            break
        if is_excluded(project, sub.name) or sub.name.lower() in archived_names(project):
            continue
        from cveFeed.correlation import split_name_version
        leads = [{'name': split_name_version(t.name)[0], 'source': 'tech'} for t in sub.technologies.all() if ':' in t.name]
        leads += unversioned_products(sub)
        plan = [e for e in probes.plan_for_host(sub, leads) if e['family'] == 'http']
        for entry in plan:
            try:
                probes.run_one(project, target.id, sub, entry)
            except resources.ScannerUnavailable as exc:  # no scanner can take the probes (they never run here): the host is read at its next scan
                logger.info('version re-read waits for a scanner: %s', exc)
                return read
            except Exception as exc:  # noqa: BLE001 - one probe failing never stops the rest; the next scan reads the host anyway
                logger.info('version re-read %s on host %s failed: %s', entry['probe'], sub.pk, type(exc).__name__)
        probes.recorrelate(sub)
        read += 1
    return read
