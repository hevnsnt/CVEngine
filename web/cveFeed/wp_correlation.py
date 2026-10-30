"""CVE matches for WordPress plugins and themes, by exact identity.

A WordPress plugin CVE names the plugin by its title ("Cloudflare Image Resizing") and often its slug ("package"), and applies only to that plugin
at a version inside the advisory's bounded range. The general correlation treats a product name as a fuzzy lead; for a plugin that would link
every "forms" or "seo" CVE to every site, so this module is stricter: a plugin sighting (the slug, and its title when WPScan or a readme gave
one) matches an advisory only when the normalized slug or title **equals** the advisory's normalized product or package name, and the version
WPScan read is inside a bounded range. A plugin whose version was not read matches nothing. Matches have source ``wp-plugin``.

The sightings are ``ProbeObservation`` rows written by cveFeed.wpscan_scan (kind ``wp-plugin`` or ``wp-theme``)."""
import logging
import re
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

SOURCE = 'wp-plugin'
FRESH_DAYS = 14  # a sighting older than this is not carried onto a new scan's host row
STALE_REASON = ('Closed automatically: the plugin or theme is no longer reported on this host, or its version moved out of the advisory\'s '
                'affected range.')


def _norm(value):
    return re.sub(r'[^a-z0-9]', '', str(value or '').lower())


def sightings(project_id, host):
    """``[{'slug', 'title', 'version', 'kind'}]`` for the plugins and themes with a read version on ``host``."""
    from cveFeed.models import ProbeObservation
    rows = ProbeObservation.objects.filter(project_id=project_id, host=host.lower(), kind__in=('wp-plugin', 'wp-theme')).exclude(version='')
    return [{'slug': r.product, 'title': (r.evidence or {}).get('title', ''), 'version': r.version, 'kind': r.kind} for r in rows]


def match_rows(sub, found, cve_by_id, product_index, scan_history=None):
    """The CVEMatch rows for ``found`` sightings on ``sub``: exact slug or title identity and a version inside a bounded range."""
    from cveFeed.correlation import (affected_product_tokens, clean_affected, confidence_for, pair_split_ranges, parse_version, version_in_range)
    rows = []
    for sighting in found:
        version = parse_version(sighting['version'])
        names = {_norm(sighting['slug']), _norm(sighting['title'])} - {''}
        if version is None or not names:
            continue
        ids = set()
        for name in names:
            ids |= set(product_index.get(name, ()))
        for cid in ids:
            cve = cve_by_id.get(cid)
            if cve is None:
                continue
            for index, item in enumerate(clean_affected(cve.affected)):
                if not names & affected_product_tokens(item):
                    continue
                hit = next((rng for rng in pair_split_ranges(item.get('ranges') or []) if version_in_range(version, rng) is True), None)
                if hit is None:
                    continue
                rows.append({
                    'cve_entry_id': cve.id, 'subdomain_id': sub.id, 'source': SOURCE,
                    'matched_product': str(item.get('product') or item.get('package') or sighting['slug'])[:255],
                    'matched_version': sighting['version'][:100], 'version_in_range': True, 'confidence': confidence_for(version, True, cve.kev),
                    'scan_history_id': scan_history.id if scan_history else sub.scan_history_id, 'distro_status': 'no_data', 'distro_fixed_version': '',
                    'evidence': {'source': 'wpscan', 'plugin': sighting['slug'], 'kind': sighting['kind'], 'raw_version': sighting['version'][:100],
                                 'affected_index': index, 'range': {k: str(v)[:60] for k, v in hit.items() if k in ('introduced', 'fixed', 'lastAffected')}}})
                break
    return rows


def _close_stale(sub, current):
    from cveFeed.match_policy import unworked
    from cveFeed.models import CVEMatch
    # a match a person worked, a template confirmed or the host reported stays: the plugin missing from one scan is not evidence about it
    stale = [m for m in unworked(CVEMatch.objects.filter(subdomain=sub, source=SOURCE)).only('id', 'cve_entry_id', 'matched_product', 'ai_verdict', 'ai_reason')
             if (m.cve_entry_id, m.matched_product) not in current
             and not (m.ai_verdict == 'not_affected' and (m.ai_reason or '').startswith('Closed automatically:'))]
    if stale:
        CVEMatch.objects.filter(pk__in=[m.pk for m in stale]).update(ai_verdict='not_affected', confidence=0.0, ai_reason=STALE_REASON,
                                                                      updated_at=timezone.now())
    return len(stale)


def run_for_host(sub, pool=None):
    """Correlate one host's plugin and theme sightings; closes the matches whose plugin is gone. Returns the number of matches recorded. Never
    fatal: a failure leaves the sightings in place for the next pass."""
    from cveFeed import correlation
    try:
        cve_by_id, index = pool or correlation.cve_pool()
        found = sightings(sub.target_domain.project_id, sub.name)
        rows = match_rows(sub, found, cve_by_id, index)
        correlation.save_matches(rows)
        _close_stale(sub, {(r['cve_entry_id'], r['matched_product']) for r in rows})
        return len(rows)
    except Exception:  # noqa: BLE001
        logger.exception('could not correlate the WordPress plugins of host %s', sub.pk)
        return 0


def carry_forward(scan):
    """Correlate the plugin sightings of this scan's hosts: hosts are stored once per scan, so a fresh row has no plugin matches until this
    runs, even when WPScan itself is not due again. Only sightings seen in the last FRESH_DAYS."""
    from cveFeed import correlation
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    cutoff = timezone.now() - timedelta(days=FRESH_DAYS)
    hosts = set(ProbeObservation.objects.filter(project_id=scan.domain.project_id, kind__in=('wp-plugin', 'wp-theme'), observed_at__gte=cutoff)
                .values_list('host', flat=True))
    if not hosts:
        return 0
    pool = correlation.cve_pool()
    return sum(run_for_host(sub, pool) for sub in Subdomain.objects.filter(scan_history=scan, name__in=hosts).select_related('target_domain'))
