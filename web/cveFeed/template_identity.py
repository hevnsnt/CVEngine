"""The update's re-read of stored template findings for what their template says about the product (``manage.py backfill_template_identities``).

Two things a template hit says were not kept before:

* The CPE a ``http/technologies`` template names in its metadata (``tomcat-detect``: ``cpe:2.3:a:apache:tomcat``). The light pass now writes it on the
  host's technology link (``SubdomainTechnology.cpe``, ``nuclei_scan.tech_cpe_from``), so correlation matches the technology CPE first
  (``source_versions.technology_cpes``). A stored info finding of such a template (the blanket pass and an adopted result file them) gives it to the
  technology of the same name on the host's current row: the link takes the template's CPE, source ``nuclei_scan.TECH_SOURCE`` and, when it had none, the finding's date.
* The product an info-level panel hit names when it extracted no version (``panel_versions.identity``): an identity reading (``vsrc:panel``, outcome
  ``hidden``, with the template's CPE) and a technology with no version on the host's current row.

The hosts whose links or readings changed are correlated again (a product without a version is a lead, never a match). The walk goes through the
findings by id in passes of ``limit`` (``BackgroundCursor`` lane ``LANE`` keeps where it stopped, so a run cut short continues), and is idempotent.
"""
import logging

logger = logging.getLogger(__name__)

LANE = 'tmpl-identity'  # BackgroundCursor lane (not ``bf``: upgrade_backfills reads those lanes as its own)


def _candidates():
    """The stored info findings of the template scanner of a technology template that names a product, or of a panel template (tag ``panel``)."""
    from django.db.models import Q

    from cveFeed import nuclei_templates, panel_versions
    from startScan.models import Vulnerability
    named = sorted(nuclei_templates.technology_products())
    return (Vulnerability.objects.filter(source=panel_versions.FINDING_SOURCE, severity=0, subdomain__isnull=False, target_domain__isnull=False)
            .filter(Q(template_id__in=named) | Q(tags__name=panel_versions.PANEL_TAG)).exclude(template_id__isnull=True).exclude(template_id=''))


def _cursor():
    from cveFeed.models import BackgroundCursor
    return BackgroundCursor.objects.get_or_create(lane=LANE)[0]


def _position():
    from cveFeed.models import BackgroundCursor
    return BackgroundCursor.objects.filter(lane=LANE).values_list('last_pk', flat=True).first() or 0


def reset():
    from cveFeed.models import BackgroundCursor
    BackgroundCursor.objects.filter(lane=LANE).delete()


def _tech_line(vuln):
    """A stored finding as the result line of a technology template, as far as it was stored (no metadata: the installed template's is read)."""
    return {'template-id': vuln.template_id or '', 'matcher-name': vuln.matcher_name or '', 'matched-at': vuln.http_url or '',
            'extracted-results': list(vuln.extracted_results or []), 'info': {'name': vuln.name or '', 'severity': 'info'}}


def _link_cpe(sub, name, cpe, seen_at):
    """Give the link of ``sub``'s technology ``name`` (or of the row of the same product and version, ``tech_rows.key``) the template's CPE.
    Returns whether a link changed."""
    from cveFeed import nuclei_scan, tech_rows
    from startScan.models import SubdomainTechnology
    wanted = tech_rows.key(name)
    for link in SubdomainTechnology.objects.filter(subdomain=sub).select_related('technology'):
        tech = link.technology.name or ''
        if tech != name and (wanted is None or tech_rows.key(tech) != wanted):
            continue
        if link.cpe == cpe:
            return False
        link.cpe, link.source = cpe[:255], nuclei_scan.TECH_SOURCE
        link.observed_at = link.observed_at or seen_at
        link.save(update_fields=['cpe', 'source', 'observed_at'])
        return True
    return False


def read_pass(limit=500):
    """Read the next ``limit`` candidate findings after the cursor. Returns ``{'findings', 'links', 'readings', 'hosts', 'matches', 'done'}``."""
    from cveFeed import correlation, nuclei_scan, nuclei_templates, panel_versions, source_versions
    from startScan.models import Subdomain
    cursor = _cursor()
    vulns = list(_candidates().filter(id__gt=cursor.last_pk).select_related('subdomain').distinct().order_by('id')[:limit])
    out = {'findings': len(vulns), 'links': 0, 'readings': 0, 'hosts': 0, 'matches': 0, 'done': len(vulns) < limit}
    if not vulns:
        return out
    tech_products, panels = nuclei_templates.technology_products(), nuclei_templates.panel_products()
    rows, moved, identities = {}, set(), {}

    def current(vuln):
        key = (vuln.subdomain.target_domain_id, vuln.subdomain.name)
        if key not in rows:
            rows[key] = source_versions._current_row(*key)
        return rows[key]

    for vuln in vulns:
        try:
            tags = list(vuln.tags.values_list('name', flat=True))
            if panel_versions.PANEL_TAG in tags:
                got = panel_versions.identity(panel_versions._line_of(vuln, tags), panels)
                if got and current(vuln) is not None:
                    identities.setdefault(current(vuln).pk, (current(vuln), []))[1].append(got)
                continue
            line = _tech_line(vuln)
            cpe = nuclei_scan.tech_cpe_from(line, tech_products)
            name = nuclei_scan.tech_name_from(line) if cpe else ''
            sub = current(vuln) if name else None
            if sub is not None and _link_cpe(sub, name, cpe, vuln.discovered_date):
                out['links'] += 1
                moved.add(sub.pk)
        except Exception:  # noqa: BLE001 - one stored finding never stops the walk
            logger.exception('template identity of finding %s could not be read', vuln.pk)
    for sub, readings in identities.values():
        try:
            count, changed = panel_versions.store(sub, readings)
        except Exception:  # noqa: BLE001 - one host's stored data never stops the walk
            logger.exception('panel identity catch-up of host %s failed', sub.pk)
            continue
        out['readings'] += count
        if changed:
            moved.add(sub.pk)
    out['hosts'] = len(moved)
    if moved:
        cve_by_id, index = correlation.cve_pool()
        ids = sorted(moved)
        for start in range(0, len(ids), 200):
            subs = list(Subdomain.objects.filter(pk__in=ids[start:start + 200]).select_related('target_domain', 'scan_history')
                        .prefetch_related('technologies', 'ip_addresses__ports'))
            out['matches'] += correlation.correlate_subdomains(subs, index, cve_by_id, min_confidence=0.4)[1]
    cursor.last_pk = vulns[-1].pk
    cursor.save(update_fields=['last_pk', 'updated_at'])
    return out


def pending():
    """How many candidate findings the walk has not read yet."""
    return _candidates().filter(id__gt=_position()).distinct().count()
