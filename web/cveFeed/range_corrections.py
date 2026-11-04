"""Sourced corrections to an advisory's affected ranges, applied wherever a CVE's ranges are stored.

cvENGINE takes a CVE's ranges from the structured records (the CVE List V5 record of the CNA, and cve.now, which carries the CVE List's and
OSV's): those win over anything the description says, and nothing is ever parsed out of the description text. A record can still be narrower
than what is known: CVE-2020-11022's CNA record and its GitHub advisory GHSA-gxr4-xjj5-5px2 were edited (July 2026) to start the affected
range at jQuery 1.12.0, the release that introduced ``jQuery.htmlPrefilter`` (the advisory's workaround needs it), while every jQuery from
1.2 expands self-closing tags in the HTML it inserts, which is the flaw: NVD's CPE configuration keeps ``versionStartIncluding 1.2`` and
Exploit-DB 49766 is a working exploit for jQuery 1.2. Taking the record as it is would miss every page on jQuery 1.2 to 1.11.x.

A correction is data: the CVE, the products it applies to (by name, the last part of a package coordinate), the bound it replaces and the
value it replaces it with, and the public sources that state the wider range. It changes only that exact bound, so when a feed changes the
bound again the correction stops applying and the feed's new value stands. The corrected block says so (``range_corrections``: from, to,
sources), so a reviewer sees which bound is the record's and which is cvENGINE's. ``manage.py apply_range_corrections`` applies them to
CVEs already stored (a dry run unless ``--apply``)."""
import re

CORRECTIONS = (
    {
        'cve': 'CVE-2020-11022',
        'names': ('jquery',),
        'field': 'introduced', 'from': '1.12.0', 'to': '1.2.0',
        'sources': ('https://nvd.nist.gov/vuln/detail/CVE-2020-11022 (CPE cpe:2.3:a:jquery:jquery, versionStartIncluding 1.2)',
                    'https://www.exploit-db.com/exploits/49766 (jQuery 1.2 - Cross-Site Scripting)'),
        'why': 'every jQuery from 1.2 expands self-closing tags in inserted HTML; 1.12.0 only added jQuery.htmlPrefilter, which the '
               'advisory\'s workaround overrides',
    },
)


def _name(item):
    """The product a block names, reduced to its last coordinate part: ``org.webjars.npm:jquery`` and ``components/jquery`` are jquery,
    ``jquery-rails`` is not."""
    text = str(item.get('package') or item.get('product') or '')
    return re.sub(r'[^a-z0-9]', '', re.split(r'[/:]', text.lower())[-1])


def apply(cve_id, affected):
    """``(affected, changed)``: ``affected`` with every correction for ``cve_id`` applied, and how many ranges changed. Blocks it does not
    touch are returned as they were."""
    wanted = [c for c in CORRECTIONS if c['cve'] == str(cve_id or '').upper()]
    if not wanted or not isinstance(affected, list):
        return affected, 0
    out, changed = [], 0
    for item in affected:
        if not isinstance(item, dict) or not isinstance(item.get('ranges'), list):
            out.append(item)
            continue
        notes = list(item.get('range_corrections') or [])
        ranges = list(item['ranges'])
        for correction in wanted:
            if _name(item) not in correction['names']:
                continue
            for i, rng in enumerate(ranges):
                if isinstance(rng, dict) and str(rng.get(correction['field']) or '') == correction['from']:
                    ranges[i] = {**rng, correction['field']: correction['to']}
                    changed += 1
                    note = {'field': correction['field'], 'from': correction['from'], 'to': correction['to'],
                            'sources': list(correction['sources']), 'why': correction['why']}
                    if note not in notes:
                        notes.append(note)
        out.append({**item, 'ranges': ranges, 'range_corrections': notes} if notes else item)
    return out, changed


def _widened_hosts(correction):
    """``{project slug: hosts}`` of the current inventory whose technologies name a product the correction applies to at a version the
    corrected bound adds (``to`` up to, not including, ``from``): the hosts whose matches the next correlation may add."""
    from django.db.models import Q

    from cveFeed.correlation import latest_scan_q, parse_version, split_name_version
    from startScan.models import Subdomain
    low, high = parse_version(correction['to']), parse_version(correction['from'])
    if correction['field'] != 'introduced' or low is None or high is None:
        return {}
    out = {}
    query = None
    for name in correction['names']:
        part = Q(technologies__name__istartswith=f'{name}:')
        query = part if query is None else query | part
    rows = (Subdomain.objects.filter(latest_scan_q()).filter(query).distinct()
            .values_list('id', 'target_domain__project__slug', 'technologies__name'))
    seen = set()
    for pk, slug, tech in rows.iterator(chunk_size=2000):
        product, version = split_name_version(tech or '')
        parsed = parse_version(version)
        if re.sub(r'[^a-z0-9]', '', (product or '').lower()) in correction['names'] and parsed is not None and low <= parsed < high:
            if (pk, slug) not in seen:
                seen.add((pk, slug))
                out[slug or '-'] = out.get(slug or '-', 0) + 1
    return out


def backfill(apply=False):
    """Apply ``CORRECTIONS`` to the CVEs already stored. Returns ``{'cves': {cve id: ranges changed}, 'hosts': {project slug: hosts}}``:
    the CVEs whose stored ranges change and, per project, the current hosts whose version falls in a span a correction adds (their
    matches come at the next correlation). With ``apply`` the ranges are written, the CVE is marked for re-correlation and its cached match
    verdicts are dropped (as a feed refresh that changes a range does); without it nothing is written."""
    from django.db import transaction

    from cveFeed.models import CVEEntry, MatchVerdict
    out = {'cves': {}, 'hosts': {}}
    for cve in CVEEntry.objects.filter(cve_id__in=sorted({c['cve'] for c in CORRECTIONS})).only('id', 'cve_id', 'affected'):
        new, changed = apply_to(cve)
        if not changed:
            continue
        out['cves'][cve.cve_id] = changed
        for correction in (c for c in CORRECTIONS if c['cve'] == cve.cve_id):
            for slug, count in _widened_hosts(correction).items():
                out['hosts'][slug] = out['hosts'].get(slug, 0) + count
        if apply:
            with transaction.atomic():
                CVEEntry.objects.filter(pk=cve.pk).update(affected=new, needs_recorrelation=True)
                MatchVerdict.objects.filter(cve_entry_id=cve.pk).delete()
    return out


def apply_to(cve):
    """``(affected, changed)`` for one stored CVEEntry."""
    return apply(cve.cve_id, cve.affected)
