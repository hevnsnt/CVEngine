"""This period's most important vulnerabilities, for an email report and for ``GET reporting/threats``: what was announced and how many of your hosts it reaches.

Two sources, both already stored (nothing is fetched or scanned here, and no AI model is asked anything):

1. **Zero Wire briefings** published in the period (``cveFeed.zero_wire``), newest first, when an App Admin has them on. Each shows the briefing's title (linked to
   it) and its own one-sentence summary, which is the action to take. The briefing's text is third-party data: it is clipped here and escaped where shown.
2. **CVEs** that CISA added to its KEV catalog (or VulnCheck's) in the period, and CVEs published in the period with a CVSS of 9.0 or more and a public exploit or a
   high exploitation probability, that no briefing already covers. Their text is the stored summary, else the title and the start of the description.

Impact is two honest numbers, counted in distinct machines (``counts.with_host_key``: two names on the same addresses are one host):

- *N hosts match by version*: open CVE matches in the scope (not closed, not ruled out by the AI, not a false positive; ``confirmed`` of them reproduced by a check);
- *M more run <product>, version unknown*: hosts with a technology or open-port product the correlation machinery connects to the CVE (``tech_coverage.connect``) and
  no version read for it, that do not already match. A product with no version read can be neither ruled in nor out.

A briefing that names CVEs we hold is counted through them (merged per host); one that names none is matched by its product tags, through the same product-name
aliases correlation uses, with a stop-list for class tags (RCE, Memory corruption, CMS, ...).

Everything filters by the scope's project ids explicitly, because it runs in a worker with no request scope.
"""
import os
import re
from collections import defaultdict
from datetime import datetime

from django.db.models import Q
from django.db.models.fields.json import KT

from cveFeed import closure, correlation, counts, mailer, report_data, tech_coverage
from cveFeed.report_data import clean

TOP_DEFAULT, TOP_CEILING = 6, 12
CANDIDATES = 200  # CVEs read for a period
IMPACT_CANDIDATES = 100  # of those, how many get an impact count (the highest by KEV and CVSS)
FALSE_POSITIVES = report_data.FALSE_POSITIVES
# tags of a briefing that name a kind of flaw, a layer or a family rather than a product: never matched against what runs on a host
STOP_TAGS = frozenset({
    'rce', 'remote code execution', 'memory corruption', 'use-after-free', 'heap overflow', 'buffer overflow', 'out-of-bounds', 'integer overflow', 'type confusion',
    'runtime', 'cms', 'web server', 'reverse proxy', 'proxy', 'http', 'http/2', 'http/3', 'tls', 'ssl', 'dns', 'rest api', 'api', 'sql injection', 'sqli', 'xss',
    'privilege escalation', 'authentication bypass', 'auth bypass', 'command injection', 'command execution', 'deserialization', 'sandbox escape', 'denial of service',
    'dos', 'information disclosure', 'path traversal', 'ssrf', 'csrf', 'supply chain', 'appliance', 'kernel', 'linux', 'windows', 'browser', 'library', 'framework',
    'language', 'database', 'cloud', 'container', 'vpn', 'firewall', 'zero-day', 'exploited', 'critical', 'patch', 'update'})
SENTENCE = re.compile(r'(?<=[.!?])\s+')


def top_limit():
    """How many entries an email's section holds (``CVENGINE_DIGEST_TOP_VULNS``, 1 to 12)."""
    try:
        return min(TOP_CEILING, max(1, int(os.environ.get('CVENGINE_DIGEST_TOP_VULNS', ''))))
    except ValueError:
        return TOP_DEFAULT


# --- what was announced ----------------------------------------------------------------------------------------------------------

def candidates(start, end):
    """The CVEs that are news in ``[start, end)``: CISA (or VulnCheck) added them to KEV in it, or they were published in it with a CVSS of 9.0 or more and a public
    exploit or a high exploitation probability. A CVE that only works from the host itself (``local_only``) is left out: it never matches a host from outside. KEV
    first, then CVSS, at most CANDIDATES."""
    from cveFeed.models import CVEEntry
    first, last = start.date().isoformat(), end.date().isoformat()
    qs = CVEEntry.objects.filter(local_only=False).annotate(cisa_added=KT('intel__kev__cisa_kev__added'), vulncheck_added=KT('intel__kev__vulncheck_kev__added'))
    added = Q(kev=True) & (Q(cisa_added__gte=first, cisa_added__lt=last) | Q(vulncheck_added__gte=first, vulncheck_added__lt=last))
    critical = Q(published_at__gte=start, published_at__lt=end, cvss__gte=9.0) & (Q(epss_reached=True) | Q(exploit_db=True))
    return list(qs.filter(added | critical).order_by('-kev', '-cvss', 'cve_id')[:CANDIDATES])


def _kev(cve):
    """The first KEV listing of ``cve`` that has detail: ``{added, ransomware, name, vendor, product}`` (empty when none)."""
    for entry in ((cve.intel or {}).get('kev') or {}).values():
        if isinstance(entry, dict):
            return entry
    return {}


def _kev_added(cve):
    added = [str(e.get('added') or '')[:10] for e in ((cve.intel or {}).get('kev') or {}).values() if isinstance(e, dict)]
    return max([a for a in added if a], default='')


def _short_date(iso):
    try:
        moment = datetime.strptime(iso[:10], '%Y-%m-%d')
    except ValueError:
        return ''
    return f'{moment:%b} {moment.day}'


def writeup(cve):
    """A short plain description of a CVE from what is stored: its summary, else the first two sentences of its title and description, at most 320 characters."""
    if (cve.summary or '').strip():
        return clean(cve.summary, 320)
    text = clean(f'{cve.title or ""}. {cve.original_description or ""}'.strip('. '), 2000)
    return clean(' '.join(SENTENCE.split(text)[:2]), 320)


def _product(cve):
    kev = _kev(cve)
    if kev.get('product'):
        return clean(kev['product'], 40)
    for item in cve.affected or []:
        name = str(item.get('product') or item.get('package') or '').strip()
        if name:
            return clean(name, 40)
    return ''


# --- how many of your hosts ------------------------------------------------------------------------------------------------------

def _sightings(ids):
    """``[(host key, normalised sighting)]``: every technology and open-port product of the scope's current hosts, each with the machine it was seen on."""
    from startScan.models import OPEN_PORT_STATES, Port, Subdomain
    current = Subdomain._base_manager.filter(correlation.latest_scan_q()).filter(target_domain__project_id__in=list(ids)).values('pk')
    keys = dict(counts.with_host_key(Subdomain._base_manager.filter(pk__in=current)).values_list('pk', 'host_key'))
    seen, out = {}, []

    def add(sub_id, name, version, source, cpe):
        if sub_id not in keys or not name:
            return
        key = (name, version, source, cpe)
        if key not in seen:
            seen[key] = tech_coverage.normalise_sighting(name, version, source=source, cpe=cpe)
        out.append((keys[sub_id], seen[key]))
    for sub_id, name, cpe in Subdomain.technologies.through.objects.filter(subdomain_id__in=current).values_list('subdomain_id', 'technology__name', 'cpe'):
        add(sub_id, name, '', 'tech', cpe or '')
    ports = Port.objects.filter(ports__ip_addresses__in=current, state__in=OPEN_PORT_STATES).exclude(product='').exclude(product__isnull=True)
    for sub_id, product, version, cpe in ports.values_list('ports__ip_addresses', 'product', 'version', 'cpe'):
        add(sub_id, product, version or '', 'port', cpe or '')
    return out


def impact(ids, cves, sightings=None):
    """``{CVE id (the CVEEntry pk): {'matched': {host key}, 'confirmed': {host key}, 'product_only': {host key}}}`` for the scope's project ids (see the module text)."""
    from cveFeed.models import CVEMatch
    from startScan.models import Subdomain
    cves = list(cves)
    out = {c.id: {'matched': set(), 'confirmed': set(), 'product_only': set()} for c in cves}
    if not cves or not ids:
        return out
    rows = list(CVEMatch._base_manager.filter(cve_entry_id__in=list(out), subdomain__target_domain__project_id__in=list(ids)).filter(correlation.latest_scan_q('subdomain__'))
                .exclude(ai_verdict='not_affected').exclude(remediation_status__in=closure.CLOSED).exclude(triage__classification__in=FALSE_POSITIVES)
                .values_list('cve_entry_id', 'subdomain_id', 'template_result', 'triage__validation_status'))
    keys = dict(counts.with_host_key(Subdomain._base_manager.filter(pk__in={r[1] for r in rows})).values_list('pk', 'host_key')) if rows else {}
    for cve_id, sub_id, result, validation in rows:
        key = keys.get(sub_id)
        if key is None:
            continue
        out[cve_id]['matched'].add(key)
        if result == 'vulnerable' or validation == 'hit':
            out[cve_id]['confirmed'].add(key)
    index = correlation.build_product_index(cves)
    by_id = {c.id: c for c in cves}
    connected, unknown, versioned = {}, defaultdict(set), defaultdict(set)
    for host, s in (_sightings(ids) if sightings is None else sightings):
        token = (s['name'], s['cpe'])
        if token not in connected:
            connected[token] = tech_coverage.connect(s['name'], s['cpe'], index, by_id)['cves']
        for cve_id in connected[token]:
            (versioned if s['version'] else unknown)[cve_id].add(host)
    for cve_id, row in out.items():
        row['product_only'] = unknown[cve_id] - versioned[cve_id] - row['matched']
    return out


def _same_product(a, b):
    """Whether two product names are the same product: equal once normalised, or one is an alias of the other (``correlation.PRODUCT_ALIASES``)."""
    na, nb = correlation._norm(a), correlation._norm(b)
    if not na or not nb:
        return False
    return na == nb or nb in correlation.PRODUCT_ALIASES.get(na, ()) or na in correlation.PRODUCT_ALIASES.get(nb, ())


def category_products(categories):
    """The tags of a briefing that name a product, in order: every tag but the class tags of ``STOP_TAGS``."""
    return [c for c in categories or [] if c.strip().lower() not in STOP_TAGS]


def _plural(n, one, many):
    return f'{n} {one if n == 1 else many}'


def impact_line(matched, confirmed, product_only, product, scope_name):
    """The sentence under a threat, from the two counts: ``(sentence, 'matched' | 'product' | 'none')``."""
    product = product or 'the affected product'
    if matched:
        text = '1 of your hosts matches by version' if matched == 1 else f'{matched} of your hosts match by version'
        if confirmed:
            text += f' ({confirmed} confirmed by a check)'
        if product_only:
            text += f" · {product_only} more {'runs' if product_only == 1 else 'run'} {product}, version unknown"
        return text, 'matched'
    if product_only:
        return f"{product_only} of your hosts {'runs' if product_only == 1 else 'run'} {product}, version unknown", 'product'
    return f'No host in {scope_name} is known to run {product}.', 'none'


# --- the section -----------------------------------------------------------------------------------------------------------------

def _cve_badges(cve):
    badges = []
    kev = _kev(cve) if cve.kev else {}
    if cve.kev:
        added = _short_date(_kev_added(cve))
        badges.append(f'CISA KEV, added {added}' if added else 'CISA KEV')
    if kev.get('ransomware'):
        badges.append('Ransomware use known')
    if cve.cvss is not None:
        badges.append(f'CVSS {cve.cvss:g}')
    if cve.epss_reached:
        badges.append('High exploitation probability (EPSS)')
    if cve.exploit_db:
        badges.append('Public exploit')
    return badges


def _cve_entry(cve, row, scope, base, source):
    from agentapi import services as svc
    product = _product(cve)
    line, tone = impact_line(len(row['matched']), len(row['confirmed']), len(row['product_only']), product, scope.label)
    return {'source': source, 'title': clean(f"{cve.cve_id}: {cve.title or _kev(cve).get('name') or ''}".strip(': '), 200), 'summary': writeup(cve),
            'link': f'{base}/cve/cves/?id={cve.cve_id}', 'badges': _cve_badges(cve), 'cve_ids': [cve.cve_id], 'impact_line': line, 'impact': tone,
            'fixed_in': [clean(v, 60) for v in svc._fixed_versions(cve, product)[:4]], 'matched': len(row['matched']), 'confirmed': len(row['confirmed']),
            'product_only': len(row['product_only']), 'product': product, 'cvss': cve.cvss, 'kev_added': _kev_added(cve) or None}


def _briefing_entry(b, held, rows, sightings, scope, base):
    cves = [held[c] for c in b.cve_ids if c in held]
    matched, confirmed, product_only = set(), set(), set()
    for c in cves:
        matched |= rows[c.id]['matched']
        confirmed |= rows[c.id]['confirmed']
        product_only |= rows[c.id]['product_only']
    product_only -= matched
    product = (_product(cves[0]) if cves else '') or ''
    if not cves:  # it names no CVE we hold: match its product tags against what runs
        names = category_products(b.categories)
        product = names[0] if names else ''
        hosts = {h for h, s in sightings if any(_same_product(s['name'], n) for n in names)} if names else set()
        product_only, matched, confirmed = hosts, set(), set()
        if hosts:
            line, tone = f"{len(hosts)} of your hosts {'runs' if len(hosts) == 1 else 'run'} {product}", 'product'
        elif names:
            line, tone = f'No host in {scope.label} is known to run {product}.', 'none'
        else:
            line, tone = '', 'none'
    else:
        line, tone = impact_line(len(matched), len(confirmed), len(product_only), product, scope.label)
    badges = ['Cloudflare Zero Wire']
    if any(c.kev for c in cves):
        badges.append('CISA KEV')
    top = max((c.cvss for c in cves if c.cvss is not None), default=None)
    if top is not None:
        badges.append(f'CVSS {top:g}')
    if any(c.exploit_db for c in cves):
        badges.append('Public exploit')
    return {'source': 'zero_wire', 'title': clean(b.title, 200), 'summary': clean(b.summary, 400), 'link': b.link, 'badges': badges, 'cve_ids': list(b.cve_ids)[:8],
            'impact_line': line, 'impact': tone, 'fixed_in': [], 'matched': len(matched), 'confirmed': len(confirmed), 'product_only': len(product_only),
            'product': product, 'published': b.published_at.isoformat(), 'categories': list(b.categories)[:8]}


NOTE_ZERO_WIRE = "Briefings from Cloudflare Radar Zero Wire (radar.cloudflare.com/zero-wire); summaries quoted from the feed; host counts from cvENGINE's own scans."
NOTE_CVES = ("Picked from the CVEs CISA added to its Known Exploited Vulnerabilities catalog this period and new critical CVEs with a public exploit or a high exploitation "
             "probability. Host counts come from what scans identified; a product with no version read cannot be ruled in or out.")


def top(scope, start, end, limit=None):
    """``(entries, note)`` for ``scope`` (an ``agentapi.report_scope.ReportScope``) and the period ``[start, end)``: Zero Wire briefings first, then KEV and critical CVEs
    no briefing covers, at most ``limit`` (``top_limit()`` by default). ``note`` is the attribution and method footnote ('' when there are no entries)."""
    from cveFeed.models import CVEEntry, ReportingSettings, ZeroWireBriefing
    limit = limit or top_limit()
    base = mailer.base_url()
    briefings = []
    if ReportingSettings.current().zero_wire_enabled:
        briefings = list(ZeroWireBriefing.objects.filter(published_at__gte=start, published_at__lt=end).order_by('-published_at', '-id')[:limit])
    covered = {c for b in briefings for c in b.cve_ids}
    held = {c.cve_id: c for c in CVEEntry.objects.filter(cve_id__in=covered)} if covered else {}
    news = [c for c in candidates(start, end) if c.cve_id not in covered][:IMPACT_CANDIDATES] if len(briefings) < limit else []
    sightings = _sightings(scope.ids) if (briefings or news) else []
    rows = impact(scope.ids, [*held.values(), *news], sightings=sightings)
    entries = [_briefing_entry(b, held, rows, sightings, scope, base) for b in briefings]
    if len(entries) < limit:
        kev_in_period = {c.cve_id: _kev_added(c)[:10] >= start.date().isoformat() for c in news}

        def rank(c):
            row = rows[c.id]
            return (bool(row['matched']), bool(row['product_only']), kev_in_period[c.cve_id], bool(_kev(c).get('ransomware')), c.cvss or 0, _kev_added(c))
        for c in sorted(news, key=rank, reverse=True)[:limit - len(entries)]:
            entries.append(_cve_entry(c, rows[c.id], scope, base, 'kev' if c.kev and kev_in_period[c.cve_id] else 'critical'))
    note = ' '.join(n for n, on in ((NOTE_ZERO_WIRE, any(e['source'] == 'zero_wire' for e in entries)), (NOTE_CVES, any(e['source'] != 'zero_wire' for e in entries))) if on)
    return entries, note
