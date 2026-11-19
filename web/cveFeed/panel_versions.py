"""The version a panel template read: nuclei's ``http/exposed-panels`` templates (tag ``panel``) often extract the product's exact version from the
login page (Grafana's ``subTitle``, Jenkins's ``X-Jenkins`` header, FortiNAC's ``"version"``). A result was only a finding; here an info-level panel
hit that names a product and extracted a version-shaped value also becomes a version reading of the host, so correlation matches it.

Where it is stored. A first-party version reading (``ProbeObservation``, probe ``vsrc:panel``, ``cveFeed.source_versions``), like the other
sources' readings: a product reading of kind ``version`` is also added to the host's technologies (``Grafana:10.2.3``, through
``version_sources.store_readings``), so correlation, search (``tech:grafana@10.2``, ``vsource:panel``) and the AI read it like any
technology, and it keeps where it came from (the template, the URL, the values extracted, the CPE). The reading carries the CPE the template names
(``cpe:2.3:a:grafana:grafana:10.2.3``), so correlation matches it CPE first (``source_versions.technology_cpes``); a fresh scan's host row takes it
again from the reading (``probes.apply_known``), as a finding is reused.

The product. From the template: its ``info.metadata`` ``vendor`` and ``product`` (else its ``classification.cpe``), which map to CVE records. A
result line from a Sentinel, and a finding stored before, carry no metadata: it is read from the installed template of that id
(``nuclei_templates.panel_products``). The name the reading is stored under is the template's ``info.name`` without "Login Panel - Detect" and the
like (``product_name``) when that names the same product, else the metadata product (with its vendor in front when the product alone is a generic
word: Citrix's ``gateway`` is "Citrix Gateway"). A template with neither names its product only by its ``info.name``.

The version. Only a value that looks like one (``version_of``): it starts with a digit and is dotted, at most ``MAX_VERSION`` characters, no build
hash, no date. Several: the highest (``nuclei_scan._version_order``, as the technology pass). A version is never invented.

No version. A panel hit that extracts none (FortiGate's SSL VPN page, GlobalProtect, Ivanti Connect Secure) still names the product: it is an identity
reading (``identity``: ``cveFeed.identity_readings``, outcome ``hidden``, with the CPE the template names of any part, so ``os:fortios`` finds FortiOS's
own panel) and a technology with no version (``bare_technology``: "Fortinet FortiGate SSL VPN", unless a technology of the host already names the
product). ``tech:fortigate@unknown``, ``vsource:panel`` and ``component:`` find it, the version source and edge build reads take it as a lead
(``version_sources.host_products``), and correlation as a lead, never a match (``identities.collect_leads``). It never replaces a version reading of the
same product the panel source stored.

Never a downgrade. A reading is stored only when no other source states a version of the same product on the host (a technology, an open port's
product or CPE, another first-party reading), or every one that does is a less precise form of the panel's (``10.2`` for ``10.2.3``). The same
version, or another one, from another source stands; the panel's is not added next to it.
"""
import logging
import re
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

PANEL_TAG = 'panel'
FINDING_SOURCE = 'nuclei'  # Vulnerability.source of a template finding (reNgine.definitions.NUCLEI)
MAX_VERSION = 30
INFO = 'info'
# what a panel template's name says about the page, not the product: "Grafana Login Panel - Detect", "Jenkins Login Detected", "Zabbix Admin"
_SUFFIX = re.compile(r'(?:^|[\s:\u2013\u2014-]+)(?:login|log[\s-]?in|logon|sign[\s-]?in|panel|detect|detected|detection|admin|administrator|'
                     r'administration|dashboard|page|interface|exposed|exposure|discovery|web\s?ui|ui)\s*$', re.IGNORECASE)
_HEX_RUN = re.compile(r'[0-9a-f]{7,}', re.IGNORECASE)  # a git or build hash inside a value ("2.1.0-a5565ad3")
_DATE = re.compile(r'^(?:19|20)\d\d\.(?:0[1-9]|1[0-2])\.(?:0[1-9]|[12]\d|3[01])$')  # 2024.01.15: a build date, not a release


def _tags(line):
    info = line.get('info') or {}
    tags = info.get('tags') if info.get('tags') is not None else line.get('tags')
    if isinstance(tags, str):
        tags = tags.split(',')
    return {str(t).strip().lower() for t in tags or () if str(t).strip()}


def is_panel_hit(line):
    """Whether a nuclei result line is an info-level hit of a panel template (tag ``panel``)."""
    info = line.get('info') or {}
    return str(info.get('severity') or '').lower() == INFO and PANEL_TAG in _tags(line)


def product_name(name):
    """A panel template's name without what it says about the page: "Grafana Login Panel - Detect" -> "Grafana", "Jenkins Login Detected" ->
    "Jenkins", "Fortinet FortiSIEM - Panel" -> "Fortinet FortiSIEM"."""
    from cveFeed import version_catalogue as catalogue
    text = catalogue.clip(name, 120)
    while True:
        shorter = _SUFFIX.sub('', text).strip()
        if shorter == text or not shorter:
            break
        text = shorter
    return re.sub(r'[\s:\u2013\u2014-]+$', '', text).strip()[:100]


def version_of(value):
    """The version a value a template extracted states, or '': it starts with a digit and is dotted (``source_versions``'s rule for a version a
    source states), at most ``MAX_VERSION`` characters, correlation can read it, and it is no build hash or date."""
    from cveFeed import source_versions
    from cveFeed import version_catalogue as catalogue
    from cveFeed.correlation import parse_version
    text = catalogue.clip(value, 80).lstrip('vV')
    if not text or len(text) > MAX_VERSION or not source_versions._STATED.match(text):
        return ''
    if _HEX_RUN.search(text) and re.search(r'[a-f]', _HEX_RUN.search(text).group(0), re.IGNORECASE):
        return ''
    if _DATE.match(text) or parse_version(text) is None:
        return ''
    return text


def highest_version(values):
    """The highest version among the values a template extracted, or '' (nuclei hands several back in no fixed order: the highest is read the
    same way every run, the technology pass's rule)."""
    from cveFeed.nuclei_scan import _version_order
    found = {v for v in (version_of(value) for value in values or () if isinstance(value, str)) if v}
    return max(found, key=_version_order) if found else ''


def _metadata(line, index=None):
    """``(vendor, product, part)`` the template names: from the line's ``info.metadata`` and ``classification.cpe``, else the installed template of
    that id (``nuclei_templates.panel_products``, ``nuclei_templates.line_metadata``)."""
    from cveFeed import nuclei_templates
    return nuclei_templates.line_metadata(line, index)


def _words(value):
    return ' '.join(w if any(c.isupper() for c in w) else w.capitalize() for w in re.split(r'[\s_]+', value) if w)


def _product(line, index=None):
    """``(label, vendor, product, part)`` of the product a panel hit names (see the module); ``vendor``, ``product`` and ``part`` are '' when the
    template names none."""
    from cveFeed import correlation
    name = product_name((line.get('info') or {}).get('name') or '')
    vendor, product, part = _metadata(line, index)
    if not product:
        return name, '', '', ''
    words = product.replace('_', ' ')
    if name and correlation.name_matches_token(correlation._norm(name), correlation._norm(words)):
        label = name
    else:
        label = _words(words)
        alone = re.findall(r'[a-z0-9]+', words)
        if vendor and (not correlation._word_run_ok(tuple(alone)) or (len(alone) == 1 and alone[0] in correlation.DESCRIPTOR_WORDS)):
            label = f'{_words(vendor)} {label}'
    return label[:80], vendor, product, part


def product_of(line, index=None):
    """``(name, CPE prefix)`` of the product a panel hit names (see the module), or ``('', '')``. The CPE prefix (``cpe:2.3:a:grafana:grafana``)
    is given only for an application CPE."""
    label, vendor, product, part = _product(line, index)
    cpe = f'cpe:2.3:a:{vendor}:{product}' if vendor and product and part in ('', 'a') else ''
    return label, cpe


def _port(url):
    try:
        parts = urlsplit(url if '://' in (url or '') else f'//{url or ""}')
        return parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError:
        return 0


def identity(line, index=None):
    """The identity reading a panel hit that states no version gives (``identity_readings.reading``'s shape, with ``port`` and ``template``), or
    None: not an info-level panel hit, a version-shaped value extracted (``reading`` reads it), or no product named. It carries the CPE the template
    names, of any part (``cpe:2.3:o:fortinet:fortios`` for FortiOS's own panel: ``os:fortios`` finds it), and is never a version: correlation reads
    it as a lead, never a match (``identities.collect_leads``)."""
    if not is_panel_hit(line) or highest_version(line.get('extracted-results') or []):
        return None
    label, vendor, product, part = _product(line, index)
    if not label:
        return None
    from cveFeed import identity_readings, nuclei_templates, source_versions
    url = str(line.get('matched-at') or line.get('host') or '')
    template = str(line.get('template-id') or '')[:120]
    got = identity_readings.reading(label, source_versions.PANEL_SOURCE, evidence=f'{template}: the panel names the product, no version',
                                    url=url, cpe=nuclei_templates.cpe_prefix(vendor, product, part))
    if not got:
        return None
    got['template'] = template
    got['port'] = _port(url)
    return got


def reading(line, index=None):
    """The version reading a panel hit gives (``source_versions.product_reading``'s shape, with ``port``), or None: not an info-level panel hit,
    no product named, or no version-shaped value extracted."""
    if not is_panel_hit(line):
        return None
    version = highest_version(line.get('extracted-results') or [])
    if not version:
        return None
    label, cpe = product_of(line, index)
    if not label:
        return None
    from cveFeed import js_libraries, source_versions
    from cveFeed.correlation import split_name_version, stored_technology_name
    stored = js_libraries.unversioned(stored_technology_name(f'{label}:{version}'))
    label, version = split_name_version(stored)  # a JavaScript library's version is read from its own file, never from a page (js_libraries)
    if not (label and version):
        return None
    url = str(line.get('matched-at') or line.get('host') or '')
    template = str(line.get('template-id') or '')[:120]
    got = source_versions.product_reading(label, version, source_versions.PANEL_SOURCE, url=url,
                                          evidence=f'{template}: {", ".join(str(v) for v in (line.get("extracted-results") or [])[:5])}',
                                          cpe=f'{cpe}:{version}' if cpe else '')
    if not got:
        return None
    got['template'] = template
    got['port'] = _port(url)
    return got


# ----------------------------------------------------------------------------- never a downgrade

def _refines(other, mine):
    """Whether ``mine`` is ``other`` stated more precisely (``10.2`` -> ``10.2.3``)."""
    other, mine = (other or '').strip().lower().lstrip('v'), (mine or '').strip().lower().lstrip('v')
    return bool(other) and mine != other and (mine.startswith(other + '.') or mine.startswith(other + '-'))


def _same(token, tokens):
    from cveFeed.correlation import name_matches_token
    return any(token == t or name_matches_token(token, t) for t in tokens if t)


def stated_elsewhere(sub, r):
    """The versions other sources state for the product of reading ``r`` on ``sub``: its technologies (less the ones this source added), the
    product and CPE of its open ports, and the other first-party readings."""
    from cveFeed import source_versions
    from cveFeed.correlation import _norm, parse_cpe, read_technology, split_port_product
    from cveFeed.models import ProbeObservation
    from startScan.models import open_services
    cpe = parse_cpe(r.get('cpe') or '')
    tokens = {_norm(r['label'])} | ({cpe[1]} if cpe else set())
    project, host = sub.target_domain.project_id, sub.name.lower().rstrip('.')
    rows = list(ProbeObservation.objects.filter(project_id=project, host=host, kind='version', outcome='found').exclude(version=''))
    own = {f'{row.product}:{row.version}' for row in rows if row.probe == source_versions.PANEL_PROBE}
    out = []
    for tech in sub.technologies.all():
        if tech.name in own:
            continue
        name, version = read_technology(tech.name)
        if version and _same(_norm(name), tokens):
            out.append(version)
    for ip in sub.ip_addresses.all():
        for port in open_services(ip):
            name, version, _rest = split_port_product(port.product, port.version)
            port_cpe = parse_cpe(port.cpe or '')
            if version and (_same(_norm(name), tokens) or (port_cpe and cpe and port_cpe[1] == cpe[1])):
                out.append(version)
    for row in rows:
        if row.probe != source_versions.PANEL_PROBE and _same(_norm(row.product), tokens):
            out.append(row.version)
    return out


def superseded(sub, r):
    """Whether another source already states a version of the product that the panel's does not refine (the same one included)."""
    return any(not _refines(other, r['version']) for other in stated_elsewhere(sub, r))


# ----------------------------------------------------------------------------- storing

def _versioned(sub, label):
    """Whether a version reading of ``label`` is already stored for ``sub`` under ``vsrc:panel`` (on any port)."""
    from cveFeed import source_versions
    from cveFeed.models import ProbeObservation
    return ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=sub.name.lower().rstrip('.'), probe=source_versions.PANEL_PROBE,
                                           kind='version', product=label, outcome='found').exclude(version='').exists()


def bare_technology(sub, r, now=None):
    """Link the product an identity reading names to ``sub`` as a technology with no version (``Fortinet FortiGate SSL VPN``), its CPE and source
    on the link, unless a technology of the host already names the product (at any version). Returns whether a link was added."""
    from cveFeed import source_versions, tech_rows
    from cveFeed.correlation import _norm, parse_cpe, read_technology
    cpe = parse_cpe(r.get('cpe') or '')
    tokens = {_norm(r['label'])} | ({cpe[1]} if cpe else set())
    if any(_same(_norm(read_technology(t.name or '')[0]), tokens) for t in sub.technologies.all()):
        return False
    from django.utils import timezone
    sub.technologies.add(tech_rows.technology(r['label']), through_defaults={
        'source': source_versions.PANEL_PROBE, 'cpe': (r.get('cpe') or '')[:255], 'observed_at': now or timezone.now()})
    return True


def store(sub, readings):
    """Store ``readings`` (``reading``'s and ``identity``'s) of one host under ``vsrc:panel``, each on its port, except a version reading another source
    supersedes (``superseded``) and an identity reading of a product the panel source already holds a version of (a version reading of the same
    product, from this pass or one before, stands: an identity never replaces it). The product an identity reading names is also linked as a
    technology with no version (``bare_technology``). Returns ``(stored, whether something new or changed was stored)``."""
    from cveFeed import source_versions, version_sources
    if sub is None or sub.target_domain_id is None:
        return 0, False
    stored, changed = 0, False
    by_port, named = {}, []
    for r in readings:
        if r and r.get('version') and not superseded(sub, r):
            by_port.setdefault(r['port'], {})[r['label']] = r
    versioned = {label for kept in by_port.values() for label in kept}
    for r in readings:
        if r and not r.get('version') and r['label'] not in versioned and not _versioned(sub, r['label']):
            by_port.setdefault(r['port'], {}).setdefault(r['label'], r)
            named.append(r)
    for port, kept in by_port.items():
        count, moved = version_sources.store_readings(sub, source_versions.PANEL_PROBE, list(kept.values()), port=port)
        stored += count
        changed = changed or moved
    for r in {r['label']: r for r in named}.values():
        if bare_technology(sub, r):
            changed = True
    return stored, changed


class Collector:
    """The panel readings of one template pass, stored per host when a chunk is in (``flush``): a host whose readings are new or changed is
    correlated again. Never fatal: the findings stand without it."""

    def __init__(self):
        self.pending = {}  # host row pk -> (row, [readings])
        self.index = None
        self.stored = 0

    def offer(self, line, sub):
        if sub is None or not is_panel_hit(line):
            return
        try:
            if self.index is None:
                from cveFeed import nuclei_templates
                self.index = nuclei_templates.panel_products()
            got = reading(line, self.index) or identity(line, self.index)
        except Exception:  # noqa: BLE001 - one odd result line never stops the pass
            logger.exception('panel version of a nuclei result could not be read')
            return
        if got:
            self.pending.setdefault(sub.pk, (sub, []))[1].append(got)

    def flush(self):
        from django.db import transaction

        from cveFeed import probes
        pending, self.pending = self.pending, {}
        for sub, readings in pending.values():
            try:
                with transaction.atomic():  # a savepoint: inside a caller's transaction (an adopted result) one host's failure leaves the rest usable
                    count, changed = store(sub, readings)
                    if changed:
                        probes.recorrelate(sub)
                self.stored += count
            except Exception:  # noqa: BLE001
                logger.exception('panel versions of host %s could not be stored', sub.pk)


# ----------------------------------------------------------------------------- the update's catch-up

def _line_of(vuln, tags):
    """A stored finding as the result line it came from, as far as it was stored: the template id, its name, info severity, its tags, the
    extracted values and the URL (no metadata: ``_metadata`` reads the installed template)."""
    return {'template-id': vuln.template_id or '', 'matched-at': vuln.http_url or '', 'extracted-results': list(vuln.extracted_results or []),
            'info': {'name': vuln.name or '', 'severity': INFO, 'tags': tags}}


def catch_up(apply=False, batch=200):
    """The one-time catch-up an update runs (``manage.py backfill_panel_versions --apply``): the stored info-level panel findings (tag ``panel``)
    with extracted values are read again as panel readings (newest first, one per host, template and port), stored on the host's current row,
    and the hosts that gained or changed one are correlated. Idempotent. Returns ``{'findings', 'readings', 'hosts', 'matches'}``."""
    from cveFeed import correlation, nuclei_templates, source_versions
    from startScan.models import Subdomain, Vulnerability
    qs = (Vulnerability.objects.filter(source=FINDING_SOURCE, severity=0, tags__name=PANEL_TAG, subdomain__isnull=False, extracted_results__len__gt=0)
          .select_related('subdomain').distinct().order_by('-id'))
    index = nuclei_templates.panel_products()
    out = {'findings': 0, 'readings': 0, 'hosts': 0, 'matches': 0}
    seen, by_host = set(), {}
    for vuln in qs.iterator(chunk_size=500):
        tags = list(vuln.tags.values_list('name', flat=True))
        r = reading(_line_of(vuln, tags), index)
        if r is None:
            continue
        key = (vuln.subdomain.target_domain_id, vuln.subdomain.name, vuln.template_id, r['port'])
        if key in seen:
            continue  # an older finding of the same template on the same host and port: the newest one stands
        seen.add(key)
        out['findings'] += 1
        by_host.setdefault((vuln.subdomain.target_domain_id, vuln.subdomain.name), []).append(r)
    if not apply:
        out['hosts'] = len(by_host)
        return out
    moved = []
    for (domain_id, host), readings in by_host.items():
        sub = source_versions._current_row(domain_id, host)
        if sub is None:
            continue
        try:
            count, changed = store(sub, readings)
        except Exception:  # noqa: BLE001 - one host's stored data never stops the catch-up
            logger.exception('panel version catch-up of host %s failed', sub.pk)
            continue
        out['readings'] += count
        if changed:
            moved.append(sub.pk)
    out['hosts'] = len(moved)
    if moved:
        cve_by_id, index = correlation.cve_pool()
        for start in range(0, len(moved), batch):
            subs = list(Subdomain.objects.filter(pk__in=moved[start:start + batch]).select_related('target_domain', 'scan_history')
                        .prefetch_related('technologies', 'ip_addresses__ports'))
            out['matches'] += correlation.correlate_subdomains(subs, index, cve_by_id, min_confidence=0.4)[1]
    return out
