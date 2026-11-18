"""Every version a source already sent: the exact product versions and CPEs that data cvENGINE already receives carries, stored as version
readings (``ProbeObservation``, probe ``vsrc:<source>``) so they become technologies or matchable readings instead of display text.
No request is made here: everything below reads what a scan, a Sentinel's result or a third-party sync already handed over.

First-party readings (our own scans: fresh, ``exact``; a product reading becomes a technology of the host, a language runtime goes to the
runtime rules of ``cveFeed.version_sources``):

  vsrc:nmap      what the port scan stored on each port beyond the product and version it already matches: the other application CPEs nmap
                 printed (``extra.cpes``; the first one is ``Port.cpe`` and is matched with the port), the CPE of a port nmap named no
                 product for, the modules nmap's ``extrainfo`` lists (``(CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16``), the Server and generator
                 lines of ``http-server-header`` and ``http-generator``, and the versions the database scripts read (``mysql-info``,
                 ``redis-info``, ``memcached-info``, ``mongodb-info``, ``ms-sql-info``) and ``ntp-info``. A reading the port row already states
                 (same product, same version) is not stored twice. Derived from the stored ports: refreshed with the other stored-data
                 readings (``version_sources.refresh_host``), and dropped when the port no longer says it.
  vsrc:testssl   testssl.sh's ``banner_server`` and ``banner_application`` items (the Server and X-Powered-By headers it read), per tested port.
  vsrc:wpscan    the ``headers`` interesting finding of a WordPress scan (``Server: Apache/2.4.29 (Ubuntu)``, ``X-Powered-By: PHP/7.2.24``).
  vsrc:db-probe  the version a credential-less database probe's reply states (``PONG (redis 7.2.4)``, ``PostgreSQL 15.4``, ``(MySQL 8.0.35)``,
                 ``VERSION 1.6.21``, ``cluster x, version 8.11.1``), per port.

Third-party readings (kind and outcome ``reported``): passive data another service collected at some earlier time, never a technology:

  vsrc:shodan-idb  a versioned CPE bbot's ``shodan_idb`` module (Shodan's InternetDB) gives a discovered host (``cpe:/a:openbsd:openssh:8.9p1``).
                   InternetDB states no scan date: the reading is dated when cvENGINE received it, and marked ``undated``.
  vsrc:runzero     the operating system and its version runZero's inventory states for an address (``os``, ``os_version``), dated by the
                   asset's ``last_seen``.

The freshness rule (``in_use``). A reported reading is matched (``collect_reported``: correlation source ``tech``, the CPE first, confidence at
most ``REPORTED_CONFIDENCE``, never proof of a version) only while all of these hold, and is otherwise shown and searched but matched to nothing,
so the next correlation closes a match it made:

  1. it is at most ``REPORTED_MAX_AGE_DAYS`` old (its source's date, else when it was received);
  2. nothing first-party names the same product on the host: a technology, a port's product or CPE (a closed port counts: our scan saw the
     product and saw it go), or a first-party reading. A first-party reading always wins, whatever its version and however old the
     third-party one is, and a product our scan saw with no version is not given the third-party version either;
  3. when it names a port, our own scan of that port does not show it closed or answering with another product.

Tenancy: a reading belongs to the project of the host it was stored for (the discovery's target, the project whose runZero sync wrote the
address's block); correlation reads only the rows of the host's own project.
"""
import logging
import re
from datetime import datetime, timedelta

from django.db.models import Q
from django.utils import timezone

from cveFeed import version_catalogue as catalogue

logger = logging.getLogger(__name__)

PREFIX = 'vsrc:'
NMAP_PROBE = 'vsrc:nmap'
TESTSSL_PROBE = 'vsrc:testssl'
WPSCAN_PROBE = 'vsrc:wpscan'
DB_PROBE = 'vsrc:db-probe'
SHODAN_PROBE = 'vsrc:shodan-idb'
RUNZERO_PROBE = 'vsrc:runzero'
FIRST_PARTY_PROBES = (NMAP_PROBE, TESTSSL_PROBE, WPSCAN_PROBE, DB_PROBE)
REPORTED_PROBES = (SHODAN_PROBE, RUNZERO_PROBE)
PROBES = FIRST_PARTY_PROBES + REPORTED_PROBES
SEARCH = {p[len(PREFIX):]: p for p in PROBES}  # vsource:<name>
REPORTED = 'reported'               # ProbeObservation kind and outcome of a third-party reading: never a technology, never a first-party read
REPORTED_MAX_AGE_DAYS = 90          # older than this, a third-party reading is not matched (version_sources.STALE_DAYS, the Java runtime's rule)
REPORTED_CONFIDENCE = 0.5           # the most a match made from a third-party reading can carry: a candidate to validate
SHODAN_PROVIDER = 'shodan_idb'
RUNZERO_PROVIDER = 'runzero'
MAX_READINGS_PER_PORT = 12
_STATED = re.compile(r'^v?\d{1,5}\.\d{1,9}[0-9A-Za-z.()+~_-]{0,50}$')  # a version as a source states it: 8.9p1, 1.0.2k-fips, 15.2(4)M7; never a bare major
_MIN_CONTAIN = 4                    # a product token this short is compared whole, never by containment

_CPE_RE = re.compile(r'^cpe:(?:/|2\.3:)a:([^:\s]*):([^:\s]+)(?::([^:\s]*))?', re.IGNORECASE)
_MODULE_RE = re.compile(r'(?<![\w.])([A-Za-z][A-Za-z0-9_.+-]{1,30})/v?(\d[^\s(),;]{0,30})')
_MYSQL = re.compile(r'(?mi)^\s*Version:\s*(\d[\w.+~-]{0,60})')
_SAME_VERSION = re.compile(r'(?mi)^\s*Version:\s*(\d[\w.+~-]{0,40})')
_MONGO = re.compile(r'(?mi)^\s*version\s*=\s*(\d[\w.+-]{0,40})')
_MSSQL = re.compile(r'(?mi)^\s*number:\s*(\d{1,2}\.\d{1,2}\.\d{1,5}(?:\.\d{1,5})?)')
_NTP = re.compile(r'(?mi)^\s*version:\s*ntpd\s+(\d[\w.]{0,30})')
_MARIADB = re.compile(r'^(?:5\.5\.5-)?(\d+\.\d+\.\d+)-MariaDB', re.IGNORECASE)
SCRIPT_PRODUCTS = (  # (script id, pattern, product)
    ('redis-info', _SAME_VERSION, 'Redis'),
    ('memcached-info', _SAME_VERSION, 'Memcached'),
    ('mongodb-info', _MONGO, 'MongoDB'),
    ('ms-sql-info', _MSSQL, 'Microsoft SQL Server'),
    ('ntp-info', _NTP, 'NTP'),
)
# the exact evidence lines a Sentinel's db_probe returns (client/dbprobe.py of the Sentinel): one pattern per database, anchored
DB_REPLIES = (
    ('Redis', re.compile(r'^PONG \(redis (\d[\w.]{0,30})\)$')),
    ('Memcached', re.compile(r'^VERSION (\d[\w.]{0,30})$')),
    ('PostgreSQL', re.compile(r'^PostgreSQL (\d[\w.]{0,30})(?: \(.{0,120}\))?$')),
    ('Elasticsearch', re.compile(r'^cluster .{0,200}, version (\d[\w.-]{0,30})$')),
    ('MySQL', re.compile(r'^connected as root with no password \(MySQL (\d[\w.+~-]{0,60})\)$')),
)


# ----------------------------------------------------------------------------- reading what sources said (pure)

def _component(label):
    return re.sub(r'[^a-z0-9]+', '-', (label or '').lower()).strip('-')[:60]


def product_reading(label, version, source, evidence='', url='', cpe=''):
    """One exact product reading in ``version_catalogue.reading``'s shape, or None when ``version`` states no version. A language runtime
    (PHP, Python, Ruby ...) is returned as the runtime reading it is (``version_catalogue.from_technology``)."""
    label = catalogue.clip(label, 80)
    version = catalogue.clip(version, 60).lstrip('vV') if _STATED.match(catalogue.clip(version, 60)) else ''
    if not label or not version:
        return None
    runtime = catalogue.from_technology(label, version)
    if runtime:
        out = {**runtime, 'source': source, 'evidence': catalogue.clip(evidence) or runtime['evidence'], 'url': catalogue.clip(url, 300)}
    else:
        out = catalogue.reading(_component(label), label, version, evidence=evidence, url=url, source=source)
    if cpe:
        out['cpe'] = catalogue.clip(cpe, 200)
    return out


def cpe_reading(cpe, source, evidence=''):
    """The product reading an application CPE states (``cpe:/a:openbsd:openssh:8.9p1``): named as the CPE's product, the CPE kept for
    correlation's CPE-first matching. None for an operating system or hardware CPE, or one without a version."""
    found = _CPE_RE.match(str(cpe or '').strip())
    if not found:
        return None
    version = found.group(3) or ''
    if version in ('*', '-'):
        return None
    label = found.group(2).replace('_', ' ').strip()
    return product_reading(label, version, source, evidence=evidence or str(cpe), cpe=str(cpe).strip())


def header_readings(headers, source, url='/'):
    """The readings response headers state (``{lowercase name: value}``): every versioned product the shared header parser reads
    (``cvengine_scanner.versions.parse_headers``: the Server header and its modules, X-Powered-By, the version headers, X-Generator, Via) and the
    runtime readers of ``version_catalogue.from_headers``."""
    from cvengine_scanner import versions
    headers = {str(k).lower(): catalogue.clip(v, 300) for k, v in (headers or {}).items() if v}
    out = []
    for item in versions.parse_headers(headers):
        name, _sep, version = item['name'].partition(':')
        if not version or name == versions.ASP_NET_RUNTIME:  # the CLR line is the runtime readers' (an inferred .NET Framework line)
            continue
        header = item['source'].partition(':')[2] or 'server'
        got = product_reading(name, version, source, evidence=f'{header}: {headers.get(header, "")}', url=url)
        if got:
            out.append(got)
    out += [{**r, 'source': source} for r in catalogue.from_headers(headers, url=url)]
    return _unique(out)


def _modules(extrainfo, source):
    """The modules and runtimes a Server-header style ``extrainfo`` lists (nmap prints what follows the web server's own version there)."""
    from cvengine_scanner import versions
    out = []
    for name, version in _MODULE_RE.findall(str(extrainfo or '')[:300]):
        key = name.lower()
        product = versions.MODULE_PRODUCTS.get(key) or (name if re.match(r'^mod_[a-z0-9_]{1,26}$', key) else None)
        if product:
            got = product_reading(product, version, source, evidence=f'extrainfo: {extrainfo}')
            if got:
                out.append(got)
    return out


def script_readings(scripts):
    """The readings the reviewed NSE scripts of one port state (``Port.extra['scripts']``)."""
    from cvengine_scanner import versions
    scripts = scripts if isinstance(scripts, dict) else {}
    out = []
    text = str(scripts.get('mysql-info') or '')[:4000]
    found = _MYSQL.search(text)
    if found:
        version = found.group(1)
        maria = _MARIADB.match(version)
        got = (product_reading('MariaDB', maria.group(1), 'nse:mysql-info', evidence=f'mysql-info Version: {version}') if maria
               else product_reading('MySQL', version, 'nse:mysql-info', evidence=f'mysql-info Version: {version}'))
        out.append(got)
    for script, pattern, product in SCRIPT_PRODUCTS:
        found = pattern.search(str(scripts.get(script) or '')[:4000])
        if found:
            out.append(product_reading(product, found.group(1), f'nse:{script}', evidence=f'{script}: {found.group(0).strip()}'))
    for line in str(scripts.get('http-server-header') or '').splitlines()[:4]:
        out += header_readings({'server': line.strip()}, 'nse:http-server-header')
    for line in str(scripts.get('http-generator') or '').splitlines()[:4]:
        got = versions.parse_generator(line)
        if got and got[1]:
            out.append(product_reading(got[0], got[1], 'nse:http-generator', evidence=f'generator: {line.strip()}'))
    return [r for r in out if r]


def port_readings(port):
    """What one stored port states beyond the product and version the port row itself is matched by: the other application CPEs, the CPE of
    a port with no product, the modules of ``extrainfo`` and the NSE script versions. The port's own reading is left out."""
    from cveFeed.correlation import _norm, parse_cpe
    extra = port.extra if isinstance(port.extra, dict) else {}
    out = []
    own = parse_cpe(port.cpe or '')
    cpes = [c for c in (extra.get('cpes') or []) if isinstance(c, str)][:8]
    if (port.product or '').strip():
        cpes = [c for c in cpes if c.strip() != (port.cpe or '').strip() and (parse_cpe(c) or (None, None))[1] != (own or (None, None))[1]]
    elif port.cpe and port.cpe not in cpes:
        cpes.insert(0, port.cpe)  # nmap named no product, only the CPE: correlation skips the port, so the CPE is the reading
    out += _modules(port.service_extra, 'nmap-extrainfo')
    out += script_readings(extra.get('scripts'))
    for got in (cpe_reading(c, 'nmap-cpe', evidence=f'nmap CPE {c}') for c in cpes):
        if not got:
            continue
        twin = next((r for r in out if r['component'] == got['component'] and r['kind'] == got['kind']), None)
        if twin is None:
            out.append(got)
        elif _same_version(got['version'], twin['version']):
            twin['cpe'] = got['cpe']  # the banner's spelling (1.0.2k-fips) with the CPE's product: one reading
    token, version = _norm(port.product or ''), (port.version or '').strip()
    return [r for r in _unique(out) if not (version and _same_version(r['version'], version) and _names_port(r['label'], token))
            ][:MAX_READINGS_PER_PORT]


def _names_port(label, port_token):
    """Whether a reading names the port's own product (nmap's "Apache httpd" is the Server header's "Apache HTTP Server"): the same product
    token, or the same first word."""
    from cveFeed.correlation import _norm
    if _same_product(_norm(label), {port_token}):
        return True
    first = re.match(r'[a-z0-9]+', (label or '').lower())
    return bool(first and len(first.group(0)) >= 3 and port_token.startswith(first.group(0)))


def nmap_readings(sub, ports):
    """``[(port number, reading)]`` of every stored open port of a host (``ports``: ``[(address, port)]``, ``version_sources._ports``)."""
    out, seen = [], set()
    for _address, port in ports:
        if port.state not in ('', 'open'):
            continue
        for r in port_readings(port):
            key = (port.number, r['component'], r['kind'], r['version'])
            if key not in seen:
                seen.add(key)
                out.append((port.number, r))
    return out


def testssl_readings(items, port=0):
    """The readings of testssl.sh's banner items (``banner_server``: the Server header; ``banner_application``: X-Powered-By and the like)."""
    headers = {}
    for item in items or ():
        if not isinstance(item, dict):
            continue
        finding = catalogue.clip(item.get('finding'), 300)
        if not finding or finding.lower().startswith(('no ', 'not ', '--', '(no')):
            continue
        if item.get('id') == 'banner_server':
            headers.setdefault('server', finding)
        elif item.get('id') == 'banner_application':
            name, sep, value = finding.partition(':')
            if sep and re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,40}', name.strip()):
                headers.setdefault(name.strip().lower(), value.strip())
    return header_readings(headers, 'testssl', url=f'port {port}' if port else '/')


def wpscan_readings(report):
    """The readings of a WordPress scan's ``headers`` interesting finding (its ``interesting_entries`` are ``Name: value`` header lines)."""
    headers = {}
    for item in (report or {}).get('interesting_findings') or []:
        if not isinstance(item, dict) or item.get('type') != 'headers':
            continue
        for entry in (item.get('interesting_entries') or [])[:20]:
            name, sep, value = str(entry).partition(':')
            if sep and re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,40}', name.strip()):
                headers.setdefault(name.strip().lower(), value.strip())
    return header_readings(headers, 'wpscan', url='/')


def db_readings(reply):
    """The reading a db_probe reply states, or ``[]``. Only the exact lines the Sentinel writes are read (anchored), so text a database
    sends cannot make another product's reading."""
    text = catalogue.clip(reply, 300)
    for product, pattern in DB_REPLIES:
        found = pattern.match(text)
        if found:
            maria = _MARIADB.match(found.group(1)) if product == 'MySQL' else None
            got = product_reading('MariaDB' if maria else product, maria.group(1) if maria else found.group(1), 'db_probe', evidence=text)
            return [got] if got else []
    return []


def reported_cpe(tech):
    """The third-party reading a technology string bbot reported is, when it is a versioned application CPE (only Shodan's InternetDB hands bbot
    CPEs), else None: anything else is a technology like any other."""
    return cpe_reading(tech, SHODAN_PROVIDER, evidence=f'Shodan InternetDB CPE {catalogue.clip(tech, 200)}')


def runzero_readings(block):
    """The operating system reading of an address's runZero block (``os``, ``os_version``), dated by the asset's ``last_seen``, or ``[]``."""
    if not isinstance(block, dict):
        return []
    os_name, os_version = catalogue.clip(block.get('os'), 100), catalogue.clip(block.get('os_version'), 100)
    if not os_name or not _STATED.match(os_version):
        return []
    label = re.sub(rf'\s*{re.escape(os_version)}\s*$', '', os_name).strip() or os_name
    got = product_reading(label, os_version, RUNZERO_PROVIDER, evidence=f'runZero os: {os_name}; os_version: {os_version}')
    return [got] if got else []


def _unique(readings):
    seen, out = set(), []
    for r in readings:
        if not r:
            continue
        key = (r['component'], r['kind'], r['version'])
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def _same_version(a, b):
    a, b = (a or '').strip().lower(), (b or '').strip().lower()
    return bool(a and b) and (a == b or b.startswith(a + ' ') or b.startswith(a + '-') or a.startswith(b + '-'))


def _same_product(token, tokens):
    """Whether a product token names the same product as one of ``tokens`` (whole, or one inside the other for tokens of four or more
    characters). Deliberately loose: it only ever decides that a third-party reading gives way, or that a reading is not stored twice."""
    if not token:
        return False
    for other in tokens:
        if not other:
            continue
        if token == other or (len(token) >= _MIN_CONTAIN and len(other) >= _MIN_CONTAIN and (token in other or other in token)):
            return True
    return False


# ----------------------------------------------------------------------------- storing

def _host(sub):
    return sub.name.lower().rstrip('.')


def store_port(sub, probe, port, readings, now=None):
    """Store one port's first-party ``readings`` of ``sub`` under ``probe`` (products become technologies, runtimes go to the runtime rules:
    ``version_sources.store_readings``) and drop that probe's rows of the port the source no longer states. Returns whether anything moved."""
    from cveFeed import version_sources
    from cveFeed.models import ProbeObservation
    if sub.target_domain_id is None:
        return False
    readings = [r for r in readings if r][:MAX_READINGS_PER_PORT]
    changed = version_sources.store_readings(sub, probe, readings, port=port, now=now)[1] if readings else False
    kept = {(version_sources.kind_of(r), r['label']) for r in version_sources.expand(readings) if r['kind'] != 'java'}
    for row in ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=_host(sub), probe=probe, port=port):
        if (row.kind, row.product) not in kept:
            row.delete()
            changed = True
    return changed


def _reported_observation(r, provider, reported_at, port=0, undated=False):
    from cveFeed import probes
    when = reported_at.isoformat() if isinstance(reported_at, datetime) else str(reported_at or '')
    evidence = {'confidence': r['confidence'], 'line_only': r['line_only'], 'component': r['component'], 'source': provider, 'said': r['evidence'],
                'version_source': True, 'reported': True, 'provider': provider, 'reported_at': when[:40],
                **({'undated': True} if undated else {}), **({'cpe': r['cpe']} if r.get('cpe') else {})}
    return probes._observation(REPORTED, r['label'], r['version'], '', REPORTED, REPORTED_CONFIDENCE, f'{provider}'[:48], port=port,
                               url=r.get('url') or '', evidence=evidence)


def store_reported(project_id, domain_id, host, probe, readings, provider, reported_at, port=0, undated=False, replace=False, now=None):
    """Store third-party ``readings`` of a host of ``project_id`` (kind and outcome ``reported``: never a technology, never read as a first-party
    fact). ``replace`` drops the probe's rows of the host the readings no longer name. Returns whether anything moved."""
    from cveFeed import probes
    from cveFeed.models import ProbeObservation
    host = (host or '').lower().rstrip('.')
    if not project_id or not domain_id or not host:
        return False
    observations = [_reported_observation(r, provider, reported_at, port=port, undated=undated) for r in readings if r]
    rows = ProbeObservation.objects.filter(project_id=project_id, host=host, probe=probe)
    before = {(o.kind, o.product, o.port): (o.version, (o.evidence or {}).get('reported_at')) for o in rows}
    changed = False
    if observations:
        probes.record(project_id, domain_id, host, probe, observations, now=now)
        changed = any(before.get((o['kind'], o['product'], o['port'])) != (o['version'], o['evidence']['reported_at']) for o in observations)
    if replace:
        keep = {(o['kind'], o['product'], o['port']) for o in observations}
        gone = [row.pk for row in rows if (row.kind, row.product, row.port) not in keep]
        if gone:
            ProbeObservation.objects.filter(pk__in=gone).delete()
            changed = True
    return changed


def store_bbot_reported(subdomain, readings, now=None):
    """Store what Shodan's InternetDB told bbot about a discovered host (``reported_cpe``), dated when it was received (InternetDB states no date)."""
    if not readings or subdomain is None or subdomain.target_domain_id is None:
        return False
    now = now or timezone.now()
    return store_reported(subdomain.target_domain.project_id, subdomain.target_domain_id, subdomain.name, SHODAN_PROBE, readings, SHODAN_PROVIDER,
                          now, undated=True, now=now)


def _runzero_block(ip, project_id, configured=None):
    """The runZero block of ``ip`` when it belongs to ``project_id``: written by that project's sync, or (a block written before the project was
    recorded) the project has a runZero token of its own or its organization's."""
    block = ((ip.fingerprint or {}).get('runzero') or {}) if isinstance(ip.fingerprint, dict) else {}
    if not isinstance(block, dict) or not block:
        return None
    owner = block.get('project_id')
    if owner is not None:
        return block if owner == project_id else None
    if configured is None:
        from cveFeed import runzero_sync
        configured = runzero_sync.configured_project_ids()
    return block if project_id in configured else None


def refresh_runzero(sub, configured=None, now=None):
    """Store the operating system readings runZero's blocks state for the addresses of ``sub`` (its own project's blocks only) and drop the ones
    no block states any more. Returns whether anything moved."""
    if sub.target_domain_id is None:
        return False
    project_id = sub.target_domain.project_id
    readings, when = [], None
    for ip in sub.ip_addresses.all():
        block = _runzero_block(ip, project_id, configured)
        if block:
            got = runzero_readings(block)
            readings += got
            if got:
                when = block.get('last_seen') or block.get('updated') or when
    return store_reported(project_id, sub.target_domain_id, sub.name, RUNZERO_PROBE, _unique(readings), RUNZERO_PROVIDER, when or '',
                          undated=not when, replace=True, now=now)


def refresh_host(sub, ports, now=None):
    """The stored-data part (``version_sources.refresh_host`` calls it): the nmap readings of the host's stored ports and its runZero readings.
    Returns ``(nmap readings, whether anything moved)``."""
    from cveFeed import version_sources
    now = now or timezone.now()
    found = nmap_readings(sub, ports)
    changed = version_sources._store_derived(sub, NMAP_PROBE, found, now)
    try:
        changed = refresh_runzero(sub, now=now) or changed
    except Exception:  # noqa: BLE001 - a malformed block never stops the host's other readings
        logger.exception('runZero readings of host %s failed', sub.pk)
    return found, changed


def store_testssl(sub, port, items):
    """After a TLS audit of ``sub``'s ``port``: store what testssl.sh's banner items state. Returns whether anything moved."""
    return store_port(sub, TESTSSL_PROBE, port, testssl_readings(items, port))


def store_wpscan(sub, url, report):
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url or '')
        port = parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError:
        port = 0
    return store_port(sub, WPSCAN_PROBE, port, wpscan_readings(report))


def store_db(sub, port, reply):
    return store_port(sub, DB_PROBE, port, db_readings(reply))


# ----------------------------------------------------------------------------- the freshness rule and correlation

def _rows(sub):
    rows = getattr(sub, '_source_rows', None)
    if rows is None:
        from cveFeed.models import ProbeObservation
        if sub.target_domain_id is None:
            return []
        rows = list(ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=_host(sub), probe__in=PROBES))
        sub._source_rows = rows  # read once per correlation of the host (the CPE map and the reported readings both read them)
    return rows


def prefetch(subs):
    """Give each of ``subs`` its source reading rows (``_source_rows``) in one query (``correlation.correlate_subdomains``)."""
    from cveFeed.models import ProbeObservation
    from targetApp.models import Domain
    subs = [s for s in subs if getattr(s, 'target_domain_id', None)]
    if not subs:
        return
    project_of = dict(Domain.objects.filter(id__in={s.target_domain_id for s in subs}).values_list('id', 'project_id'))
    by_key = {}
    for row in ProbeObservation.objects.filter(project_id__in=set(project_of.values()), host__in={_host(s) for s in subs}, probe__in=PROBES):
        by_key.setdefault((row.project_id, row.host), []).append(row)
    for sub in subs:
        sub._source_rows = by_key.get((project_of.get(sub.target_domain_id), _host(sub)), [])


def technology_cpes(sub):
    """``{technology name: CPE}`` for the technologies a first-party CPE reading made (``vsrc:nmap`` from nmap's other CPEs), so correlation
    matches them CPE first like the port row's own CPE."""
    out = {}
    for row in _rows(sub):
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        if row.probe in FIRST_PARTY_PROBES and row.kind == 'version' and row.outcome == 'found' and row.version and ev.get('cpe'):
            out[f'{row.product}:{row.version}'] = ev['cpe']
    return out


def _reported_at(row):
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    text = ev.get('reported_at')
    if isinstance(text, str) and text:
        try:
            when = datetime.fromisoformat(text.replace('Z', '+00:00'))
            return when if timezone.is_aware(when) else timezone.make_aware(when)
        except ValueError:
            pass
    return row.observed_at


def first_party(sub):
    """``(product tokens, CPE products, {port number: [(state, product token)]})`` of what our own scans saw on ``sub``: its technologies, every
    port row of its addresses (closed ones too) with its CPEs, and its first-party readings."""
    from cveFeed.correlation import _norm, parse_cpe, split_name_version
    tokens, cpes, ports = set(), set(), {}
    for tech in sub.technologies.all():
        tokens.add(_norm(split_name_version(tech.name or '')[0]))
    for ip in sub.ip_addresses.all():
        for port in ip.ports.all():
            if (port.source or '') == 'bbot' and not port.product:
                continue  # an open port bbot reported (Shodan's InternetDB among its sources) is not a scan of the service
            token = _norm(port.product or '')
            tokens.add(token)
            extra = port.extra if isinstance(port.extra, dict) else {}
            for cpe in [port.cpe, *(extra.get('cpes') or [])]:
                parsed = parse_cpe(cpe) if isinstance(cpe, str) else None
                if parsed:
                    cpes.add(parsed[1])
            ports.setdefault(port.number, []).append((port.state or 'open', token))
    for row in _rows(sub):
        if row.probe in FIRST_PARTY_PROBES:
            tokens.add(_norm(row.product))
            parsed = parse_cpe((row.evidence or {}).get('cpe') or '') if isinstance(row.evidence, dict) else None
            if parsed:
                cpes.add(parsed[1])
    tokens.discard('')
    return tokens, cpes, ports


def verdict(row, seen, now=None):
    """Why a reported reading is not matched (``aged``, ``superseded``, ``port_closed``, ``port_other_product``), or '' when it is (``in_use``).
    ``seen`` is ``first_party(sub)``."""
    from cveFeed.correlation import _norm, parse_cpe
    now = now or timezone.now()
    when = _reported_at(row)
    if when is None or when < now - timedelta(days=REPORTED_MAX_AGE_DAYS):
        return 'aged'
    tokens, cpes, ports = seen
    token = _norm(row.product)
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    parsed = parse_cpe(ev.get('cpe') or '')
    if _same_product(token, tokens) or (parsed and (parsed[1] in cpes or _same_product(parsed[1], tokens))):
        return 'superseded'
    if row.port and row.port in ports:
        states = ports[row.port]
        if all(state not in ('', 'open') for state, _t in states):
            return 'port_closed'
        if any(t and not _same_product(token, {t}) for state, t in states if state in ('', 'open')):
            return 'port_other_product'
    return ''


def in_use(sub, now=None):
    """The reported readings of ``sub`` the freshness rule lets correlation match (``verdict``)."""
    rows = [r for r in _rows(sub) if r.kind == REPORTED and r.outcome == REPORTED and r.version]
    if not rows:
        return []
    seen = first_party(sub)
    return [r for r in rows if not verdict(r, seen, now)]


def collect_reported(subdomain, product_index, cve_by_id, rows, scan_history=None, min_confidence=0.0, fix_lookup=None):
    """Append the matches of the reported readings ``in_use`` lets through: named like a technology (correlation source ``tech``), the CPE
    first, the confidence capped at ``REPORTED_CONFIDENCE``, the provider and its date in the evidence. Returns how many."""
    from cveFeed.correlation import _MIN_TOKEN, _norm, _record_matches, parse_cpe
    if not product_index:
        return 0
    found = 0
    for row in in_use(subdomain):
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        cpe = ev.get('cpe') or ''
        token = _norm(row.product)
        if len(token) < _MIN_TOKEN and parse_cpe(cpe):
            token = parse_cpe(cpe)[1]
        if len(token) < _MIN_TOKEN:
            continue
        evidence = {'source': 'tech', 'reported': True, 'reported_by': ev.get('provider') or row.source, 'reported_at': ev.get('reported_at') or '',
                    'reading_id': row.pk, **({'undated': True} if ev.get('undated') else {}), **({'cpe': cpe[:255]} if cpe else {})}
        found += _record_matches(subdomain, row.product, row.version, token, 'tech', product_index, cve_by_id, min_confidence, scan_history, rows,
                                 cpe=cpe, fix_lookup=fix_lookup, evidence=evidence, confidence_cap=REPORTED_CONFIDENCE)
    return found


def reported_host_ids(base_qs):
    """The ids of the Subdomain rows of ``base_qs`` with a reported reading (``correlation.candidate_subdomains``)."""
    from django.db.models import Exists, OuterRef
    from cveFeed.models import ProbeObservation
    readings = ProbeObservation.objects.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'), kind=REPORTED)
    return base_qs.filter(Exists(readings)).values('id')


# ----------------------------------------------------------------------------- the one-time backfill

def _current_row(domain_id, host):
    from cveFeed import correlation
    from startScan.models import Subdomain
    return (Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain_id=domain_id, name=host)
            .select_related('target_domain').order_by('-id').first())


def catch_up(apply=False, batch=200):
    """The one-time catch-up an update runs (``manage.py backfill_source_versions --apply``): re-read what is still stored into readings, then
    correlate the hosts that gained or lost one. Read: every current host's stored ports and runZero blocks (``refresh_host``), the Shodan
    InternetDB CPEs the discovery feed kept (``DiscoveryEvent``, dated when received; the CPE technology an earlier discovery stored on the host
    under its normalized name is taken off the current row, the reading replaces it), and the replies of the database exposure findings. testssl.sh
    banners and WordPress scan headers were never stored: they are read from the next audit and scan. Idempotent. Returns
    ``{'hosts', 'readings', 'matches'}``."""
    from cveFeed import correlation, version_sources
    from cveFeed.models import DiscoveryEvent
    from cvengine_scanner import versions
    from startScan.models import Subdomain, Technology, Vulnerability
    base = Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__isnull=False)
    ids = list(base.order_by('id').values_list('id', flat=True))
    out = {'hosts': len(ids), 'readings': 0, 'matches': 0}
    if not apply:
        return out
    moved = set()
    configured = None
    for start in range(0, len(ids), batch):
        subs = list(Subdomain.objects.filter(id__in=ids[start:start + batch]).select_related('target_domain', 'scan_history')
                    .prefetch_related('technologies', 'ip_addresses__ports'))
        if configured is None:
            from cveFeed import runzero_sync
            configured = runzero_sync.configured_project_ids()
        for sub in subs:
            try:
                ports = version_sources._ports(sub)
                found = nmap_readings(sub, ports)
                changed = version_sources._store_derived(sub, NMAP_PROBE, found, timezone.now())
                changed = refresh_runzero(sub, configured=configured) or changed
            except Exception:  # noqa: BLE001 - one host's stored data never stops the catch-up
                logger.exception('source version catch-up of host %s failed', sub.pk)
                continue
            out['readings'] += len(found)
            if changed:
                moved.add(sub.pk)
    # the CPEs Shodan's InternetDB handed bbot, as the discovery feed kept them ("<technology> on <host>"), newest first
    seen = set()
    for event in DiscoveryEvent.objects.filter(type='TECHNOLOGY', label__istartswith='cpe:').order_by('-id').iterator(chunk_size=500):
        tech, sep, host = event.label.rpartition(' on ')
        host = (host or event.host or '').strip().lower().rstrip('.')
        reading = reported_cpe(tech.strip()) if sep else None
        if not reading or (event.domain_id, host, reading['label']) in seen:
            continue
        seen.add((event.domain_id, host, reading['label']))
        sub = _current_row(event.domain_id, host)
        if sub is None:
            continue
        if store_reported(sub.target_domain.project_id, sub.target_domain_id, sub.name, SHODAN_PROBE, [reading], SHODAN_PROVIDER, event.created_at,
                          undated=True):
            moved.add(sub.pk)
        out['readings'] += 1
        stored = Technology.objects.filter(name=versions.normalize_technology(tech.strip())).values_list('id', flat=True)
        links = Subdomain.technologies.through.objects.filter(subdomain_id=sub.pk, technology_id__in=list(stored))
        if links.exists():
            links.delete()  # an earlier discovery stored the CPE as a first-party technology: the reported reading replaces it
            moved.add(sub.pk)
    # the replies the database exposure findings kept
    for vuln in Vulnerability.objects.filter(source='db_exposure').exclude(subdomain__isnull=True).select_related('subdomain').iterator(chunk_size=500):
        replies = [r for r in (vuln.extracted_results or []) if isinstance(r, str)] if isinstance(vuln.extracted_results, list) else []
        readings = [r for reply in replies[:1] for r in db_readings(reply)]
        port = re.search(r':(\d{1,5})$', vuln.http_url or '')
        sub = _current_row(vuln.subdomain.target_domain_id, vuln.subdomain.name) if readings and port else None
        if sub is None:
            continue
        if store_db(sub, int(port.group(1)), replies[0]):
            moved.add(sub.pk)
        out['readings'] += len(readings)
    if moved:
        # every host that gained or lost a reading (or a technology): one that lost its only one is correlated too, so its matches close
        cve_by_id, index = correlation.cve_pool()
        ordered = sorted(moved)
        for start in range(0, len(ordered), batch):
            subs = list(Subdomain.objects.filter(pk__in=ordered[start:start + batch]).select_related('target_domain', 'scan_history')
                        .prefetch_related('technologies', 'ip_addresses__ports'))
            out['matches'] += correlation.correlate_subdomains(subs, index, cve_by_id, min_confidence=0.4)[1]
    return out


def payload_fields(row):
    """The host payload's fields of a reported reading (``version_sources.as_dict``): who reported it and as of when; ``stale`` and ``matched``
    follow its age (``REPORTED_MAX_AGE_DAYS``). A reading a first-party one supersedes is not told apart here: ``in_use`` decides at correlation."""
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    when = _reported_at(row)
    aged = when is None or when < timezone.now() - timedelta(days=REPORTED_MAX_AGE_DAYS)
    return {'reported': {'by': ev.get('provider') or '', 'at': ev.get('reported_at') or '', 'undated': bool(ev.get('undated'))},
            'stale': aged, 'matched': not aged}


def refresh_runzero_project(project):
    """After a runZero sync of ``project``: refresh the runZero readings of its current hosts that sit on an address with a block or already carry
    a runZero reading, and correlate the ones that moved. Returns how many moved."""
    from cveFeed import correlation, probes
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    hosts = set(ProbeObservation.objects.filter(project_id=project.pk, probe=RUNZERO_PROBE).values_list('host', flat=True))
    on_blocks = Subdomain.objects.filter(target_domain__project=project, ip_addresses__fingerprint__has_key='runzero').values('id')
    subs = (Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__project=project)
            .filter(Q(id__in=on_blocks) | Q(name__in=hosts)).select_related('target_domain').prefetch_related('ip_addresses').distinct())
    moved = 0
    for sub in subs:
        if refresh_runzero(sub):
            moved += 1
            probes.recorrelate(sub)
    return moved
