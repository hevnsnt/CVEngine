"""The build of an internet-facing VPN or edge appliance, pinned from outside: the version source entries for NetScaler (Citrix ADC and
Gateway), PAN-OS (GlobalProtect), FortiOS (FortiGate SSL-VPN) and Pulse Connect Secure, and the matching of a build RANGE against CVEs.

Most CISA KEV entries are in these appliances, and cvENGINE already names them (a WAF or edge signature, a favicon, a certificate, the WAF fingerprint),
but a name is only a lead: it matches no advisory. Public scanners pin the build from what the appliance's static files say about
themselves. Each fingerprint here is one such fact, with the published table that maps it to a release (``data/edge_fingerprints.json``:
source, licence and a citation per entry):

  NetScaler       the gzip header timestamp of /vpn/js/rdx/core/lang/rdx_en.json.gz (a ``digest`` read, contract 8: the file's first bytes,
                  never the file) and the ?v= build value /vpn/index.html puts on its resources; Fox-IT's table maps either to one build: EXACT
  PAN-OS          the build time a GlobalProtect portal's static files carry in Last-Modified and ETag; Bishop Fox's table of release dates
                  maps it to the releases of that day (often several, of several branches): a RANGE
  FortiOS         an ETag carrying the build time on a FortiGate's SSL-VPN front page, which Fortinet's FG-IR-23-224 (CVE-2024-23662) says
                  only releases before 7.2.6 and 7.4.2 send: a RANGE
  Connect Secure  the version the 8.x Network Connect file and the 9.x Host Checker installer state (9.1.11.12173 is 9.1R11, build 12173):
                  the release, not its service release: a RANGE

An EXACT build is a product reading like any version source's: a technology (``NetScaler ADC:13.1-49.15``), matched by the correlation's
own rules, version only, under the triage ceilings and the heat cap (``match_policy.version_read_from_component`` never counts it as proof).

A RANGE is a reading with confidence ``inferred`` and no version (``ProbeObservation`` outcome ``range``, the range in its evidence): never a
technology, never ``version_in_range`` True. ``collect_matches`` matches it against the CVEs whose own record names the product (vendor and
product, as NVD and the vendor name it: ``PRODUCTS``): a CVE no release of the range reaches is not matched; one it can reach is a
needs-validation candidate (``evidence.range_read``: the same treatment as a version-unknown match, lowest priority, never fire), with the
range and how it was read. A range only ever ADDS such candidates: a product seen without a version matches nothing at all.

Safety. Every request is a GET of a static file or the front page, the fixed paths below, asked only of a host already identified as that
product (``leads``; no port warrants one), through the version source reads' gates, caps and Sentinel kinds. No login page is posted to, no
credential is sent, no path a vulnerability is known to be reached by is asked. Every entry also asks a control path next to its first request:
a host that answers it the same way answers every path that way (a catch-all, a soft 404, a redirect to a login page), and nothing is read.
An answer a redirect served is never read either (``redirected`` for a digest; a text or header read must have its own shape and status).

Left out (no public fingerprint whose source and licence allow it here, or none that is reliable): Cisco ASA and FTD (the version
config-auth once stated, CVE-2014-3398, is fixed; no public table for its WebVPN files), SonicWall SMA and SSL-VPN, F5 BIG-IP, Check Point,
MOVEit Transfer and Sophos XG (docs/PIPELINE.md, "Edge appliance builds").
"""
import json
import re
from datetime import date, datetime, timedelta, timezone as dt_timezone
from email.utils import parsedate_to_datetime
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent / 'data' / 'edge_fingerprints.json'
MATCH_SOURCE = 'build_range'          # CVEMatch.source of a range match
RANGE_OUTCOME = 'range'               # ProbeObservation.outcome of a range reading
UNKNOWN_CONFIDENCE = 0.4              # a range that can reach the affected range (the version-unknown floor)
INSIDE_CONFIDENCE = 0.5               # every release of the range is inside the affected range: still never version_in_range
EARLIEST_BUILD = datetime(2014, 1, 1, tzinfo=dt_timezone.utc)  # a "build time" before this is not one


@lru_cache(maxsize=1)
def data():
    return json.loads(DATA.read_text(encoding='utf-8'))


@lru_cache(maxsize=1)
def _tables():
    tables = data()['tables']
    return {
        'stamp': {e['stamp']: e for e in tables['netscaler_rdx_stamp']['entries']},
        'vhash': {e['vhash']: e for e in tables['netscaler_vhash']['entries']},
        'panos': [(date.fromisoformat(e['released']), e) for e in tables['panos_release_dates']['entries']],
        'panos_window': int(tables['panos_release_dates'].get('window_days') or 2),
        'fortios': tables['fortios_etag']['entries'][0],
        'pcs_lines': set(tables['connect_secure_lines']['entries'][0]['lines']),
    }


def _norm(text):
    return re.sub(r'[^a-z0-9]', '', str(text or '').lower())


@lru_cache(maxsize=1)
def product_names():
    """``{product key: {(vendor token, product token)}}``: how the CVE records name each product (NVD's CPE and the vendor's own CNA names)."""
    return {key: {(_norm(v), _norm(p)) for v, p in spec['names']} for key, spec in data()['products'].items()}


def _answer(answers, index, statuses=(200,)):
    answer = answers[index] if index < len(answers) else None
    if not isinstance(answer, dict) or answer.get('error') or answer.get('status') not in statuses or answer.get('redirected'):
        return None
    return answer


def _headers(answer):
    return {str(k).lower(): str(v) for k, v in (answer.get('headers') or {}).items()} if isinstance(answer.get('headers'), dict) else {}


def _range_reading(catalogue, product, label, ranges, candidates, basis, url, source, evidence):
    out = catalogue.reading(product, label, '', confidence='inferred', evidence=evidence, url=url, source=source)
    out['range'] = {'product': product, 'ranges': ranges[:40], 'candidates': candidates[:40], 'basis': catalogue.clip(basis, 200)}
    return out


# ----------------------------------------------------------------------------- NetScaler: exact builds

def _netscaler(catalogue, entry, evidence, url, source):
    version = entry['version']
    return [catalogue.reading('netscaler', label, version, evidence=evidence, url=url, source=source)
            for label in data()['products']['netscaler']['labels']]


def read_netscaler_vhash(answers):
    """/vpn/index.html: the ?v= value on its own resources (rdx.css?v=<32 hex>). Only a value Fox-IT's table knows reads; values that disagree
    within the page read nothing."""
    from cveFeed import version_catalogue as catalogue
    answer = _answer(answers, 0)
    if answer is None or not str(answer.get('content_type') or '').startswith('text/html'):
        return []
    text = str(answer.get('text') or '')
    if not text.startswith('?v='):
        return []
    found = set(re.findall(r'\?v=([0-9a-f]{32})(?![0-9a-f])', text[:1024]))
    if len(found) != 1:
        return []
    entry = _tables()['vhash'].get(found.pop())
    if not entry:
        return []
    return _netscaler(catalogue, entry, f'/vpn/index.html resource ?v={entry["vhash"]}: build {entry["version"]} (Fox-IT table)',
                      '/vpn/index.html', 'netscaler-vhash')


def gzip_stamp(head):
    """The gzip header timestamp of a body whose first bytes (hex) are a gzip file named rdx_en..., or None."""
    try:
        raw = bytes.fromhex(str(head or ''))
    except ValueError:
        return None
    if len(raw) < 16 or raw[:4] != b'\x1f\x8b\x08\x08' or raw[10:16] != b'rdx_en':
        return None
    return int.from_bytes(raw[4:8], 'little') or None


def read_netscaler_gzip(answers):
    """/vpn/js/rdx/core/lang/rdx_en.json.gz (a digest read): the build time its gzip header carries, one per build in Fox-IT's table."""
    from cveFeed import version_catalogue as catalogue
    answer = _answer(answers, 0)
    digest = (answer or {}).get('digest')
    stamp = gzip_stamp(digest.get('head')) if isinstance(digest, dict) else None
    entry = _tables()['stamp'].get(stamp) if stamp else None
    if not entry:
        return []
    return _netscaler(catalogue, entry, f'rdx_en.json.gz gzip timestamp {stamp} ({entry["built"]}): build {entry["version"]} (Fox-IT table)',
                      '/vpn/js/rdx/core/lang/rdx_en.json.gz', 'netscaler-gzip')


# ----------------------------------------------------------------------------- PAN-OS: a range from the build time

def build_time(headers):
    """The build time a static file's Last-Modified (or, without one, the last 8 hex digits of its ETag) states, or None. When both are there
    and disagree by more than a day, neither is believed."""
    modified = etag_time = None
    try:
        modified = parsedate_to_datetime(headers['last-modified']) if headers.get('last-modified') else None
    except (TypeError, ValueError, IndexError):
        modified = None
    if modified is not None and modified.tzinfo is None:
        modified = modified.replace(tzinfo=dt_timezone.utc)
    found = re.fullmatch(r'(?:W/)?"?(?:[0-9a-f]{0,16}-)?[0-9a-f]{0,8}?([0-9a-f]{8})"?', headers.get('etag', '').strip().lower())
    if found:
        etag_time = datetime.fromtimestamp(int(found.group(1), 16), tz=dt_timezone.utc)
    if modified and etag_time and abs(modified - etag_time) > timedelta(days=1):
        return None
    when = modified or etag_time
    if when is None or when < EARLIEST_BUILD or when > datetime.now(dt_timezone.utc) + timedelta(days=1):
        return None
    return when


PANOS_ASSETS = (('/global-protect/portal/css/login.css', 'text/css'), ('/global-protect/portal/images/favicon.ico', 'image/'))


def panos_candidates(when):
    """The PAN-OS releases published within the table's window of ``when`` (a date), or [] outside the table (a build after its last date is
    a release it does not know)."""
    rows, window = _tables()['panos'], _tables()['panos_window']
    if not rows or when > max(d for d, _e in rows) + timedelta(days=window) or when < min(d for d, _e in rows) - timedelta(days=window):
        return []
    return [e for d, e in rows if abs((d - when).days) <= window]


def read_panos(answers):
    from cveFeed import version_catalogue as catalogue
    times = []
    for index, (path, kind) in enumerate(PANOS_ASSETS):
        answer = _answer(answers, index)
        if answer is None or not str(answer.get('content_type') or '').startswith(kind):
            continue
        when = build_time(_headers(answer))
        if when is not None:
            times.append((path, when))
    if not times or max(w for _p, w in times) - min(w for _p, w in times) > timedelta(days=1):
        return []  # nothing read, or two files of one portal that disagree
    path, when = times[0]
    entries = panos_candidates(when.date())
    if not entries:
        return []
    versions = sorted({e['version'] for e in entries}, key=lambda v: [int(x) for x in re.findall(r'\d+', v)])
    return [_range_reading(catalogue, 'pan-os', 'PAN-OS', [{'introduced': v, 'lastAffected': v} for v in versions], versions,
                           f'GlobalProtect static file build time {when.date().isoformat()}: released within '
                           f'{_tables()["panos_window"]} days of it', path, 'panos-globalprotect',
                           f'{path} built {when.isoformat()[:19]}Z; PAN-OS releases of that date (Bishop Fox table): {", ".join(versions[:12])}')]


# ----------------------------------------------------------------------------- FortiOS: a range from the ETag exposure

def read_fortios(answers):
    """The FortiGate SSL-VPN front page (the stub that sends a browser to /remote/login) with an ETag ending in a build time."""
    from cveFeed import version_catalogue as catalogue
    answer = _answer(answers, 0)
    if answer is None or not str(answer.get('text') or '').startswith('top.location="/remote/login"'):
        return []
    found = re.fullmatch(r'(?:W/)?"([0-9a-z]{1,16})-([0-9a-f]{8})"', _headers(answer).get('etag', '').strip().lower())
    if not found:
        return []
    when = datetime.fromtimestamp(int(found.group(2), 16), tz=dt_timezone.utc)
    if when < EARLIEST_BUILD or when > datetime.now(dt_timezone.utc) + timedelta(days=1):
        return []
    rule = _tables()['fortios']
    return [_range_reading(catalogue, 'fortios', 'FortiOS', rule['ranges'], ['before 7.2.6', '7.4.0 to 7.4.1'],
                           f'ETag build time {when.date().isoformat()} ({rule["cve"]}: only releases before 7.2.6 and 7.4.2 send it)', '/',
                           'fortios-etag', f'front page ETag "{found.group(1)}-{found.group(2)}": build time {when.isoformat()[:19]}Z')]


# ----------------------------------------------------------------------------- Pulse Connect Secure: a release, not its service release

_PCS = (('/dana-na/nc/nc_gina_ver.txt', r'^NAME="ProductVersion"\s+VALUE="(\d{1,2})\.(\d{1,2})\.(\d{1,3})\.(\d{1,6})"'),
        ('/dana-cached/hc/HostCheckerInstaller.osx', r'^<key>version</key>\s*<string>(\d{1,2})\.(\d{1,2})\.(\d{1,3})\.(\d{1,6})</string>'))


def read_connect_secure(answers):
    from cveFeed import version_catalogue as catalogue
    for index, (path, pattern) in enumerate(_PCS):
        answer = _answer(answers, index)
        found = re.match(pattern, str((answer or {}).get('text') or ''))
        if not found:
            continue
        line, release, build = f'{found.group(1)}.{found.group(2)}', int(found.group(3)), found.group(4)
        if line not in _tables()['pcs_lines'] or release < 1:
            return []  # a 22.x Host Checker version names no Connect Secure release in this form
        first = f'{line}R{release}'
        return [_range_reading(catalogue, 'connect-secure', 'Pulse Connect Secure', [{'introduced': first, 'lastAffected': f'{first}.999'}],
                               [f'{first} to {first}.x'], f'{first}, build {build}: the service release is not read', path, 'connect-secure',
                               f'{path} states {".".join(found.groups())}: {first} build {build}')]
    return []


# ----------------------------------------------------------------------------- the catalogue entries

def sources():
    """The edge entries of the version source catalogue (``version_catalogue.SOURCES`` adds them)."""
    from cveFeed.version_catalogue import Request, Source
    asset = ('etag', 'last-modified', 'content-type', 'server')
    return (
        Source('netscaler-vhash', 'NetScaler build (login page resource value)', 'product',
               (Request('/vpn/index.html', read='text', find='?v='),), read_netscaler_vhash,
               leads=r'netscaler|citrix[ _-]?(?:adc|gateway)', control=True,
               verified=data()['tables']['netscaler_vhash']['method'],
               note='Fox-IT citrix-netscaler-triage (Apache-2.0): the ?v= value per build; not every build sends one'),
        Source('netscaler-gzip', 'NetScaler build (rdx_en.json.gz timestamp)', 'product',
               (Request('/vpn/js/rdx/core/lang/rdx_en.json.gz', read='digest', headers=asset),), read_netscaler_gzip,
               leads=r'netscaler|citrix[ _-]?(?:adc|gateway)', control=True,
               verified=data()['tables']['netscaler_rdx_stamp']['method'],
               note='a digest read (contract 8, version_digest): the file\'s first bytes, whose gzip timestamp is the build time'),
        Source('panos-globalprotect', 'PAN-OS build time (GlobalProtect static files)', 'product',
               tuple(Request(path, read='headers', headers=asset) for path, _kind in PANOS_ASSETS), read_panos,
               leads=r'global ?protect|\bpan-?os\b|palo ?alto', control=True,
               verified=data()['tables']['panos_release_dates']['method'],
               note='a range: the releases published within two days of the build time (Bishop Fox, MIT)'),
        Source('fortios-etag', 'FortiOS build time (SSL-VPN front page ETag)', 'product',
               (Request('/', read='text', find='top.location="/remote/login"', headers=('etag', 'content-type', 'server')),), read_fortios,
               leads=r'forti ?gate|forti ?os\b|fortinet[ _-]?(?:ssl[ _-]?vpn|fortigate)', control=True,
               verified='https://www.fortiguard.com/psirt/FG-IR-23-224',
               note='a range: only releases before 7.2.6 and 7.4.2 send the build time (CVE-2024-23662)'),
        Source('connect-secure', 'Pulse Connect Secure release (static version files)', 'product',
               tuple(Request(path, read='text', find=find) for path, find in
                     (('/dana-na/nc/nc_gina_ver.txt', 'NAME="ProductVersion"'), ('/dana-cached/hc/HostCheckerInstaller.osx', '<key>version</key>'))),
               read_connect_secure, leads=r'pulse[ _-]?(?:connect[ _-]?)?secure|ivanti[ _-]?connect[ _-]?secure|\bconnect secure\b', control=True,
               verified='https://censys.com/blog/pulse-connect-secure-a-view-from-the-internet/',
               note='a range: the release (9.1R11), not its service release (9.1R11.4)'),
    )


# ----------------------------------------------------------------------------- matching a range

def _ver(text):
    from cveFeed.correlation import parse_version
    return parse_version(text, strict=True)


def _bounds(rng):
    """``(low, low inclusive, high, high inclusive)`` of an affected range, parsed; ``None`` when a bound cannot be read."""
    if str(rng.get('type') or 'SEMVER').upper() not in ('SEMVER', 'ECOSYSTEM'):
        return None
    values = {}
    for key in ('introduced', 'fixed', 'lastAffected'):
        raw = rng.get(key)
        values[key] = _ver(raw) if raw else None
        if raw and values[key] is None:
            return None
    if values['fixed'] is not None:
        return values['introduced'], True, values['fixed'], False
    return values['introduced'], True, values['lastAffected'], True


def overlap(reading_ranges, affected_ranges):
    """Whether a release of the reading's range can be inside the affected ranges: True, False, or None (no affected bound can be read)."""
    from cveFeed.correlation import _vcmp, prepared_ranges
    usable, unknown = [], False
    for rng in prepared_ranges(affected_ranges):
        got = _bounds(rng)
        if got is None or (got[0] is None and got[2] is None):
            unknown = True
            continue
        usable.append(got)
    for mine in reading_ranges:
        low, high = _ver(mine.get('introduced') or '0'), _ver(mine.get('lastAffected') or mine.get('introduced'))
        if low is None or high is None:
            continue
        for a_low, _a_inc, a_high, a_high_inc in usable:
            above = a_low is None or _vcmp(high, a_low) >= 0
            below = a_high is None or (_vcmp(low, a_high) <= 0 if a_high_inc else _vcmp(low, a_high) < 0)
            if above and below:
                return True
    return None if unknown and not usable else False


def inside(reading_ranges, affected_ranges):
    """Whether every release of the reading's range is inside one affected range (both of its ends)."""
    from cveFeed.correlation import prepared_ranges, version_in_range
    ranges = prepared_ranges(affected_ranges)
    for mine in reading_ranges:
        low, high = _ver(mine.get('introduced') or '0'), _ver(mine.get('lastAffected') or mine.get('introduced'))
        if low is None or high is None or not any(version_in_range(low, r) is True and version_in_range(high, r) is True for r in ranges):
            return False
    return bool(reading_ranges)


def items_of(cve, product):
    """The affected entries of ``cve`` that name ``product`` by vendor and product (an entry with no vendor only by a name listed without one)."""
    names = product_names().get(product, set())
    return [item for item in cve.affected or [] if isinstance(item, dict) and (_norm(item.get('vendor')), _norm(item.get('product'))) in names]


_POOL = {}


def range_cves(cve_by_id):
    """``{product: [(cve, [items])]}`` of a correlation pool: the CVEs whose own affected entries name an edge product (memoised per pool)."""
    if _POOL.get('id') != id(cve_by_id) or _POOL.get('size') != len(cve_by_id):
        out = {}
        for cve in cve_by_id.values():
            for product in product_names():
                items = items_of(cve, product)
                if items:
                    out.setdefault(product, []).append((cve, items))
        _POOL.update(id=id(cve_by_id), size=len(cve_by_id), cves=out)
    return _POOL['cves']


def range_readings(sub, now=None):
    """The fresh range readings of a host: ``[(product, range dict, label, source, port, evidence text)]``."""
    from django.utils import timezone

    from cveFeed import version_sources
    from cveFeed.models import ProbeObservation
    if sub.target_domain_id is None:
        return []
    rows = getattr(sub, '_range_rows', None)
    if rows is None:
        rows = list(ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=sub.name.lower().rstrip('.'),
                                                    probe__startswith=version_sources.PROBE_PREFIX, outcome=RANGE_OUTCOME))
    cutoff = (now or timezone.now()) - timedelta(days=version_sources.STALE_DAYS)
    out = []
    for row in rows:
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        rng = ev.get('range') if isinstance(ev.get('range'), dict) else None
        if not rng or not row.observed_at or row.observed_at < cutoff or rng.get('product') not in product_names():
            continue
        out.append((rng['product'], rng, row.product, ev.get('source') or '', row.port or 0, ev.get('said') or ''))
    return out


def collect_matches(subdomain, cve_by_id, rows, scan_history=None, min_confidence=0.0):
    """Append the range matches of ``subdomain`` to ``rows`` (see the module docstring). A CVE ``rows`` already holds for the host (an exact
    build's technology match) is not matched twice. Returns how many."""
    readings = range_readings(subdomain)
    if not readings:
        return 0
    pool = range_cves(cve_by_id)
    taken = {r['cve_entry_id'] for r in rows if r.get('subdomain_id') == subdomain.id}
    found = 0
    for product, rng, label, source, port, said in readings:
        for cve, items in pool.get(product, ()):
            if cve.id in taken:
                continue
            affected = [r for item in items for r in (item.get('ranges') or [])]
            reach = overlap(rng.get('ranges') or [], affected) if affected else None
            if reach is False:
                continue  # no release of the range is affected
            unbounded = reach is None
            if unbounded and not cve.kev:
                continue  # no bound decides: only an actively exploited CVE is kept, as for a product with no range
            confidence = INSIDE_CONFIDENCE if not unbounded and inside(rng.get('ranges') or [], affected) else UNKNOWN_CONFIDENCE
            if confidence < min_confidence:
                continue
            candidates = ', '.join(rng.get('candidates') or [])[:200]
            rows.append({
                'cve_entry_id': cve.id, 'subdomain_id': subdomain.id, 'source': MATCH_SOURCE,
                'matched_product': (items[0].get('product') or label)[:255], 'matched_version': '', 'version_in_range': None,
                'confidence': confidence, 'scan_history_id': scan_history.id if scan_history else subdomain.scan_history_id,
                'distro_status': 'no_data', 'distro_fixed_version': '',
                'evidence': {'source': MATCH_SOURCE, 'range_read': True, 'product': product, 'label': label, 'raw_version': '',
                             'build_range': {'candidates': rng.get('candidates') or [], 'ranges': rng.get('ranges') or [],
                                             'basis': rng.get('basis') or ''},
                             'reading': f'{label}: {candidates} ({rng.get("basis") or source})'[:300], 'read_by': source, 'port': port,
                             'said': said[:300], **({'unbounded': True} if unbounded else {})}})
            taken.add(cve.id)
            found += 1
    return found


def range_host_ids(base_qs):
    """The ids of the Subdomain rows of ``base_qs`` with a range reading (``correlation.candidate_subdomains``)."""
    from django.db.models import Exists, OuterRef

    from cveFeed import version_sources
    from cveFeed.models import ProbeObservation
    readings = ProbeObservation.objects.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'),
                                               probe__startswith=version_sources.PROBE_PREFIX, outcome=RANGE_OUTCOME)
    return base_qs.filter(Exists(readings)).values('id')
