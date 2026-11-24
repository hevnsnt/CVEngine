"""The Windows release an NTLM challenge states, and the Windows CVEs it makes candidates to check: "release known, patch level unknown".

What is read. A Windows service that offers NTLM sign-in answers nmap's ``*-ntlm-info`` scripts with the system's version before anyone signs in
(``Product_Version: 10.0.20348``): ``rdp-ntlm-info``, ``ms-sql-ntlm-info``, ``http-ntlm-info``, ``smtp-ntlm-info``, ``imap-ntlm-info``,
``pop3-ntlm-info``, ``telnet-ntlm-info`` and ``nntp-ntlm-info`` all print the same field (``Port.extra['scripts']``). ``smb-os-discovery`` (a host
script, ``IpAddress.fingerprint['scripts']``) names the system and its build (``Windows Server 2019 Standard 17763``). Only these count: nmap's own
OS guess (``-O``, ``IpAddress.os_guess``) and a service's ``ostype`` never make a reading. Nothing here sends a request.

What it means. The build names a Windows RELEASE exactly (``data/windows_builds.json``: 10.0.20348 is Windows Server 2022, 10.0.17763 Windows
Server 2019 or Windows 10 Version 1809), but never its update revision (UBR, the ``.2762`` of ``10.0.20348.2762``), so the patch level is unknown.
Microsoft's CVE records state ranges such as ``10.0.20348.0`` to ``< 10.0.20348.2762``: reading the build as ``10.0.20348.0`` would put every host
inside every range. It is never read that way. A server and a client release often share one build; ``smb-os-discovery``'s system name tells them
apart (``Windows Server ...`` or ``Windows 10 ...``), and when nothing does, both releases are kept and the reading says so (``ambiguous``).

Where it goes. One version source reading per release (``ProbeObservation``, probe ``vsrc:ntlm``, kind ``hint``: shown under ``version_sources``,
searched with ``vsource:ntlm`` and ``tech:"windows server 2022"``, never a technology), product = the release name the CVE records use, version =
the build, ``release_only`` true, the script and port it came from. Refreshed with the other stored-data readings (``source_versions.refresh_host``)
and dropped when the scripts no longer say it.

Correlation (``collect_matches``, from ``correlation.collect_subdomain_matches``). A CVE whose own affected entry names the release is a candidate
only when all of these hold:

  * its CVSS vector is network-reachable with no user interaction (``AV:N``, and not ``UI:R``/``UI:P``/``UI:A``): something that reaches the
    host's own listening services, which is what an outside check can speak to;
  * it is not ``local_only`` (``cveFeed.locality``; the pool already leaves those out);
  * it is on the CISA KEV list, or critical (CVSS 9.0 or more): ``eligible``. A Windows release is named by hundreds of CVEs a year; every
    candidate needs a person to read the UBR, so only the ones worth that minute are raised;
  * the entry's range covers the release, comparing the build with the range's first three components only (``covers``).

The match (source ``windows``) carries ``evidence.windows_patch_unknown``, which ``match_policy.is_version_unknown`` reads as version unknown, the
way it reads ``java_unknown``: needs validation, heat ice, never fire, never validated or AI-triaged automatically, and it never raises the host's
heat on its own. ``version_in_range`` is always None and ``matched_version`` empty. The explanation (``match_explain``, ``confirm_guide``) gives
the read-only commands that read the UBR on the host and how the answer decides.

End of support. A release past Microsoft's end of support (2008 R2 and Windows 7 in January 2020, 2012 and 2012 R2 in October 2023, with the
dates in the data file) gets no update after that day without a paid Extended Security Update subscription. A CVE published after that day that
names the release is very likely unpatched on it, unless the host has ESU: the candidate's confidence is raised (``END_OF_SUPPORT_CONFIDENCE``)
but it stays version unknown, and the explanation says "end of support".
"""
import functools
import json
import logging
import re
from datetime import date, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

DATA = Path(__file__).with_name('data') / 'windows_builds.json'
PROBE = 'vsrc:ntlm'                # ProbeObservation.probe of a reading (source_versions.NTLM_PROBE)
MATCH_SOURCE = 'windows'           # CVEMatch.source of a candidate
FLAG = 'windows_patch_unknown'     # the evidence flag match_policy reads as version unknown
NTLM_SCRIPTS = ('rdp-ntlm-info', 'ms-sql-ntlm-info', 'http-ntlm-info', 'smtp-ntlm-info', 'imap-ntlm-info', 'pop3-ntlm-info',
                'telnet-ntlm-info', 'nntp-ntlm-info')
SMB_SCRIPT = 'smb-os-discovery'
UNKNOWN_CONFIDENCE = 0.4           # a release known, its patch level not (the correlation floor)
END_OF_SUPPORT_CONFIDENCE = 0.5    # a CVE published after the release's end of support: very likely unpatched unless the host has ESU
MIN_CVSS = 9.0                     # a CVE not on the KEV list must be critical to be raised (``eligible``)

_NTLM_BUILD = re.compile(r'(?mi)^\s*Product_Version\s*:\s*(\d{1,2})\.(\d{1,2})\.(\d{3,6})\s*$')
_NTLM_BUILD_OLD = re.compile(r'(?mi)^\s*Product_Version\s*:\s*(\d{1,2})\.(\d{1,2})\s*\(\s*Build\s+(\d{3,6})\s*\)')  # older nmap releases
_SMB_OS = re.compile(r'(?mi)^\s*OS\s*:\s*(Windows\b[^\r\n]{0,160})$')
_SERVER = re.compile(r'\bserver\b', re.I)
_CLIENT = re.compile(r'^Windows\s+(?:Vista|7|8|8\.1|10|11)\b', re.I)
_AV_N = re.compile(r'(?:^|/)AV:N(?:/|$)')
_UI_NEEDED = re.compile(r'(?:^|/)UI:[RPA](?:/|$)')  # CVSS 3 Required, CVSS 4 Passive or Active
_VERSION = re.compile(r'^\d{1,5}(?:\.\d{1,6}){0,3}$')


# ----------------------------------------------------------------------------- the build table

@functools.lru_cache(maxsize=1)
def data():
    return json.loads(DATA.read_text(encoding='utf-8'))


def name_key(name):
    """A release name as the records may spell it, reduced for comparison: case, punctuation, a "(Server Core installation)" suffix and a
    "for x64-based Systems" platform do not matter (``Windows Server 2019 (Server Core installation)`` is Windows Server 2019)."""
    text = str(name or '').lower()
    text = re.sub(r'\(\s*server core installation\s*\)', ' ', text)
    text = re.sub(r'\bfor\s+(?:x64|x86|32-bit|64-bit|arm64|itanium)(?:[- ]based)?\s+systems\b', ' ', text)
    return re.sub(r'[^a-z0-9]', '', text) if 'windows' in text else ''


@functools.lru_cache(maxsize=1)
def _tables():
    by_build, by_name = {}, {}
    for entry in data()['releases']:
        for build in (entry['build'], *entry.get('aliases', ())):
            by_build.setdefault(build, []).append(entry)
        for name in (entry['name'], *entry.get('names', ())):
            by_name.setdefault(name_key(name), entry)
    numbers = {}
    for build, entries in by_build.items():
        numbers.setdefault(build.split('.')[2], build)
    return by_build, by_name, numbers


def release_id(entry):
    return f"{entry['build']}|{entry['line']}"


def releases(build):
    """The table's entries for a build (``10.0.17763``: Windows Server 2019 and Windows 10 Version 1809), [] for a build it does not list."""
    return list(_tables()[0].get(str(build or '').strip(), ()))


def release_named(name):
    """The table entry a CVE record's product name names, or None."""
    return _tables()[1].get(name_key(name))


# ----------------------------------------------------------------------------- reading the scripts (pure)

def parse_ntlm(text):
    """``{'build', 'said'}`` from any ``*-ntlm-info`` script's output (``Product_Version: 10.0.20348``), or {} when it states none."""
    text = str(text or '')[:4000]
    found = _NTLM_BUILD.search(text) or _NTLM_BUILD_OLD.search(text)
    if not found:
        return {}
    build = '.'.join(str(int(part)) for part in found.groups())
    return {'build': build, 'said': f'Product_Version: {build}'}


def parse_smb_os(text):
    """``{'build', 'line', 'os', 'said'}`` from smb-os-discovery's ``OS:`` line (``Windows Server 2019 Standard 17763 (Windows Server 2019
    Standard 6.3)``), or {} for a system that is not Windows or a build the table does not list. ``line`` is ``server`` or ``client`` when the
    system name says which."""
    found = _SMB_OS.search(str(text or '')[:4000])
    if not found:
        return {}
    os_line = re.sub(r'\\x00.*', '', found.group(1)).strip()
    head = re.split(r'\s*\(', os_line, maxsplit=1)[0]
    numbers = _tables()[2]
    build = next((numbers[n] for n in re.findall(r'\b(\d{4,5})\b', head) if n in numbers), '')
    if not build:
        return {}
    line = 'server' if _SERVER.search(head) else 'client' if _CLIENT.match(head) else ''
    return {'build': build, 'line': line, 'os': head[:120], 'said': f'OS: {head[:120]}'}


def _component(label):
    return re.sub(r'[^a-z0-9]+', '-', (label or '').lower()).strip('-')[:60]


def readings_from(sources):
    """``[(port, reading)]`` from what the scripts said: ``sources`` is ``[(script, port, parsed)]`` (``parse_ntlm`` or ``parse_smb_os``). One
    reading per release the builds name; a server/client pair is narrowed to one when smb-os-discovery named the system, else both are kept
    (``ambiguous``). Pure."""
    from cveFeed import version_catalogue as catalogue
    by_build = {}
    for script, port, parsed in sources:
        if not parsed or not releases(parsed.get('build')):
            continue
        item = by_build.setdefault(parsed['build'], {'sources': [], 'lines': set(), 'said': []})
        item['sources'].append({'script': script, 'port': int(port or 0)})
        if parsed.get('line'):
            item['lines'].add(parsed['line'])
        item['said'].append(f"{script}{f' on port {port}' if port else ''}: {parsed['said']}")
    out = []
    for build in sorted(by_build):
        item = by_build[build]
        entries = releases(build)
        canonical = entries[0]['build']
        lines = item['lines']
        if len(lines) == 1:
            narrowed = [e for e in entries if e['line'] in lines]
            entries = narrowed or entries
        names = [e['name'] for e in entries]
        ambiguous = len(entries) > 1
        basis = ('smb-os-discovery names the system' if len(lines) == 1 and not ambiguous else
                 'the build alone: it is ' + ' or '.join(names) + ', and nothing read tells which' if ambiguous else
                 'the build names one release')
        first = item['sources'][0]
        for entry in entries:
            reading = catalogue.reading(_component(entry['name']), entry['name'], build, confidence='exact',
                                        evidence='; '.join(item['said'])[:300], source=first['script'])
            reading['release_only'] = True
            reading['windows'] = {'release': entry['name'], 'build': build, 'canonical_build': canonical, 'line': entry['line'],
                                  'candidates': names, 'ambiguous': ambiguous, 'basis': basis, 'sources': item['sources'][:8],
                                  'end_of_support': entry.get('end_of_support') or '', 'esu_until': entry.get('esu_until') or '',
                                  'lifecycle': entry.get('lifecycle') or ''}
            out.append((first['port'], reading))
    return out


def host_sources(sub, ports=None):
    """``[(script, port, parsed)]``: what the NTLM scripts on the open ports of ``sub`` and the smb-os-discovery of its addresses say. ``ports``
    is ``[(address, Port)]`` (``version_sources._ports``). nmap's OS guess is never read."""
    if ports is None:
        from cveFeed import version_sources
        ports = version_sources._ports(sub)
    out, smb_port = [], {}
    for address, port in ports:
        if (port.state or 'open') not in ('', 'open'):
            continue
        if port.number == 445:
            smb_port[address] = 445
        scripts = ((port.extra or {}).get('scripts') or {}) if isinstance(port.extra, dict) else {}
        if not isinstance(scripts, dict):
            continue
        for script in NTLM_SCRIPTS:
            if isinstance(scripts.get(script), str):
                parsed = parse_ntlm(scripts[script])
                if parsed:
                    out.append((script, port.number, parsed))
    for ip in sub.ip_addresses.all():
        scripts = ((ip.fingerprint or {}).get('scripts') or {}) if isinstance(ip.fingerprint, dict) else {}
        text = scripts.get(SMB_SCRIPT) if isinstance(scripts, dict) else None
        if isinstance(text, str):
            parsed = parse_smb_os(text)
            if parsed:
                out.append((SMB_SCRIPT, smb_port.get(ip.address, 0), parsed))
    return out


def host_readings(sub, ports=None):
    """``[(port, reading)]`` of the Windows releases ``sub``'s stored scripts state (``readings_from(host_sources(...))``)."""
    return readings_from(host_sources(sub, ports))


# ----------------------------------------------------------------------------- matching (pure)

def _parts(text):
    text = str(text or '').strip()
    if not _VERSION.match(text):
        return None
    return tuple(int(x) for x in text.split('.'))


def covers(build, rng):
    """Whether an affected range can hold some update revision of ``build`` (``10.0.20348``): its first three components are compared with the
    range's, the revision is free. ``10.0.20348.0`` to ``< 10.0.20348.2762`` covers 10.0.20348; ``< 10.0.20348.0`` does not; ``10.0.0`` to ``<
    10.0.22000.3197`` covers 10.0.20348; a range with no upper bound, or a bound that is not a Windows version, covers nothing. The build is never
    read as revision 0: that is the question a host owner answers (``match_explain``)."""
    b = _parts(build)
    if not isinstance(rng, dict) or b is None or len(b) != 3:
        return False
    if str(rng.get('type') or 'SEMVER').upper() not in ('SEMVER', 'ECOSYSTEM', 'CUSTOM'):
        return False
    low = rng.get('introduced')
    low = (0, 0, 0, 0) if low in (None, '', '0', '*') else _parts(low)
    if rng.get('fixed') not in (None, ''):
        high, inclusive = _parts(rng['fixed']), False
    elif rng.get('lastAffected') not in (None, ''):
        high, inclusive = _parts(rng['lastAffected']), True
    else:
        return False
    if low is None or high is None or len(high) < 3:
        return False
    low, high = (low + (0, 0, 0, 0))[:4], (high + (0, 0, 0, 0))[:4]
    if b < low[:3] or b > high[:3]:
        return False
    first = low[3] if b == low[:3] else 0  # the lowest revision of the build inside the range
    if b == high[:3]:
        return first <= high[3] if inclusive else first < high[3]
    return True


def eligible(cve):
    """``'kev'`` or ``'critical'`` when a CVE may be raised as a Windows candidate, else '': a network vector with no user interaction, not
    local only, and on the KEV list or CVSS ``MIN_CVSS`` or more (see the module docstring)."""
    vector = str(getattr(cve, 'cvss_vector', '') or '')
    if not _AV_N.search(vector) or _UI_NEEDED.search(vector):
        return ''
    if cve.__dict__.get('local_only'):  # read only when loaded: the correlation pool leaves local-only CVEs out already
        return ''
    if getattr(cve, 'kev', False):
        return 'kev'
    cvss = getattr(cve, 'cvss', None)
    return 'critical' if isinstance(cvss, (int, float)) and cvss >= MIN_CVSS else ''


_POOL = {}


def windows_cves(cve_by_id):
    """``{release id: [(cve, why, [(affected index, item)])]}``: the eligible CVEs of a correlation pool whose affected entries name a release of the
    table (memoised per pool)."""
    if _POOL.get('pool') is not cve_by_id:  # the pool itself, not its id: a refreshed pool can reuse a freed one's id and size
        out = {}
        for cve in cve_by_id.values():
            items = {}
            for index, item in enumerate(cve.affected or []):
                if not isinstance(item, dict):
                    continue
                vendor = str(item.get('vendor') or '').lower()
                if vendor and 'microsoft' not in vendor:
                    continue
                entry = release_named(item.get('product'))
                if entry is not None:
                    items.setdefault(release_id(entry), []).append((index, item))
            if not items:
                continue
            why = eligible(cve)
            if not why:
                continue
            for key, found in items.items():
                out.setdefault(key, []).append((cve, why, found))
        _POOL.update(pool=cve_by_id, cves=out)
    return _POOL['cves']


def end_of_support(windows, published):
    """``{'date', 'esu_until', 'after_esu'}`` when ``published`` (a CVE's publication datetime) is after the release's end of support, else None."""
    try:
        eos = date.fromisoformat(str((windows or {}).get('end_of_support') or ''))
    except ValueError:
        return None
    day = published.date() if hasattr(published, 'date') else None
    if day is None or day <= eos:
        return None
    esu = str((windows or {}).get('esu_until') or '')
    try:
        after_esu = bool(esu) and day > date.fromisoformat(esu)
    except ValueError:
        after_esu = False
    return {'date': eos.isoformat(), 'esu_until': esu, 'after_esu': after_esu}


def host_releases(sub, now=None):
    """The fresh Windows release readings of a host: ``[(entry, windows dict, port, said)]``."""
    from django.utils import timezone

    from cveFeed import source_versions, version_sources
    cutoff = (now or timezone.now()) - timedelta(days=version_sources.STALE_DAYS)
    out = []
    for row in source_versions._rows(sub):
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        if row.probe != PROBE or not ev.get('release_only') or not isinstance(ev.get('windows'), dict):
            continue
        if not row.observed_at or row.observed_at < cutoff:
            continue
        entry = release_named(row.product)
        if entry is None or row.version not in (entry['build'], *entry.get('aliases', ())):
            continue
        out.append((entry, ev['windows'], row.port or 0, str(ev.get('said') or '')))
    return sorted(out, key=lambda r: (r[0]['build'], r[0]['line']))


def collect_matches(subdomain, cve_by_id, rows, scan_history=None, min_confidence=0.0):
    """Append the Windows candidates of ``subdomain`` to ``rows`` (see the module docstring): one per host and CVE, never a version in range.
    Returns how many."""
    pool = windows_cves(cve_by_id)
    if not pool:
        return 0  # no eligible CVE in the pool names a Windows release: no query for the host's readings
    readings = host_releases(subdomain)
    if not readings:
        return 0
    taken = {r['cve_entry_id'] for r in rows if r.get('subdomain_id') == subdomain.id}
    found = 0
    for entry, windows, port, said in readings:
        build = entry['build']
        for cve, why, items in pool.get(release_id(entry), ()):
            if cve.id in taken:
                continue
            hit = next(((index, item, rng) for index, item in items for rng in (item.get('ranges') or []) if covers(build, rng)), None)
            if hit is None:
                continue  # no range of the record reaches this release (or none has an upper bound)
            index, item, rng = hit
            eos = end_of_support(windows, getattr(cve, 'published_at', None))
            confidence = END_OF_SUPPORT_CONFIDENCE if eos else UNKNOWN_CONFIDENCE
            if confidence < min_confidence:
                continue
            fixed = str(rng.get('fixed') or '')
            sources = ', '.join(_source_text(s) for s in (windows.get('sources') or [])[:4] if isinstance(s, dict))
            evidence = {'source': MATCH_SOURCE, FLAG: True, 'raw_version': '', 'release': entry['name'], 'build': build,
                        'windows': {k: windows.get(k) for k in ('line', 'candidates', 'ambiguous', 'basis', 'sources', 'end_of_support',
                                                                'esu_until', 'lifecycle')},
                        'affected_index': index, 'range': {k: rng[k] for k in ('introduced', 'fixed', 'lastAffected') if rng.get(k)},
                        'fixed_build': fixed if _parts(fixed) and len(_parts(fixed)) == 4 else '', 'limit': why,
                        'reading': f"{entry['name']}, build {build}" + (f' ({sources})' if sources else ''), 'port': port, 'said': said[:300],
                        **({'end_of_support': eos} if eos else {})}
            rows.append({'cve_entry_id': cve.id, 'subdomain_id': subdomain.id, 'source': MATCH_SOURCE,
                         'matched_product': (str(item.get('product') or '') or entry['name'])[:255], 'matched_version': '',
                         'version_in_range': None, 'confidence': confidence,
                         'scan_history_id': scan_history.id if scan_history else subdomain.scan_history_id,
                         'distro_status': 'no_data', 'distro_fixed_version': '', 'evidence': evidence})
            taken.add(cve.id)
            found += 1
    return found


def _source_text(source):
    port = source.get('port')
    return f"{source.get('script')}" + (f' on port {port}' if port else '')


def host_ids(base_qs):
    """The ids of the Subdomain rows of ``base_qs`` with a Windows release reading (``correlation.candidate_subdomains``)."""
    from django.db.models import Exists, OuterRef

    from cveFeed.models import ProbeObservation
    readings = ProbeObservation.objects.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'), probe=PROBE)
    return base_qs.filter(Exists(readings)).values('id')


def fix_revision(fixed):
    """The update revision (UBR) a fixed build names (``10.0.20348.2762`` is 2762), or None."""
    parts = _parts(fixed)
    return parts[3] if parts and len(parts) == 4 else None


# ----------------------------------------------------------------------------- the one-time catch-up after an update

def catch_up(apply=False, batch=200):
    """The one-time catch-up an update runs (``manage.py backfill_windows_builds --apply``, an upgrade backfill): for every current host whose stored
    ports carry an NTLM script's output or whose addresses carry smb-os-discovery's (or that already has a reading), store the Windows release
    readings, then correlate those hosts against the stored Windows CVEs. Idempotent. Returns ``{'hosts', 'readings', 'matches'}``."""
    from django.db.models import Q
    from django.utils import timezone

    from cveFeed import correlation, version_sources
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    base = Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__isnull=False)
    stated = (Q(ip_addresses__ports__extra__scripts__has_any_keys=list(NTLM_SCRIPTS))
              | Q(ip_addresses__fingerprint__scripts__has_key=SMB_SCRIPT))
    ids = set(base.filter(stated).values_list('id', flat=True))
    names = set(ProbeObservation.objects.filter(probe=PROBE).values_list('host', flat=True))
    if names:
        ids |= set(base.filter(name__in=names).values_list('id', flat=True))
    ids = sorted(ids)
    out = {'hosts': len(ids), 'readings': 0, 'matches': 0}
    if not apply or not ids:
        return out
    cve_by_id, _index = correlation.cve_pool()
    pool = {cve.id: cve for entries in windows_cves(cve_by_id).values() for cve, _why, _items in entries}
    index = correlation.build_product_index(pool.values())
    for start in range(0, len(ids), batch):
        subs = list(Subdomain.objects.filter(id__in=ids[start:start + batch]).select_related('target_domain', 'scan_history')
                    .prefetch_related('technologies', 'ip_addresses__ports'))
        for sub in subs:
            try:
                found = host_readings(sub)
                version_sources._store_derived(sub, PROBE, found, timezone.now())
            except Exception:  # noqa: BLE001 - one host's stored data never stops the catch-up
                logger.exception('Windows build catch-up of host %s failed', sub.pk)
                continue
            out['readings'] += len(found)
            sub.__dict__.pop('_source_rows', None)  # read again at correlation: the rows just written
        if pool:
            out['matches'] += correlation.correlate_subdomains(subs, index, pool, min_confidence=0.4)[1]
    return out
