"""CVE matches from what a host reported about itself (cveFeed.host_inventory).

An external scan guesses a version from a banner and cannot see a kernel or a patch level at all, which is why cvENGINE never turns a
local-only CVE (cveFeed.locality) into a finding. A host's own report is different evidence: the exact operating system build and every
installed package with its version, from the machine that has them. So this module is the one place a local-only CVE can become a
finding, and only from that report. Everything it writes has ``source='host'`` and evidence ``host_reported: true``, so it is labelled
wherever it shows and the locality rule stays what it was for everything else.

Rules that keep it honest:

* A match needs a version inside a real affected range (``version_in_range is True``). A product named with no usable range, or a
  name that merely resembles another, never makes a match: only an exact product name is looked up.
* A distribution's package is judged against the distribution's own fixed versions when the tracker data has them (cveFeed.distro): a
  patched one is kept at low confidence and labelled, like an external match. Without that data a distribution package is at most
  moderate confidence, because an upstream version range cannot see a backported fix. The kernel of a backporting distribution (Ubuntu,
  Debian, RHEL and relatives) is not matched at all, for the same reason: its version number says nothing about its patches.
* A report older than the project's staleness limit creates nothing and closes nothing. A fresh report that no longer lists the
  affected version closes only the matches that same report's earlier version created.
* A CVE an external scan already matched on the host gets the host's evidence added to that match instead of a second row.
"""
import re
from datetime import timedelta

from django.utils import timezone

from cveFeed import correlation, distro as distro_lib, inventory_schema as schema

SOURCE = 'host'
MAX_MATCHES_PER_HOST = 3000
CLOSED_REASON = ('Closed automatically: the host\'s latest inventory report no longer lists an affected version of this software '
                 '(reported {when}).')
# a distribution backports security fixes without changing the upstream version: its kernel version cannot be compared with a range
BACKPORTING = {'ubuntu', 'debian', 'raspbian', 'linuxmint', 'pop', 'kali', 'rhel', 'centos', 'rocky', 'almalinux', 'ol', 'amzn', 'sles',
               'sled', 'opensuse-leap'}
BACKPORTING_LIKE = {'debian', 'ubuntu', 'rhel', 'centos', 'suse'}
# distribution ids cveFeed.distro keeps fixed versions for (os-release ID -> its name there)
TRACKED = {'ubuntu': 'ubuntu', 'debian': 'debian', 'rhel': 'rhel', 'centos': 'centos', 'rocky': 'rhel', 'almalinux': 'rhel'}
# how sure a version inside a range is, by where the version came from, before the distribution's tracker or a known-exploited CVE moves it
CONFIDENCE = {'os': 0.95, 'kernel': 0.8, 'dpkg': 0.6, 'rpm': 0.6, 'apk': 0.8, 'pacman': 0.85}
DEFAULT_CONFIDENCE = 0.85
PATCHED_CONFIDENCE, VULNERABLE_CONFIDENCE = 0.2, 0.95
MACOS_NAMES = {11: 'Big Sur', 12: 'Monterey', 13: 'Ventura', 14: 'Sonoma', 15: 'Sequoia', 26: 'Tahoe'}
_VERSION_SUFFIX = re.compile(r'[-_]?\d+(?:\.\d+)*$')
_WINDOWS = re.compile(r'windows (?P<n>server \d{4}(?: r2)?|11|10|8\.1|8|7)', re.I)
_LEADING_VERSION = re.compile(r'^[vV]?([0-9][0-9A-Za-z.+~^:_-]*)')
_KERNEL = re.compile(r'^\d+\.\d+(?:\.\d+)?')


def _kernel_package(pkg):
    """The kernel's own packages (and the headers built from its source): the running kernel is assessed once, from ``uname``."""
    return (pkg.get('s') or pkg['n']) == 'linux' or bool(re.match(r'^(?:linux-(?:image|headers|modules)|kernel-(?:core|modules|devel))', pkg['n']))


def windows_names(os_block):
    """The product names the CVE feed uses for this Windows build, most specific first: ``Windows 11 Version 23H2``, ``Windows 11``."""
    found = _WINDOWS.search(f'{os_block.get("name", "")} {os_block.get("pretty", "")}')
    if not found:
        return []
    base = 'Windows ' + found.group('n').title()
    release = os_block.get('version') or ''
    named = [f'{base} Version {release}'] if release and not base.startswith('Windows Server') else []
    return named + [base]


def os_components(os_block):
    """The operating system itself as components to look up: ``[{names, version, kind}]``. Linux's is the running kernel."""
    family, version = os_block.get('family'), os_block.get('build') or os_block.get('version') or ''
    if family == 'windows':
        return [{'names': windows_names(os_block), 'version': version, 'kind': 'os', 'ecosystem': 'os'}]
    if family == 'macos':
        major = re.match(r'\d+', os_block.get('version') or '')
        named = [f'macOS {MACOS_NAMES[int(major.group())]}'] if major and int(major.group()) in MACOS_NAMES else []
        return [{'names': ['macOS', *named, 'Mac OS X'], 'version': os_block.get('version') or '', 'kind': 'os', 'ecosystem': 'os'}]
    kernel = _KERNEL.match(os_block.get('kernel') or '')
    if family == 'linux' and kernel and not backports(os_block):
        return [{'names': ['Linux Kernel'], 'version': kernel.group(), 'kind': 'kernel', 'ecosystem': 'kernel'}]
    return []


def backports(os_block):
    """Whether the system's distribution patches its software without changing upstream version numbers."""
    ident = os_block.get('id') or ''
    return ident in BACKPORTING or bool(set(os_block.get('id_like') or []) & BACKPORTING_LIKE and ident not in ('fedora', 'arch', 'alpine'))


def _names_of(pkg):
    """The names to look a package up by: its source package (``libssl3`` is built from ``openssl``), then its own name, each also
    without a trailing version (``php8.1``, ``postgresql-14``)."""
    names = []
    for raw in (pkg.get('s'), pkg['n']):
        if raw:
            names += [raw, _VERSION_SUFFIX.sub('', raw)]
    return [n for n in dict.fromkeys(names) if len(correlation._norm(n)) >= correlation._MIN_TOKEN]


def package_components(os_block, packages):
    """One component per distinct (names, version) of the package list, kernel packages left out."""
    seen, out = set(), []
    for pkg in packages:
        if not pkg.get('v') or _kernel_package(pkg):
            continue
        names = _names_of(pkg)
        key = (tuple(names), pkg['v'])
        if names and key not in seen:
            seen.add(key)
            out.append({'names': names, 'version': pkg['v'], 'kind': 'package', 'ecosystem': pkg['e'], 'package': pkg})
    return out


def _exact_view(index, tokens):
    """A copy of a product index whose name lookups for ``tokens`` are exact (the same name or a listed alias), not the fuzzy word
    match an external banner needs: a package manager names the software precisely, so "php" must not find "phpmyadmin"."""
    view = correlation.ProductIndex(index)
    view.memo = {token: set(index.get(token, ())) for token in tokens}
    return view


def _info(os_block, pkg):
    """The distribution record cveFeed.distro judges a package release by, or None for a package that has no tracked distribution."""
    distro = TRACKED.get(os_block.get('id') or '')
    if not distro or pkg['e'] not in ('dpkg', 'rpm'):
        return None
    release = os_block.get('version') or ''
    release = release.split('.')[0] if distro in ('debian', 'rhel', 'centos') else '.'.join(release.split('.')[:2])
    source = pkg.get('s') or pkg['n']
    return {'distro': distro, 'release': release, 'package': source if distro_lib.is_known_package(source) else '',
            'package_release': pkg['v'], 'upstream_version': distro_lib.upstream_of(pkg['v'])}


def _confidence(component, cve, status):
    if status == distro_lib.PATCHED:
        return PATCHED_CONFIDENCE
    if status == distro_lib.VULNERABLE:
        return VULNERABLE_CONFIDENCE
    base = CONFIDENCE.get(component['kind'] if component['kind'] != 'package' else component['ecosystem'], DEFAULT_CONFIDENCE)
    return round(min(1.0, base + (0.1 if cve.kev else 0.0)), 2)


def _evidence(inv, component, ver, details, local):
    out = {'source': SOURCE, 'host_reported': True, 'scope': 'local' if local else 'external', 'inventory_id': inv.id,
           'reported_at': inv.reported_at.isoformat(), 'component': component['names'][0][:120],
           'ecosystem': component['ecosystem'], 'raw_version': shown_version(component, ver)}
    pkg = component.get('package')
    if pkg:
        from cveFeed import inventory_schema
        out['purl'] = inventory_schema.purl(pkg, inv.os_info or {})[:300]
    return {**out, **details}


def collect(inv, sub, fix_lookup=None):
    """``(rows, external, notes)``: the CVEMatch rows the host's report supports on ``sub`` (a current row of its host), the
    external matches it only adds evidence to (``{cve id: (CVEMatch, row)}``), and notes on what was not assessed and why."""
    from cveFeed.models import CVEMatch
    fix_lookup = fix_lookup or correlation.DbFixLookup()
    os_block, packages = inv.os_info or {}, inv.packages or []
    components = os_components(os_block) + package_components(os_block, packages)
    notes = []
    if os_block.get('family') == 'linux' and backports(os_block):
        notes.append('The kernel was not assessed: this distribution backports fixes, so the kernel version number cannot decide a CVE.')
    pools = ((correlation.local_pool(), True), (correlation.cve_pool(), False))
    external = {m.cve_entry_id: m for m in CVEMatch.objects.filter(
        subdomain__target_domain__project_id=inv.project_id, subdomain__name__iexact=sub.name,
        source__in=correlation._CORRELATED_SOURCES).exclude(ai_verdict='not_affected')}
    tokens = {correlation._norm(name) for component in components for name in component['names']}
    rows, annotated, distinct = [], {}, set()
    for (cve_by_id, index), local in pools:
        if not cve_by_id:
            continue
        view = _exact_view(index, tokens)
        for component in components:
            ver = parse_reported_version(component)
            if ver is None:
                continue
            for name in component['names']:
                token = correlation._norm(name)
                details = {}
                for cve, product, in_range in correlation._match_candidates(name, ver, token, view, cve_by_id, details=details):
                    if in_range is not True:
                        continue
                    row = _row(inv, sub, component, ver, cve, product, details.get(cve.id, {}), local, fix_lookup)
                    if cve.id in external and not local:
                        annotated[cve.id] = row
                    else:
                        rows.append(row)
                        distinct.add((row['cve_entry_id'], row['matched_product']))
                if len(distinct) >= MAX_MATCHES_PER_HOST:
                    notes.append(f'Stopped at {MAX_MATCHES_PER_HOST} matches.')
                    return rows, {cid: (external[cid], r) for cid, r in annotated.items()}, notes
    return rows, {cid: (external[cid], r) for cid, r in annotated.items()}, notes


def parse_reported_version(component):
    """The comparable version of a component, or None. The reported text must itself start like a version: free text with a version
    somewhere in it ("junk 1.8.3") is not one, and is never read as one."""
    raw = distro_lib.upstream_of(component['version']) if component['kind'] == 'package' else component['version']
    return correlation.parse_version(raw, strict=True)


def shown_version(component, ver):
    """The version to store on a match: the reported text when it is plain version text, else only what was parsed from it."""
    raw = component['version']
    if schema.is_version_text(raw):
        return raw[:100]
    lead = _LEADING_VERSION.match(raw)  # "23.01 <b>x</b>": the part that is a version
    return (lead.group(1) if lead else '.'.join(str(part) for part in ver))[:100]


def _row(inv, sub, component, ver, cve, product, details, local, fix_lookup):
    status, fixed = distro_lib.NO_DATA, ''
    pkg = component.get('package')
    info = _info(inv.os_info or {}, pkg) if pkg else None
    if info and info['package']:
        status, fixed = distro_lib.judge(info, fix_lookup(info['distro'], info['package'], cve.cve_id))
    return {'cve_entry_id': cve.id, 'subdomain_id': sub.id, 'source': SOURCE, 'matched_product': (product or component['names'][0])[:255],
            'matched_version': shown_version(component, ver), 'version_in_range': True,
            'confidence': _confidence(component, cve, status), 'scan_history_id': sub.scan_history_id,
            'distro_status': status, 'distro_fixed_version': fixed[:64], 'evidence': _evidence(inv, component, ver, details, local)}


def _add_evidence(external, now):
    """Put the host's own evidence on the external match of the same CVE: the version is confirmed from the machine, so its
    confidence is at least that of a host-reported version."""
    from cveFeed.models import CVEMatch
    for match, row in external.values():
        evidence = {**(match.evidence or {}), 'host_reported': {k: row['evidence'][k] for k in ('inventory_id', 'reported_at', 'component', 'raw_version')
                                                              if k in row['evidence']}}
        if evidence != (match.evidence or {}) or match.confidence < row['confidence']:
            CVEMatch.objects.filter(pk=match.pk).update(evidence=evidence, confidence=max(match.confidence, row['confidence']), updated_at=now)


def _close_unreported(inv, sub_id, current, now):
    """Close this report's earlier matches that the latest version of the same report no longer supports. Returns the host rows touched."""
    from cveFeed.models import CVEMatch
    reason = CLOSED_REASON.format(when=inv.reported_at.date().isoformat())
    stale = [m for m in CVEMatch.objects.filter(source=SOURCE, subdomain_id=sub_id, evidence__inventory_id=inv.id)
             .exclude(ai_verdict='not_affected', ai_reason__startswith='Closed automatically:')
             if (m.cve_entry_id, m.subdomain_id, m.source, m.matched_product) not in current]
    if stale:
        CVEMatch.objects.filter(pk__in=[m.pk for m in stale]).update(
            ai_verdict='not_affected', confidence=0.0, ai_reason=reason, ai_model='deterministic-inventory', updated_at=now)
    return {m.subdomain_id for m in stale}


def _reopen(inv, rows):
    """A match this very report closed earlier that it supports again (the old version came back) is open again. Another report's
    closures are not this one's to undo."""
    from cveFeed.models import CVEMatch
    CVEMatch.objects.filter(source=SOURCE, subdomain_id__in={r['subdomain_id'] for r in rows}, cve_entry_id__in={r['cve_entry_id'] for r in rows},
                            evidence__inventory_id=inv.id, ai_model='deterministic-inventory', ai_reason__startswith='Closed automatically:').update(
        ai_verdict='', ai_reason='', ai_model='', updated_at=timezone.now())


def current_row(project_id, name):
    """The newest row of the host ``name`` in the project's current inventory, or None while no scan has seen it."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    return Subdomain.objects.filter(latest_scan_q(), target_domain__project_id=project_id, name__iexact=name).select_related(
        'target_domain').order_by('-id').first()


def refresh(inv, stale_days, now=None, fix_lookup=None):
    """Bring the host's host-reported matches in line with this report. Returns what happened: ``{'status', 'local', 'external', ...}``.
    ``status`` is ``skipped`` (with a ``reason``: stale, unmatched, superseded by a newer report of the host, or no scanned host yet)
    or ``done``. A skipped refresh changes nothing: an old report neither creates nor closes a finding."""
    from cveFeed import scoring
    from cveFeed.models import HostInventory
    now = now or timezone.now()
    if now - inv.reported_at > timedelta(days=stale_days):
        return {'status': 'skipped', 'reason': 'stale'}
    if not inv.host:
        return {'status': 'skipped', 'reason': 'unmatched'}
    newest = HostInventory.objects.filter(project_id=inv.project_id, host=inv.host).order_by('-reported_at', '-id').first()
    if newest and newest.id != inv.id:
        return {'status': 'skipped', 'reason': 'superseded'}
    sub = current_row(inv.project_id, inv.host)
    if sub is None:
        return {'status': 'skipped', 'reason': 'no scanned host'}
    rows, external, notes = collect(inv, sub, fix_lookup)
    current = {(r['cve_entry_id'], r['subdomain_id'], r['source'], r['matched_product']) for r in rows}
    _reopen(inv, rows)
    correlation.save_matches(rows)
    _add_evidence(external, now)
    touched = _close_unreported(inv, sub.id, current, now) | ({sub.id} if rows or external else set())
    if touched:
        scoring.rescore_subdomain_ids(touched)
        from cveFeed.views import bump_stats_revision
        bump_stats_revision()
    local = sum(1 for r in rows if r['evidence']['scope'] == 'local')
    if rows:
        from cveFeed import activity
        activity.log('inventory', f'{inv.host}: the host\'s own report matched {len(rows)} CVE{"s" if len(rows) != 1 else ""} '
                                  f'({local} only usable from the host itself)', project=inv.project_id)
    return {'status': 'done', 'local': local, 'external': len(rows) - local, 'confirmed': len(external), 'notes': notes}
