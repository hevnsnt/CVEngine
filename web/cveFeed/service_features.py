"""Service features: what a Sentinel read about one feature of a service, and the CVEs whose advisory says the flaw needs that feature.

Some flaws are only reachable when the service has a feature turned on: the nginx HTTP/2 module flaws (CVE-2026-123007, CVE-2026-123633) need
HTTP/2, Terrapin needs an SSH algorithm, an SMBv3 compression flaw needs compression. A version match cannot tell; a reading of the feature can.
Everything here is written once for every feature:

- The vocabulary is the Sentinel library's (``cvengine_scanner.features``: ``FEATURES`` and the validator ``clean_features``), one copy for both
  sides. ``SERVER`` adds what only the server needs per feature: its label and words, which of a host's ports must be read before its absence
  can be concluded (``relevant``) and whether an edge (a CDN, WAF or reverse proxy answering for the host) answers the reading instead of the
  origin (``edge_sensitive``). A feature without an entry there gets ``DEFAULT``.
- Readings arrive as the optional ``service_features`` list any result kind may carry (cleaned for every kind by
  ``agentapi.sentinel_broker.clean_result``) and are stored by ``ingest``, the one function every kind's ingest calls, as ``ServiceFeature`` rows
  (one per host, port and feature; no row is unknown). ``ingest`` re-evaluates the matches of the hosts whose readings changed.
- The rule table is ``detection_classes.FEATURE_RULES``: a CVE predicate (the advisory's wording) and, for the feature it needs, the reading values
  that expose the host and those that rule it out. ``requirements(cve)`` gives a CVE's needs; a person's detection record (source ``manual``) can
  correct the rule either way (``requires_features``: ``{feature: true | false}``). The rules write the same field on the records they build;
  a model's answer never sets it.
- One evaluation path (``assess``, ``closure_reason``, ``adjust``) gives three states. ``exposed``: a fresh reading on some port has an exposing
  value; the match's confidence rises by ``BOOST``, at most to ``BOOST_CAP``, never its classification: a feature being on is a precondition, not
  proof, and a version-only match stays under the triage ceiling (``triage.ceiling``). ``ruled_out``: every relevant port of the host was read
  recently, each reading clears it, and the advisory names no way to the feature that is not read; the match is closed as not applicable with
  the reason, through the path every deterministic rule-out uses (``correlation.invalid_identity_reason`` and ``close_invalid_correlation``).
  ``unknown``: anything else (no fresh reading, a relevant port not read, an inconclusive value, an edge): no change.

Edges. Behind a CDN or a reverse proxy the TLS handshake (and so ALPN) is the edge's, not the origin nginx's: CloudFront offers h2 whatever the
origin does. For an ``edge_sensitive`` feature a host that ``host_context.edge_for`` reports as fronted (its CNAME, a CDN flag on the host or an
address, a WAF fingerprint, edge response headers, a probe that saw an edge page) reads as unknown, neither ruled out nor raised. That is wider
than the DNS-verified edge that may clear a match (``triage.closure_basis``): a header alone is the host's own say-so, but here it can only keep a
match open. A reading counts as the origin's own when the host is reached directly: a name or an address no edge indicator names (a host that is
an address and not a CDN address is the origin address itself).

Adding a feature (HTTP/3 next, for the same nginx family: an ``Alt-Svc: h3`` response header, nginx's QUIC module): a vocabulary entry in
``cvengine_scanner.features`` (say ``http3: yes | no``), the Sentinel kind that reads it adds items to its result's ``service_features``, the kind's
server ingest passes them to ``ingest``, a ``SERVER`` entry here (label, words, the HTTPS ports, edge-sensitive) and a rule in
``detection_classes.FEATURE_RULES`` (the advisory's words for "when HTTP/3 / QUIC is enabled"). Correlation, triage, the closure, the explanation
and the host page need no change.
"""
import logging
import re
from dataclasses import dataclass, field
from datetime import timedelta

from cvengine_scanner.features import FEATURES, clean_features

logger = logging.getLogger(__name__)

FRESH = timedelta(days=14)  # a reading older than this is unknown: the hygiene check reads every target daily
BOOST = 0.05  # the confidence a fresh exposing reading adds to a match: a precondition, never proof
BOOST_CAP = 0.9  # never at or above what hard evidence gives (a distribution tracker listing the build: 0.95)
CLOSED = 'Closed automatically: precondition not met'  # the lead of the closure reason (correlation.PRECONDITION_CLOSED)
AUTOMATIC_MODEL = 'deterministic-correlation'  # what correlation.close_invalid_correlation writes
STATES = ('exposed', 'ruled_out', 'unknown')
_SOURCE = re.compile(r'[a-z0-9_]{1,24}')
_WORD = re.compile(r'[^A-Za-z0-9 ._:/;,()+@-]')


def _https_port(number, service='', tunnel=''):
    """A port a TLS web server (nginx, Apache, Tomcat ...) answers HTTPS on: the usual numbers, or a TLS tunnel the port scan read as HTTP."""
    service = str(service or '').lower()
    return number in (443, 8443, 9443) or (tunnel == 'ssl' and 'http' in service) or service in ('https', 'https-alt', 'ssl/http', 'ssl/https')


@dataclass(frozen=True)
class Server:
    label: str
    relevant: object = None  # (port number, service name, tunnel) -> whether the port must be read before the feature can be ruled out; None: any read port
    edge_sensitive: bool = False  # an edge in front of the host answers this reading instead of the origin
    words: dict = field(default_factory=dict)  # 'exposed' / 'ruled_out': how the host is described ("offers HTTP/2")


SERVER = {
    'http2': Server('HTTP/2', _https_port, edge_sensitive=True, words={'exposed': 'offers HTTP/2', 'ruled_out': 'does not offer HTTP/2'}),
}


# --- web service features (Sentinel ``probes.service_reads``: the http_probe and hygiene_check kinds) ---------------------------------------
def _vpn_port(number, service='', tunnel=''):
    """A port an appliance serves its VPN portal on: the HTTPS ports, and the ones FortiGate, GlobalProtect and Connect Secure portals are often
    moved to."""
    return _https_port(number, service, tunnel) or number in (4433, 4443, 10443)


SERVER.update({
    'http3': Server('HTTP/3', _https_port, edge_sensitive=True,
                    words={'exposed': 'advertises HTTP/3 (QUIC) in Alt-Svc', 'ruled_out': 'does not advertise HTTP/3'}),
    # PHP and the operating system named by one answer's headers: one web port speaks for the machine
    'php_windows': Server('PHP on Windows', None, edge_sensitive=True,
                          words={'exposed': 'runs PHP on Windows', 'ruled_out': 'runs PHP on an operating system other than Windows'}),
    # IIS turns WebDAV on for the server, so one port's OPTIONS answer speaks for it; a module's per-path WebDAV is a rule that never rules out
    'webdav': Server('WebDAV', None, edge_sensitive=True, words={'exposed': 'answers WebDAV (a DAV header)', 'ruled_out': 'answers no WebDAV at /'}),
    'http_methods': Server('HTTP methods listed', None, edge_sensitive=True),
    'vpn_fortinet': Server('FortiGate SSL-VPN portal', _vpn_port, edge_sensitive=True,
                           words={'exposed': 'answers its SSL-VPN web portal', 'ruled_out': 'serves no SSL-VPN web portal'}),
    'vpn_globalprotect': Server('GlobalProtect portal or gateway', _vpn_port, edge_sensitive=True,
                                words={'exposed': 'answers a GlobalProtect portal or gateway', 'ruled_out': 'serves no GlobalProtect portal or gateway'}),
    'vpn_cisco': Server('Cisco WebVPN / AnyConnect', _vpn_port, edge_sensitive=True,
                        words={'exposed': 'answers its WebVPN / AnyConnect login page', 'ruled_out': 'serves no WebVPN / AnyConnect login page'}),
    'vpn_citrix': Server('NetScaler Gateway or AAA', _vpn_port, edge_sensitive=True,
                         words={'exposed': 'answers a Gateway or AAA login page', 'ruled_out': 'serves no Gateway or AAA login page'}),
    'vpn_ivanti': Server('Connect Secure sign-in page', _vpn_port, edge_sensitive=True,
                         words={'exposed': 'answers its Connect Secure sign-in page', 'ruled_out': 'serves no Connect Secure sign-in page'}),
    'slp': Server('SLP (TCP 427)', lambda number, service='', tunnel='': number == 427, edge_sensitive=False,
                  words={'exposed': 'answers SLP on TCP 427', 'ruled_out': 'refuses TCP 427 (SLP)'}),
})
# --- end of the web service features


def server(feature):
    return SERVER.get(feature) or Server(feature)


def _words(feature, state):
    spec = server(feature)
    return spec.words.get(state) or (f'has {spec.label} on' if state == 'exposed' else f'does not have {spec.label} on')


def _clean(text, limit=200):
    return _WORD.sub('', str(text or ''))[:limit]


# --- storing readings ------------------------------------------------------------------------------------------------------------------------

def _domains(project_id, hosts):
    """``{host: Domain}`` for the names the project holds (a discovered host, or a target named like it). A reading of a name the project does not
    hold is not stored."""
    from startScan.models import Subdomain
    from targetApp.models import Domain
    out = {}
    for name, domain in Subdomain.objects.filter(target_domain__project_id=project_id, name__in=list(hosts)).select_related('target_domain') \
            .order_by('-id').values_list('name', 'target_domain'):
        out.setdefault(name.lower(), domain)
    for domain in Domain.objects.filter(project_id=project_id, name__in=list(hosts)):
        out.setdefault(domain.name.lower(), domain.pk)
    return out


def ingest(project_id, items, source, allowed=None, covered=None, now=None, reevaluate_matches=True):
    """Store a result's ``service_features`` readings for the project: the one ingest every result kind calls.

    ``items`` is the result's list (validated again here with ``clean_features``: anything malformed or outside the vocabulary is dropped).
    ``source`` names the reading (the task kind, ``[a-z0-9_]{1,24}``). ``allowed``, when given, is the set of ``(host, port)`` the task asked
    about: a reading of anything else is dropped. ``covered``, when given, is the set of ``(host, port, feature)`` the task read: a stored reading
    of such an endpoint from the same source that this result did not repeat is removed (the reading is unknown now, never "no"). A host the
    project does not hold is skipped. The hosts whose readings changed have their CVE matches re-evaluated (``reevaluate``). Returns
    ``{'stored', 'removed', 'changed_hosts'}``."""
    from django.utils import timezone

    from cveFeed.models import ServiceFeature
    if not _SOURCE.fullmatch(str(source or '')):
        raise ValueError('a reading names its source')
    now = now or timezone.now()
    readings = clean_features(items)
    if allowed is not None:
        allowed = {(str(h).lower().rstrip('.'), p) for h, p in allowed}
        readings = [r for r in readings if (r['host'], r['port']) in allowed]
    covered = {(str(h).lower().rstrip('.'), p, f) for h, p, f in covered or ()}
    hosts = {r['host'] for r in readings} | {h for h, _p, _f in covered}
    domains = _domains(project_id, hosts) if hosts else {}
    changed, stored, removed = set(), 0, 0
    seen = set()
    for r in readings:
        domain = domains.get(r['host'])
        if domain is None:
            continue
        seen.add((r['host'], r['port'], r['feature']))
        before = ServiceFeature.objects.filter(domain_id=domain, host=r['host'], port=r['port'], feature=r['feature']).values_list('value', flat=True).first()
        ServiceFeature.objects.update_or_create(domain_id=domain, host=r['host'], port=r['port'], feature=r['feature'], defaults={
            'value': r['value'], 'detail': r['detail'], 'transport': r['transport'], 'source': source, 'observed_at': now})
        stored += 1
        if before != r['value']:
            changed.add(r['host'])
    for host, port, feature in covered - seen:
        domain = domains.get(host)
        if domain is None:
            continue
        gone = ServiceFeature.objects.filter(domain_id=domain, host=host, port=port, feature=feature, source=source).delete()[0]
        if gone:
            removed += gone
            changed.add(host)
    if changed and reevaluate_matches:
        try:
            reevaluate(project_id, changed, now=now)
        except Exception:
            logger.exception('could not re-evaluate the CVE matches of %d host(s) after new service feature readings', len(changed))
    return {'stored': stored, 'removed': removed, 'changed_hosts': sorted(changed)}


def readings_for(project_ids, hosts):
    """``{(project id, host): [{port, transport, feature, label, value, detail, source, observed_at, fresh}]}`` for the host page (one query)."""
    from django.utils import timezone

    from cveFeed.models import ServiceFeature
    out, now = {}, timezone.now()
    if not hosts:
        return out
    for row in ServiceFeature.objects.filter(domain__project_id__in=list(project_ids), host__in=list(hosts)).order_by('host', 'port', 'feature') \
            .values('domain__project_id', 'host', 'port', 'transport', 'feature', 'value', 'detail', 'source', 'observed_at'):
        if row['feature'] not in FEATURES:
            continue
        out.setdefault((row['domain__project_id'], row['host']), []).append({
            'port': row['port'], 'transport': row['transport'], 'feature': row['feature'], 'label': server(row['feature']).label, 'value': row['value'],
            'meaning': meaning(row['feature'], row['value']), 'detail': row['detail'], 'source': row['source'],
            'observed_at': row['observed_at'].isoformat(), 'fresh': row['observed_at'] >= now - FRESH})
    return out


def meaning(feature, value):
    """What one reading does for a CVE that needs ``feature``, by the feature's first rule (``detection_classes.feature_rule``): ``exposed``,
    ``ruled_out`` or ``unknown`` (neither), or '' when no rule reads the feature. For one port only: whether a match is ruled out also needs every
    relevant port of the host read, recently and directly (``assess``)."""
    from cveFeed.detection_classes import feature_rule
    rule = feature_rule(feature)
    if rule is None:
        return ''
    need = {'exposed': tuple(rule['exposed']), 'clears': tuple(rule['rule_out']) if rule['rule_out'] is not None else None}
    return 'exposed' if _exposes(value, need) else 'ruled_out' if _clears(value, need) else 'unknown'


# --- which CVEs need a feature ---------------------------------------------------------------------------------------------------------

def _from_words(title, description, stated):
    from cveFeed.detection_classes import feature_preconditions, feature_rule
    found = feature_preconditions(title or '', description or '')
    if isinstance(stated, dict):
        for key, needed in stated.items():
            if key not in FEATURES or not isinstance(needed, bool):
                continue
            rule = feature_rule(key)
            if needed and key not in found and rule is not None:
                found[key] = {'rule': rule['id'], 'quote': '', 'rule_out': True, 'exposed': tuple(rule['exposed']),
                              'clears': tuple(rule['rule_out']) if rule['rule_out'] is not None else None}
            elif not needed:
                found.pop(key, None)
    return {k: v for k, v in found.items() if k in FEATURES}


def _stated(strategy):
    return strategy.get('requires_features') if isinstance(strategy, dict) else None


def requirements(cve):
    """``{feature: {'rule', 'quote', 'rule_out', 'exposed', 'clears'}}``: the service features the CVE's flaw needs (see the module docstring).
    Read from ``index()``, so a CVE that needs nothing costs no query (triage asks this of every match)."""
    if getattr(cve, 'pk', None) is None:  # not stored: its own words
        return _from_words(getattr(cve, 'title', ''), getattr(cve, 'original_description', '') or getattr(cve, 'summary', ''), None)
    return index().get(cve.pk, {})


_INDEX = {'checked': 0.0, 'stamp': None, 'value': {}}
INDEX_CHECK = 60  # seconds between two looks at whether the CVE table or a detection record changed


def reset_index():
    _INDEX.update(checked=0.0, stamp=None, value={})


def index():
    """``{CVEEntry id: requirements}`` for every CVE that needs a feature: one query for the CVEs whose words name one
    (``detection_classes.FEATURE_PREFILTER``, then the rules themselves) and one for the people's detection records that state
    ``requires_features``. Cached per process, and read again when the CVE table or a detection record changed (looked at once every
    ``INDEX_CHECK`` seconds)."""
    import time

    from django.db.models import Count, Max, Q

    from cveFeed.detection_classes import FEATURE_PREFILTER
    from cveFeed.models import CVEDetection, CVEEntry
    if _INDEX['checked'] and time.monotonic() - _INDEX['checked'] < INDEX_CHECK:
        return _INDEX['value']
    entries = CVEEntry.objects.aggregate(n=Count('id'), latest=Max('synced_at'))
    detections = CVEDetection.objects.aggregate(n=Count('id'), latest=Max('updated_at'))
    stamp = (entries['n'], entries['latest'], detections['n'], detections['latest'])
    if stamp == _INDEX['stamp']:
        _INDEX['checked'] = time.monotonic()
        return _INDEX['value']
    # a person's record only (source manual): the rules' own value is the rule below, and a model's answer never sets one (detection.merge_strategies)
    stated = dict(CVEDetection.objects.filter(source='manual', strategy__has_key='requires_features').values_list('cve_entry_id', 'strategy'))
    words = Q(title__iregex=FEATURE_PREFILTER) | Q(original_description__iregex=FEATURE_PREFILTER) | Q(summary__iregex=FEATURE_PREFILTER)
    out = {}
    for pk, title, description, summary in CVEEntry.objects.filter(words | Q(pk__in=list(stated))).values_list(
            'pk', 'title', 'original_description', 'summary').iterator(chunk_size=500):
        found = _from_words(title, description or summary, _stated(stated.get(pk)))
        if found:
            out[pk] = found
    _INDEX.update(checked=time.monotonic(), stamp=stamp, value=out)
    return out


# --- what the host's readings say -------------------------------------------------------------------------------------------------------

def _ports_of(sub):
    """``{number: (service, tunnel)}`` of the host's open TCP ports."""
    from startScan.models import open_ports
    out = {}
    for ip in sub.ip_addresses.all():
        for port in open_ports(ip):
            out.setdefault(port.number, ((port.service_name or ''), ((port.extra or {}).get('tunnel') or '')))
    return out


def _edge(sub, project_id):
    from cveFeed import host_context
    try:
        return host_context.edge_for(sub, project_id)
    except Exception:
        logger.warning('could not read the edge of host %s', sub.pk, exc_info=True)
        return {'fronted': True, 'providers': [], 'basis': ['the edge could not be read']}


def _ports_text(rows):
    return '; '.join(f'on {r.port}: {r.detail or r.value}' for r in sorted(rows, key=lambda r: r.port)[:6])


def _exposes(value, need):
    return any(token in need['exposed'] for token in str(value).split(','))


def _clears(value, need):
    if _exposes(value, need):
        return False
    clears = need.get('clears')
    return clears is None or all(token in clears for token in str(value).split(','))


def _rows(sub, feature, project_id):
    """The host's stored readings of ``feature``, read once per Subdomain object."""
    memo = sub.__dict__.setdefault('_feature_rows', {})
    if feature not in memo:
        from cveFeed.models import ServiceFeature
        memo[feature] = list(ServiceFeature.objects.filter(domain__project_id=project_id, host=sub.name.lower(), feature=feature))
    return memo[feature]


def assess(sub, feature, need, project_id=None, now=None):
    """``{'feature', 'label', 'state', 'detail', 'why', 'ports'}``: what the host's readings say about ``feature`` under one requirement ``need``
    (what exposes it and what clears it). See the module docstring for the three states."""
    from django.utils import timezone
    spec = server(feature)
    now = now or timezone.now()
    project_id = project_id or (sub.target_domain.project_id if sub.target_domain_id else None)
    allowed = FEATURES[feature]['values']
    rows = [r for r in _rows(sub, feature, project_id) if all(t in allowed for t in str(r.value).split(','))]
    fresh = [r for r in rows if r.observed_at >= now - FRESH]
    out = {'feature': feature, 'label': spec.label, 'state': 'unknown', 'detail': _ports_text(fresh), 'ports': {r.port: r.value for r in fresh}, 'why': ''}
    if spec.edge_sensitive and fresh:
        edge = sub.__dict__.get('_feature_edge')
        if edge is None:
            edge = sub.__dict__['_feature_edge'] = _edge(sub, project_id)
        if edge.get('fronted'):
            named = ', '.join(edge.get('providers') or []) or 'an edge'
            out['why'] = (f'the host is fronted by {named}: the reading is the edge\'s, not the origin\'s, so it neither rules the match out nor '
                          'supports it')
            return out
    exposing = [r for r in fresh if _exposes(r.value, need)]
    if exposing:
        out.update(state='exposed', detail=_ports_text(exposing), why=f'the host {_words(feature, "exposed")} ({_ports_text(exposing)})')
        return out
    if not fresh:
        out['why'] = f'no recent reading of {spec.label} on this host' + (f' (the last one is older than {FRESH.days} days)' if rows else '')
        return out
    known = _ports_of(sub)
    relevant = spec.relevant or (lambda number, service='', tunnel='': True)
    read = {r.port for r in fresh if relevant(r.port, *known.get(r.port, ('', '')))}
    missing = sorted(number for number, (service, tunnel) in known.items() if spec.relevant and relevant(number, service, tunnel) and number not in read)
    if not read:
        out['why'] = f'no port of this host where {spec.label} would be served was read'
    elif missing:
        out['why'] = f'port{"s" if len(missing) > 1 else ""} {", ".join(map(str, missing[:6]))} of this host {"were" if len(missing) > 1 else "was"} not read'
    elif not all(_clears(r.value, need) for r in fresh if r.port in read):
        out['why'] = f'a reading of {spec.label} on this host neither exposes it nor clears it'
    else:
        out.update(state='ruled_out', why=f'the host {_words(feature, "ruled_out")} ({_ports_text(fresh)})')
    return out


def preconditions_for(sub, cve, now=None):
    """``[{feature, label, state, detail, why, ports, rule, quote, rule_out, exposed, clears}]``: one entry per feature ``cve`` needs, as the
    readings of the host ``sub`` say; [] when it needs none or there is no host."""
    reqs = requirements(cve)
    if not reqs or sub is None:
        return []
    return [{**assess(sub, key, need, now=now), **need} for key, need in reqs.items()]


def preconditions(match, now=None):
    """``preconditions_for`` a CVEMatch (``cve_entry`` and ``subdomain`` loaded)."""
    return preconditions_for(getattr(match, 'subdomain', None), match.cve_entry, now=now)


def closure_reason(match, now=None):
    """The reason to close a match whose CVE needs a feature the host's fresh, direct readings rule out, or ''."""
    for item in preconditions(match, now=now):
        if item['state'] != 'ruled_out' or not item['rule_out']:
            continue
        said = f' The advisory says: "{_clean(item["quote"], 300)}"' if item['quote'] else ' Its detection record says the flaw needs it.'
        return (f'{CLOSED}: the host {_words(item["feature"], "ruled_out")} ({item["detail"]}), which this CVE needs.{said} '
                'This closes this candidate match only; a later reading that shows the feature reopens it.')
    return ''


def is_precondition_closure(match):
    return (getattr(match, 'ai_verdict', '') == 'not_affected' and (getattr(match, 'ai_reason', '') or '').startswith(CLOSED)
            and (getattr(match, 'ai_model', '') or '') == AUTOMATIC_MODEL)


def evidence_of(items, boost):
    """The ``evidence['preconditions']`` a match stores: per feature its state, the reading in words and the confidence it added."""
    return {item['feature']: {'state': item['state'], 'detail': _clean(item['detail']), 'boost': boost if item['state'] == 'exposed' else 0.0}
            for item in items}


def adjust(confidence, items, eligible=True):
    """``(confidence, evidence)`` of a match after its preconditions: ``BOOST`` for a feature a fresh, direct reading shows on (once, however many
    features), capped at ``BOOST_CAP`` and never below where it was; ``eligible`` False (a version outside the range, a distribution that lists
    the build as fixed) adds nothing."""
    if not items:
        return confidence, {}
    boost = 0.0
    if eligible and any(i['state'] == 'exposed' for i in items) and confidence < BOOST_CAP:
        boost = round(min(BOOST_CAP, confidence + BOOST) - confidence, 2)
    return round(confidence + boost, 2), evidence_of(items, boost)


def stored_boost(evidence):
    stored = (evidence or {}).get('preconditions') if isinstance(evidence, dict) else None
    if not isinstance(stored, dict):
        return 0.0
    return max((float(v.get('boost') or 0) for v in stored.values() if isinstance(v, dict)), default=0.0)


def _eligible(match):
    return match.version_in_range is not False and (match.distro_status or '') != 'patched'


# --- a new reading reaches the matches ---------------------------------------------------------------------------------------------------

def _base_confidence(match):
    """The confidence correlation gives the match's version (``correlation.confidence_for`` and the distribution's verdict), for a match a
    precondition closure set to 0: the next correlation of the host writes the exact figure."""
    from cveFeed import correlation
    if match.distro_status == 'patched':
        return 0.2
    if match.distro_status == 'vulnerable':
        return 0.95
    value = correlation.confidence_for(correlation.parse_version(match.matched_version or ''), match.version_in_range,
                                       getattr(match.cve_entry, 'kev', False))
    if match.distro_status == 'backport':
        value = min(value, correlation.BACKPORT_CONFIDENCE)
    return value


def reevaluate(project_id, hosts, now=None):
    """Apply the current readings to the current matches of ``hosts`` (names) in the project whose CVE needs a feature: close the ones a reading
    rules out, reopen the ones a precondition closure holds that no reading rules out any more, and move the confidence of the rest with the
    state. Returns ``{'closed', 'reopened', 'raised', 'lowered'}``."""
    from django.db import transaction
    from django.utils import timezone

    from cveFeed import correlation, scoring
    from cveFeed.models import CVEMatch, Triage
    counts = {'closed': 0, 'reopened': 0, 'raised': 0, 'lowered': 0}
    names = {str(h).lower() for h in hosts or () if h}
    needing = list(index())
    if not names or not project_id or not needing:
        return counts
    now = now or timezone.now()
    matches = list(CVEMatch.objects.filter(subdomain__target_domain__project_id=project_id, subdomain__name__in=names, cve_entry_id__in=needing)
                   .filter(correlation.latest_scan_q('subdomain__'))
                   .select_related('cve_entry', 'subdomain__target_domain').order_by('pk'))
    subs, touched = {}, []
    for match in matches:
        match.subdomain = subs.setdefault(match.subdomain_id, match.subdomain)  # one Subdomain object per host: its readings are read once
        items = preconditions(match, now=now)
        if not items:
            continue
        if is_precondition_closure(match):
            if closure_reason(match, now=now):
                continue
            confidence, evidence = adjust(_base_confidence(match), items, _eligible(match))
            evidence = {**(match.evidence if isinstance(match.evidence, dict) else {}), 'preconditions': evidence}
            with transaction.atomic():
                CVEMatch.objects.filter(pk=match.pk, ai_verdict='not_affected').update(
                    ai_verdict='', ai_reason='', ai_model='', confidence=confidence, evidence=evidence, updated_at=now)
                Triage.objects.filter(match_id=match.pk, classification='not_applicable').update(
                    verdict=None, status='pending', classification='', reason='', updated_at=now)
            counts['reopened'] += 1
            touched.append(match.pk)
            continue
        if match.ai_verdict == 'not_affected' and (match.ai_reason or '').startswith('Closed automatically:'):
            continue  # closed by another rule: not this one's to touch
        reason = closure_reason(match, now=now)
        if reason:
            if correlation.close_invalid_correlation(match, reason):
                counts['closed'] += 1
            continue
        confidence, evidence = adjust(round(match.confidence - stored_boost(match.evidence), 2), items, _eligible(match))
        merged = {**(match.evidence if isinstance(match.evidence, dict) else {}), 'preconditions': evidence}
        if confidence != match.confidence or merged != match.evidence:
            CVEMatch.objects.filter(pk=match.pk).update(confidence=confidence, evidence=merged, updated_at=now)
            if confidence > match.confidence:
                counts['raised'] += 1
            elif confidence < match.confidence:
                counts['lowered'] += 1
            touched.append(match.pk)
    if touched:
        scoring.rescore_for_matches(CVEMatch.objects.filter(pk__in=touched).select_related('subdomain__target_domain'))
    if counts['closed'] or counts['reopened']:
        from cveFeed import activity
        activity.log('confirm', f'Service feature readings: {counts["closed"]} CVE match(es) closed (a precondition is not met), '
                                f'{counts["reopened"]} reopened (a reading no longer rules them out)', project=project_id,
                     decision='service_feature_preconditions', **counts)
    return counts
