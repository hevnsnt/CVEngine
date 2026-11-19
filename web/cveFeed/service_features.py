"""Service features: what a Sentinel read about one feature of a service, and the CVEs whose advisory says the flaw needs that feature.

Some flaws are only reachable when the service has a feature turned on: the nginx HTTP/2 module flaws (CVE-2026-123007, CVE-2026-123633) need
HTTP/2, Terrapin needs an SSH algorithm, an SMBv3 compression flaw needs compression. A version match cannot tell; a reading of the feature can.
This module holds the three parts, written once for every feature:

- ``FEATURES``: the closed vocabulary. Each feature names its values, which value means "offered", the readings that set it (``sources``), which
  of a host's ports must be read before its absence can be concluded (``relevant``), and whether an edge (a CDN, WAF or reverse proxy that answers
  for the host) answers it instead of the origin (``edge_sensitive``). The readings are stored as ``ServiceFeature`` rows, one per host, port and
  feature; no row is unknown.
- ``requirements(cve)``: the features a CVE needs. The advisory's own words decide (``detection_classes.FEATURE_PRECONDITIONS``, a table with one
  wording rule per feature), unless a person's detection record (source ``manual``) says otherwise (``requires_features``: ``{feature: true |
  false}``, which corrects the rule either way). The rules write the same field on the records they build, for people and agents to read; a
  model's answer never sets it.
- ``assess`` and ``closure_reason``: for a match of such a CVE, the state of the feature on its host: ``offered`` (a fresh reading shows it:
  the match's confidence rises by ``BOOST``, never to proof, see below), ``absent`` (every relevant port was read recently and none offers it:
  the match is closed as not applicable with the reason, through the same path as every other deterministic rule-out,
  ``correlation.close_invalid_correlation``) or ``unknown`` (no fresh reading, a relevant port not read, or an edge answers for the host: no
  change). A feature being on is a precondition, not proof: it never lifts a version-only match above the triage ceiling (``triage.ceiling``)
  and it never raises the classification, only the 0..1 confidence, and at most to ``BOOST_CAP``.

Edges. Behind a CDN or a reverse proxy the TLS handshake (and so ALPN) is the edge's, not the origin nginx's: CloudFront offers h2 whatever
the origin does. For an ``edge_sensitive`` feature a host that ``host_context.edge_for`` reports as fronted (its CNAME, a CDN flag on the host
or an address, a WAF fingerprint, edge response headers, a probe that saw an edge page) reads as unknown, neither ruled out nor raised. That is
deliberately wider than the DNS-verified edge that may clear a match (``triage.closure_basis``): a header alone is the host's own say-so, but
here it can only keep a match open. A reading is the origin's own when the host is reached directly: a name or an address no edge indicator
names (a host that is an address and not a CDN address is the origin address itself).

Re-evaluation. Correlation reads the state for each new or moved match (``adjust``). A new reading reaches the existing matches through
``reevaluate``, run by the hygiene check right after it stores the readings: a match the reading rules out is closed, one an earlier reading
closed is reopened (unjudged, at its version's confidence, its triage row pending again) when the reading no longer rules it out, and the
confidence of the rest follows the state.

Adding a feature (HTTP/3 next: an ``Alt-Svc: h3`` response header, nginx's QUIC module): an entry in ``FEATURES`` (values, sources, relevant
ports), a wording rule in ``detection_classes.FEATURE_PRECONDITIONS``, and a writer that stores its readings with ``store`` from the result
that carries them. Correlation, triage, the closure and the explanation need no change.
"""
import logging
import re
from dataclasses import dataclass, field
from datetime import timedelta

logger = logging.getLogger(__name__)

FRESH = timedelta(days=14)  # a reading older than this is unknown: the hygiene check reads every target daily
BOOST = 0.05  # the confidence a fresh reading that the feature is offered adds to a match: a precondition, never proof
BOOST_CAP = 0.9  # never at or above what hard evidence gives (a distribution tracker listing the build: 0.95)
CLOSED = 'Closed automatically: precondition not met'  # the lead of the closure reason (correlation.AUTO_CLOSED)
AUTOMATIC_MODEL = 'deterministic-correlation'  # what correlation.close_invalid_correlation writes
STATES = ('offered', 'absent', 'unknown')
_WORD = re.compile(r'[^A-Za-z0-9 ._:/;()-]')


def _https_port(number, service='', tunnel=''):
    """A port a TLS web server (nginx, Apache, Tomcat ...) answers HTTPS on: the usual numbers, or a TLS tunnel nmap read as HTTP."""
    service = str(service or '').lower()
    return number in (443, 8443, 9443) or (tunnel == 'ssl' and 'http' in service) or service in ('https', 'https-alt', 'ssl/http', 'ssl/https')


@dataclass(frozen=True)
class Feature:
    key: str
    label: str
    values: tuple  # what a reading may say (a stored value outside it is ignored)
    offered: str  # the value that means the feature is on
    sources: tuple  # the readings that set it
    relevant: object  # (port number, service name, tunnel) -> whether the port must be read before the feature's absence holds
    edge_sensitive: bool = True  # an edge in front of the host answers this reading instead of the origin
    transport: str = 'tls'
    words: dict = field(default_factory=dict)


FEATURES = {
    'http2': Feature('http2', 'HTTP/2', ('yes', 'no'), 'yes', ('tls_alpn',), _https_port, edge_sensitive=True, transport='tls',
                     words={'reading': 'ALPN', 'absent': 'does not offer HTTP/2', 'offered': 'offers HTTP/2',
                            'unread': 'cleartext HTTP/2 (h2c) is not read'}),
}

# what a hygiene_check certificate's ``alpn`` (agentapi.probe_results.ALPN_VALUES) means for the http2 feature; "unknown" or a missing field is no row
ALPN_HTTP2 = {'h2': ('yes', 'ALPN h2'), 'http/1.1': ('no', 'ALPN http/1.1'), 'none': ('no', 'no ALPN protocol chosen')}


def _clean(text, limit=120):
    return _WORD.sub('', str(text or ''))[:limit]


# --- storing readings ------------------------------------------------------------------------------------------------------------------------

def store(domain, host, port, feature, value, source, detail='', now=None):
    """Upsert one reading (``value`` None removes it: the reading said nothing, which is unknown). Returns whether the stored value changed.
    Only the vocabulary is stored: an unknown feature, a value outside the feature's or a source it does not take raises ValueError."""
    from django.utils import timezone

    from cveFeed.models import ServiceFeature
    spec = FEATURES.get(feature)
    if spec is None or source not in spec.sources or (value is not None and value not in spec.values):
        raise ValueError(f'not a {feature} reading: {value!r} from {source!r}')
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise ValueError('port out of range')
    host = str(host or '').strip().lower().rstrip('.')[:500]
    rows = ServiceFeature.objects.filter(domain=domain, host=host, port=port, feature=feature)
    if value is None:
        return rows.filter(source=source).delete()[0] > 0
    before = rows.values_list('value', flat=True).first()
    rows.update_or_create(domain=domain, host=host, port=port, feature=feature,
                          defaults={'value': value, 'detail': _clean(detail), 'source': source, 'transport': spec.transport,
                                    'observed_at': now or timezone.now()})
    return before != value


def store_alpn(domain, infos, nothing_there=(), now=None):
    """Store the http2 readings of one hygiene check: ``infos`` maps ``(host, port)`` to the cleaned certificate info (its ``alpn``), and
    ``nothing_there`` lists the endpoints that answered with no TLS service (their reading goes). Returns the hosts whose state changed."""
    changed = set()
    for (host, port), info in infos.items():
        value, detail = ALPN_HTTP2.get((info or {}).get('alpn'), (None, ''))
        if store(domain, host, port, 'http2', value, 'tls_alpn', detail, now=now):
            changed.add(str(host).lower())
    for host, port in nothing_there:
        if store(domain, host, port, 'http2', None, 'tls_alpn', now=now):
            changed.add(str(host).lower())
    return changed


def readings_for(project_ids, hosts):
    """``{(project id, host): [{port, feature, label, value, detail, source, observed_at, fresh}]}`` for the host page (one query)."""
    from django.utils import timezone

    from cveFeed.models import ServiceFeature
    out, now = {}, timezone.now()
    if not hosts:
        return out
    for row in ServiceFeature.objects.filter(domain__project_id__in=list(project_ids), host__in=list(hosts)).order_by('host', 'port', 'feature') \
            .values('domain__project_id', 'host', 'port', 'feature', 'value', 'detail', 'source', 'observed_at'):
        spec = FEATURES.get(row['feature'])
        if spec is None:
            continue
        out.setdefault((row['domain__project_id'], row['host']), []).append({
            'port': row['port'], 'feature': row['feature'], 'label': spec.label, 'value': row['value'], 'offered': row['value'] == spec.offered,
            'detail': row['detail'], 'source': row['source'], 'observed_at': row['observed_at'].isoformat(),
            'fresh': row['observed_at'] >= now - FRESH})
    return out


# --- which CVEs need a feature ---------------------------------------------------------------------------------------------------------

def _from_words(title, description, stated):
    from cveFeed.detection_classes import feature_preconditions
    found = feature_preconditions(title or '', description or '')
    if isinstance(stated, dict):
        for key, needed in stated.items():
            if key not in FEATURES or not isinstance(needed, bool):
                continue
            if needed:
                found.setdefault(key, {'quote': '', 'rule_out': True})
            else:
                found.pop(key, None)
    return {k: v for k, v in found.items() if k in FEATURES}


def _stated(strategy):
    return strategy.get('requires_features') if isinstance(strategy, dict) else None


def requirements(cve):
    """``{feature: {'quote', 'rule_out'}}``: the service features the CVE's flaw needs. The detection strategy's ``requires_features`` decides
    for a feature it names (True keeps it, with the advisory's sentence when the rule found one; False drops it); the advisory's words decide the
    rest (``detection_classes.feature_preconditions``). Read from ``index()``, so a CVE that needs nothing costs no query (triage asks this of
    every match)."""
    if getattr(cve, 'pk', None) is None:  # not stored: its own words
        return _from_words(getattr(cve, 'title', ''), getattr(cve, 'original_description', '') or getattr(cve, 'summary', ''), None)
    return index().get(cve.pk, {})


_INDEX = {'checked': 0.0, 'stamp': None, 'value': {}}
INDEX_CHECK = 60  # seconds between two looks at whether the CVE table or a detection record changed


def reset_index():
    _INDEX.update(checked=0.0, stamp=None, value={})


def index():
    """``{CVEEntry id: requirements}`` for every CVE that needs a feature: one query for the CVEs whose words name a feature
    (``detection_classes.FEATURE_PREFILTER``, then the rule itself) and one for the detection records that state ``requires_features``. Cached per
    process, and read again when the CVE table or a detection record changed (looked at once every ``INDEX_CHECK`` seconds)."""
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
    except Exception:  # noqa: BLE001 - an edge that cannot be read is an edge that cannot be ruled out: unknown
        logger.warning('could not read the edge of host %s', sub.pk, exc_info=True)
        return {'fronted': True, 'providers': [], 'basis': ['the edge could not be read']}


def _ports_text(rows):
    return '; '.join(f'on {r.port}: {r.detail or r.value}' for r in sorted(rows, key=lambda r: r.port)[:6])


def assess(sub, feature, project_id=None, now=None):
    """``{'feature', 'label', 'state', 'detail', 'why', 'ports'}``: what the readings say about ``feature`` on the host ``sub`` (a Subdomain).
    See the module docstring for the three states. Memoised on the Subdomain object for the life of the object."""
    memo = sub.__dict__.setdefault('_feature_assessments', {})
    if feature in memo:
        return memo[feature]
    from django.utils import timezone

    from cveFeed.models import ServiceFeature
    spec = FEATURES[feature]
    now = now or timezone.now()
    project_id = project_id or (sub.target_domain.project_id if sub.target_domain_id else None)
    rows = [r for r in ServiceFeature.objects.filter(domain__project_id=project_id, host=sub.name.lower(), feature=feature, source__in=spec.sources)
            if r.value in spec.values]
    fresh = [r for r in rows if r.observed_at >= now - FRESH]
    out = {'feature': feature, 'label': spec.label, 'state': 'unknown', 'detail': _ports_text(fresh),
           'ports': {r.port: r.value for r in fresh}, 'why': ''}
    if spec.edge_sensitive and fresh:
        edge = _edge(sub, project_id)
        if edge.get('fronted'):
            named = ', '.join(edge.get('providers') or []) or 'an edge'
            out['why'] = (f'the host is fronted by {named}: its {spec.words.get("reading", "reading")} answer is the edge\'s, not the origin\'s, so it '
                          f'neither rules the match out nor supports it')
            memo[feature] = out
            return out
    offered = [r for r in fresh if r.value == spec.offered]
    if offered:
        out.update(state='offered', detail=_ports_text(offered),
                   why=f'the host {spec.words.get("offered", "offers " + spec.label)} ({_ports_text(offered)})')
    elif not fresh:
        out['why'] = f'no recent reading of {spec.label} on this host' + (' (the last one is older than %d days)' % FRESH.days if rows else '')
    else:
        read = {r.port for r in fresh if spec.relevant(r.port)}
        known = {number for number, (service, tunnel) in _ports_of(sub).items() if spec.relevant(number, service, tunnel)}
        missing = sorted(known - read)
        if not read:
            out['why'] = f'no port of this host where {spec.label} would be served was read'
        elif missing:
            out['why'] = f'port{"s" if len(missing) > 1 else ""} {", ".join(map(str, missing[:6]))} of this host {"were" if len(missing) > 1 else "was"} not read'
        else:
            out.update(state='absent', why=f'the host {spec.words.get("absent", "does not offer " + spec.label)} ({_ports_text(fresh)})')
    memo[feature] = out
    return out


def preconditions_for(sub, cve, now=None):
    """``[{feature, label, state, detail, why, ports, quote, rule_out}]``: one entry per feature ``cve`` needs, as the readings of the host ``sub``
    say; [] when it needs none or there is no host."""
    reqs = requirements(cve)
    if not reqs or sub is None:
        return []
    return [{**assess(sub, key, now=now), **need} for key, need in reqs.items()]


def preconditions(match, now=None):
    """``preconditions_for`` a CVEMatch (``cve_entry`` and ``subdomain`` loaded)."""
    return preconditions_for(getattr(match, 'subdomain', None), match.cve_entry, now=now)


def closure_reason(match, now=None):
    """The reason to close a match whose CVE needs a feature its host does not offer (fresh, direct readings of every relevant port), or ''."""
    for item in preconditions(match, now=now):
        if item['state'] != 'absent' or not item['rule_out']:
            continue
        spec = FEATURES[item['feature']]
        said = f' The advisory says: "{_clean(item["quote"], 300)}"' if item['quote'] else ' Its detection record says the flaw needs it.'
        return (f'{CLOSED}: the host {spec.words.get("absent", "does not offer " + spec.label)} ({item["detail"]}), which this CVE needs.{said} '
                'This closes this candidate match only; a later reading that shows the feature reopens it.')
    return ''


def is_precondition_closure(match):
    return (match.ai_verdict == 'not_affected' and (match.ai_reason or '').startswith(CLOSED)
            and (match.ai_model or '') == AUTOMATIC_MODEL)


def evidence_of(items, boost):
    """The ``evidence['preconditions']`` a match stores: per feature its state, the reading in words and the confidence it added."""
    return {item['feature']: {'state': item['state'], 'detail': _clean(item['detail']), 'boost': boost if item['state'] == 'offered' else 0.0}
            for item in items}


def adjust(confidence, items, eligible=True):
    """``(confidence, evidence)`` of a match after its preconditions: ``BOOST`` for a feature a fresh, direct reading shows offered (once, however
    many features), capped at ``BOOST_CAP`` and never below where it was; ``eligible`` False (a version outside the range, a distribution that lists
    the build as fixed) adds nothing."""
    if not items:
        return confidence, {}
    boost = 0.0
    if eligible and any(i['state'] == 'offered' for i in items) and confidence < BOOST_CAP:
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
    state. Returns ``{'closed', 'reopened', 'raised', 'lowered'}``. Never fatal to the caller."""
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
                   .select_related('cve_entry__detection', 'subdomain__target_domain').order_by('pk'))
    subs = {}
    touched = []
    for match in matches:
        if not requirements(match.cve_entry):
            continue
        match.subdomain = subs.setdefault(match.subdomain_id, match.subdomain)  # one Subdomain object per host: its assessment is read once
        items = preconditions(match, now=now)
        if is_precondition_closure(match):
            if closure_reason(match, now=now):
                continue
            base = _base_confidence(match)
            confidence, evidence = adjust(base, items, _eligible(match))
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
        old = stored_boost(match.evidence)
        confidence, evidence = adjust(round(match.confidence - old, 2), items, _eligible(match))
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
                                f'{counts["reopened"]} reopened (it no longer rules them out)', project=project_id,
                     decision='service_feature_preconditions', **counts)
    return counts
