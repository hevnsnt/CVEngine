"""The AI host review: everything cvENGINE knows about one host, read together by the model (docs/AI-REVIEWER.md, "Host review").

The finding review (``cveFeed.reviewer``) judges one finding at a time. The host review gives the model the open results of one host in one
packet, asks for a verdict on each and for ONE next step chosen from a fixed list (``cveFeed.host_actions``). This module builds that packet.
The packet is the only thing the model reads, and every part of it is one of three kinds:

* ``text`` parts that cvENGINE wrote: enums, counts, dates and short refs (``f1``, ``f2``, ...), never a word that came from a host;
* ``fence`` parts, data that a scanned host, a scanner or a feed wrote (banners, titles, page text, advisory prose): cleaned to an identifier-like
  alphabet, stripped of sentences that talk to a model, clipped, and delimited by the reviewer container with a fresh nonce, so it cannot close
  its own fence or add a part;
* the wording of cvENGINE's own results that can quote the host (heat reasons, hard-evidence lines), fenced as ``COMPUTED_TEXT``.

The model never sees a host name, an address or a secret value, and refers to a finding only by its ref; ``refs`` (ref to triage id) stays on
this side. The packet is bounded: at most ``MAX_FINDINGS`` findings (fire first, then smoke, then findings cvENGINE has proof of, then by
severity; the rest are only counted by kind and are not judged in this call) and ``PACKET_CHARS`` characters in all.
"""
import hashlib
import json
import logging
from collections import Counter

from django.db.models import Count
from django.utils import timezone

logger = logging.getLogger(__name__)

MAX_FINDINGS = 60
PACKET_CHARS = 80_000
CONTEXT_LIMIT = 9000       # characters of the host's context (host_context.clipped)
FINDING_CHARS = 1200       # one finding's description, once serialised
DESCRIPTION_CHARS = 600    # a CVE's description and its guidance inside that
REASON_CHARS = 300         # an earlier model-written triage reason
COMPUTED_CHARS = 200       # a heat reason or a hard-evidence line
TITLE_CHARS = 100          # a page title, a hygiene title
MAX_STEPS = 5              # checks shown per finding
MAX_RETESTS = 3
MAX_LISTED = 30            # hygiene rows, screenshots and secret kinds listed
HEAT_ORDER = {'fire': 0, 'smoke': 1}


class HostReviewError(ValueError):
    """The host cannot be reviewed now (it has no open finding, or is not a host of the project)."""


class Built(tuple):
    """``(parts, refs, offered)`` of ``build``, with what the job and its answer need besides: ``state_key``, ``injection`` (the families of
    AI-directed text found in the host's evidence), ``rows`` (``[(ref, triage)]`` in ref order), ``domain``, ``sub`` and ``counts``."""

    def __new__(cls, parts, refs, offered, **extra):
        self = super().__new__(cls, (parts, refs, offered))
        self.__dict__.update(extra)
        return self


# ---------------------------------------------------------------------------------------------------------------------------- reading

def unavailable(project, host):
    """Why this host is not reviewed now, or '': it is not a host of the project, it is excluded, archived or gone from its target."""
    from cveFeed.exclusions import is_excluded
    from cveFeed.models import HostState
    state = HostState.objects.filter(project=project, host=host).first()
    if state is None:
        return 'not a host of this project'
    if state.archived_at:
        return 'the host is archived'
    if state.retired_at:
        return 'the host is no longer found'
    if is_excluded(project.pk, host):
        return 'the host is excluded from scanning'
    return ''


def open_rows(project, host):
    """The Triage rows of the host's open findings (the reviewer's own definition of open, web routes left out)."""
    from cveFeed import reviewer
    from cveFeed.models import Triage
    return list(Triage.objects.filter(reviewer.open_q(), project=project, host=host).exclude(kind='route_auth').order_by('id'))


def _load_sub(state):
    from startScan.models import Subdomain
    return (Subdomain.objects.filter(name=state.host, target_domain=state.domain).select_related('target_domain')
            .prefetch_related('technologies', 'ip_addresses__ports', 'waf').order_by('-id').first())


def state_key(fingerprint, rows):
    """The key of one host state: the host's fingerprint and the sorted ``(kind, evidence_key)`` of the open findings shown. A new port, a new
    version, a finding that came or went is a new key, and the host is reviewed again."""
    basis = json.dumps([fingerprint or '', sorted((r.kind, r.evidence_key or r.signature) for r in rows)])
    return hashlib.sha1(basis.encode()).hexdigest()


def _jsonable(value):
    return json.loads(json.dumps(value, default=str))


def _fit(value, limit):
    """``value`` (already cleaned) shrunk until it serialises to at most ``limit`` characters: its longest strings are halved, then its lists
    shortened, then its last keys dropped. Never raises, and what is left is still the same shape."""
    value = _jsonable(value)
    for _ in range(60):
        if len(json.dumps(value)) <= limit:
            return value
        strings = []

        def walk(node, depth=0):
            if isinstance(node, dict):
                for key, item in node.items():
                    if isinstance(item, str):
                        strings.append((len(item), node, key))
                    else:
                        walk(item, depth + 1)
            elif isinstance(node, list):
                for index, item in enumerate(node):
                    if isinstance(item, str):
                        strings.append((len(item), node, index))
                    else:
                        walk(item, depth + 1)
        walk(value)
        strings.sort(key=lambda t: -t[0])
        if strings and strings[0][0] > 40:
            _, node, key = strings[0]
            node[key] = node[key][:max(20, len(node[key]) // 2)]
            continue
        if isinstance(value, dict) and value:
            value.pop(list(value)[-1])
            continue
        break
    return value if len(json.dumps(value)) <= limit else {}


def _raw_text(project, host):
    """What the host said in the places the packet quotes besides its findings, as stored (for the injection scan only, never sent)."""
    from cveFeed.models import HostScreenshot, HygieneFinding
    return [list(HostScreenshot.objects.filter(project=project, host=host).values_list('title', 'reason', 'final_url')[:MAX_LISTED]),
            list(HygieneFinding.objects.filter(domain__project=project, host=host).values_list('title', 'detail', 'evidence')[:MAX_LISTED])]


def _described(finding):
    """``triage.describe`` of one finding with the pieces the packet re-clips: the CVE description and the CVE guidance at most 600 characters,
    the affected list at most three products, and no host context (the host's own is sent once, for all findings)."""
    from cveFeed import triage as triage_lib
    d = triage_lib.describe(finding)
    payload = _jsonable(d.get('payload') or {})
    cve = payload.get('cve')
    if isinstance(cve, dict):
        for key in ('description', 'guidance'):
            if isinstance(cve.get(key), str):
                cve[key] = cve[key][:DESCRIPTION_CHARS]
        if isinstance(cve.get('affected'), list):
            cve['affected'] = cve['affected'][:3]
    return d, payload


def _heat_rank(heat):
    return HEAT_ORDER.get(heat, 2)


def _gather(project, host, rows):
    """One entry per open finding, with everything the packet says about it. Reads each finding once; the host's context is read once for all of them."""
    from cveFeed import injection_guard, reviewer
    from cveFeed import triage as triage_lib
    token = triage_lib._CONTEXT_MEMO.set({})
    try:
        found = {(triage_lib.KIND_FK[triage_lib.describe_kind(f)], f.pk): f for f in triage_lib.load_findings(rows)}
        entries = []
        for row in rows:
            fk = triage_lib.KIND_FK.get(row.kind)
            finding = found.get((fk, getattr(row, f'{fk}_id', None))) if fk else None
            if finding is None:
                continue
            d, payload = _described(finding)
            injection = injection_guard.families(reviewer._raw_evidence(row, finding), d.get('payload'))
            blocked, why = reviewer.close_gate(row.kind, row, finding, injection, d.get('facts'))
            heat, heat_reason = reviewer._heat(row.kind, finding)
            heat = row.heat_override or heat
            entries.append({'row': row, 'finding': finding, 'payload': payload, 'injection': injection, 'blocked': blocked, 'why': why,
                            'heat': heat, 'heat_reason': heat_reason, 'severity': d.get('severity') if d.get('severity') is not None else -1,
                            'proven': bool(reviewer.proof(row.kind, row, finding))})
        return entries
    finally:
        triage_lib._CONTEXT_MEMO.reset(token)


def _ordered(entries):
    """Fire, then smoke, then the rest; findings cvENGINE has proof of first within a heat; then by severity, then oldest id."""
    return sorted(entries, key=lambda e: (_heat_rank(e['heat']), 0 if e['proven'] else 1, -(e['severity'] or 0), e['row'].pk))


def _latest_reviews(triage_ids):
    from cveFeed.models import FindingReview
    out = {}
    for r in (FindingReview.objects.filter(triage_id__in=triage_ids).exclude(outcome='refused').order_by('triage_id', '-created_at', '-id')
              .values('triage_id', 'verdict', 'confidence', 'created_at')):
        out.setdefault(r['triage_id'], r)
    return out


def _retests(triage_ids):
    from cveFeed.models import FixRetest
    out = {}
    for r in FixRetest.objects.filter(triage_id__in=triage_ids).exclude(outcome='').order_by('triage_id', '-created_at').values('triage_id', 'outcome', 'created_at'):
        rows = out.setdefault(r['triage_id'], [])
        if len(rows) < MAX_RETESTS:
            rows.append({'outcome': r['outcome'], 'on': r['created_at'].date().isoformat()})
    return out


def _secrets(project, host):
    """Counts of the host's exposed secrets by kind and status: never a value, a fingerprint, a mask or a place."""
    from cveFeed import triage as triage_lib
    from cveFeed.models import SecretOccurrence
    rows = (SecretOccurrence.objects.filter(project=project, host=host, retired_at__isnull=True).values('finding__kind', 'finding__status')
            .annotate(n=Count('finding', distinct=True)).order_by('finding__kind', 'finding__status')[:MAX_LISTED])
    return [{'kind': triage_lib._s(r['finding__kind'], 60), 'status': triage_lib._s(r['finding__status'], 20), 'count': r['n']} for r in rows]


def _hygiene(project, host):
    from cveFeed import triage as triage_lib
    from cveFeed.models import HygieneFinding
    rows = HygieneFinding.objects.filter(domain__project=project, host=host).order_by('-severity', 'check_name')[:MAX_LISTED]
    return [{'check': triage_lib._s(r.check_name, 40), 'title': triage_lib._s(r.title, TITLE_CHARS), 'status': r.status} for r in rows]


def _screenshots(project, host):
    from cveFeed import triage as triage_lib
    from cveFeed import web_shot
    from cveFeed.models import HostScreenshot
    rows = sorted(HostScreenshot.objects.filter(project=project, host=host), key=web_shot.rank)[:MAX_LISTED]
    return [{'scheme': r.scheme, 'port': r.port, 'outcome': r.outcome, 'title': triage_lib._s(r.title, TITLE_CHARS)} for r in rows]


def _host_facts(project, state, sub):
    from cveFeed import internal_view
    day = lambda value: value.date().isoformat() if value else ''  # noqa: E731
    return {'first_seen': day(state.first_seen), 'last_seen': day(state.last_seen), 'internal': bool(internal_view.is_internal(project.pk, state.host)),
            'archived': bool(state.archived_at), 'zombie': bool(state.zombie_since), 'pinned': bool(state.pinned), 'has_inventory_record': sub is not None}


# ---------------------------------------------------------------------------------------------------------------------------- the packet

def build(project, host, offered=None, now=None):
    """The packet of one host: ``(parts, refs, offered)``, a ``Built`` that also carries ``state_key``, ``injection``, ``rows``, ``domain``, ``sub``
    and ``counts``. ``parts`` is what ``ai_jobs.enqueue`` takes, ``refs`` maps ``f1`` ... to triage ids (server side only), and ``offered`` is
    what the model may choose as its next step now (``cveFeed.host_actions.offered``; pass a precomputed one to use that instead). Raises
    ``HostReviewError`` when there is nothing to review, or the packet would not fit ``PACKET_CHARS``."""
    from cveFeed import host_context, injection_guard
    from cveFeed import triage as triage_lib
    from cveFeed.models import HostState
    state = HostState.objects.filter(project=project, host=host).select_related('domain').first()
    if state is None:
        raise HostReviewError('not a host of this project')
    rows = open_rows(project, host)
    if not rows:
        raise HostReviewError('the host has no open finding')
    now = now or timezone.now()
    entries = _ordered(_gather(project, host, rows))
    if not entries:
        raise HostReviewError('the host has no open finding that can be read')
    shown, rest = entries[:MAX_FINDINGS], entries[MAX_FINDINGS:]
    sub = _load_sub(state)
    refs = {f'f{i}': e['row'].pk for i, e in enumerate(shown, 1)}
    pairs = [(f'f{i}', e['row']) for i, e in enumerate(shown, 1)]
    if offered is None:
        from cveFeed import host_actions
        offered = host_actions.offered(project, sub, pairs)
    context = host_context.host_context(sub, project.pk) if sub is not None else {}
    injection = injection_guard.families(context, _raw_text(project, host))
    injection = sorted(set(injection) | {name for e in shown for name in e['injection']})
    ids = [e['row'].pk for e in shown]
    latest, retests = _latest_reviews(ids), _retests(ids)

    trusted_findings, described, computed, earlier = [], [], [], []
    for i, e in enumerate(shown, 1):
        ref, row, finding = f'f{i}', e['row'], e['finding']
        steps = [{'kind': str(s.get('kind') or '')[:20], 'result': str(s.get('result') or '')[:40]}
                 for s in (row.validation_steps or [])[:MAX_STEPS] if isinstance(s, dict)]
        seen = latest.get(row.pk)
        trusted_findings.append({
            'ref': ref, 'kind': row.kind, 'heat': e['heat'], 'severity': triage_lib.SEVERITY_NAMES.get(e['severity'], 'unknown'),
            'validation_status': row.validation_status, 'validation_checks': steps, 'status': finding.remediation_status,
            'retest_state': row.retest_state, 'retests': retests.get(row.pk, []), 'server_may_close': not e['blocked'],
            'instructions_aimed_at_ai_found_in_evidence': e['injection'], 'hard_evidence_lines': len(row.hard_evidence or []),
            'first_seen': row.first_seen.date().isoformat() if row.first_seen else '', 'last_seen': row.last_seen.date().isoformat() if row.last_seen else '',
            'earlier_review': ({'verdict': seen['verdict'], 'confidence': seen['confidence'], 'on': seen['created_at'].date().isoformat()} if seen else None)})
        described.append({'ref': ref, 'facts': _fit(e['payload'], FINDING_CHARS)})
        computed.append({'ref': ref, 'heat_reason': str(e['heat_reason'] or '')[:COMPUTED_CHARS],
                         'hard_evidence': [str(x)[:COMPUTED_CHARS] for x in (row.hard_evidence or [])][:8],
                         'server_will_not_close_because': str(e['why'] or '')[:COMPUTED_CHARS]})
        if row.reason:
            earlier.append({'ref': ref, 'written_by_a_model': triage_lib.strip_instructions(str(row.reason)[:REASON_CHARS])})
    counts = Counter(e['row'].kind for e in rest)
    key = state_key(state.fingerprint, [e['row'] for e in shown])
    header = {
        'host': _host_facts(project, state, sub), 'findings': trusted_findings,
        'not_judged_in_this_call': {'count': len(rest), 'by_kind': dict(sorted(counts.items()))},
        'instructions_aimed_at_ai_found_anywhere_in_the_host_evidence': injection,
        'offered_next_steps': _offered_view(offered), 'refs': sorted(refs, key=lambda r: int(r[1:])),
    }
    parts = [{'text': 'TRUSTED (computed by cvENGINE): ' + json.dumps(header, sort_keys=True)},
             {'fence': 'COMPUTED_TEXT', 'data': computed},
             {'fence': 'UNTRUSTED', 'data': {'host_context': host_context.clipped(context, limit=CONTEXT_LIMIT, stable=True) if context else {},
                                              'findings': described,
                                              'secrets_by_kind_and_status': _secrets(project, host), 'hygiene': _hygiene(project, host),
                                              'screenshots': _screenshots(project, host)}},
             {'fence': 'EARLIER_REASONS', 'data': earlier}]
    size = sum(len(json.dumps(p, default=str)) for p in parts)
    if size > PACKET_CHARS:
        parts = _shrink(parts, size)
        size = sum(len(json.dumps(p, default=str)) for p in parts)
    if size > PACKET_CHARS:
        raise HostReviewError(f'the packet is too large ({size} characters)')
    return Built(parts, refs, offered, state_key=key, injection=injection, rows=pairs, domain=state.domain, sub=sub, counts=dict(counts),
                 size=size, state=state)


def _offered_view(offered):
    """The offered actions as the packet shows them: action, class, the refs it may name. Nothing else about them."""
    out = []
    for action, offer in sorted((offered or {}).items()):
        out.append({'action': action, 'class': offer.get('class', ''), 'targets': list(offer.get('targets') or [])})
    return out


def _shrink(parts, size):
    """A packet over the limit: the fenced findings are cut to a third of their room, then the host's context to a third, until it fits."""
    parts = _jsonable(parts)
    untrusted = parts[2]['data']
    for limit in (FINDING_CHARS // 3, FINDING_CHARS // 6):
        untrusted['findings'] = [{'ref': f['ref'], 'facts': _fit(f['facts'], limit)} for f in untrusted['findings']]
        if sum(len(json.dumps(p)) for p in parts) <= PACKET_CHARS:
            return parts
    untrusted['host_context'] = host_context_clip(untrusted['host_context'], CONTEXT_LIMIT // 3)
    return parts


def host_context_clip(context, limit):
    return _fit(context, limit)
