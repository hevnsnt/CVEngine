"""What counts as evidence for a CVE match, and what happens to a product seen without any.

A CVE match is a finding, so it needs hard evidence about *this host*, not a name that also appears in an advisory:

  * the product seen on the host is the same product the advisory names (``correlation.name_matches_token``) and its version is
    inside a bounded affected range of that advisory; or
  * a confirming check (a template hit), a distribution tracker listing the package as affected, a host-reported inventory
    (source ``host``) or a runZero report of the same CVE (those attach to a match that exists, they do not create one);
  * one exception, kept deliberately: a version of the same product against a CISA KEV advisory that gives no usable version bound
    (empty ranges, "unspecified"). Actively exploited and untestable by version, it is kept as a low-confidence match flagged
    ``evidence.unbounded``: a candidate that needs validation, never an "affected" verdict, and the host is template-tested too.
    It is a "version unknown" match (``is_version_unknown``): marked for review (the Needs validation list, with the reason below),
    very low priority (heat ice, a tiny capped share of the host score, no automatic AI triage or validation spend), and re-evaluated
    by the next correlation as soon as the CVE gains a version range.

A product seen *without a version* is not evidence of anything: "nginx" is in hundreds of advisories and most of them do not
apply to the version the host runs. It stays on the host as a technology or port (metadata is never dropped), and
``unversioned_products`` lists it as an unverified product, the lead for whatever finds its version (a banner, a version probe, a
host inventory). The same goes for an advisory that gives no usable version bound ("all versions", "unspecified"): there is
nothing to test the host's version against. An operating-system fingerprint ("Ubuntu", "Windows Server 2019") is decided by the
host's own report of its patch level, so it never matches by name either.

This module holds the pure rules and the maintenance step; ``correlation`` applies them while it correlates and ``tasks`` runs
``close_policy_matches`` after every update, so matches made before the policy existed close with a stored reason. A match someone took
a position on (remediation other than open, an assignee, a comment, a manual validation request, an AI "affected" verdict) or that
has a template hit, a distribution "vulnerable" verdict, a runZero report or a host-reported source is never closed by any
automatic sweep (``has_standing`` / ``closable``).
"""
import re

NO_EVIDENCE = 'Closed automatically: no version evidence'
REASON_NO_VERSION = (NO_EVIDENCE + '. The product was seen without a version, so cvENGINE cannot tell which '
                     'of its advisories apply; it is kept as a technology on the host (Unverified products) and is matched again '
                     'as soon as a version is identified.')
REASON_NO_BOUND = (NO_EVIDENCE + '. The advisory gives no version bound to test this version against, so '
                   'the product name alone is not evidence that the host is affected.')
REASON_OS = (NO_EVIDENCE + '. An operating-system fingerprint is not matched to CVEs by name from outside; '
             'only the host\'s own inventory report can place its kernel or patch level.')

REASON_VERSION_UNKNOWN = ('Version of the CVE is not known: review when the affected versions are published. The advisory gives no '
                          'usable affected version range, so this host cannot be tested by version. It is kept for review at very '
                          'low priority and is re-evaluated automatically when a range is published; until then only a person '
                          'can decide it.')

# an operating system named by a scanner, as a technology or an nmap product: never a CVE match by name
_OS_NAME = re.compile(
    r'^(?:(?:microsoft|canonical|gnu)\s+)?(?:windows(?:\s+(?:server|nt|\d[\w.]*|xp|vista|rt|ce|embedded)\b.*)?'
    r'|ubuntu(?:\s+linux)?|debian(?:\s+(?:gnu\s*/\s*)?linux)?|centos(?:\s+linux)?|(?:red\s*hat\s+)?(?:enterprise\s+)?linux(?:\s+kernel)?'
    r'|rhel|fedora|alpine(?:\s+linux)?|(?:open)?suse(?:\s+linux)?|rocky(?:\s+linux)?|almalinux|oracle\s+linux|amazon\s+linux'
    r'|freebsd|openbsd|netbsd|macos|mac\s+os(?:\s+x)?|os\s+x|unix|android|ios)$', re.I)
_OS_CPE = re.compile(r'^cpe:(?:/o:|2\.3:o:)', re.I)
# a product that is not software on its own: what a scanner calls a page it could not identify further
_NOT_A_LEAD = frozenset({'unknown', 'tcpwrapped'})


def is_os_sighting(name, cpe=''):
    """Whether a scanner's technology or product name (or CPE) names an operating system rather than an application. The CPE only
    speaks when the name says nothing: nmap gives "Microsoft HTTPAPI httpd" and "Linux telnetd" the CPE of the system they run on,
    but they are applications."""
    if _OS_NAME.match(re.sub(r'[_\-]+', ' ', (name or '').strip())):
        return True
    from cveFeed.correlation import GENERIC_PRODUCT_TOKENS, GENERIC_WORDS, _norm
    token = _norm(name)
    return bool(_OS_CPE.match((cpe or '').strip())) and (not token or token in GENERIC_PRODUCT_TOKENS | GENERIC_WORDS or token in _NOT_A_LEAD)


def hard_version_evidence(in_range, detail=None):
    """Whether a version result is evidence: inside a bounded range, or older than every branch an advisory fixes (an end-of-life
    release that never got a fix, which correlation records as ``branch_unlisted``). An unknown result is not."""
    return in_range is True or bool((detail or {}).get('branch_unlisted'))


def is_version_unknown(evidence, version_in_range, template_result='', distro_status=''):
    """Whether a match stands only on a name and an actively exploited advisory with no version bound (``evidence.unbounded``): kept
    for review, never a verdict. Hard evidence that does not depend on a version (a template hit, a distribution tracker, a runZero
    report) is not "unknown": that match is judged on it. A version inside a range cannot be unknown either."""
    evidence = evidence or {}
    return bool(evidence.get('unbounded')) and version_in_range is None and template_result != 'vulnerable' \
        and distro_status != 'vulnerable' and not evidence.get('runzero')


def version_unknown(match):
    """``is_version_unknown`` of a CVEMatch."""
    return is_version_unknown(match.evidence, match.version_in_range, getattr(match, 'template_result', ''), getattr(match, 'distro_status', ''))


def version_unknown_q(prefix=''):
    """The database form of ``is_version_unknown`` over CVEMatch rows (``prefix`` reaches the match from another model)."""
    from django.db.models import Q
    return (Q(**{prefix + 'evidence__has_key': 'unbounded'}) & Q(**{prefix + 'version_in_range__isnull': True})
            & ~Q(**{prefix + 'template_result': 'vulnerable'}) & ~Q(**{prefix + 'distro_status': 'vulnerable'})
            & ~Q(**{prefix + 'evidence__has_key': 'runzero'}))


def _has_other_evidence(match):
    """A match with hard evidence that does not depend on a version: it stays whatever the sighting says."""
    return (match.template_result == 'vulnerable' or match.distro_status == 'vulnerable'
            or bool((match.evidence or {}).get('runzero')))


def sighting_of(match):
    """``(product name, cpe)`` of the technology or port a correlated match was made from, read from the evidence it stored. A sighting
    that is gone (a rescan replaced it) falls back to the matched product."""
    from startScan.models import Port, Technology
    from cveFeed.correlation import split_name_version
    evidence = match.evidence or {}
    source_id = evidence.get('source_id')
    if source_id and evidence.get('source') == 'tech':
        name = Technology.objects.filter(pk=source_id).values_list('name', flat=True).first()
        if name:
            return split_name_version(name)[0], ''
    if source_id and evidence.get('source') == 'port':
        row = Port.objects.filter(pk=source_id).values_list('product', 'cpe').first()
        if row and row[0]:
            return row[0].strip(), row[1] or evidence.get('cpe') or ''
    return match.matched_product, evidence.get('cpe') or ''


def has_standing(match):
    """Whether someone or something vouches for this match beyond the name it was made from, so no automatic sweep may close it: a
    person worked it (remediation other than open, an assignee, a comment, a manual validation request: not the one running right now,
    which is the very check that re-reads the product identity), the AI confirmed it, a
    template, a distribution tracker or runZero reported it, or the host reported it itself. (``unworked`` is the queryset form.)"""
    from cveFeed.models import FindingComment, OnDemandValidation
    if (match.remediation_status != 'open' or match.assignee_id or match.ai_verdict == 'affected' or match.source == 'host'
            or _has_other_evidence(match)):
        return True
    return (FindingComment.objects.filter(finding_kind='match', finding_id=match.pk).exists()
            or OnDemandValidation.objects.filter(match=match, source='manual').exclude(status='running').exists())


def unworked(qs):
    """The matches of ``qs`` that nobody vouches for (the queryset form of ``not has_standing``)."""
    from django.db.models import Exists, OuterRef

    from cveFeed.models import FindingComment, OnDemandValidation
    return (qs.filter(remediation_status='open', assignee__isnull=True).exclude(source='host')
            .exclude(template_result='vulnerable').exclude(distro_status='vulnerable').exclude(evidence__has_key='runzero')
            .exclude(ai_verdict='affected')
            .exclude(Exists(FindingComment.objects.filter(finding_kind='match', finding_id=OuterRef('pk'))))
            .exclude(Exists(OnDemandValidation.objects.filter(match=OuterRef('pk'), source='manual').exclude(status='running'))))


def no_evidence_reason(match, name, cpe=''):
    """The stored reason to close a correlated (tech or port) match that rests on a name alone, else ''."""
    if match.source not in ('tech', 'port') or has_standing(match):
        return ''
    if is_os_sighting(name, cpe):
        return REASON_OS
    evidence = match.evidence or {}
    if match.version_in_range is True or evidence.get('branch_unlisted') or evidence.get('unbounded'):
        return ''
    return REASON_NO_VERSION if not match.matched_version else REASON_NO_BOUND


def closable(qs):
    """Open, unworked, correlated matches that carry no evidence beyond a name (``unworked``, and not a branch-unlisted or unbounded KEV
    candidate, which are evidence by policy). A row already ruled out (by an earlier pass or by the AI) is left alone."""
    return (unworked(qs.filter(source__in=('tech', 'port')))
            .exclude(evidence__has_key='branch_unlisted').exclude(evidence__has_key='unbounded')
            .exclude(ai_verdict='not_affected'))


def settle_triage(match_ids, reason, now):
    """Give the triage rows of just-closed matches the classification the closure means. The closure writes the match's legacy verdict,
    which every list and count reads, but the triage list and its queues read the row: left alone it keeps saying needs_validation."""
    from cveFeed.models import Triage
    Triage.objects.filter(match_id__in=match_ids).update(classification='not_applicable', status='triaged', reason=reason, updated_at=now)


def close_policy_matches(limit=5000):
    """Close the open matches made before the evidence policy: a sighting with no version, or one whose advisory gave no version bound.
    Bounded (``limit`` matches per run, oldest first) and idempotent: a closed match is never picked again, so repeated runs finish
    the backlog. Rescores the hosts that lost a match. Returns how many were closed. (Wrong-product and operating-system matches need
    the sighting's name and are closed by ``correlation.invalid_identity_reason`` through ``reconcile_invalid_correlations``.)"""
    from django.db.models import Q
    from django.utils import timezone

    from cveFeed import scoring
    from cveFeed.models import CVEMatch
    from cveFeed.views import bump_stats_revision
    ids = list(closable(CVEMatch.objects.filter(version_in_range__isnull=True)).order_by('id').values_list('id', flat=True)[:limit])
    if not ids:
        return 0
    hosts = sorted({h for h in CVEMatch.objects.filter(id__in=ids).values_list('subdomain_id', flat=True) if h})
    now = timezone.now()
    closed = 0
    for reason, selector in ((REASON_NO_VERSION, Q(matched_version='')), (REASON_NO_BOUND, ~Q(matched_version=''))):
        # the guard is part of the UPDATE itself: a person or a template may have acted since the ids were read
        count = closable(CVEMatch.objects.filter(id__in=ids).filter(selector)).update(
            ai_verdict='not_affected', ai_model='deterministic-policy', confidence=0.0, updated_at=now, ai_reason=reason)
        if count:
            settle_triage(CVEMatch.objects.filter(id__in=ids, ai_reason=reason, updated_at=now).values('id'), reason, now)
        closed += count
    for start in range(0, len(hosts), scoring.CHUNK):
        scoring.rescore_subdomain_ids(hosts[start:start + scoring.CHUNK])
    if closed:
        bump_stats_revision()
    return closed


# ----------------------------------------------------------------------------- unversioned products (the leads)

def _lead(name, source, source_id, **extra):
    return {'name': name, 'source': source, 'source_id': source_id, **extra}


def unversioned_leads(technologies, ports):
    """The products a host runs that no version was found for, as ``{name, source, source_id, ...}``: from ``technologies`` (pairs of
    ``(id, stored name)``) and ``ports`` (pairs of ``(ip address, Port)``). One lead per product, and none for a product some other
    sighting on the same host did give a version, an operating system, or a generic label. Pure, so it is unit tested without a database."""
    from cveFeed.correlation import (_MIN_TOKEN, GENERIC_PRODUCT_TOKENS, _norm, name_matches_token, parse_cpe, parse_version,
                                     split_name_version)
    seen, candidates = [], []
    for source_id, stored in technologies:
        name, version = split_name_version(stored or '')
        candidates.append((name or (stored or '').strip(), parse_version(version) is not None, _lead(name or stored, 'tech', source_id)))
    for ip, port in ports:
        name = (port.product or '').strip()
        version = (port.version or '').strip() or (parse_cpe(port.cpe or '') or ('', '', ''))[2]
        candidates.append((name, parse_version(version) is not None,
                           _lead(name, 'port', port.id, ip=ip, port=port.number, protocol=port.protocol, cpe=(port.cpe or '')[:255],
                                 service=port.service_name or '')))
    versioned = [_norm(name) for name, has_version, _lead in candidates if has_version and name]
    leads, listed = [], set()
    for name, has_version, lead in candidates:
        token = _norm(name)
        if (has_version or len(token) < _MIN_TOKEN or token in GENERIC_PRODUCT_TOKENS or name.lower() in _NOT_A_LEAD
                or is_os_sighting(name, lead.get('cpe', ''))):
            continue
        key = (token, lead['source'], lead.get('ip'), lead.get('port'))
        if key in listed or any(name_matches_token(token, other) for other in versioned):
            continue
        listed.add(key)
        leads.append(lead)
    return leads


def unversioned_products(subdomain):
    """The unverified products of one host (a ``Subdomain``): see ``unversioned_leads``. This is what a version probe or an AI
    investigation starts from to find the missing version; the host page shows the same list."""
    from startScan.models import open_services
    technologies = [(t.id, t.name) for t in subdomain.technologies.all()]
    ports = [(ip.address, port) for ip in subdomain.ip_addresses.all() for port in open_services(ip)]
    return unversioned_leads(technologies, ports)
