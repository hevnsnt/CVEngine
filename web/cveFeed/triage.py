"""AI triage of every finding: a CVE match, a scanner finding (nuclei, a database exposure, bbot), an open web route and a
hygiene finding each get a Triage row with a classification, why it matters, and a fix.

The model never decides alone. ``apply_rules`` is the deterministic layer over its answer:

* **No false negatives.** A finding with hard evidence (a version inside the affected range, a distribution tracker that lists the
  package release as affected, a template hit, a database that answered without credentials, a credential served by an open
  route ...) can never be classified below the floor that evidence sets, whatever the model says. Triage never deletes, closes or
  hides a finding: a likely_false_positive is still listed.
* **No false positives from the model.** ``confirmed`` needs hard evidence or a validation hit (cveFeed.validation); a model that
  says confirmed without either is stored as likely. A reply that fails validation is stored as needs_validation.
* **No provider** means "not triaged": the classification stays empty (never confirmed by the model's absence), and validation
  still runs.

One AI call serves every finding with the same evidence signature (a hash of the evidence, never a hostname), so fifty hosts
running the same nginx for one CVE are one question; a changed signature resets the verdict and the host is rescored. Prompts carry
only cleaned, structured evidence (see reNgine.ai_providers.build_triage_prompt) with the host's own names redacted.

The builders and ``apply_rules`` are pure (duck-typed on the model fields) so they are unit tested without a database.
"""
import hashlib
import json
import logging
import os
import re
from datetime import timedelta
from urllib.parse import urlparse

from django.utils import timezone

from reNgine.ai_providers import AIProviderError, clean_text, triage_finding

logger = logging.getLogger(__name__)

KINDS = ('cve_match', 'nuclei', 'db_exposure', 'route_auth', 'hygiene', 'bbot')
KIND_FK = {'cve_match': 'match', 'nuclei': 'vulnerability', 'db_exposure': 'vulnerability', 'bbot': 'vulnerability',
           'route_auth': 'route', 'hygiene': 'hygiene'}
ORDER = ('likely_false_positive', 'not_applicable', 'needs_validation', 'likely', 'confirmed')
RANK = {name: i for i, name in enumerate(ORDER)}
AI_VERDICT = {'confirmed': 'affected', 'likely': 'affected', 'needs_validation': 'uncertain',
              'likely_false_positive': 'not_affected', 'not_applicable': 'not_affected'}
SEVERITY_NAMES = {-1: 'unknown', 0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
MEDIUM = 2
ADMIN_PATH = re.compile(r'^/(admin|api|actuator|swagger|console|manager)(/|$|\.|\?)', re.I)
CREDENTIAL_TYPES = ('aws_key', 'google_key', 'slack_token', 'github_token', 'stripe_key', 'jwt', 'private_key')
HEAD_STATUS = re.compile(r'^HTTP/\S+\s+(\d{3})')
CHUNK = 500
DEFAULT_CAPS = {'TRIAGE_MAX_PER_RUN': 100, 'TRIAGE_MAX_PER_PROJECT_DAY': 500, 'TRIAGE_MAX_PER_DAY': 2000}


def rank(classification):
    return RANK.get(classification, -1)


def cap(name):
    """A triage cap, overridable by CVENGINE_<NAME> in the environment."""
    try:
        return max(1, int(os.environ.get(f'CVENGINE_{name}', '')))
    except ValueError:
        return DEFAULT_CAPS[name]


def verdict_for(classification):
    """The legacy CVEMatch.ai_verdict a classification maps to, so heat, scoring, auto-fire and work items keep working."""
    return AI_VERDICT.get(classification, '')


# ----------------------------------------------------------------------------- hard evidence and the rules (pure)

def hard_evidence(kind, facts):
    """``(floor, [fact text])`` for one finding: the classification it can never fall below, and the facts that set it. ``facts`` is
    the plain dict a builder made. An empty floor means the model may rate the finding anywhere, including as a false positive."""
    found, floor = [], ''

    def raise_to(level, text):
        nonlocal floor
        found.append(text)
        if rank(level) > rank(floor):
            floor = level
    if kind == 'cve_match':
        if facts.get('template_result') == 'vulnerable':
            raise_to('confirmed', 'a nuclei template check matched this host')
        if facts.get('distro_status') == 'vulnerable':
            raise_to('confirmed', "the distribution's security tracker lists this package release as affected")
        if facts.get('version_in_range') is True and facts.get('distro_status') != 'patched':
            raise_to('needs_validation', 'the version found is inside the affected range')
    elif kind == 'nuclei':
        if facts.get('source') == 'nuclei-cve':
            raise_to('confirmed', 'a CVE template check matched this host')
        if facts.get('matcher_name'):
            raise_to('confirmed' if facts.get('severity', 0) >= MEDIUM else 'needs_validation',
                     f'a template matcher fired ({facts["matcher_name"]})')
        elif facts.get('severity', 0) >= MEDIUM:
            raise_to('needs_validation', 'the scanner rated it medium or higher')
    elif kind == 'db_exposure':
        if facts.get('reply'):
            raise_to('confirmed', 'the service answered with no credentials at all')
        else:
            raise_to('needs_validation', 'a database service was found open')
    elif kind == 'route_auth':
        if facts.get('credential_count', 0) >= 1:
            raise_to('confirmed', 'the open route serves a credential')
        elif facts.get('admin_path') and 200 <= (facts.get('http_status') or 0) < 300:
            raise_to('likely', 'an admin or API route answers anonymously')
    elif kind == 'hygiene':
        raise_to('confirmed', 'a deterministic check failed')
    return floor, found


def apply_rules(kind, facts, parsed):
    """The classification a finding ends with: the model's answer (``parsed`` from parse_triage, None when its reply was unusable)
    held against the hard evidence. Returns a dict with ``classification``, ``reason``, ``overridden`` (the model said something
    else), the model's own words, the advisory fields, ``invalid_output`` and the ``hard_evidence`` facts.

    1. An unusable reply is needs_validation.
    2. ``confirmed`` from the model without hard evidence that confirms is likely: text alone never confirms.
    3. The result is never below the floor the hard evidence sets, so the model cannot clear a finding the evidence supports."""
    floor, evidence = hard_evidence(kind, facts)
    invalid = parsed is None
    said = 'needs_validation' if invalid else parsed['classification']
    reason = 'unparseable model reply' if invalid else parsed['reason']
    final, prefix = said, ''
    if said == 'confirmed' and rank(floor) < rank('confirmed'):
        final = 'likely'
        prefix = 'AI said confirmed but there is no hard evidence or validation hit; kept as likely: '
    if rank(floor) > rank(final):
        if not invalid:
            prefix = f'AI said {said.replace("_", " ")} but {"; ".join(evidence)}; kept as {floor.replace("_", " ")}: '
        else:
            prefix = f'{"; ".join(evidence)}; classified {floor.replace("_", " ")}. '
        final = floor
    adjust = 0 if invalid else parsed['severity_adjust']
    return {
        'classification': final, 'reason': (prefix + reason)[:700], 'overridden': (not invalid) and final != said,
        'model_classification': '' if invalid else said, 'model_reason': '' if invalid else reason,
        'impact': '' if invalid else parsed['impact'], 'severity_adjust': adjust,
        'severity_reason': '' if invalid else parsed['severity_reason'],
        'remediation': '' if invalid else parsed['remediation'],
        'validation_notes': [] if invalid else parsed['validation_steps'], 'invalid_output': invalid, 'hard_evidence': evidence}


def adjusted_severity(base, adjust, has_hard_evidence):
    """The severity (0 info .. 4 critical) after the model's bounded step. One step at most; never above critical; a finding with hard
    evidence is never moved below medium (or below where it already was, when that is lower)."""
    adjust = max(-1, min(1, int(adjust or 0)))
    result = max(0, min(4, base + adjust))
    if has_hard_evidence and adjust < 0:
        result = max(result, min(base, MEDIUM))
    return result


def signature_for(kind, fields):
    """The sha1 of the evidence a verdict depends on. Never a host: the same evidence on fifty hosts is one signature."""
    # Change this when the prompt or deterministic decision rules materially change.
    blob = json.dumps(['decision-v2', kind, fields], sort_keys=True, default=str, separators=(',', ':'))
    return hashlib.sha1(blob.encode()).hexdigest()


# Signature fields that are not evidence about the asset: advisory text and scores from the CVE feed. When only these, or the
# decision scheme above, change, the finding is reviewed again but keeps what was proven about it until the new verdict lands.
NON_ASSET_FIELDS = ('intelligence',)


def evidence_key_for(kind, fields, review_nonce=''):
    """The sha1 of the asset evidence alone: the signature fields without NON_ASSET_FIELDS and without the scheme version. An explicit
    fresh review (a nonce) is part of it, so asking for one still starts over."""
    asset = {k: v for k, v in fields.items() if k not in NON_ASSET_FIELDS} if isinstance(fields, dict) else fields
    blob = [kind, asset, review_nonce] if review_nonce else [kind, asset]
    return hashlib.sha1(json.dumps(blob, sort_keys=True, default=str, separators=(',', ':')).encode()).hexdigest()


def effective_signature(description, review_nonce=''):
    """Evidence signature, with a persisted nonce only for an explicit fresh review."""
    return (signature_for(description['kind'], [description['signature_fields'], review_nonce])
            if review_nonce else description['signature'])


# ----------------------------------------------------------------------------- evidence builders (pure, duck-typed)

def _redact(text, names):
    text = str(text if text is not None else '')
    for name in names:
        if name and len(name) >= 3:
            text = re.sub(re.escape(name), '[host]', text, flags=re.I)
    return text


def _s(value, limit=120, names=()):
    """Target-controlled text (a banner, a product, a version, a title, a path): the host's names redacted, then strictly cleaned."""
    return clean_text(_redact(value, names), limit, strict=True)


def _prose(value, limit, names=()):
    """Feed or template prose: redacted and cleaned, but sentences stay sentences."""
    return clean_text(_redact(value, names), limit)


def _names(*values):
    out = set()
    for value in values:
        value = str(value or '').strip().lower()
        if value:
            out.add(value)
            out.add(urlparse(value if '://' in value else '//' + value).hostname or value)
    return sorted(out, key=len, reverse=True)


def _range(rng, names=()):
    return {k: _s(rng[k], 80, names) for k in ('introduced', 'fixed', 'lastAffected', 'last_affected', 'version', 'status', 'less_than')
            if isinstance(rng, dict) and rng.get(k) not in (None, '')}


def affected_brief(affected, names=()):
    """The part of a CVE's ``affected`` list a prompt needs: vendor, product, package and ranges, each value cleaned, 20 items."""
    out = []
    for item in (affected or [])[:20]:
        if not isinstance(item, dict):
            continue
        row = {k: _s(item[k], 80, names) for k in ('vendor', 'product', 'package') if item.get(k)}
        row['ranges'] = [_range(r, names) for r in (item.get('ranges') or [])[:10] if isinstance(r, dict)]
        out.append(row)
    return out


def describe_cve_match(m):
    """The facts, prompt payload and signature fields of one CVEMatch (``m.cve_entry`` and ``m.subdomain`` loaded)."""
    from cveFeed import detection
    cve, sub = m.cve_entry, getattr(m, 'subdomain', None)
    domain = getattr(sub, 'target_domain', None)
    names = _names(getattr(sub, 'name', ''), getattr(domain, 'name', ''))
    evidence = getattr(m, 'evidence', None) or {}
    facts = {'version_in_range': m.version_in_range, 'distro_status': getattr(m, 'distro_status', '') or '',
             'template_result': getattr(m, 'template_result', '') or ''}
    payload = {
        'product': _s(m.matched_product, 120, names), 'version': _s(m.matched_version, 120, names),
        'version_in_range': m.version_in_range, 'source': _s(m.source, 20),
        'range': _range(evidence.get('range') or {}, names), 'cpe': _s(evidence.get('cpe'), 120, names),
        'service_extra': _s(evidence.get('service_extra'), 120, names),
        'distro_status': facts['distro_status'], 'template_result': facts['template_result'],
        'cve': {'id': _s(cve.cve_id, 40), 'title': _prose(cve.title, 300, names),
                'description': _prose(cve.original_description or cve.summary, 3000, names), 'cvss': cve.cvss,
                'kev': bool(getattr(cve, 'kev', False)), 'epss_reached': bool(getattr(cve, 'epss_reached', False)),
                'exploit_db': bool(getattr(cve, 'exploit_db', False)),
                'affected': affected_brief(cve.affected, names)}}
    guidance = detection.prompt_guidance(cve)  # earlier notes on what makes this CVE apply or not: a hint, the evidence above decides
    if guidance:
        payload['cve']['guidance'] = guidance
    floor, _ = hard_evidence('cve_match', facts)
    fields = {'cve': getattr(m, 'cve_entry_id', None), 'product': m.matched_product, 'version': m.matched_version, 'in_range': m.version_in_range,
              'source': m.source, 'distro': facts['distro_status'], 'template_vulnerable': facts['template_result'] == 'vulnerable',
              'intelligence': hashlib.sha1(json.dumps([cve.affected, cve.cvss, cve.kev, cve.epss_reached, cve.exploit_db,
                                                       cve.original_description or cve.summary], sort_keys=True, default=str).encode()).hexdigest()[:16]}
    cvss = cve.cvss
    base = 4 if cvss and cvss >= 9 else 3 if cvss and cvss >= 7 else 2 if cvss and cvss >= 4 else 1 if cvss else 0
    return {'kind': 'cve_match', 'facts': facts, 'payload': payload, 'signature_fields': fields, 'severity': base,
            'priority': (0 if floor else 3, -base)}


def _status_of(response):
    first = str(response or '').lstrip()[:200].splitlines()[:1]
    found = HEAD_STATUS.match(first[0]) if first else None
    return int(found.group(1)) if found else None


def kind_of_vulnerability(v):
    source = (getattr(v, 'source', '') or '').lower()
    return 'db_exposure' if source == 'db_exposure' else 'bbot' if source == 'bbot' else 'nuclei'


def _vuln_names(v):
    sub, domain = getattr(v, 'subdomain', None), getattr(v, 'target_domain', None)
    return _names(getattr(sub, 'name', ''), getattr(domain, 'name', ''), getattr(v, 'http_url', ''))


def _path_only(url, names):
    try:
        return _s(urlparse(str(url or '')).path or '/', 200, names)
    except ValueError:
        return '/'


def _safe_url_port(url):
    try:
        return urlparse(str(url or '')).port
    except ValueError:
        return None


def describe_vulnerability(v, cves=(), cwes=(), tags=(), port=None):
    """Facts, payload and signature fields of one Vulnerability row. ``cves``/``cwes``/``tags`` are the names of its M2M rows and
    ``port`` a ``(product, version)`` for a database exposure. Nothing from ``request``, ``response`` or ``curl_command`` is read
    except the response's status code, parsed, never quoted."""
    kind = kind_of_vulnerability(v)
    names = _vuln_names(v)
    extracted = [_s(e, 120, names) for e in (v.extracted_results or [])[:5]]
    severity = v.severity if v.severity is not None else 0
    source = v.source or ''
    if kind == 'db_exposure':
        label = (v.template_id or '').replace('db-exposure-', '', 1)
        number = _safe_url_port(v.http_url)
        reply = extracted[0] if extracted else ''
        facts = {'reply': reply}
        payload = {'service': _s(label, 40), 'port': number, 'server_reply': reply,
                   'product': _s((port or ('', ''))[0], 120, names), 'version': _s((port or ('', ''))[1], 120, names),
                   'name': _prose(v.name, 200, names)}
        fields = {'label': label, 'port': number, 'reply': reply}
        priority = (1, 0)
    elif kind == 'bbot':
        facts = {}
        payload = {'module': _s(v.template_id, 60, names), 'name': _prose(v.name, 200, names), 'severity': SEVERITY_NAMES.get(severity),
                   'description': _prose(v.description, 1000, names), 'path': _path_only(v.http_url, names),
                   'snippet': (extracted or [''])[0][:200]}
        fields = {'module': v.template_id or '', 'name': v.name, 'severity': severity}
        priority = (4, -severity)
    else:
        matcher = _s(v.matcher_name, 120, names)
        facts = {'source': source, 'matcher_name': matcher, 'severity': severity}
        payload = {'template_id': _s(v.template_id, 120, names), 'name': _prose(v.name, 200, names), 'severity': SEVERITY_NAMES.get(severity),
                   'matcher_name': matcher, 'extracted_results': extracted, 'cve_ids': sorted(_s(c, 40) for c in cves)[:10],
                   'cwe_ids': sorted(_s(c, 40) for c in cwes)[:10], 'tags': sorted(_s(t, 40) for t in tags)[:15],
                   'description': _prose(v.description, 1500, names), 'path': _path_only(v.http_url, names),
                   'http_status': _status_of(v.response), 'source': _s(source, 40)}
        fields = {'source': source, 'template_id': v.template_id or '', 'matcher': v.matcher_name or '', 'name': v.name,
                  'cves': sorted(cves), 'severity': severity, 'extracted': sorted(extracted)}
        priority = (0, 0) if source == 'nuclei-cve' else (3, -severity)
    return {'kind': kind, 'facts': facts, 'payload': payload, 'signature_fields': fields, 'severity': severity, 'priority': priority}


def describe_route(r, port=None):
    """Facts, payload and signature fields of an open RouteAuth row. Sensitive data goes in as ``{type: count}`` only: never a sample,
    not even a masked one."""
    names = _names(r.host, getattr(getattr(r, 'domain', None), 'name', ''))
    sensitive = r.sensitive or {}
    counts = {_s(k, 40): int((v or {}).get('count', 0) or 0) for k, v in sensitive.items() if isinstance(v, dict)}
    credentials = sum(c for k, c in counts.items() if k in CREDENTIAL_TYPES)
    evidence = r.evidence or {}
    admin = bool(ADMIN_PATH.search(r.path or '/'))
    facts = {'credential_count': credentials, 'admin_path': admin, 'http_status': r.http_status}
    payload = {'path': _s(r.path, 200, names), 'auth_state': _s(r.auth_state, 20), 'http_status': r.http_status,
               'title': _s(r.title, 120, names), 'content_type': _s(r.content_type, 60),
               'markers': [_s(x, 40) for x in (evidence.get('markers') or [])[:10]],
               'cookie_names': [_s(x, 40, names) for x in (evidence.get('cookies') or [])[:10]],
               'sensitive_types': counts, 'sensitive_score': r.sensitive_score, 'admin_path': admin,
               'product': _s((port or ('', ''))[0], 120, names), 'version': _s((port or ('', ''))[1], 120, names)}
    fields = {'path': r.path, 'auth_state': r.auth_state, 'http_status': r.http_status, 'types': sorted(counts), 'admin': admin}
    return {'kind': 'route_auth', 'facts': facts, 'payload': payload, 'signature_fields': fields, 'severity': 2 if admin or credentials else 1,
            'priority': (2 if credentials else 3, 0)}


def describe_hygiene(f):
    names = _names(f.host, getattr(getattr(f, 'domain', None), 'name', ''))
    evidence = {_s(k, 40): _s(v if not isinstance(v, (list, dict)) else json.dumps(v, default=str), 200, names)
                for k, v in list((f.evidence or {}).items())[:20]}
    payload = {'check': _s(f.check_name, 40), 'severity': SEVERITY_NAMES.get(f.severity), 'title': _prose(f.title, 300, names),
               'detail': _prose(f.detail, 600, names), 'evidence': evidence}
    return {'kind': 'hygiene', 'facts': {}, 'payload': payload, 'signature_fields': {'check': f.check_name, 'severity': f.severity,
            'evidence': evidence}, 'severity': f.severity, 'priority': (5, -f.severity)}


# ----------------------------------------------------------------------------- database side

def _port_for(sub, number):
    """``(product, version)`` of the open port ``number`` on a host's addresses, or None."""
    if not sub or not number:
        return None
    for ip in sub.ip_addresses.all():
        for p in ip.ports.all():
            if p.number == number:
                return (p.product or '', p.version or '')
    return None


def describe(finding):
    """The description of a model instance of any triaged kind, with its signature: a dict with kind, facts, payload, signature,
    severity, priority, project_id, domain_id, host, first_seen."""
    from cveFeed.models import CVEMatch, HygieneFinding, RouteAuth
    if isinstance(finding, CVEMatch):
        d = describe_cve_match(finding)
        sub = finding.subdomain
        domain = sub.target_domain if sub else None
        base = {'project_id': domain.project_id if domain else None, 'domain_id': domain.pk if domain else None,
                'host': sub.name if sub else '', 'first_seen': finding.created_at}
    elif isinstance(finding, RouteAuth):
        from startScan.models import Subdomain
        try:
            parsed = urlparse(finding.url or '')
            number = parsed.port or (443 if parsed.scheme == 'https' else 80)
        except ValueError:
            number = None
        sub = Subdomain.objects.filter(name=finding.host, target_domain_id=finding.domain_id).order_by('-id').first()
        d = describe_route(finding, port=_port_for(sub, number))
        base = {'project_id': finding.project_id, 'domain_id': finding.domain_id, 'host': finding.host, 'first_seen': finding.first_seen}
    elif isinstance(finding, HygieneFinding):
        d = describe_hygiene(finding)
        base = {'project_id': finding.domain.project_id, 'domain_id': finding.domain_id, 'host': finding.host,
                'first_seen': finding.first_seen}
    else:  # a startScan.Vulnerability
        sub = finding.subdomain
        # Scanner supplied URLs are evidence, not trusted parser input. Port
        # extraction is only needed for DB exposures and malformed values must
        # not prevent AI review of an otherwise valid finding.
        number = _safe_url_port(finding.http_url) if finding.source == 'db_exposure' else None
        d = describe_vulnerability(
            finding, cves=[c.name for c in finding.cve_ids.all()], cwes=[c.name for c in finding.cwe_ids.all()],
            tags=[t.name for t in finding.tags.all()], port=_port_for(sub, number) if finding.source == 'db_exposure' else None)
        domain = finding.target_domain
        base = {'project_id': domain.project_id if domain else None, 'domain_id': domain.pk if domain else None,
                'host': sub.name if sub else '', 'first_seen': finding.discovered_date}
    d.update(base)
    d['signature'] = signature_for(d['kind'], d['signature_fields'])
    d['evidence_key'] = evidence_key_for(d['kind'], d['signature_fields'])
    d['first_seen'] = d['first_seen'] or timezone.now()
    return d


def _rereview_fields(d, now):
    """The asset evidence is unchanged but the signature is not (new feed intelligence, or a new decision scheme): queue a fresh
    AI review and keep the verdict, classification, validation record and legacy CVE verdict until that review replaces them."""
    return {'signature': d['signature'], 'evidence_key': d['evidence_key'], 'status': 'pending', 'attempts': 0, 'next_attempt_at': None,
            'hard_evidence': hard_evidence(d['kind'], d['facts'])[1], 'updated_at': now}


def _reset_fields(d, now):
    return {'signature': d['signature'], 'evidence_key': d['evidence_key'], 'verdict': None, 'status': 'pending', 'classification': '', 'reason': '',
            'hard_evidence': hard_evidence(d['kind'], d['facts'])[1], 'validation_status': 'none', 'validation_steps': [],
            'validation_evidence': {}, 'validated_at': None, 'attempts': 0, 'next_attempt_at': None, 'confidence_adjust': 0.0,
            'updated_at': now}




def describe_kind(finding):
    from cveFeed.models import CVEMatch, HygieneFinding, RouteAuth
    if isinstance(finding, CVEMatch):
        return 'cve_match'
    if isinstance(finding, RouteAuth):
        return 'route_auth'
    if isinstance(finding, HygieneFinding):
        return 'hygiene'
    return kind_of_vulnerability(finding)


def _fetch(fk, ids):
    from cveFeed.models import Triage
    return {getattr(t, f'{fk}_id'): t for t in Triage.objects.filter(**{f'{fk}_id__in': ids})}


def track(findings):
    """Make sure each finding has a Triage row carrying the signature of its current evidence, and mark it seen now. A row whose
    evidence changed is reset (verdict detached, classification cleared, validation plan dropped), the stale legacy verdict of a CVE
    match is cleared with it, and the hosts are rescored so a stale AI bonus goes. A row whose asset evidence is unchanged and whose
    signature moved only because of the CVE feed or the decision scheme is queued for review without losing its record. Returns ``[(Triage row, description)]`` in the
    order given; a finding with no owning project is skipped (nothing is stored without a tenancy scope)."""
    from cveFeed.models import CVEMatch, Triage
    now = timezone.now()
    pairs, reset_matches = [], []
    findings = [f for f in findings if f is not None]
    for start in range(0, len(findings), CHUNK):
        described = [(f, describe(f)) for f in findings[start:start + CHUNK]]
        described = [(f, d) for f, d in described if d['project_id'] is not None]
        existing = {}
        for fk in set(KIND_FK[d['kind']] for _, d in described):
            ids = [f.pk for f, d in described if KIND_FK[d['kind']] == fk]
            existing[fk] = _fetch(fk, ids)
        new_rows, changed = [], []
        for f, d in described:
            fk = KIND_FK[d['kind']]
            row = existing[fk].get(f.pk)
            if row is not None and row.review_nonce:
                d['signature'] = effective_signature(d, row.review_nonce)
                d['evidence_key'] = evidence_key_for(d['kind'], d['signature_fields'], row.review_nonce)
            if row is None:
                fields = {k: v for k, v in _reset_fields(d, now).items() if k != 'updated_at'}
                new_rows.append(Triage(project_id=d['project_id'], domain_id=d['domain_id'], host=d['host'][:500], kind=d['kind'],
                                       first_seen=d['first_seen'], last_seen=now, **{f'{fk}_id': f.pk}, **fields))
                continue
            row.last_seen, row.host, row.kind = now, d['host'][:500], d['kind']
            if row.signature != d['signature']:
                if row.evidence_key and row.evidence_key == d['evidence_key']:
                    for key, value in _rereview_fields(d, now).items():
                        setattr(row, key, value)
                else:  # the evidence the decision rested on changed (or is unknown, on a row older than evidence_key): start over
                    for key, value in _reset_fields(d, now).items():
                        setattr(row, key, value)
                    if isinstance(f, CVEMatch):
                        reset_matches.append(f)
            elif row.evidence_key != d['evidence_key']:
                row.evidence_key = d['evidence_key']  # rows written before evidence_key existed learn it while their signature still holds
            changed.append(row)
        if new_rows:
            Triage.objects.bulk_create(new_rows, ignore_conflicts=True)  # ids are not set on a conflict-tolerant insert: read back
            for fk in set(KIND_FK[d['kind']] for _, d in described):
                existing[fk].update(_fetch(fk, [f.pk for f, d in described if KIND_FK[d['kind']] == fk and f.pk not in existing[fk]]))
        if changed:
            Triage.objects.bulk_update(changed, ['last_seen', 'host', 'kind', 'signature', 'evidence_key', 'verdict', 'status', 'classification', 'reason',
                                                 'hard_evidence', 'validation_status', 'validation_steps', 'validation_evidence',
                                                 'validated_at', 'attempts', 'next_attempt_at', 'confidence_adjust', 'updated_at'],
                                       batch_size=CHUNK)
        for f, d in described:
            row = existing[KIND_FK[d['kind']]].get(f.pk)
            if row is not None:
                pairs.append((row, d))
    if reset_matches:
        CVEMatch.objects.filter(pk__in=[m.pk for m in reset_matches]).update(ai_verdict='', ai_reason='', ai_model='', updated_at=now)
        for m in reset_matches:
            m.ai_verdict = m.ai_reason = m.ai_model = ''
        from cveFeed import scoring
        scoring.rescore_for_matches(reset_matches)
    return pairs


def load_findings(rows):
    """The finding behind each Triage row, with what ``describe`` reads loaded, for the sweeps (which start from rows, not from a
    scan). A CVE entry shared by many matches is loaded once."""
    from cveFeed.models import CVEMatch, HygieneFinding, RouteAuth
    from startScan.models import Vulnerability
    ids = {fk: [getattr(r, f'{fk}_id') for r in rows if getattr(r, f'{fk}_id')] for fk in ('match', 'vulnerability', 'route', 'hygiene')}
    out = with_cves(CVEMatch.objects.filter(pk__in=ids['match']).select_related('subdomain__target_domain'))
    out += vulnerabilities(Vulnerability.objects.filter(pk__in=ids['vulnerability']))
    out += list(RouteAuth.objects.filter(pk__in=ids['route']).select_related('domain'))
    out += list(HygieneFinding.objects.filter(pk__in=ids['hygiene']).select_related('domain'))
    return out


def with_cves(matches):
    """CVE matches with ``cve_entry`` attached, each distinct CVE read once (its ``affected`` list is large)."""
    from cveFeed.models import CVEEntry
    matches = list(matches)
    entries = CVEEntry.objects.in_bulk({m.cve_entry_id for m in matches})
    for m in matches:
        m.cve_entry = entries[m.cve_entry_id]
    return matches


def vulnerabilities(queryset, limit=None):
    qs = queryset.select_related('subdomain', 'target_domain').prefetch_related('cve_ids', 'cwe_ids', 'tags').defer('request', 'curl_command')
    return list(qs[:limit] if limit else qs)


def collect_for_scan(scan):
    """Everything one scan produced that is triaged: its CVE matches, its scanner findings, and the open admin or sensitive web routes
    its route check just looked at."""
    from django.db.models import Q

    from cveFeed.models import CVEMatch, RouteAuth
    from startScan.models import Vulnerability
    found = with_cves(CVEMatch.objects.filter(subdomain__scan_history=scan).select_related('subdomain__target_domain'))
    found += vulnerabilities(Vulnerability.objects.filter(scan_history=scan))
    routes = RouteAuth.objects.filter(project_id=scan.domain.project_id, domain=scan.domain, auth_state='open',
                                      checked_at__gte=scan.start_scan_date).filter(
        Q(sensitive_score__gt=0) | Q(path__iregex=ADMIN_PATH.pattern)).select_related('domain')
    return found + list(routes)


# ----------------------------------------------------------------------------- asking the model, with caps

def _today():
    return timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)


def asked_today(project_id=None):
    """Billable provider attempts today, including errors and expired worker claims."""
    from cveFeed.models import TriageCall
    since = _today()
    calls = TriageCall.objects.filter(started_at__gte=since)
    return calls.filter(project_id=project_id).count() if project_id is not None else calls.count()


def _reserve_call(kind, signature, project_id):
    """Atomically claim an evidence signature and reserve all daily budgets."""
    from django.db import connection, transaction
    from cveFeed.models import TriageCall, TriageVerdict
    with transaction.atomic():
        # One short global admission lock closes races between different projects.
        if connection.vendor == 'postgresql':
            with connection.cursor() as cursor:
                cursor.execute('SELECT pg_advisory_xact_lock(%s)', [21860073])
        now = timezone.now()
        TriageCall.objects.filter(status='running', expires_at__lte=now).update(status='expired', finished_at=now)
        verdict = TriageVerdict.objects.filter(kind=kind, signature=signature, invalid_output=False).first()
        if verdict:
            return 'cached', verdict
        if TriageCall.objects.filter(kind=kind, signature=signature, status='running').exists():
            return 'inflight', None
        today = TriageCall.objects.filter(started_at__gte=_today())
        if today.count() >= cap('TRIAGE_MAX_PER_DAY') or today.filter(project_id=project_id).count() >= cap('TRIAGE_MAX_PER_PROJECT_DAY'):
            return 'capped', None
        return 'reserved', TriageCall.objects.create(
            kind=kind, signature=signature, project_id=project_id, expires_at=now + timedelta(minutes=10))


def _finish_call(call, status):
    from cveFeed.models import TriageCall
    return TriageCall.objects.filter(pk=call.pk, status='running').update(status=status, finished_at=timezone.now())


def _save_answer(call, kind, signature, outcome, model):
    from django.db import transaction
    from cveFeed.models import TriageCall
    with transaction.atomic():
        current = TriageCall.objects.select_for_update().get(pk=call.pk)
        if current.status != 'running' or current.expires_at <= timezone.now():
            return None
        verdict = _store_verdict(kind, signature, outcome, model)
        current.status, current.finished_at = 'succeeded', timezone.now()
        current.save(update_fields=['status', 'finished_at'])
        return verdict


def _resolve_provider(provider):
    """``False`` means the configured one; None (or any failure to build it) means none: findings are then not triaged."""
    if provider is not False:
        return provider
    try:
        from reNgine.ai_settings import get_configured_provider
        return get_configured_provider()
    except Exception as exc:  # noqa: BLE001 - a misconfigured provider is "no provider", never a failed stage
        logger.warning('triage: no usable AI provider: %s', exc)
        return None


def suggest_local_checks(row, provider=False):
    """AI-suggested, read-only commands a host owner can run themselves to check whether the CVE's own affected
    product (not what was fingerprinted; a CVE match often names a distinct, externally-unconfirmable add-on layered
    on top of the matched one, such as a vendor module bundled with nginx) is actually installed. Only worth asking
    once validation itself found there is no external check at all (``row.validation_status == 'no_check'``); kept on
    the row itself and never regenerated once set, since a no_check row is already the rare case. Never raises: a
    missing provider or an unusable reply just leaves it empty for the next time this row comes up. Returns whether
    anything was stored."""
    if row.kind != 'cve_match' or row.local_checks or not row.match_id:
        return False
    cve = row.match.cve_entry
    resolved = _resolve_provider(provider)
    if resolved is None:
        return False
    from reNgine.ai_providers import AIProviderError, suggest_local_checks as ask
    context = {
        'cve_id': cve.cve_id, 'title': cve.title,
        'affected': [{k: item.get(k) for k in ('vendor', 'product') if isinstance(item.get(k), str) and item.get(k)}
                     for item in (cve.affected if isinstance(cve.affected, list) else [])[:10] if isinstance(item, dict)],
        'matched_product': row.match.matched_product,
    }
    try:
        answer = ask(resolved, context)
    except AIProviderError as exc:
        logger.warning('local-check suggestion failed for %s: %s', cve.cve_id, exc)
        return False
    if answer['parsed'] is None:
        return False
    row.local_checks = {**answer['parsed'], 'model': answer['model'], 'generated_at': timezone.now().isoformat()}
    row.save(update_fields=['local_checks', 'updated_at'])
    return True


def _store_verdict(kind, signature, outcome, model):
    from django.db import IntegrityError

    from cveFeed.models import TriageVerdict
    fields = {k: outcome[k] for k in ('classification', 'reason', 'model_classification', 'model_reason', 'overridden', 'impact',
                                      'severity_adjust', 'severity_reason', 'remediation', 'validation_notes', 'invalid_output')}
    try:
        verdict, _ = TriageVerdict.objects.get_or_create(kind=kind, signature=signature, defaults={**fields, 'model': model[:128]})
    except IntegrityError:
        verdict = TriageVerdict.objects.get(kind=kind, signature=signature)
    if verdict.invalid_output:
        for key, value in fields.items():
            setattr(verdict, key, value)
        verdict.model = model[:128]
        verdict.save(update_fields=[*fields, 'model'])
    return verdict


def _apply(verdict, group):
    """Give every row of one signature group the verdict. A row a validation hit already confirmed keeps confirmed. The legacy
    ``ai_verdict`` of a CVE match follows, and is stored (MatchVerdict) for later correlations to reuse. Returns the ids of the CVE matches whose legacy verdict was written."""
    from cveFeed.models import CVEMatch, MatchVerdict, Triage
    now = timezone.now()
    rows = []
    # The rows were read before the model answered, which can take a while. Re-read them: a row whose evidence changed meanwhile
    # (new signature) or that was deleted is left for the next pass, and a validation hit that landed meanwhile is honoured.
    fresh = {t.pk: t for t in Triage.objects.filter(pk__in=[row.pk for row, _ in group])}
    current = []
    for row, d in group:
        latest = fresh.get(row.pk)
        if latest is None or latest.signature != d['signature']:
            continue
        row.validation_status, row.reason = latest.validation_status, latest.reason
        current.append((row, d))
    group = current
    matches_by_id = {m.pk: m for m in CVEMatch.objects.filter(pk__in=[row.match_id for row, _ in group if row.match_id])}
    for row, d in group:
        classification, reason = verdict.classification, verdict.reason
        if row.validation_status == 'hit' and rank(classification) < rank('confirmed'):
            classification, reason = 'confirmed', row.reason or reason
        match = matches_by_id.get(row.match_id) if row.match_id else None
        # A match is only ever made on hard evidence (the same product, its version inside a bounded range), and a name-only or
        # wrong-product candidate was already closed on its own (correlation.invalid_identity_reason), so what is left here is a match
        # that stands on its version: the model's "not applicable" cannot overrule that, while a version outside the range, a patched
        # distribution package or an unknown range (an end-of-life release no advisory lists) is the model's to judge.
        if match and classification in ('likely_false_positive', 'not_applicable') and match.version_in_range is True \
                and match.distro_status != 'patched':
            classification = 'needs_validation'
            reason = ('AI suggested the match may be inapplicable, but the recorded version is inside the advisory\'s affected range '
                      'for the same product, so there is no supported evidence to close it. ' + reason)[:700]
        row.verdict, row.status, row.classification, row.reason = verdict, 'triaged', classification, reason
        row.hard_evidence = hard_evidence(d['kind'], d['facts'])[1]
        row.updated_at = now
        rows.append(row)
    Triage.objects.bulk_update(rows, ['verdict', 'status', 'classification', 'reason', 'hard_evidence', 'updated_at'], batch_size=CHUNK)
    matches = [(row, d) for row, d in group if row.match_id]
    if not matches:
        return []
    by_class = {}
    for row, _ in matches:
        by_class.setdefault((row.classification, row.reason), []).append(row.match_id)
    for (classification, reason), ids in by_class.items():
        CVEMatch.objects.filter(pk__in=ids).update(ai_verdict=verdict_for(classification), ai_reason=reason[:2000], ai_model=verdict.model,
                                                   updated_at=now)
    m = CVEMatch.objects.filter(pk=matches[0][0].match_id).first()
    if m:  # kept for correlation: a new host with the same evidence starts out judged (save_matches never seeds a clearing verdict onto hard evidence)
        MatchVerdict.objects.update_or_create(
            cve_entry_id=m.cve_entry_id, matched_product=m.matched_product, matched_version=m.matched_version,
            version_in_range=m.version_in_range, source=m.source,
            defaults={'ai_verdict': verdict_for(matches[0][0].classification),
                      'ai_reason': matches[0][0].reason, 'ai_model': verdict.model})
    return [row.match_id for row, _ in matches]


def _mark(group, status, diagnostic=None):
    from cveFeed.models import Triage
    fields = {'status': status, 'updated_at': timezone.now()}
    if diagnostic is not None:
        fields['reason'] = json.dumps(diagnostic, sort_keys=True)
    Triage.objects.filter(pk__in=[row.pk for row, _ in group]).update(**fields)
    for row, _ in group:
        row.status = status
        if diagnostic is not None:
            row.reason = fields['reason']


def _error_diagnostic(error, stage, group, provider=None, claim=None):
    """Copyable metadata only; never store a provider reply, prompt, URL, key or exception string."""
    now = timezone.now()
    category = getattr(error, 'category', 'internal_error')
    name = getattr(provider, 'name', '')
    name = name if name in ('anthropic', 'openai', 'openrouter', 'ollama', 'vllm', 'lmstudio') else 'configured'
    model = getattr(provider, '_model', '') if provider else ''  # avoid a network-backed model property while reporting an error
    model = model if isinstance(model, str) and re.fullmatch(r'(?:claude|gpt|o[1-9]|gemini|llama)[A-Za-z0-9./:_-]{0,60}', model) else ''
    signature = group[0][0].signature
    diagnostic_id = hashlib.sha256(f'{stage}:{category}:{signature}:{now.isoformat()}'.encode()).hexdigest()[:12]
    data = {'id': diagnostic_id, 'time': now.isoformat(), 'stage': stage, 'category': category,
            'finding_ids': [row.pk for row, _ in group][:20], 'provider': name, 'model': model,
            'attempt_id': getattr(claim, 'pk', None), 'outcome': 'retry_scheduled',
            'action': 'Check AI provider settings and retry; share this diagnostic without credentials.'}
    for key in ('http_status', 'stop_reason', 'output_length', 'digest', 'reason', 'attempts'):
        value = getattr(error, key, None)
        if value is not None:
            data[key] = value
    return data


def run_triage(pairs, provider=False, scan_id=None):
    """Triage ``pairs`` (from ``track``): rows that already have a verdict for their current signature are left alone; the rest are
    grouped by signature, each group is answered from the stored verdicts or by one model call, within the per-run, per-project and
    per-day caps. With no provider the rows are marked not_triaged; a provider error marks only that group's rows ``error`` (the
    sweep retries them); rows over a cap stay ``pending`` ("queued"). Honours the stop flag of ``scan_id``. Never raises for one
    group's trouble. Returns the counts."""
    from cveFeed.models import CVEMatch, MatchVerdict, Triage, TriageVerdict
    from reNgine import resources
    stats = {'rows': len(pairs), 'asked': 0, 'cached': 0, 'queued': 0, 'not_triaged': 0, 'errors': 0, 'stopped': False}
    # A product identity that never matched the advisory is a bad correlation, not a
    # question worth charging the AI provider for. Retain a deterministic, auditable closure.
    from cveFeed import correlation
    matches = {m.pk: m for m in CVEMatch.objects.filter(pk__in=[row.match_id for row, _ in pairs if row.match_id])
               .select_related('cve_entry', 'subdomain__target_domain')}
    eligible = []
    for row, described in pairs:
        match = matches.get(row.match_id) if row.match_id else None
        if match and correlation.invalid_identity_reason(match):
            correlation.close_invalid_correlation(match)
            continue
        eligible.append((row, described))
    pairs = eligible
    invalid_ids = set(TriageVerdict.objects.filter(pk__in=[row.verdict_id for row, _ in pairs if row.verdict_id],
                                                   invalid_output=True).values_list('id', flat=True))
    invalid_rows = [row for row, _ in pairs if row.verdict_id in invalid_ids]
    if invalid_rows:
        Triage.objects.filter(pk__in=[row.pk for row in invalid_rows]).update(
            verdict=None, status='pending', classification='', reason='', updated_at=timezone.now())
        match_ids = [row.match_id for row in invalid_rows if row.match_id]
        if match_ids:
            CVEMatch.objects.filter(pk__in=match_ids).update(ai_verdict='', ai_reason='', ai_model='')
            MatchVerdict.objects.filter(ai_reason='unparseable model reply',
                                        cve_entry_id__in=CVEMatch.objects.filter(pk__in=match_ids).values('cve_entry_id')).delete()
        for row in invalid_rows:
            row.verdict_id, row.status, row.classification, row.reason = None, 'pending', '', ''
    groups = {}
    for row, d in pairs:
        if row.status != 'triaged' or row.verdict_id is None:
            groups.setdefault((d['kind'], d['signature']), []).append((row, d))
    if not groups:
        return stats
    known = {(v.kind, v.signature): v for v in TriageVerdict.objects.filter(signature__in=[sig for _, sig in groups],
                                                                          invalid_output=False)}
    state = {'provider': False, 'run': 0}
    applied = []
    for key in sorted(groups, key=lambda k: (groups[k][0][1]['priority'], k[1])):
        group = groups[key]
        verdict = known.get(key)
        if verdict is not None:
            stats['cached'] += len(group)
            applied += _apply(verdict, group)
            continue
        if scan_id is not None and resources.abort_requested(scan_id):
            stats['stopped'] = True
            stats['queued'] += len(group)
            continue
        if state['provider'] is False:
            state['provider'] = _resolve_provider(provider)
        if state['provider'] is None:
            stats['not_triaged'] += len(group)
            _mark(group, 'not_triaged')
            continue
        project_id = group[0][0].project_id
        if state['run'] >= cap('TRIAGE_MAX_PER_RUN'):
            stats['queued'] += len(group)
            continue
        try:
            admission, claim = _reserve_call(key[0], key[1], project_id)
        except Exception:
            logger.exception('triage: could not reserve provider budget')
            stats['errors'] += len(group)
            _mark(group, 'error')
            continue
        if admission == 'cached':
            stats['cached'] += len(group)
            applied += _apply(claim, group)
            continue
        if admission != 'reserved':
            stats['queued'] += len(group)
            continue
        state['run'] += 1
        rep_d = group[0][1]
        try:
            answer = triage_finding(state['provider'], rep_d['kind'], rep_d['payload'])
        except AIProviderError as exc:
            _finish_call(claim, 'failed')
            diagnostic = _error_diagnostic(exc, 'ai_triage', group, state['provider'], claim)
            logger.warning('triage provider error: %s', diagnostic)
            stats['errors'] += len(group)
            _mark(group, 'error', diagnostic)
            from cveFeed import activity
            activity.log('confirm', f'AI review failed ({diagnostic["category"]}); diagnostic {diagnostic["id"]}',
                         project=project_id, status='failed', finding_ids=diagnostic['finding_ids'], diagnostic=diagnostic)
            continue
        except Exception:  # noqa: BLE001 - one finding must not stop the others
            _finish_call(claim, 'failed')
            logger.exception('triage failed for a %s finding', rep_d['kind'])
            stats['errors'] += len(group)
            _mark(group, 'error')
            continue
        try:
            outcome = apply_rules(rep_d['kind'], rep_d['facts'], answer['parsed'])
            verdict = _save_answer(claim, key[0], key[1], outcome, answer['model'])
            if verdict is None:
                stats['queued'] += len(group)  # the lease expired while the provider ran
                continue
            known[key] = verdict
            stats['asked'] += 1
            applied += _apply(verdict, group)
        except Exception:
            _finish_call(claim, 'failed')
            logger.exception('triage: could not save provider verdict')
            stats['errors'] += len(group)
            _mark(group, 'error')
    if applied:
        from cveFeed import scoring
        from cveFeed.models import CVEMatch
        scoring.rescore_for_matches(list(CVEMatch.objects.filter(pk__in=set(applied)).select_related('subdomain__target_domain')[:2000]))
    return stats


def triage_matches(matches, cve=None, provider=None):
    """Auto-fire's step: triage ``matches`` of one CVE. The legacy fields on each in-memory match are refreshed, so the caller's
    host selection sees the mapped ``ai_verdict``. Returns the number of questions put to the model."""
    from cveFeed.models import CVEMatch
    matches = list(matches)
    if cve is not None:
        for m in matches:
            m.cve_entry = cve
    stats = run_triage(track(matches), provider=False if provider is None else provider)
    if matches:
        current = {pk: (v, r, m) for pk, v, r, m in CVEMatch.objects.filter(pk__in=[m.pk for m in matches]).values_list(
            'pk', 'ai_verdict', 'ai_reason', 'ai_model')}
        for m in matches:
            if m.pk in current:
                m.ai_verdict, m.ai_reason, m.ai_model = current[m.pk]
    return stats['asked']


def run_for_scan(scan_id, provider=False):
    """The pipeline stage: triage what ``scan_id`` produced (see collect_for_scan)."""
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    pairs = track(collect_for_scan(scan))
    stats = run_triage(pairs, provider=provider, scan_id=scan_id)
    if not stats['stopped']:
        try:  # validation needs no AI, so it is queued whether or not the findings could be triaged
            from cveFeed import validation
            stats['validation_queued'] = validation.dispatch([row for row, _ in pairs], scan_id)
        except Exception:  # noqa: BLE001 - never fatal to the stage
            logger.exception('could not queue validation for scan %s', scan_id)
            stats['validation_queued'] = 0
    return stats


def triage_hygiene(domain_id, provider=False):
    """Triage the open MEDIUM-and-above hygiene findings of one target (called after the hygiene check)."""
    from cveFeed.models import HygieneFinding
    rows = HygieneFinding.objects.filter(domain_id=domain_id, status='open', severity__gte=MEDIUM).select_related('domain')
    return run_triage(track(list(rows)), provider=provider)


BACKFILL_LIMIT = 2000


def backfill(project_id, limit=BACKFILL_LIMIT):
    """Give the findings of ``project_id`` that have no Triage row yet one (findings from before triage existed, or from scans it did
    not run for): its current CVE matches, open scanner findings, open admin or sensitive routes and open MEDIUM-and-worse hygiene
    findings, at most ``limit`` of each kind per call. Returns the number of rows created."""
    from django.db.models import Q

    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch, HygieneFinding, RouteAuth, Triage
    from startScan.models import Vulnerability
    before = Triage.objects.filter(project_id=project_id).count()
    found = with_cves(CVEMatch.objects.filter(subdomain__target_domain__project_id=project_id, triage__isnull=True)
                      .filter(latest_scan_q('subdomain__')).select_related('subdomain__target_domain')[:limit])
    found += vulnerabilities(Vulnerability.objects.filter(target_domain__project_id=project_id, open_status=True, triage__isnull=True),
                             limit)
    found += list(RouteAuth.objects.filter(project_id=project_id, auth_state='open', triage__isnull=True).filter(
        Q(sensitive_score__gt=0) | Q(path__iregex=ADMIN_PATH.pattern)).select_related('domain')[:limit])
    found += list(HygieneFinding.objects.filter(domain__project_id=project_id, status='open', severity__gte=MEDIUM, triage__isnull=True)
                  .select_related('domain')[:limit])
    track(found)
    return Triage.objects.filter(project_id=project_id).count() - before


def sweep(project_id=None, provider=False, limit=None):
    """Triage the rows that still wait: pending (over a cap earlier, or new), error (a provider failure) and, when a provider is now
    configured, not_triaged; oldest first, within the caps. Rows whose evidence changed since are reset by ``track`` first, so they
    are judged on what they hold now."""
    from cveFeed.models import Triage
    if project_id is not None:
        backfill(project_id)
    wanted = ['pending', 'error']
    if _resolve_provider(provider) is not None:
        wanted.append('not_triaged')
    from django.db.models import Q
    qs = Triage.objects.filter(Q(status__in=wanted) | Q(verdict__invalid_output=True))
    if project_id is not None:
        qs = qs.filter(project_id=project_id)
    rows = list(qs.order_by('updated_at', 'id')[:limit or cap('TRIAGE_MAX_PER_RUN') * 5])
    if not rows:
        return {'rows': 0}
    return run_triage(track(load_findings(rows)), provider=provider)
