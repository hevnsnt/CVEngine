"""How hot a hygiene finding is once what is known about its endpoint is taken into account.

``cveFeed.hygiene`` and ``cveFeed.testssl_scan`` rate a finding from the record or the handshake alone. Some of those ratings are too
hot for where the endpoint is (1.3.5 audit):

* a name the client points at a vendor's platform by CNAME (Zendesk, Squarespace, Railway, Microsoft 365, ...) is served by the
  vendor: its TLS configuration is the vendor's, so a finding about it is tagged ``vendor-managed`` and rated ice or info;
* a Microsoft 365 discovery / enrolment name (msoid, enterpriseenrollment, enterpriseregistration, autodiscover) that points at
  Microsoft is Microsoft's own service, not a client asset: no findings, except the certificate name mismatch it has by design, at info;
* a target whose devices use their vendor's private CA (``Domain.expect_private_ca``) has untrusted chains by design: info;
* BREACH is smoke only where the response carries a secret worth stealing (a session or auth cookie, or a signed-in page): ice otherwise;
* a certificate on an auto-renewing managed platform with a week or more left is ice; an expired certificate on a dev host is smoke.

``rate`` applies these to a list of ``Finding`` objects before they are stored, so the stored severity, and with it the Findings list
and the host heat (critical/high fire, medium smoke, low ice, info none), follow. It only ever lowers a severity, and it says why in
``evidence['rating']``. The vendor list is data: ``data/vendor_platforms.json``."""
import functools
import json
import logging
import os
import re

logger = logging.getLogger(__name__)

INFO, LOW, MEDIUM = 0, 1, 2
DATA_FILE = os.path.join(os.path.dirname(__file__), 'data', 'vendor_platforms.json')
VENDOR_TAG = 'vendor-managed'
ENDPOINT_PREFIXES = ('tls_', 'tlsa_', 'spf_')  # findings about what a name serves (its certificate, TLS, its TXT record)
TRUST_CHECKS = ('tls_hostname_mismatch', 'tls_untrusted_chain', 'tls_self_signed')
CHAIN_CHECKS = ('tls_untrusted_chain', 'tls_self_signed')
EXPIRY_CHECKS = ('tls_expiring', 'tls_expired')
BREACH_CHECK = 'tlsa_breach'
AUTH_STATES = ('login', 'session_required', 'sso')
SESSION_COOKIE = re.compile(r'sess|^sid$|[._-]sid$|auth|token|jwt|logged.?in|remember|csrf|xsrf|identity|saml|oidc', re.I)
DEV_LABEL = re.compile(r'^(dev|devel|develop|development|test|testing|qa|uat|stage|staging|stg|sandbox|sbx|preprod|demo|preview|nonprod)\d*$')
MANAGED_MIN_DAYS = 7


@functools.lru_cache(maxsize=1)
def platforms():
    with open(DATA_FILE, encoding='utf-8') as fh:
        data = json.load(fh)
    return {'platforms': [(p['vendor'], tuple(s.lower() for s in p['suffixes'])) for p in data.get('platforms', [])],
            'discovery_vendor': data.get('discovery', {}).get('vendor', 'Microsoft'),
            'discovery_labels': frozenset(x.lower() for x in data.get('discovery', {}).get('labels', [])),
            'auto_renew_issuers': tuple(x.lower() for x in data.get('auto_renew_issuers', []))}


def _clean(name):
    return (name or '').strip().lower().rstrip('.')


def vendor_of(target):
    """The vendor whose platform ``target`` (a CNAME target or a certificate name) is on, '' when none is known."""
    target = _clean(target).lstrip('*.')
    for vendor, suffixes in platforms()['platforms']:
        if any(target == s or target.endswith('.' + s) for s in suffixes):
            return vendor
    return ''


def split_cname(value):
    """Stored CNAME text (one name, or several separated by commas or spaces) as a list of names."""
    return [_clean(x) for x in re.split(r'[,\s]+', value or '') if _clean(x)]


def endpoint_name(host):
    """The host name of a finding's host ('www.example.com:443' -> 'www.example.com')."""
    host = _clean(host)
    m = re.fullmatch(r'(.+):(\d{1,5})', host)
    return m.group(1).strip('[]') if m else host


def is_dev_host(name):
    """A development / test / staging name: one of its labels (or a dash-separated part of one) says so."""
    labels = _clean(name).split('.')[:-2]  # the registrable domain says nothing about the host's role
    return any(DEV_LABEL.match(part) for label in labels for part in [label, *label.split('-')])


def ownership(name, cnames=(), cert_names=()):
    """``(kind, vendor)``: ``('vendor', V)`` when the endpoint is the vendor's own service (a Microsoft discovery name pointing at
    Microsoft), ``('vendor-managed', V)`` when the client's name is served by a vendor platform, ``('', '')`` otherwise."""
    data = platforms()
    targets = [c for c in cnames if c and c != _clean(name)]
    vendors = [v for v in (vendor_of(t) for t in targets) if v]
    first = _clean(name).split('.', 1)[0]
    if first in data['discovery_labels']:
        names = [n for n in cert_names if n]
        by_cert = bool(names) and all(vendor_of(n) == data['discovery_vendor'] for n in names)
        if data['discovery_vendor'] in vendors or by_cert:
            return 'vendor', data['discovery_vendor']
    if vendors:
        return VENDOR_TAG, vendors[0]
    return '', ''


def stored_cnames(project_id, names):
    """``{name: [cname, ...]}`` from what discovery stored about the project's hosts (no DNS)."""
    from startScan.models import Subdomain
    out = {}
    if not names:
        return out
    qs = Subdomain.objects.filter(name__in=sorted(names)).exclude(cname__isnull=True).exclude(cname='')
    if project_id:
        qs = qs.filter(target_domain__project_id=project_id)
    for name, cname in qs.values_list('name', 'cname'):
        out.setdefault(_clean(name), [])
        out[_clean(name)] += [c for c in split_cname(cname) if c not in out[_clean(name)]]
    return out


def resolve_cnames(project_id, names, live=False, lookup=None):
    """Stored CNAMEs first; with ``live`` a name with none stored is looked up once (``hosting.canonical_names``, read by a Sentinel, cached)."""
    found = stored_cnames(project_id, names)
    if live:
        from cveFeed import hosting
        missing = [name for name in names if name not in found and not re.fullmatch(r'[\d.]+|[0-9a-f:]+', name)]
        read = {} if lookup or not missing else hosting.canonical_names(missing)  # one identity_check read by a Sentinel; no answer is no CNAME here
        for name in missing:
            canon = lookup(name) if lookup else read.get(hosting._host(name), '')
            if canon:
                found[name] = [_clean(canon)]
    return found


def session_context(project_id, host):
    """What the route probes saw on ``host``: ``{'authenticated': [paths], 'session_cookies': [names]}`` (empty when nothing)."""
    from cveFeed.models import RouteAuth
    out = {'authenticated': [], 'session_cookies': []}
    if not project_id:
        return out
    for path, state, evidence in RouteAuth.objects.filter(project_id=project_id, host=_clean(host)).values_list('path', 'auth_state', 'evidence')[:200]:
        if state in AUTH_STATES and len(out['authenticated']) < 5:
            out['authenticated'].append(path)
        for cookie in (evidence or {}).get('cookies') or []:
            if SESSION_COOKIE.search(str(cookie)) and cookie not in out['session_cookies'] and len(out['session_cookies']) < 5:
                out['session_cookies'].append(str(cookie)[:64])
    return out


def _lower(f, ceiling, why):
    if f.severity > ceiling:
        rating = dict((f.evidence or {}).get('rating') or {})
        rating.setdefault('from', f.severity)
        rating['why'] = [*rating.get('why', []), why]
        f.evidence = {**(f.evidence or {}), 'rating': rating}
        f.severity = ceiling


def rate(domain, found, cnames=None, live=False, label=True):
    """``found`` (hygiene ``Finding`` objects of ``domain``) with the endpoint-aware ratings applied: some lowered, the vendor's own
    endpoints' findings left out. ``cnames`` maps a host name to its CNAME targets (looked up when not given; ``live`` allows DNS for
    names with none stored). ``label`` records the ``vendor-managed`` chip on the host."""
    project_id = getattr(domain, 'project_id', None)
    names = {endpoint_name(f.host or domain.name) for f in found if (f.check or '').startswith(ENDPOINT_PREFIXES)}
    if cnames is None:
        cnames = resolve_cnames(project_id, names, live=live) if names else {}
    sessions, out, labelled = {}, [], set()
    private_ca = bool(getattr(domain, 'expect_private_ca', False))
    for f in found:
        check = f.check or ''
        name = endpoint_name(f.host or domain.name)
        if check.startswith(ENDPOINT_PREFIXES):
            kind, vendor = ownership(name, cnames.get(name, ()), (f.evidence or {}).get('names') or ())
            if kind == 'vendor':  # not the client's asset: nothing to report, but the name mismatch it has by design, as information
                if check != 'tls_hostname_mismatch':
                    continue
                f.evidence = {**(f.evidence or {}), 'owner': vendor, 'tags': [VENDOR_TAG]}
                _lower(f, INFO, f'{name} is a {vendor} discovery name pointing at {vendor}: the certificate is {vendor}\'s by design')
            elif kind == VENDOR_TAG:
                f.evidence = {**(f.evidence or {}), 'vendor': vendor, 'tags': [VENDOR_TAG], 'cname': cnames.get(name, [])[:3]}
                if check not in EXPIRY_CHECKS:  # an expiring certificate is rated below: a platform's renewal can be stuck
                    _lower(f, INFO if check in TRUST_CHECKS else LOW, f'{name} is served by {vendor} (CNAME): its configuration is the vendor\'s')
                if label and project_id and name not in labelled:
                    from cveFeed import labels
                    labels.record_label(project_id, domain.id, name, VENDOR_TAG, f'CNAME to {vendor} ({", ".join(cnames.get(name, [])[:2])})',
                                        source='hygiene', kind='ownership')
                    labelled.add(name)
        if private_ca and check in CHAIN_CHECKS:
            f.evidence = {**(f.evidence or {}), 'expected_private_ca': True}
            _lower(f, INFO, 'this target is set to expect a private CA')
        if check == BREACH_CHECK:
            if name not in sessions:
                sessions[name] = session_context(project_id, name)
            ctx = sessions[name]
            f.evidence = {**(f.evidence or {}), 'session_context': ctx}
            if ctx['authenticated'] or ctx['session_cookies']:
                _lower(f, MEDIUM, 'the host sets a session or auth cookie, or serves a signed-in page')
            else:
                _lower(f, LOW, 'no session or auth cookie and no signed-in page seen: compression leaks nothing secret')
        if check == 'tls_expiring':
            days = (f.evidence or {}).get('days_left')
            issuer = str((f.evidence or {}).get('issuer') or '').lower()
            managed = ownership(name, cnames.get(name, ()))[0] == VENDOR_TAG or any(i and i in issuer for i in platforms()['auto_renew_issuers'])
            if managed and isinstance(days, int) and days >= MANAGED_MIN_DAYS:
                _lower(f, LOW, 'the certificate is on an auto-renewing managed platform and has a week or more left')
        if check == 'tls_expired' and is_dev_host(name):
            _lower(f, MEDIUM, f'{name} is a development / test host')
        out.append(f)
    return out


def rerate_open(project=None, apply=False, out=None):
    """Apply ``rate`` to the open hygiene findings already stored (the ones rated before 1.3.5), from stored CNAMEs and route probes only
    (no DNS). Counts per project: ``{slug: {'rows', 'lowered', 'dropped', 'heat': {'fire->ice': n, ...}}}``. Nothing is written unless
    ``apply``; then a lowered row takes its new severity and evidence, a vendor's own endpoint's row is resolved, and the touched hosts are
    rescored. A person's remediation status is never changed. ``project`` narrows to one project slug."""
    from django.utils import timezone

    from cveFeed import scoring
    from cveFeed.hygiene import Finding
    from cveFeed.models import HygieneFinding
    from cveFeed.threat import SEVERITY_HEAT
    from targetApp.models import Domain
    qs = HygieneFinding.objects.filter(status='open').select_related('domain__project').order_by('domain_id', 'id')
    if project:
        qs = qs.filter(domain__project__slug=project)
    report, by_domain = {}, {}
    for row in qs.iterator(chunk_size=500):
        by_domain.setdefault(row.domain_id, []).append(row)
    for domain_id, rows in by_domain.items():
        domain = Domain.objects.select_related('project').get(pk=domain_id)
        slug = domain.project.slug if domain.project_id else '-'
        stats = report.setdefault(slug, {'rows': 0, 'lowered': 0, 'dropped': 0, 'heat': {}})
        findings = [Finding(r.check_name, r.severity, r.title, r.detail, r.host, dict(r.evidence or {})) for r in rows]
        before = {id(f): (r, r.severity) for f, r in zip(findings, rows)}
        rated = {id(f) for f in rate(domain, findings, label=apply)}
        touched = set()
        for f in findings:
            row, was = before[id(f)]
            stats['rows'] += 1
            heat = lambda sev: SEVERITY_HEAT.get(sev, 'info')  # noqa: E731
            if id(f) not in rated:
                stats['dropped'] += 1
                key = f'{heat(was)}->resolved'
                stats['heat'][key] = stats['heat'].get(key, 0) + 1
                if apply:
                    HygieneFinding.objects.filter(pk=row.pk, status='open').update(status='resolved', resolved_at=timezone.now())
                    touched.add(row.host.lower())
            elif f.severity < was:
                stats['lowered'] += 1
                key = f'{heat(was)}->{heat(f.severity)}'
                stats['heat'][key] = stats['heat'].get(key, 0) + 1
                if apply:
                    HygieneFinding.objects.filter(pk=row.pk).update(severity=f.severity, evidence=f.evidence)
                    touched.add(row.host.lower())
        if apply and touched and domain.project_id:
            touched = sorted(touched)
            for i in range(0, len(touched), scoring.CHUNK):
                scoring.rescore_quietly(domain.project_id, touched[i:i + scoring.CHUNK])
    return report
