"""Cloud storage exposure checks: public or dangling AWS S3, Google Cloud Storage and Azure Blob storage that belongs to a project's domains.

A slow, polite background sweep, never part of a scan. It finds buckets a project's own data points at, asks each storage platform's
documented endpoint (``cveFeed.bucket_probe``: anonymous HTTPS GET and HEAD only, one listing page, one HEAD, never an object's content)
and stores what is wrong as hygiene findings (check names ``bkt_*``). A bucket that exists and refuses anonymous access is recorded as an
observation, never as a finding.

Candidate buckets, strongest ownership evidence first (the tier says which, and it decides the severity):

* ``cname``: a host of the project has a CNAME to a storage endpoint (``<bucket>.s3.amazonaws.com``, an S3 website endpoint,
  ``c.storage.googleapis.com`` where the host name is the bucket, ``<account>.blob.core.windows.net``). The name is stated outright.
* ``served``: a host of the project answers with a storage server header (``AmazonS3``, ``UploadServer``). The bucket is inferred from the host
  name, so it is checked for exposure but a missing bucket is never called a takeover (a CDN in front may use another name).
* ``reference``: a storage URL in data cvENGINE already holds (crawled and archived endpoints, page URLs, route redirects, stored scanner
  responses). The bucket name is stated by the URL.
* ``guess``: permutations of the target's own domain label with a short curated suffix list. Anyone may own a bucket of that name, so a
  finding says "name guess, ownership unconfirmed, verify the bucket is yours" and is never worse than medium.

Findings: a public listing of a ``cname``/``served`` bucket, or of a ``reference`` bucket whose name carries the project's own label, is high
(critical when listed names look like backups, database dumps or keys); other public listings are medium. A ``cname`` or ``reference`` name
that no one has registered is a takeover (high; medium for a GCS name with a dot, which only a verified domain owner may create).
A finding resolves when a later check of the same bucket ran and no longer finds it, and when the reference that led there is gone. A
check with no answer changes nothing.

Politeness: one global request rate (``bucket_probe.Pacer``), ``CVENGINE_BUCKETS_MAX_PER_SWEEP`` buckets per project per sweep, a weekly
ledger window per bucket, one sweep at a time, a stop while scanning is paused, a stop for a project whose bug bounty engagement has not
confirmed automated testing, and no name an organization excluded."""
import logging
import os
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from cveFeed import bucket_probe as probe
from cveFeed.bucket_probe import AZURE, GCS, S3

logger = logging.getLogger(__name__)

SERVICE = 'buckets'
FAILED_SERVICE = 'buckets-failed'  # a bucket that gave no answer: asked again tomorrow, not at every sweep
QUEUE = 'bucketscan_queue'
PREFIX = 'bkt_'  # hygiene must not resolve these (see cveFeed.hygiene.run_hygiene)
CHECK_LISTING = 'bkt_listing'
CHECK_TAKEOVER = 'bkt_takeover'
OBS_PROBE = 'storage-bucket'
OBS_KIND = 'storage'
DEFAULT_MAX_PER_SWEEP = 100
ENDPOINT_LIMIT = 5000  # crawled endpoint rows read per project; a full read marks the reference tier incomplete
VULN_LIMIT = 200
VULN_TEXT = 200_000
MAX_HOSTS = 10  # referencing hosts kept per bucket

INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4
LEVELS = ('info', 'low', 'medium', 'high', 'critical')
TIERS = ('cname', 'served', 'reference', 'guess')
RANK = {t: i for i, t in enumerate(TIERS)}

# Name permutations of a target's own label: ``example`` -> ``example``, ``example-backup`` ... Short on purpose (a request each, three
# providers' worth of unconfirmed names): the common places an owner puts files, no wordlist.
SUFFIXES = ('backup', 'backups', 'assets', 'dev', 'prod', 'production', 'staging', 'stage', 'test', 'static', 'media', 'files', 'logs',
            'data', 'uploads', 'images', 'img', 'public', 'private', 'internal', 'cdn', 'web', 'www', 'docs', 'downloads', 'archive',
            'db', 'database', 'config', 'content', 'bucket', 'storage', 's3', 'temp', 'tmp', 'qa', 'uat', 'demo', 'reports', 'dumps')
MIN_LABEL, MAX_LABEL = 3, 40


# ----------------------------------------------------------------------------- settings

def _flag(name, default='1'):
    return os.environ.get(name, default).strip().lower() not in ('0', 'false', 'no', 'off')


def enabled():
    return _flag('CVENGINE_BUCKETS')


def guesses_enabled():
    return _flag('CVENGINE_BUCKETS_GUESS')


def max_per_sweep():
    try:
        return max(1, min(1000, int(os.environ.get('CVENGINE_BUCKETS_MAX_PER_SWEEP', DEFAULT_MAX_PER_SWEEP))))
    except ValueError:
        return DEFAULT_MAX_PER_SWEEP


# ----------------------------------------------------------------------------- reading storage names out of hosts and URLs

@dataclass(frozen=True)
class Ref:
    provider: str
    name: str  # the bucket, or the Azure storage account
    container: str = ''  # Azure only
    explicit: bool = True  # the data states the name (False: inferred, as from a Server header)


_S3_HOST = re.compile(r'^(?:(?P<bucket>[a-z0-9][a-z0-9.-]*[a-z0-9])\.)?s3(?:[.-](?:website[.-]|dualstack\.)?(?P<region>[a-z]{2}(?:-[a-z]+)+-\d{1,2}))?\.amazonaws\.com$')
_GCS_HOST = re.compile(r'^(?:(?P<bucket>[a-z0-9][a-z0-9._-]*[a-z0-9])\.)?storage\.googleapis\.com$')
_AZURE_BLOB = re.compile(r'^(?P<account>[a-z0-9]{3,24})\.(?:blob|dfs)\.core\.windows\.net$')
_AZURE_WEB = re.compile(r'^(?P<account>[a-z0-9]{3,24})\.z\d{1,2}\.web\.core\.windows\.net$')
_GCS_API_PATH = re.compile(r'^/(?:(?:download|upload)/)?storage/v1/b/([^/?#]+)')
_TEXT_URL = re.compile(r'(?i)(?:https?:)?//[a-z0-9._~%-]*(?:amazonaws\.com|storage\.googleapis\.com|storage\.cloud\.google\.com|core\.windows\.net)'
                       r'(?:/[^\s"\'<>\\)\]]*)?')
MARKERS = ('amazonaws.com', 'storage.googleapis.com', 'storage.cloud.google.com', 'core.windows.net')


def valid_name(provider, name):
    if provider == S3:
        return bool(probe.S3_NAME.match(name)) and '..' not in name and not re.fullmatch(r'\d+(?:\.\d+){3}', name)
    if provider == GCS:
        return bool(probe.GCS_NAME.match(name)) and not name.startswith('goog') and 'google' not in name
    return bool(probe.AZURE_ACCOUNT.match(name))


def refs_from_host(host, path=''):
    """The storage references of one host name and path (a URL's host and path, or a CNAME target with no path)."""
    host = (host or '').strip().lower().rstrip('.')
    out = []
    match = _S3_HOST.match(host)
    if match:
        bucket = match.group('bucket') or unquote((path or '/').lstrip('/').split('/', 1)[0])
        if bucket and valid_name(S3, bucket):
            out.append(Ref(S3, bucket))
    match = _GCS_HOST.match(host)
    if match or host == 'storage.cloud.google.com':
        bucket = match.group('bucket') if match else None
        if not bucket:  # the shared endpoint: the bucket is in the path, either path style or the JSON API
            api = _GCS_API_PATH.match(path or '')
            first = unquote((path or '/').lstrip('/').split('/', 1)[0])
            bucket = unquote(api.group(1)) if api else ('' if first in ('storage', 'download', 'upload') else first)
        if bucket and valid_name(GCS, bucket):
            out.append(Ref(GCS, bucket))
    match = _AZURE_BLOB.match(host)
    if match:
        container = unquote((path or '/').lstrip('/').split('/', 1)[0].split('?', 1)[0])
        out.append(Ref(AZURE, match.group('account'), container if probe.AZURE_CONTAINER.match(container) else ''))
    match = _AZURE_WEB.match(host)
    if match:
        out.append(Ref(AZURE, match.group('account')))
    return out


def refs_from_url(value):
    """The storage references in one URL (a bare host is read as a host)."""
    value = (value or '').strip()
    if not value:
        return []
    try:
        parts = urlsplit(value if '//' in value else '//' + value)
        return refs_from_host(parts.hostname or '', parts.path)
    except ValueError:
        return []


def refs_from_text(text):
    """The storage references in free text (a stored scanner response): every storage URL in it."""
    found = []
    for url in _TEXT_URL.findall((text or '')[:VULN_TEXT]):
        for ref in refs_from_url(url):
            if ref not in found:
                found.append(ref)
    return found


def refs_from_cname(host, cname):
    """The storage references a host's CNAME states. ``c.storage.googleapis.com`` names no bucket: the host name is the bucket."""
    out = []
    for token in re.split(r'[\s,;]+', (cname or '').strip().lower()):
        token = token.rstrip('.')
        if token == 'c.storage.googleapis.com':
            if valid_name(GCS, host):
                out.append(Ref(GCS, host))
        else:
            out += refs_from_host(token)
    return out


# ----------------------------------------------------------------------------- candidates

@dataclass
class Candidate:
    provider: str
    name: str
    container: str = ''
    tier: str = 'guess'
    domain_id: int = 0
    hosts: list = field(default_factory=list)  # every host of the project whose data leads here
    own_hosts: list = field(default_factory=list)  # the ones that point at it (CNAME) or are served by it
    via: str = ''  # how it was found, in a few words
    name_match: bool = False  # the name carries one of the project's own domain labels

    @property
    def key(self):
        return (self.provider, self.name, self.container)

    @property
    def asset(self):
        return ':'.join(x for x in (self.provider, self.name, self.container) if x)

    @property
    def endpoint(self):
        if self.provider == S3:
            return f'{self.name}.s3.amazonaws.com' if '.' not in self.name else f's3.amazonaws.com/{self.name}'
        if self.provider == GCS:
            return f'storage.googleapis.com/{self.name}'
        return f'{self.name}.blob.core.windows.net' + (f'/{self.container}' if self.container else '')

    @property
    def host(self):
        """The ``host`` of its finding: the project's own host for a name its data states or infers, else the storage endpoint's name."""
        if self.tier in ('cname', 'served') and self.own_hosts:
            return sorted(self.own_hosts)[0][:500]
        if self.provider == S3:
            return f'{self.name}.s3.amazonaws.com'
        if self.provider == GCS:
            return f'{self.name}.storage.googleapis.com'
        return (f'{self.name}.blob.core.windows.net' + (f'/{self.container}' if self.container else ''))[:500]


def domain_labels(domain_names):
    """``{label: domain name}`` for the first label of each target's registrable domain: ``www.example.co.uk`` gives ``example``. IP targets, shared
    provider domains and labels that are too short or long to name a bucket are left out."""
    from targetApp import shared_domains
    from targetApp.target_types import DOMAIN, apex_domain, classify_target
    out = {}
    for name in domain_names:
        name = (name or '').strip().lower().rstrip('.')
        if classify_target(name) != DOMAIN:
            continue
        apex = apex_domain(name) or '.'.join(name.split('.')[-2:])
        if shared_domains.is_shared_apex(apex) or shared_domains.is_shared_apex(name):
            continue
        label = apex.split('.')[0]
        if MIN_LABEL <= len(label) <= MAX_LABEL and re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', label):
            out.setdefault(label, apex)
    return out


def guess_names(label, apex):
    """``[(provider, name)]`` permutations of one label: the bare label and ``label-<suffix>`` at S3 and GCS, plus the domain itself and its
    ``www.`` form at S3 (S3 website buckets are named after their host). Azure account names are never guessed."""
    names = [label] + [f'{label}-{s}' for s in SUFFIXES]
    out = [(p, n) for n in names for p in (S3, GCS) if valid_name(p, n)]
    out += [(S3, n) for n in (apex, f'www.{apex}') if valid_name(S3, n)]
    return out


def _merge(found, ref, tier, domain_id, host='', via=''):
    cand = Candidate(ref.provider, ref.name, ref.container, tier, domain_id, [host] if host else [], [host] if host and tier in ('cname', 'served') else [], via)
    old = found.get(cand.key)
    if old is None:
        found[cand.key] = cand
        return
    if RANK[tier] < RANK[old.tier]:
        old.tier, old.via, old.domain_id = tier, via, domain_id
    if host and host not in old.hosts and len(old.hosts) < MAX_HOSTS:
        old.hosts.append(host)
    if host and tier in ('cname', 'served') and host not in old.own_hosts and len(old.own_hosts) < MAX_HOSTS:
        old.own_hosts.append(host)


def _marked(*fields):
    from django.db.models import Q
    query = Q()
    for field_name in fields:
        for marker in MARKERS:
            query |= Q(**{f'{field_name}__icontains': marker})
    return query


def collect(project_id):
    """``(candidates, complete)``: every bucket the project's data points at or its domain labels suggest, strongest tier first, and the set of
    tiers whose list is complete (a tier read up to a row limit is not, so a finding is never closed for a reference that was merely not read)."""
    from django.db.models import Q

    from cveFeed import exclusions
    from cveFeed.models import RouteAuth
    from startScan.models import EndPoint, Subdomain, Vulnerability
    from targetApp.models import Domain
    from targetApp.target_types import scannable_hosts
    domains = list(Domain.objects.filter(project_id=project_id).values_list('id', 'name'))
    found, complete = {}, {'cname', 'served', 'reference'} | ({'guess'} if guesses_enabled() else set())

    named = set(Subdomain.objects.filter(target_domain__project_id=project_id).filter(
        _marked('cname', 'http_url') | Q(webserver__iregex=r'^(amazons3|uploadserver)')).values_list('name', flat=True))
    from cveFeed.manual_only import held_expr
    rows = (Subdomain.objects.filter(target_domain__project_id=project_id, name__in=sorted(named)).annotate(held=held_expr()).order_by('name', 'held', '-id').distinct('name')
            .values_list('name', 'cname', 'webserver', 'http_url', 'target_domain_id'))  # the newest row of each host: a CNAME that was removed is gone
    for name, cname, webserver, http_url, domain_id in rows:
        host = (name or '').lower()
        stated = refs_from_cname(host, cname)
        for ref in stated:
            _merge(found, ref, 'cname', domain_id, host, f'CNAME of {host}')
        server = (webserver or '').strip().lower()
        if not stated and valid_name(S3, host) and server.startswith('amazons3'):
            _merge(found, Ref(S3, host, explicit=False), 'served', domain_id, host, f'{host} is served by Amazon S3')
        elif not stated and valid_name(GCS, host) and server.startswith('uploadserver'):
            _merge(found, Ref(GCS, host, explicit=False), 'served', domain_id, host, f'{host} is served by Google Cloud Storage')
        for ref in refs_from_url(http_url) if http_url and any(m in http_url.lower() for m in MARKERS) else []:
            _merge(found, ref, 'reference', domain_id, host, f'page URL of {host}')

    sources = [('crawled endpoint', EndPoint.objects.filter(target_domain__project_id=project_id).filter(_marked('http_url'))
                .values_list('http_url', 'subdomain__name', 'target_domain_id')[:ENDPOINT_LIMIT], 'endpoint'),
               ('route redirect', RouteAuth.objects.filter(project_id=project_id).filter(_marked('redirect_to', 'url'))
                .values_list('redirect_to', 'host', 'domain_id')[:ENDPOINT_LIMIT], 'url'),
               ('scanner response', Vulnerability.objects.filter(target_domain__project_id=project_id).filter(_marked('http_url', 'response'))
                .values_list('http_url', 'subdomain__name', 'target_domain_id', 'response')[:VULN_LIMIT], 'text')]
    for label, queryset, kind in sources:
        rows = list(queryset)
        if len(rows) >= (VULN_LIMIT if kind == 'text' else ENDPOINT_LIMIT):
            complete.discard('reference')
        for row in rows:
            url, host, domain_id = row[0], (row[1] or '').lower(), row[2]
            refs = refs_from_url(url)
            if kind == 'text':
                refs += [r for r in refs_from_text(row[3]) if r not in refs]
            for ref in refs:
                _merge(found, ref, 'reference', domain_id, host, f'{label} on {host}' if host else label)

    banned = exclusions.excluded_names(project_id)
    labels = domain_labels(name for _id, name in domains if name not in banned)  # an excluded domain gets no name guesses
    by_name = {name: pk for pk, name in domains}
    if guesses_enabled():
        for label, apex in labels.items():
            owner = next((pk for name, pk in by_name.items() if name == apex or name.endswith('.' + apex)), domains[0][0] if domains else 0)
            for provider, name in guess_names(label, apex):
                _merge(found, Ref(provider, name, explicit=False), 'guess', owner, '', f'name guess from {apex}')
    keep = []
    via = sorted({h for c in found.values() for h in c.hosts})
    allowed = set(scannable_hosts(via, project=project_id)) if via else set()
    for cand in found.values():
        had_hosts = bool(cand.hosts)
        cand.hosts = [h for h in cand.hosts if h in allowed]
        cand.own_hosts = [h for h in cand.own_hosts if h in allowed]
        if had_hosts and not cand.hosts:
            continue  # every host that led here is excluded, archived or prohibited
        if cand.name in banned or cand.endpoint.split('/')[0] in banned or any(h in banned for h in cand.hosts):
            continue
        cand.name_match = any(label in cand.name for label in labels) or any(
            cand.name == apex or cand.name.endswith('.' + apex) for apex in labels.values())
        keep.append(cand)
    keep.sort(key=lambda c: (RANK[c.tier], c.asset))
    return keep, complete


def due(project_id, candidates):
    """The candidates to check now: never-checked first, then the longest waiting, minus those checked inside the ledger window and those that
    gave no answer recently; stronger tiers before name guesses."""
    from cveFeed import ledger
    by_asset = {c.asset: c for c in candidates}
    rows = ledger.stale_first(SERVICE, [(0, asset, project_id) for asset in by_asset])
    failed = ledger.fresh(FAILED_SERVICE, [r[1] for r in rows], project_id)
    ordered = [by_asset[r[1]] for r in rows if r[1] not in failed]
    return sorted(ordered, key=lambda c: RANK[c.tier])  # stable: staleness order is kept within a tier


# ----------------------------------------------------------------------------- what a verdict means

@dataclass
class Outcome:
    findings: list = field(default_factory=list)  # hygiene.Finding
    conclusive: bool = False  # the check answered: findings not found again may be resolved
    observation: str = ''  # ProbeObservation outcome ('' for none)


OWNERSHIP = {
    'cname': 'confirmed: a host of the project has a CNAME to this storage',
    'served': 'likely: a host of the project is served by this storage and the bucket is named like the host',
    'reference': 'referenced by data of the project',
    'guess': 'name guess, ownership unconfirmed: verify the bucket is yours',
}


def confident(cand):
    """Whether the data ties the bucket to the project strongly enough to call an exposure high."""
    return cand.tier in ('cname', 'served') or (cand.tier == 'reference' and cand.name_match)


def takeover_severity(cand):
    """A name no one has registered. Not for an inferred name, which says nothing about a CDN's own bucket. A GCS name with a dot can only be
    created by the owner of that verified domain, so it is medium."""
    if cand.tier not in ('cname', 'reference'):
        return None
    return MEDIUM if cand.provider == GCS and '.' in cand.name else HIGH


def _label(cand):
    return probe.PROVIDER_LABELS[cand.provider]


def _where(cand):
    return f'{cand.name}' + (f'/{cand.container}' if cand.container else '')


def listing_finding(cand, verdict, now_text=''):
    from cveFeed.hygiene import Finding
    objects = [probe.redact_name(n) for n in verdict.objects[:probe.MAX_KEYS]]
    sensitive = sum(1 for n in verdict.objects if probe.is_sensitive_name(n))
    sure = confident(cand)
    severity = (CRITICAL if sensitive else HIGH) if sure else MEDIUM
    read = {True: 'allowed', False: 'refused', None: 'not tested'}[verdict.object_read]
    basis = (f'The listing is public and {OWNERSHIP[cand.tier]}.' + (' Object names that look like backups, database dumps or keys are listed.' if sensitive and sure else '')
             if sure else f'The listing is public but {OWNERSHIP[cand.tier] if cand.tier == "guess" else "the name carries no label of the project: ownership is unconfirmed"}.')
    fix = (f'Block public access on the {_label(cand)} {"container" if cand.container else "bucket"} {_where(cand)} (S3 Block Public Access, GCS uniform '
           'access with allUsers removed, Azure container access level Private) and review what was exposed.')
    if not sure:
        fix = f'Verify the bucket is yours. If it is: {fix[0].lower() + fix[1:]} If it is not, it belongs to someone else and needs no action here.'
    title = f'{_label(cand)} {"container" if cand.container else "bucket"} {_where(cand)} lists its objects to anyone' + (
        ' (name guess, ownership unconfirmed)' if cand.tier == 'guess' else '')
    detail = (f'{_label(cand)} {"container" if cand.container else "bucket"} {_where(cand)} answers an anonymous listing: the first page shows '
              f'{len(verdict.objects)} object{"s" if len(verdict.objects) != 1 else ""}{" and more follow" if verdict.truncated else ""}. '
              f'Anonymous read of one listed object: {read}. {basis} Fix: {fix}')
    evidence = {'source': 'bucket check', 'provider': cand.provider, 'bucket': cand.name, 'endpoint': cand.endpoint, 'tier': cand.tier,
                'ownership': OWNERSHIP[cand.tier], 'referenced_by': cand.hosts[:MAX_HOSTS], 'via': cand.via, 'listing': 'public',
                'objects_first_page': len(verdict.objects), 'more_objects': verdict.truncated, 'object_read': read,
                'sensitive_looking_names': sensitive, 'objects': objects, 'severity_basis': basis, 'remediation': fix}
    if cand.container:
        evidence['container'] = cand.container
    return Finding(CHECK_LISTING, severity, title, detail, cand.host, evidence)


def takeover_finding(cand, verdict):
    from cveFeed.hygiene import Finding
    severity = takeover_severity(cand)
    what = f'the {_label(cand)} {"storage account" if cand.provider == AZURE else "bucket"} {cand.name}'
    who = f'{cand.host} points at' if cand.tier == 'cname' and cand.own_hosts else 'data of the project points at'
    basis = ('A GCS bucket named like a domain can only be created by that domain\'s verified owner, so the takeover is much harder.'
             if severity == MEDIUM else f'Anyone can register the name {cand.name} on {_label(cand)} and serve content to everything that uses it.')
    fix = (f'Remove the DNS record or the reference, or recreate {what} in an account you control.')
    title = f'Dangling storage reference: {cand.host} points at {what}, which does not exist'
    detail = f'{who.capitalize()} {what}, and {_label(cand)} says it does not exist ({verdict.code or "not found"}). {basis} Fix: {fix}'
    evidence = {'source': 'bucket check', 'provider': cand.provider, 'bucket': cand.name, 'endpoint': cand.endpoint, 'tier': cand.tier,
                'ownership': OWNERSHIP[cand.tier], 'referenced_by': cand.hosts[:MAX_HOSTS], 'via': cand.via, 'provider_answer': verdict.code,
                'severity_basis': basis, 'remediation': fix}
    return Finding(CHECK_TAKEOVER, severity, title, detail, cand.host, evidence)


def evaluate(cand, verdict):
    """The findings one verdict gives, whether it answered, and the observation to record."""
    out = Outcome()
    if verdict.state == 'unknown':
        return out
    out.conclusive = True
    if cand.tier != 'guess' or verdict.state == 'public':
        out.observation = {'public': 'found', 'private': 'hidden', 'missing': 'absent'}[verdict.state]
    if verdict.state == 'public':
        out.findings.append(listing_finding(cand, verdict))
    elif verdict.state == 'missing' and takeover_severity(cand) is not None:
        out.findings.append(takeover_finding(cand, verdict))
    return out


# ----------------------------------------------------------------------------- storing it

def record_observation(project_id, cand, verdict, outcome):
    """The durable record that a bucket was checked: found (it lists), hidden (it exists and is private: info, not a finding), absent."""
    from django.utils import timezone

    from cveFeed.models import ProbeObservation
    ProbeObservation.objects.update_or_create(
        project_id=project_id, host=cand.host.lower(), probe=OBS_PROBE, port=0, kind=OBS_KIND, product=cand.asset[:120],
        defaults={'domain_id': cand.domain_id, 'outcome': outcome, 'confidence': 0.9 if cand.tier != 'guess' else 0.3, 'source': 'bucket check',
                  'evidence': {'provider': cand.provider, 'bucket': cand.name, 'state': verdict.state, 'tier': cand.tier,
                               'ownership': OWNERSHIP[cand.tier]}, 'observed_at': timezone.now()})


def store(domain, found, hosts):
    """Upsert the findings of one target and resolve the ``bkt_`` rows of the checked hosts that were not found again."""
    from cveFeed.hygiene import store_findings
    return store_findings(domain, found, hosts=set(hosts), owns=lambda check: check.startswith(PREFIX))


def resolve_gone(project_id, candidates, complete):
    """A finding whose reference no longer exists (the CNAME was removed, the page stopped linking, the label is no longer a target) is
    resolved, for the tiers whose candidate list was read in full. Returns the rows resolved."""
    from django.utils import timezone

    from cveFeed.models import HygieneFinding
    current = {c.host for c in candidates}
    gone = 0
    for row in HygieneFinding.objects.filter(domain__project_id=project_id, status='open', check_name__startswith=PREFIX):
        if (row.evidence or {}).get('tier') in complete and row.host not in current:
            row.status, row.resolved_at = 'resolved', timezone.now()
            row.save(update_fields=['status', 'resolved_at'])
            gone += 1
    return gone


# ----------------------------------------------------------------------------- the sweep

def sweep(project_id, fetch=None, dns=None):
    """Check the due buckets of one project, one at a time. Returns ``{'checked', 'public', 'takeover', 'private', 'missing', 'unknown',
    'resolved'}`` (and ``skipped`` with the reason when nothing ran). ``fetch`` and ``dns`` replace the network in tests."""
    from cveFeed import activity, exclusions, ledger
    from cveFeed.conductor import bounty_blocked_projects
    from reNgine import resources
    from targetApp.models import Domain
    summary = {'checked': 0, 'public': 0, 'takeover': 0, 'private': 0, 'missing': 0, 'unknown': 0, 'resolved': 0}
    if not enabled():
        return {**summary, 'skipped': 'bucket checks are turned off (CVENGINE_BUCKETS=0)'}
    if project_id in bounty_blocked_projects():
        return {**summary, 'skipped': 'the bug bounty engagement has not confirmed automated testing'}
    fetch, dns = fetch or probe.http_fetch, dns or probe.dns_exists
    owner = f'buckets-{os.getpid()}'
    with resources.redis_claim(f'cvengine:buckets:{project_id}', owner, 300) as holder:
        if holder is not True:
            return {**summary, 'skipped': 'another bucket sweep is running for this project'}
        candidates, complete = collect(project_id)
        domains = {d.pk: d for d in Domain.objects.filter(project_id=project_id)}
        manual = {pk for pk, d in domains.items() if d.discovery_mode == Domain.DISCOVERY_MANUAL}
        found_by_domain, checked_by_domain = {}, {}
        running = activity.log('run_check', f'Cloud storage check: {len(candidates)} candidate bucket{"s" if len(candidates) != 1 else ""}',
                               project=project_id, status='running')
        for cand in due(project_id, candidates)[:max_per_sweep()]:
            if resources.global_pause_requested(fail_closed=True):
                summary['skipped'] = 'scanning is paused: the buckets stay due'
                break
            banned = exclusions.excluded_names(project_id)  # read again: an exclusion made while the sweep runs stops the next request
            if cand.name in banned or any(h in banned for h in cand.hosts) or cand.domain_id not in domains:
                continue
            if cand.domain_id in manual:  # a manual only target's names are not checked on a schedule, unless a target that is not manual only holds a host that leads here
                from cveFeed.manual_only import other_holder
                holders = [d for d in (other_holder(project_id, h) for h in cand.hosts) if d is not None]
                if not holders:
                    continue
                cand.domain_id = holders[0].pk
            verdict = probe.check(cand.provider, cand.name, cand.container, fetch=fetch, dns=dns)
            summary['checked'] += 1
            if verdict.state == 'unknown':
                summary['unknown'] += 1
                ledger.record(FAILED_SERVICE, [cand.asset], project_id)
                continue
            outcome = evaluate(cand, verdict)
            summary[verdict.state] += 1
            summary['takeover'] += sum(1 for f in outcome.findings if f.check == CHECK_TAKEOVER)
            checked_by_domain.setdefault(cand.domain_id, set()).add(cand.host)
            found_by_domain.setdefault(cand.domain_id, []).extend(outcome.findings)
            if outcome.observation:
                record_observation(project_id, cand, verdict, outcome.observation)
            ledger.record(SERVICE, [cand.asset], project_id)
        for domain_id, hosts in checked_by_domain.items():
            summary['resolved'] += len(store(domains[domain_id], found_by_domain.get(domain_id, []), hosts))
        summary['resolved'] += resolve_gone(project_id, candidates, complete)
        activity.settle(running, 'done', message=(
            f'Cloud storage check: {summary["checked"]} checked, {summary["public"]} public listing{"s" if summary["public"] != 1 else ""}'
            f', {summary["takeover"]} dangling' + (f', {summary["unknown"]} without an answer' if summary['unknown'] else '')), **summary)
    return summary


def sweep_all(fetch=None, dns=None):
    """Every project's due buckets. One sweep at a time; the work is spread over days by ``max_per_sweep`` per project."""
    from cveFeed import ledger
    from dashboard.models import Project
    if not enabled():
        return {'skipped': 'bucket checks are turned off (CVENGINE_BUCKETS=0)'}
    if not ledger.sweep_claim('buckets', 3 * 60 * 60):
        return {'skipped': 'another sweep is running'}
    totals = {'checked': 0, 'public': 0, 'takeover': 0, 'private': 0, 'missing': 0, 'unknown': 0, 'resolved': 0}
    for project_id in Project.objects.values_list('id', flat=True):
        part = sweep(project_id, fetch=fetch, dns=dns)
        for key in totals:
            totals[key] += part.get(key, 0)
        if part.get('skipped', '').startswith('scanning is paused'):
            totals['skipped'] = part['skipped']
            break
    return totals
