"""The exposed-secrets inventory: one row per project and secret, however many hosts, URLs, scans and detectors saw it (docs/SECRETS-PLAN.md, section 7).

Detectors feed it through ``record``:

* the route check (``route_auth._persist``): the credentials ``sensitive.credential_values`` read in a body before it was dropped;
* nuclei token templates and bbot's badsecrets and trufflehog modules (``take_from_finding`` and ``feed_finding``, called by
  ``reNgine.tasks.save_vulnerability``): the value is taken out of the finding, which keeps only its mask;
* the ``secrets_scan`` Sentinel kind (``cveFeed.secrets_results``): Kingfisher's findings, and validation outcomes when the project opted in.

The value itself is never stored. ``fingerprint`` is a keyed HMAC-SHA256 of the normalised value, with an install key of its own
(``SecretFingerprintKey``): not derived from SECRET_KEY or the field key, so rotating those never splits a row, and a database dump without the field
key cannot confirm a guessed secret. ``masked`` is the format prefix and the last four characters.
"""
import hashlib
import hmac
import logging
import re
import secrets as _secrets
import threading
from urllib.parse import urlsplit, urlunsplit

from django.db import IntegrityError, transaction
from django.utils import timezone

from cveFeed import secrets_catalog as catalog

logger = logging.getLogger(__name__)

FP_VERSION = 1
MIN_VALUE, MAX_VALUE = 8, 8192
MAX_RULE_IDS = 20
MAX_URL = 2000
META_KEYS = ('restriction', 'active_google_key', 'gemini_access', 'account_type')  # docs/SECRETS-PLAN.md 6.4: nothing else is kept
META_VALUE = 60
CONFIDENCE_RANK = {'': 0, 'low': 1, 'medium': 2, 'high': 3}
CLOSED_REMEDIATION = ('fixed', 'accepted_risk', 'false_positive')
SOURCES = ('kingfisher', 'nuclei', 'route', 'bbot')

_KEY = []
_KEY_LOCK = threading.Lock()


# ----------------------------------------------------------------------------- identity

def _fingerprint_key():
    """The install's fingerprint key (32 bytes), made the first time it is needed. Every worker converges on the oldest row whose key decrypts: two
    workers that both found none and both created one use the first one written."""
    if _KEY:
        return _KEY[0]
    from cveFeed.models import SecretFingerprintKey
    with _KEY_LOCK:
        if _KEY:
            return _KEY[0]
        for _ in range(2):
            for stored in SecretFingerprintKey.objects.order_by('id'):
                if re.fullmatch(r'[0-9a-f]{64}', stored.key or ''):
                    _KEY.append(bytes.fromhex(stored.key))
                    return _KEY[0]
            logger.warning('no usable secrets fingerprint key: making one (an existing key that no longer decrypts splits the inventory)')
            SecretFingerprintKey.objects.create(key=_secrets.token_hex(32))
        raise RuntimeError('the secrets fingerprint key could not be stored')


def reset_key_cache():
    """For tests, and after a key row is replaced."""
    _KEY.clear()


def fingerprint(value):
    """The inventory identity of ``value``: HMAC-SHA256 under the install key, of the value without surrounding whitespace or quotes."""
    return hmac.new(_fingerprint_key(), catalog.normalise(value).encode('utf-8', 'surrogatepass'), hashlib.sha256).hexdigest()


def clean_url(url):
    """The URL an occurrence keeps: no query string, no fragment, no user info, at most MAX_URL characters."""
    try:
        parts = urlsplit(str(url or '').strip())
    except ValueError:
        return ''
    netloc = parts.netloc.rsplit('@', 1)[-1]
    return urlunsplit((parts.scheme.lower(), netloc.lower(), parts.path or '/', '', ''))[:MAX_URL] if netloc else str(url or '')[:MAX_URL]


def clean_meta(meta):
    """Validation metadata as it may be kept: the allow-listed keys only, a boolean as it is, a string of at most META_VALUE characters."""
    out = {}
    for key in META_KEYS:
        value = (meta or {}).get(key) if isinstance(meta, dict) else None
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, str) and value:
            out[key] = re.sub(r'[^\w .:/-]', '', value)[:META_VALUE]
    return out


def usable(value):
    text = catalog.normalise(value)
    return MIN_VALUE <= len(text) <= MAX_VALUE


# ----------------------------------------------------------------------------- recording

def kind_of(row):
    """The catalog ``Kind`` of an inventory row (what the remediation text and the severity read): the catalog entry of one of its rules that names
    the row's kind, else the row's own fields with the catalog's remediation for its first rule."""
    for rule_id in row.rule_ids or ():
        found = catalog.classify(rule_id, '')
        if found.kind == row.kind:
            return found
    found = catalog.classify((row.rule_ids or [row.kind])[0], '')
    return catalog.Kind(row.provider, row.kind, row.klass, found.remediation, found.docs, found.level, row.catalogued)


def rate(row, now=None):
    """Set ``severity`` and ``severity_basis`` of ``row`` from its kind, status, validation metadata and facts."""
    row.severity, basis = catalog.severity(kind_of(row), row.status, row.validation_meta, row.facts, now=now)
    row.severity_basis = basis[:300]
    return row


def _better(new, row):
    """Whether ``new`` (a Kind) describes the secret better than the row does: a catalogued kind replaces an uncatalogued one, and a server secret
    replaces a browser key or an identifier of the same value (a value two rules read differently is treated as the worse of the two)."""
    if not row.catalogued and new.catalogued:
        return True
    order = {'I': 0, 'P': 1, 'S': 2}
    return new.catalogued and order.get(new.klass, 0) > order.get(row.klass, 0)


def record(project_id, *, host, url, source, rule_id, value, domain_id=None, scan_id=None, line=None, vulnerability_id=None, confidence='',
           outcome='', meta=None, now=None):
    """File one sighting of ``value``: the inventory row (made or updated) and its occurrence at ``url``. Returns the row, or None when the value or
    the rule ID cannot be one (too short, too long, a malformed rule ID). ``outcome`` is Kingfisher's validation outcome, when it validated."""
    from cveFeed.models import SecretFinding, SecretOccurrence
    if source not in SOURCES or not catalog.rule_id_ok(rule_id) or not usable(value):
        return None
    now = now or timezone.now()
    value = catalog.normalise(value)
    kind = catalog.classify(rule_id, value)
    fp = fingerprint(value)
    host = str(host or urlsplit(str(url or '')).hostname or '').strip().lower()[:255]
    url = clean_url(url) or host
    confidence = confidence if confidence in CONFIDENCE_RANK else ''
    for attempt in range(2):
        try:
            with transaction.atomic():
                row = SecretFinding.objects.select_for_update().filter(project_id=project_id, fingerprint=fp).first()
                created = row is None
                if created:
                    row = SecretFinding(project_id=project_id, domain_id=domain_id, fingerprint=fp, fp_version=FP_VERSION, provider=kind.provider,
                                        kind=kind.kind, klass=kind.klass, catalogued=kind.catalogued, rule_ids=[rule_id],
                                        masked=catalog.mask(value, kind.kind), length=len(value), confidence=confidence,
                                        facts=catalog.facts(kind, value), first_seen=now, last_seen=now)
                else:
                    if _better(kind, row):
                        row.provider, row.kind, row.klass, row.catalogued = kind.provider, kind.kind, kind.klass, kind.catalogued
                        row.masked = catalog.mask(value, kind.kind)
                    if rule_id not in row.rule_ids and len(row.rule_ids) < MAX_RULE_IDS:
                        row.rule_ids = [*row.rule_ids, rule_id]
                    if CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK.get(row.confidence, 0):
                        row.confidence = confidence
                    row.facts = {**(row.facts or {}), **catalog.facts(kind, value)}
                    row.last_seen = now
                    if row.domain_id is None:
                        row.domain_id = domain_id
                if outcome in catalog.OUTCOMES and outcome != 'not_attempted':
                    row.validation_outcome = outcome
                    row.validated_at = now
                    row.validation_meta = clean_meta(meta)
                    row.status = catalog.status_after_validation(row.status, outcome)
                rate(row, now=now)
                row.save()
                occurrence, made = SecretOccurrence.objects.get_or_create(
                    finding=row, url=url, source=source, rule_id=rule_id,
                    defaults={'project_id': project_id, 'domain_id': domain_id, 'scan_id': scan_id, 'host': host, 'line': line,
                              'vulnerability_id': vulnerability_id, 'first_seen': now, 'last_seen': now})
                if not made:
                    occurrence.last_seen, occurrence.retired_at = now, None
                    occurrence.scan_id = scan_id or occurrence.scan_id
                    occurrence.line = line if line is not None else occurrence.line
                    occurrence.vulnerability_id = vulnerability_id or occurrence.vulnerability_id
                    occurrence.save(update_fields=['last_seen', 'retired_at', 'scan_id', 'line', 'vulnerability_id'])
                _refresh_counts(row)
                if row.remediation_status in CLOSED_REMEDIATION[:1] and row.status != 'revoked':
                    row.remediation_status = 'open'  # marked fixed, and served again
                    row.save(update_fields=['remediation_status'])
            return row
        except IntegrityError:  # a parallel sighting made the row or the occurrence first: read it again
            if attempt:
                raise
    return None


def _refresh_counts(row):
    from cveFeed.models import SecretOccurrence
    live = SecretOccurrence.objects.filter(finding=row, retired_at__isnull=True)
    row.occurrence_count = live.count()
    row.host_count = live.values('host').distinct().count()
    row.save(update_fields=['occurrence_count', 'host_count'])


def retire_missing(project_id, source, seen_by_url, now=None):
    """After a detector read some URLs again (``seen_by_url``: ``{url: {inventory row ids it saw there}}``): its occurrences at those URLs of the
    secrets it did not see there this time are retired. A secret no longer seen anywhere is resolved (remediation ``fixed``), which is also how a
    ``revoked`` secret closes. Returns how many occurrences were retired."""
    from cveFeed.models import SecretFinding, SecretOccurrence
    seen = {}
    for url, ids in (seen_by_url or {}).items():
        if url:
            seen.setdefault(clean_url(url), set()).update(ids)
    if not seen:
        return 0
    now = now or timezone.now()
    urls = sorted(seen)
    stale, finding_ids = [], set()
    for start in range(0, len(urls), 500):
        for occ in SecretOccurrence.objects.filter(project_id=project_id, source=source, url__in=urls[start:start + 500],
                                                   retired_at__isnull=True).only('id', 'url', 'finding_id'):
            if occ.finding_id not in seen.get(occ.url, ()):
                stale.append(occ.id)
                finding_ids.add(occ.finding_id)
    if not stale:
        return 0
    SecretOccurrence.objects.filter(id__in=stale).update(retired_at=now)
    for row in SecretFinding.objects.filter(id__in=finding_ids):
        _refresh_counts(row)
        if row.occurrence_count == 0 and row.remediation_status not in CLOSED_REMEDIATION:
            row.remediation_status = 'fixed'
            row.save(update_fields=['remediation_status'])
    rescore_hosts = sorted(set(SecretOccurrence.objects.filter(id__in=stale).values_list('host', flat=True)))
    if rescore_hosts:
        from cveFeed import scoring
        scoring.rescore_quietly(project_id, rescore_hosts)
    return len(stale)


# ----------------------------------------------------------------------------- people

class StatusError(ValueError):
    pass


def set_status(row, status, user=None, note='', now=None):
    """A person's decision on a secret: one of ``catalog.PERSON_STATUSES``. The linked findings follow the new severity, and the hosts are rescored (a
    quiet status counts for nothing). Audited by the caller (the view knows the organization)."""
    if status not in catalog.PERSON_STATUSES:
        raise StatusError(f'status must be one of {", ".join(catalog.PERSON_STATUSES)}')
    now = now or timezone.now()
    row.status, row.status_by, row.status_at, row.status_note = status, user, now, str(note or '')[:2000]
    if status == 'false_positive':
        row.remediation_status = 'false_positive'
    elif status == 'accepted':
        row.remediation_status = 'accepted_risk'
    elif row.remediation_status in ('accepted_risk', 'false_positive'):
        row.remediation_status = 'open'
    rate(row, now=now)
    row.save()
    sync_findings(row)
    rescore(row)
    return row


def sync_findings(row):
    """The nuclei and bbot findings an inventory row came from follow its severity (docs/SECRETS-PLAN.md 8.3)."""
    from startScan.models import Vulnerability
    ids = list(row.occurrences.exclude(vulnerability_id=None).values_list('vulnerability_id', flat=True))
    if ids:
        Vulnerability.objects.filter(id__in=ids).exclude(severity=row.severity).update(severity=row.severity)


def rescore(row):
    from cveFeed import scoring
    hosts = list(row.occurrences.values_list('host', flat=True).distinct())
    if hosts:
        scoring.rescore_quietly(row.project_id, hosts)


# ----------------------------------------------------------------------------- scoring

def host_secrets(project_id, hosts):
    """``{host: [{severity, klass, path, label}]}``: the counting secrets each host serves now (occurrences not retired, of rows whose status counts),
    and ``{host}`` of the hosts the inventory covers at all (any status), whose route samples then no longer score credentials."""
    from cveFeed.models import SecretOccurrence
    out, covered = {}, set()
    rows = (SecretOccurrence.objects.filter(project_id=project_id, host__in=hosts, retired_at__isnull=True)
            .values('host', 'url', 'finding__severity', 'finding__klass', 'finding__status', 'finding__provider', 'finding__kind'))
    for r in rows:
        covered.add(r['host'])
        if not catalog.counts(r['finding__status']):
            continue
        out.setdefault(r['host'], []).append({'severity': r['finding__severity'], 'klass': r['finding__klass'],
                                              'path': urlsplit(r['url']).path or '/',
                                              'label': f'{r["finding__provider"]} {r["finding__kind"]}'.strip()})
    return out, covered


# ----------------------------------------------------------------------------- feeders

def from_route(project_id, domain_id, scan_id, url, values, now=None):
    """The credentials the route check read in one body (``sensitive.credential_values``: ``[(type, value)]``). Returns the rows."""
    rows = []
    for name, value in values or ():
        row = record(project_id, host=urlsplit(url).hostname, url=url, source='route', rule_id=f'route:{name}', value=value, domain_id=domain_id,
                     scan_id=scan_id, now=now)
        if row is not None:
            rows.append(row)
    return rows


TOKEN_PATH = re.compile(r'(?:^|/)exposures/tokens/')
TOKEN_TAGS = frozenset({'token', 'tokens'})
BBOT_SECRET_MODULES = ('badsecrets', 'trufflehog')
_BBOT_VALUES = (re.compile(r'\b(?:Secret|Raw ?(?:V2)? result)\s{0,3}:\s{0,3}\[([^\[\]\n]{1,1024})\]'),
                re.compile(r'\bProduct\s{0,3}:\s{0,3}\[([^\[\]\s]{40,2048})\]'))
_PLAUSIBLE = re.compile(r'^\S{8,8192}$')
MASK_MARK = '\u2026'  # every mask holds it (this module's and cveFeed.secret_redaction's): a mask is never filed again as a secret


def _plausible(value):
    return bool(_PLAUSIBLE.match(value)) and MASK_MARK not in value


def is_token_finding(data, tags=()):
    """Whether a finding about to be saved carries a secret: a nuclei token template (under ``http/exposures/tokens/`` or tagged ``token``), or a
    bbot badsecrets or trufflehog finding."""
    source = str(data.get('source') or '').lower()
    if source == 'bbot':
        return str(data.get('template_id') or '').lower() in BBOT_SECRET_MODULES
    if source != 'nuclei':
        return False
    names = {str(t).strip().lower() for t in tags or ()}
    where = f'{data.get("template") or ""} {data.get("template_url") or ""}'
    return bool(names & TOKEN_TAGS) or bool(TOKEN_PATH.search(where))


def _status_and_headers(response):
    """A stored HTTP response with its body removed: the status line and the headers."""
    text = str(response or '')
    head = re.split(r'\r?\n\r?\n', text, maxsplit=1)[0]
    return head[:8000] + ('\n\n[body removed: it served a secret, tracked in Secrets]' if head != text else '')


def take_from_finding(data, tags=()):
    """Take the secret values out of a finding about to be saved (``data``, the keyword arguments of ``save_vulnerability``), in place: a token
    template's ``extracted_results`` become their masks and its response keeps the status line and headers only; a bbot finding's description
    keeps its masked value. Returns ``[(rule_id, value)]`` for ``feed_finding``, or ``[]`` when the finding carries none."""
    if not is_token_finding(data, tags):
        return []
    found = []
    if str(data.get('source') or '').lower() == 'bbot':
        module = str(data.get('template_id') or '').lower()
        text = str(data.get('description') or '')
        for pattern in _BBOT_VALUES:
            for match in pattern.finditer(text):
                if _plausible(match.group(1).strip()):
                    found.append((f'bbot:{module}', match.group(1).strip()))
        for rule_id, value in found:
            text = text.replace(value, catalog.mask(value, catalog.classify(rule_id, value).kind))
        data['description'] = text
        return found
    template = re.sub(r'[^a-z0-9._-]', '-', str(data.get('template_id') or 'token').lower())[:110]
    masked = []
    for value in data.get('extracted_results') or ():
        text = catalog.normalise(value)
        if _plausible(text):
            found.append((f'nuclei:{template}', text))
            masked.append(catalog.mask(text, catalog.classify(f'nuclei:{template}', text).kind))
        else:
            masked.append(str(value)[:5000])
    data['extracted_results'] = masked
    if found and data.get('response'):
        data['response'] = _status_and_headers(data['response'])
    return found


def feed_finding(vuln, found, now=None):
    """File the values ``take_from_finding`` took out of ``vuln`` (now saved) in the inventory, linked to it; ``vuln``'s severity follows the row."""
    if not found:
        return []
    domain = vuln.target_domain
    project_id = getattr(domain, 'project_id', None)
    if not project_id:
        return []
    host = (vuln.subdomain.name if vuln.subdomain_id else '') or urlsplit(vuln.http_url or '').hostname or ''
    source = 'bbot' if str(vuln.source or '').lower() == 'bbot' else 'nuclei'
    rows = []
    for rule_id, value in found:
        row = record(project_id, host=host, url=vuln.http_url or host, source=source, rule_id=rule_id, value=value, domain_id=domain.id,
                     scan_id=vuln.scan_history_id, vulnerability_id=vuln.id, now=now)
        if row is not None:
            rows.append(row)
    if rows:
        worst = max(r.severity for r in rows)
        if vuln.severity != worst:
            type(vuln).objects.filter(pk=vuln.pk).update(severity=worst)
            vuln.severity = worst
    return rows


def feed_finding_quietly(vuln, found):
    """``feed_finding`` for the save path: an inventory problem never loses the finding (which is already masked)."""
    try:
        return feed_finding(vuln, found)
    except Exception:  # noqa: BLE001
        logger.exception('could not file the secret of finding %s in the inventory', getattr(vuln, 'pk', '?'))
        return []


def tracked(vuln_id):
    """The inventory rows a finding is linked to, for the finding detail ("Tracked in Secrets")."""
    from cveFeed.models import SecretFinding
    return list(SecretFinding.objects.filter(occurrences__vulnerability_id=vuln_id).distinct())
