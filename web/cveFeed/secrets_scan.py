"""The ``secrets_scan`` stage: Kingfisher over the pages and scripts a project's web hosts serve, in a scanner, never on this server
(docs/SECRETS-PLAN.md section 6).

Runs right after the web route check, so it reads the routes just probed. Per host it sends the probed URLs (2xx or 404 with a text content type,
at most ``MAX_URLS``) and the front page's own scripts (``RouteAuth.evidence['script_urls']``, at most ``MAX_SCRIPT_URLS``), in tasks of at most
``MAX_HOSTS`` hosts. The scanner fetches them with the route check's bounded, anonymous GET (same origin only, source maps of those scripts,
the caps of ``LIMITS``) and runs Kingfisher with ``--no-validate``. There is no local path: with no scanner that takes the kind, the stage waits
and the hosts stay due (``reNgine.resources.ScannerUnavailable``). A host is read again after ``ledger.ttl('secrets-scan')`` (7 days).

What comes back (``agentapi.sentinel_broker`` cleaned and bound it to the task first) is filed by ``persist``:

* each finding in the secrets inventory (``cveFeed.secrets_inventory.record``), the value fingerprinted and masked there and dropped;
* an AWS key ID found in the same file as its secret key is one secret, the pair, fingerprinted on the secret half;
* a URL read again that no longer serves a secret retires its occurrence;
* storage and database references as ``ResourceRef`` rows, which the bucket sweep checks (``cveFeed.bucket_scan``);
* a source map that is served as the hygiene finding ``src_sourcemap_public`` (info, low when it embeds the sources).

Validation (``cveFeed.secrets_validation``) only for a project that opted in, by the built-in scanner only, for hosts the gate allows.
"""
import logging
from urllib.parse import urlsplit

from django.utils import timezone

logger = logging.getLogger(__name__)

KIND = 'secrets_scan'
SERVICE = 'secrets-scan'
MAX_HOSTS = 25
MAX_URLS = 20
MAX_SCRIPT_URLS = 8
MAX_FINDINGS = 500
MAX_FETCHED = 1000
MAX_REFERENCES = 200
MAX_EXCLUSIONS = 500
LIMITS = {'max_scripts_per_host': 8, 'max_script_bytes': 2 * 1024 * 1024, 'max_map_bytes': 8 * 1024 * 1024, 'max_total_bytes': 32 * 1024 * 1024,
          'follow_sourcemaps': True}
CHECK_SOURCEMAP = 'src_sourcemap_public'
REFERENCE_KINDS = ('s3', 'gcs', 'azure', 'firebase_rtdb', 'firebase_storage', 'gcr', 'ecr', 'ghcr', 'dockerhub', 'url')
AWS_KEY_RULE = 'betterleaks.aws-access-token'
AWS_SECRET_RULE = 'betterleaks.aws-secret-access-key'


# ----------------------------------------------------------------------------- what to read

def _scannable(route):
    from cveFeed import sensitive
    status = route['http_status'] or 0
    return (200 <= status < 300 or status == 404) and sensitive.is_text(route['content_type'])


def plan(project, domain_id=None, hosts=None, force=False):
    """``{host: {'urls': [...], 'script_urls': [...], 'domain_id': id}}`` for the web hosts that are due (of one target, or the named ``hosts``):
    routes checked by the route check, hosts that pass the route check's own vetting, the organization's exclusions and the bug bounty gate, and
    (unless ``force``) not read within the ledger's TTL."""
    from cveFeed import exclusions, ledger, route_auth
    from cveFeed.bounty_gate import Gate
    from cveFeed.models import RouteAuth
    rows = RouteAuth.objects.filter(project_id=project, retired_at__isnull=True)
    if domain_id is not None:
        rows = rows.filter(domain_id=domain_id)
    if hosts is not None:
        rows = rows.filter(host__in=[h.lower() for h in hosts])
    rows = rows.values('host', 'url', 'path', 'http_status', 'content_type', 'evidence', 'domain_id').order_by('host', 'path', 'url')
    found = {}
    for row in rows:
        host = (row['host'] or '').lower()
        if not host:
            continue
        entry = found.setdefault(host, {'urls': [], 'script_urls': [], 'domain_id': row['domain_id']})
        if _scannable(row) and len(entry['urls']) < MAX_URLS:
            entry['urls'].append(row['url'][:2000])
        for url in ((row['evidence'] or {}).get('script_urls') or [])[:MAX_SCRIPT_URLS] if row['path'] == '/' else ():
            if isinstance(url, str) and url not in entry['script_urls'] and len(entry['script_urls']) < MAX_SCRIPT_URLS:
                entry['script_urls'].append(url[:2000])
    banned = exclusions.excluded_names(project)
    gate = Gate()
    keep = {h: e for h, e in found.items() if e['urls'] and h not in banned and route_auth.host_allowed(h, project) and not gate.refusal(project, h)}
    if not force and keep:
        fresh = ledger.fresh(SERVICE, list(keep), project)
        keep = {h: e for h, e in keep.items() if ledger._norm(h) not in fresh}
    return keep


def build_target(hosts, plan_rows, exclusions_list, validate=False):
    """The ``secrets_scan`` target of one task: the hosts, the scope (only the batch's own hosts may be fetched), the limits, the validation half
    and the rules half. Every value is built here, never taken from a scanned host."""
    from cveFeed import secret_rules, secrets_validation
    return {'hosts': [{'host': h, 'urls': plan_rows[h]['urls'][:MAX_URLS], 'script_urls': plan_rows[h]['script_urls'][:MAX_SCRIPT_URLS]}
                      for h in hosts],
            'scope': {'names': list(hosts), 'exclusions': sorted(exclusions_list)[:MAX_EXCLUSIONS]},
            'limits': dict(LIMITS), **secrets_validation.target_fields(validate), **secret_rules.target_fields()}


def _batches(hosts):
    return [hosts[i:i + MAX_HOSTS] for i in range(0, len(hosts), MAX_HOSTS)]


# ----------------------------------------------------------------------------- the stage

def run_for_scan(scan_id, force=False, dispatch=None):
    """Dispatch the scan's due web hosts to a scanner and file what comes back. Returns ``{'hosts', 'tasks', 'findings', 'secrets', 'waiting'}``.
    ``dispatch(project, target, hosts, scan)`` replaces ``sentinel_dispatch.dispatch_or_none`` in tests. Raises ``ScannerUnavailable`` when no scanner
    can take the kind (the stage then waits; it never runs here)."""
    from agentapi import sentinel_dispatch
    from cveFeed import activity
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain__project__org').get(pk=scan_id)
    project = scan.domain.project
    summary = {'hosts': 0, 'tasks': 0, 'findings': 0, 'secrets': 0, 'waiting': 0}
    rows = plan(project.pk, domain_id=scan.domain_id, force=force)
    if not rows:
        activity.log('run_check', f'Secrets scan skipped for {scan.domain.name}: no web host is due', project=project.pk, scan_id=scan.id)
        return summary
    if dispatch is None:
        if not sentinel_dispatch.any_scanner_for(project, KIND):
            sentinel_dispatch._no_scanner(KIND, project)  # never local: this raises ScannerUnavailable
            return summary

        def dispatch(project_, target, hosts, scan_):
            return sentinel_dispatch.dispatch_or_none(project_, KIND, target, host=','.join(hosts)[:500], scan=scan_)
    _send(project, scan.domain, scan, rows, dispatch, force, summary)
    activity.log('run_check', f'Secrets scan of {summary["hosts"]} web hosts of {scan.domain.name}: {summary["secrets"]} secrets in '
                 f'{summary["findings"]} findings' + (f'; {summary["waiting"]} hosts wait for a scanner' if summary['waiting'] else ''),
                 project=project.pk, scan_id=scan.id)
    return summary


def _send(project, domain, scan, rows, dispatch, force, summary):
    """Send the planned ``rows`` (``plan``) of ``domain`` in tasks of at most ``MAX_HOSTS`` hosts and file what comes back, as the stage does: validation only
    where ``secrets_validation.plan`` allows it. ``scan`` is the scan the tasks belong to (None for the work planner's, which has none). Adds to ``summary``."""
    from agentapi import sentinel_broker
    from cveFeed import exclusions, ledger, secrets_validation
    builtin = sentinel_broker.any_scanner_for(project, KIND, builtin_only=True)
    validate, validating = secrets_validation.plan(project.pk, sorted(rows), builtin, force=force)
    banned = exclusions.excluded_names(project.pk)
    batches = [(b, True) for b in _batches(sorted(validating))] + [(b, False) for b in _batches(sorted(set(rows) - set(validating)))]
    with ledger.claim_many(f'{SERVICE}@{project.pk}', sorted(rows)) as won:
        won = set(won)
        for hosts, validating_batch in batches:
            hosts = [h for h in hosts if ledger._norm(h) in won]
            if not hosts:
                continue
            target = build_target(hosts, rows, banned, validate=validating_batch)
            if validating_batch:
                secrets_validation.audit_requested(project, hosts)
            result = dispatch(project, target, hosts, scan)
            summary['tasks'] += 1
            if result is None or result.get('outcome') != 'done':
                summary['waiting'] += len(hosts)
                if result is not None:
                    ledger.record(SERVICE, hosts, project.pk, scan, status='failed')
                continue
            filed = persist(project, domain, getattr(scan, 'id', None), target, result)
            summary['hosts'] += len(hosts)
            summary['findings'] += filed['findings']
            summary['secrets'] += filed['secrets']
            ledger.record(SERVICE, hosts, project.pk, scan)
            if validating_batch and filed['validated']:
                ledger.record(secrets_validation.LEDGER, hosts, project.pk, scan)


def run_for_hosts(project, domain, hosts, dispatch=None, priority=1):
    """Read the named web hosts of ``domain`` (a target of ``project``) with Kingfisher on a Sentinel and file what comes back: the work planner's entry
    (``cveFeed.work_planner``), the same plan (routes already checked, exclusions, the bug bounty gate, the ledger window), validation rules and storage as
    ``run_for_scan``, with no scan of its own. ``dispatch(project, target, hosts, scan)`` replaces the Sentinel call in tests. Returns the summary of
    ``run_for_scan``; raises ``ScannerUnavailable`` when no Sentinel can take the kind."""
    from agentapi import sentinel_dispatch
    summary = {'hosts': 0, 'tasks': 0, 'findings': 0, 'secrets': 0, 'waiting': 0}
    rows = plan(project.pk, domain_id=domain.pk, hosts=hosts)
    if not rows:
        return summary
    if dispatch is None:
        if not sentinel_dispatch.any_scanner_for(project, KIND):
            sentinel_dispatch._no_scanner(KIND, project)  # never local: this raises ScannerUnavailable

        def dispatch(project_, target, hosts_, scan_):
            return sentinel_dispatch.dispatch_or_none(project_, KIND, target, host=','.join(hosts_)[:500], scan=scan_, priority=priority)
    _send(project, domain, None, rows, dispatch, False, summary)
    return summary


def validate_hosts(project_id, hosts, user_id=None, dispatch=None):
    """A validation a person asked for (``agentapi.secrets_api.request_validation``): the named hosts read again by the built-in scanner with
    ``validate: true``, whatever the ledgers say. Every lock is checked again here, at run time. Returns the summary of ``run_for_scan``."""
    from django.contrib.auth import get_user_model

    from agentapi import sentinel_broker, sentinel_dispatch
    from cveFeed import exclusions, ledger, secrets_validation
    from dashboard.models import Project
    from targetApp.models import Domain
    project = Project.objects.select_related('org').get(pk=project_id)
    user = get_user_model().objects.filter(pk=user_id).first() if user_id else None
    summary = {'hosts': 0, 'tasks': 0, 'findings': 0, 'secrets': 0, 'waiting': 0}
    builtin = dispatch is not None or sentinel_broker.any_scanner_for(project, KIND, builtin_only=True)
    validate, allowed = secrets_validation.plan(project.pk, list(hosts or ()), builtin, force=True)
    if not validate:
        return {**summary, 'skipped': secrets_validation.blocked_reason(project.pk) or 'no host may be validated now'}
    rows = plan(project.pk, hosts=allowed, force=True)
    if dispatch is None:
        def dispatch(project_, target, hosts_, scan_):
            return sentinel_dispatch.dispatch_or_none(project_, KIND, target, host=','.join(hosts_)[:500], scan=scan_, created_by=user)
    banned = exclusions.excluded_names(project.pk)
    by_domain = {}
    for host, entry in rows.items():
        by_domain.setdefault(entry['domain_id'], []).append(host)
    for domain_id, names in by_domain.items():
        domain = Domain.objects.get(pk=domain_id)
        for batch in _batches(sorted(names)):
            target = build_target(batch, rows, banned, validate=True)
            secrets_validation.audit_requested(project, batch, user=user)
            result = dispatch(project, target, batch, None)
            summary['tasks'] += 1
            if result is None or result.get('outcome') != 'done':
                summary['waiting'] += len(batch)
                continue
            filed = persist(project, domain, None, target, result)
            summary['hosts'] += len(batch)
            summary['findings'] += filed['findings']
            summary['secrets'] += filed['secrets']
            ledger.record(SERVICE, batch, project.pk)
            if filed['validated']:
                ledger.record(secrets_validation.LEDGER, batch, project.pk)
    return summary


# ----------------------------------------------------------------------------- what comes back

def _host_of(url):
    return (urlsplit(url).hostname or '').lower()


def _aws_pairs(findings):
    """``{id(secret key finding): its key ID finding}``: an AWS key ID whose secret key was found in the same file. The pair is one secret, filed on
    the secret half (``aws-access-key-pair``) with the key ID's validation; the key ID is then not filed alone as an identifier."""
    keys = {}
    for f in findings:
        if f['rule_id'] == AWS_KEY_RULE:
            keys.setdefault(f['url'], f)
    return {id(f): keys[f['url']] for f in findings if f['rule_id'] == AWS_SECRET_RULE and f['url'] in keys}


def persist(project, domain, scan_id, target, result, now=None):
    """File a cleaned ``secrets_scan`` result of hosts of ``domain`` (the target), read by scan ``scan_id`` (None for a validation a person asked
    for). Returns ``{'findings', 'secrets', 'validated'}``."""
    from cveFeed import secrets_inventory, secrets_validation
    if result.get('values_scrubbed'):  # a result read again after its values were filed and dropped (``sentinel_broker.scrub_values``): nothing left to file
        return {'findings': 0, 'secrets': 0, 'validated': False}
    now = now or timezone.now()
    validating = bool(target.get('validate'))
    findings = list(result.get('findings') or [])
    pairs = _aws_pairs(findings)
    paired_keys = {id(k) for k in pairs.values()}
    seen = {f['url']: set() for f in result.get('fetched') or []}
    filed, validated = {}, False
    for f in findings:
        if id(f) in paired_keys:
            continue  # filed with its secret key
        key = pairs.get(id(f))
        judged = key or f  # Kingfisher validates the pair through the key ID's rule
        outcome = secrets_validation.allowed_outcome(judged['rule_id'], (judged.get('validation') or {}).get('outcome'), validating)
        row = secrets_inventory.record(project.pk, host=_host_of(f['url']), url=f['url'], source='kingfisher', rule_id=f['rule_id'], value=f['secret'],
                                       domain_id=domain.pk, scan_id=scan_id, line=f.get('line'), confidence=f.get('confidence') or '',
                                       outcome=outcome, meta=judged.get('validation_meta'), now=now, context=f.get('context') or '')
        if row is None:
            continue
        if key is not None and AWS_KEY_RULE not in row.rule_ids:
            row.rule_ids = [*row.rule_ids, AWS_KEY_RULE]
            row.save(update_fields=['rule_ids'])
        seen.setdefault(f['url'], set()).add(row.pk)
        filed[row.pk] = row
        if outcome != 'not_attempted':
            validated = True
            secrets_validation.audit_result(project, row, judged['rule_id'], outcome)
    secrets_inventory.retire_missing(project.pk, 'kingfisher', seen, now=now)
    _store_references(project, domain, result.get('references') or [], now)
    _store_sourcemaps(domain, result.get('fetched') or [], target)
    if filed:
        from cveFeed import scoring
        scoring.rescore_quietly(project.pk, sorted({_host_of(f['url']) for f in findings}))
    if getattr(result, 'task_id', None):  # the values are filed (fingerprinted and masked): the task row does not keep them
        from agentapi import sentinel_broker
        sentinel_broker.scrub_values(result.task_id)
    return {'findings': len(findings), 'secrets': len(filed), 'validated': validated}


def _store_references(project, domain, references, now):
    from cveFeed.models import ResourceRef
    for ref in references[:MAX_REFERENCES]:
        kind, value, url = ref.get('kind'), (ref.get('value') or '').strip().lower()[:255], ref.get('url') or ''
        if kind not in REFERENCE_KINDS or not value:
            continue
        host = _host_of(url)
        row, made = ResourceRef.objects.get_or_create(project_id=project.pk, kind=kind, identifier=value,
                                                      defaults={'domain_id': domain.pk, 'host': host[:255], 'found_url': url[:2000],
                                                                'first_seen': now, 'last_seen': now})
        if not made:
            ResourceRef.objects.filter(pk=row.pk).update(last_seen=now, host=host[:255] or row.host, found_url=url[:2000] or row.found_url)


def sourcemap_finding(entry):
    from cveFeed.hygiene import Finding
    embeds = bool(entry.get('sources_content'))
    url = entry['url']
    title = f'Source map served: {url}' + (' (with the original sources)' if embeds else '')
    fix = ('Stop publishing source maps to the public site (upload them to your error tracker instead), or serve them only to your own '
           'network.')
    detail = (f'{url} is a JavaScript source map for {entry.get("sourcemap_of") or "a script of the site"}, served to anyone. '
              + ('It embeds the original source files (sourcesContent): comments, internal names and anything the build left in. '
                 if embeds else 'It names the original source files and their structure. ') + f'Fix: {fix}')
    evidence = {'source': 'secrets scan', 'url': url, 'script': entry.get('sourcemap_of') or '', 'sources_content': embeds, 'remediation': fix}
    return Finding(CHECK_SOURCEMAP, 1 if embeds else 0, title[:300], detail, _host_of(url), evidence)


def _store_sourcemaps(domain, fetched, target):
    """A served source map is a hygiene finding of its host; the hosts read in this task that serve none any more have theirs resolved."""
    from cveFeed.hygiene import store_findings
    found = [sourcemap_finding(e) for e in fetched if e.get('kind') == 'sourcemap' and (e.get('status') or 0) // 100 == 2]
    hosts = {h['host'] for h in target.get('hosts') or []}
    store_findings(domain, found, hosts=hosts, owns=lambda check: check == CHECK_SOURCEMAP)


# ----------------------------------------------------------------------------- cleaning (agentapi.sentinel_broker)

def clean_result(body, task_target=None):
    """A Sentinel's ``secrets_scan`` report, typed and clipped: only the fields of the contract, a finding only for a URL it reports fetching on a
    host of the task, never a validation response, never metadata outside ``secrets_inventory.META_KEYS``. Given the task's target, fetched URLs
    on a host the task did not name are dropped, and so are their findings."""
    from cveFeed import secrets_catalog as catalog
    from cveFeed import secrets_inventory
    names = None
    if isinstance(task_target, dict):
        names = {str(h.get('host') or '').lower() for h in task_target.get('hosts') or [] if isinstance(h, dict)}
    fetched, urls = [], set()
    for item in (body.get('fetched') or [])[:MAX_FETCHED]:
        if not isinstance(item, dict) or not isinstance(item.get('url'), str) or item.get('kind') not in ('page', 'script', 'sourcemap'):
            continue
        url = item['url'][:2000]
        parts = urlsplit(url)
        if parts.scheme not in ('http', 'https') or not parts.hostname or (names is not None and parts.hostname.lower() not in names):
            continue
        status = item.get('status')
        row = {'url': url, 'kind': item['kind'], 'status': status if isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 999 else None,
               'bytes': item['bytes'] if isinstance(item.get('bytes'), int) and not isinstance(item.get('bytes'), bool) and item['bytes'] >= 0 else 0,
               'content_type': str(item.get('content_type') or '')[:100]}
        if item['kind'] == 'sourcemap':
            if isinstance(item.get('sourcemap_of'), str):
                row['sourcemap_of'] = item['sourcemap_of'][:2000]
            row['sources_content'] = item.get('sources_content') is True
        fetched.append(row)
        urls.add(url)
    findings = []
    for item in (body.get('findings') or [])[:MAX_FINDINGS]:
        if not isinstance(item, dict) or not catalog.rule_id_ok(item.get('rule_id')) or item.get('url') not in urls:
            continue
        secret = item.get('secret')
        if not isinstance(secret, str) or not secrets_inventory.MIN_VALUE <= len(secret) <= secrets_inventory.MAX_VALUE:
            continue
        line = item.get('line')
        outcome = (item.get('validation') or {}).get('outcome') if isinstance(item.get('validation'), dict) else None
        row = {'rule_id': item['rule_id'], 'rule_name': str(item.get('rule_name') or '')[:200], 'url': item['url'], 'secret': secret,
               'line': line if isinstance(line, int) and not isinstance(line, bool) and line >= 0 else None,
               'confidence': item.get('confidence') if item.get('confidence') in ('', 'low', 'medium', 'high') else '',
               'entropy': str(item.get('entropy') or '')[:20],
               'validation': {'outcome': outcome if outcome in catalog.OUTCOMES else 'not_attempted'}}
        meta = secrets_inventory.clean_meta(item.get('validation_meta'))
        if meta:
            row['validation_meta'] = meta
        context = catalog.clean_context(item.get('context'))  # optional, masked by the Sentinel; masked again with the value in hand when it is filed (secrets_inventory.record)
        if context:
            row['context'] = context
        findings.append(row)
    references = []
    for item in (body.get('references') or [])[:MAX_REFERENCES]:
        if (isinstance(item, dict) and item.get('kind') in REFERENCE_KINDS and isinstance(item.get('value'), str) and item['value'].strip()
                and isinstance(item.get('url'), str) and item['url'] in urls):
            references.append({'kind': item['kind'], 'value': item['value'].strip()[:255], 'url': item['url']})
    stats = body.get('stats') if isinstance(body.get('stats'), dict) else {}
    clean_stats = {k: stats[k] for k in ('files', 'bytes', 'findings', 'rules_loaded')
                   if isinstance(stats.get(k), int) and not isinstance(stats.get(k), bool) and stats[k] >= 0}
    clean_stats.update({k: stats[k] for k in ('truncated', 'validated') if isinstance(stats.get(k), bool)})
    if isinstance(stats.get('kingfisher_version'), str):
        clean_stats['kingfisher_version'] = stats['kingfisher_version'][:20]
    out = {'findings': findings, 'fetched': fetched, 'references': references}
    if isinstance(body.get('summary'), str):
        out['summary'] = body['summary'][:300]
    if clean_stats:
        out['stats'] = clean_stats
    return out
