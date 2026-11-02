"""Automatic validation of findings: after triage, CVEngine tries to reproduce a finding itself with a small fixed set of read-only
checks and records exactly what it ran and what came back.

The owner of every target has authorised this, and it stays inside these limits. There is no free-form command: only five kinds of
check exist.

* ``nuclei_template``: an installed template for the CVE, or a generated template that is status valid, still passes the safety gate and
  lives in the generated-templates directory. Either must be read-only by its own text (methods GET, HEAD or OPTIONS, no payloads,
  attack, fuzzing or body, no code, file or out-of-band protocols); anything else is refused ("template not validated").
* ``nmap_sv``: ``nmap -sV`` against the single port the finding names.
* ``http_head``: one HEAD (a GET only when the server answers 405 to HEAD), through the route check's probe: no cookies, no
  credentials, no redirects, the body never kept.
* ``db_probe``: the existing single credential-less database exposure check.
* ``fact_probe``: a version or identity probe from the catalogue in ``cveFeed.probes`` (a few GETs with the front page's headers, an
  error page signature, a framework script, or ``nmap -sV --version-all`` on one port). It finds the fact an advisory depends on (the
  version, which look-alike product runs, what answers behind a CDN) and records it; it never exploits anything.

Everything is read-only; every host goes through the scannable-host filter and must belong to the finding's project; work is
dispatched per project; each check waits its turn for memory (heavy_job), is kept off the ledger while fresh (CVENGINE_TTL_VALIDATE),
and counts against per-run, per-project and per-day caps. The stop flag is honoured, every check is non-fatal, and an error or a
timeout is "failed" and retried later, never "clean".

What a result does to the classification is deterministic (``apply_validation``): a hit confirms; a check that did not reproduce
the finding never lowers it, and in particular never takes a finding with hard evidence below its floor, because a template can miss
(a WAF, a virtual host, a different path); a failure changes nothing and schedules a retry.
"""
import ipaddress
import hashlib
import logging
import os
import re
import shlex
import subprocess
from datetime import timedelta
from urllib.parse import urlparse

import yaml
from django.utils import timezone

from cveFeed import triage
from cveFeed.safeyaml import load_template

logger = logging.getLogger(__name__)

CHECK_KINDS = ('nuclei_template', 'nmap_sv', 'http_head', 'db_probe', 'fact_probe')
PLANNED_KINDS = ('cve_match', 'db_exposure', 'route_auth')  # the finding kinds that have a validated check
READONLY_METHODS = {'GET', 'HEAD', 'OPTIONS'}
# Keys that make a template send something other than a plain read: an inline payload list, an attack mode, a body, raw sockets,
# code or file access. The installed community templates are not held to the generated-template gate (matchers, request counts),
# but never to less than this.
READONLY_FORBIDDEN_KEYS = {'payloads', 'attack', 'fuzzing', 'iterate-all', 'body', 'unsafe', 'race', 'pipeline', 'cookie-reuse',
                           'code', 'javascript', 'headless', 'file', 'flow', 'workflows', 'self-contained'}
MAX_INSTALLED_TEMPLATE_BYTES = 200_000
# Out of band: the {{interactsh-url}} placeholder, the interactsh_* match parts, or an interactsh page as the evidence (an
# SSRF check that makes the target fetch one). A matcher that only recognizes an interactsh server by its
# X-Interactsh-Version header, as tech-detect does, stays in band.
OAST_RE = re.compile(r'interactsh-url|interactsh_(?:protocol|request|response|ip)|interactsh server|\boast\b')
EVIDENCE_CAP = 4096
OUTPUT_CAP = 600
CLEAN_CONFIDENCE_ADJUST = -0.2
NMAP_TIMEOUT = 90
HOST_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$')
SERVER_RE = re.compile(r'^([A-Za-z][A-Za-z0-9_.-]*)[/ ]v?(\d[\w.+-]*)')
DEFAULT_CAPS = {'VALIDATE_MAX_PER_RUN': 50, 'VALIDATE_MAX_PER_PROJECT_DAY': 300, 'VALIDATE_MAX_PER_DAY': 1500}
DB_EQUIVALENT = {
    'redis': 'redis-cli -h {ip} -p {port} PING',
    'memcached': "printf 'version\\r\\n' | nc -w 3 {ip} {port}",
    'postgres': 'psql "host={ip} port={port} dbname=postgres user=postgres connect_timeout=3" -w -c "select 1"',
    'postgresql': 'psql "host={ip} port={port} dbname=postgres user=postgres connect_timeout=3" -w -c "select 1"',
    'elastic': 'curl -s --max-time 3 http://{ip}:{port}/',
    'couchdb': 'curl -s --max-time 3 http://{ip}:{port}/_all_dbs',
}


def cap(name):
    """A validation cap: what an App Admin saved on Settings, configMaxxing, else CVENGINE_<NAME> in the environment, else the default
    (``cveFeed.tunables``; read on every use, so a change applies within seconds)."""
    from cveFeed import tunables
    return tunables.value(name.lower(), DEFAULT_CAPS[name])


# ----------------------------------------------------------------------------- templates (read-only by their own text)

def all_templates_allowed():
    """True when Settings > Scan engines lets every installed Nuclei template run. Fails closed: any doubt is the read-only policy."""
    try:
        from dashboard.models import ScanPolicy
        return bool(ScanPolicy.current().nuclei_all_templates)
    except Exception:  # noqa: BLE001
        return False


def readonly_problem(yaml_text):
    """Why a template may not be run by validation, or "" when its text is read-only: plain GET, HEAD or OPTIONS requests (a ``method``
    or the first line of each ``raw`` request), none of the keys in READONLY_FORBIDDEN_KEYS, no out-of-band protocol, and no data sent
    over a raw network connection. Pure."""
    if not yaml_text or len(yaml_text.encode()) > MAX_INSTALLED_TEMPLATE_BYTES:
        return 'template not validated: empty or too large'
    try:
        doc = load_template(yaml_text)
    except yaml.YAMLError:
        return 'template not validated: not valid YAML'
    if not isinstance(doc, dict):
        return 'template not validated: not a template'
    from cveFeed import templategen
    forbidden = set(doc) & templategen.FORBIDDEN_PROTOCOLS
    unknown = set(doc) - templategen.ALLOWED_TOP_KEYS
    if forbidden or unknown:
        return 'template not validated: unsupported protocol or top-level feature'
    destination = templategen.destination_check(doc, allow_host_redirects=True)
    if destination:
        return f'template not validated: {destination}'

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).lower() in READONLY_FORBIDDEN_KEYS:
                    return f'template not validated: it uses {key!r}'
                found = walk(value)
                if found:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = walk(value)
                if found:
                    return found
        return ''
    problem = walk({k: v for k, v in doc.items() if k != 'info'})
    if problem:
        return problem
    if not set(doc) & {'http', 'requests', 'network', 'tcp', 'dns', 'ssl'}:
        return 'template not validated: no protocol section'
    lowered = yaml_text.lower()
    if OAST_RE.search(lowered):
        return 'template not validated: it uses out-of-band checks'
    for proto in ('http', 'requests', 'network', 'tcp', 'dns', 'ssl'):
        if proto in doc and not isinstance(doc[proto], list):
            return 'template not validated: malformed protocol section'
    for proto in ('http', 'requests'):
        for block in doc.get(proto) or []:
            if not isinstance(block, dict):
                return 'template not validated: malformed http section'
            if 'raw' not in block and str(block.get('method', 'GET')).upper() not in READONLY_METHODS:
                return f'template not validated: http method {str(block.get("method")).upper()} is not read-only'
            if 'raw' in block and not isinstance(block['raw'], list):
                return 'template not validated: malformed raw requests'
            for raw in block.get('raw') or []:
                first = str(raw).strip().splitlines()[0] if str(raw).strip() else ''
                verb = first.split(' ', 1)[0].upper()
                if verb not in READONLY_METHODS:
                    return f'template not validated: raw request method {verb or "?"} is not read-only'
    for proto in ('network', 'tcp'):
        for block in doc.get(proto) or []:
            if not isinstance(block, dict) or ('inputs' in block and not isinstance(block['inputs'], list)):
                return 'template not validated: malformed network section'
            if any(not isinstance(i, dict) or i.get('data') for i in block.get('inputs') or []):
                return 'template not validated: it sends data over a raw connection'
    return ''


def _inside(path, root):
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def approved_template(path, cve_id=None):
    """Return approved immutable text and an error, applying policy at every execution.

    Generated files must still match an approved row. Installed files must be read-only
    and destination-bound. Both are read with a size cap and fail closed outside roots.
    """
    from cveFeed import templategen
    from cveFeed.models import GeneratedTemplate
    generated = _inside(path, templategen.GENERATED_DIR)
    if not generated and not _inside(path, templategen.TEMPLATES_ROOT):
        return '', 'template not validated: outside the template directories'
    limit = templategen.MAX_TEMPLATE_BYTES if generated else MAX_INSTALLED_TEMPLATE_BYTES
    try:
        with open(path, 'rb') as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            return '', 'template not validated: too large'
        text = data.decode('utf-8')
    except (OSError, UnicodeError):
        return '', 'template not validated: cannot read UTF-8 template'
    if generated:
        rows = GeneratedTemplate.objects.filter(path=path, status=GeneratedTemplate.STATUS_VALID,
                    positive_fixture_verified_at__isnull=False).exclude(positive_fixture_source='')
        if cve_id:
            rows = rows.filter(cve_entry__cve_id__iexact=cve_id)
        row = rows.select_related('cve_entry').first()
        if row is None or row.yaml != text:
            return '', 'template not validated: not an unchanged valid generated template with a reviewed positive fixture'
        ok, why = templategen.static_check(text, expected_cve_id=row.cve_entry.cve_id)
        problem = '' if ok else f'template not validated: {why}'
    else:
        problem = '' if all_templates_allowed() else readonly_problem(text)
    return ('', problem) if problem else (text, '')


def resolve_template(cve_id):
    """Choose only a currently approved, read-only and destination-bound template."""
    from cveFeed import templategen
    reason = 'no template covers this CVE'
    for path in templategen.find_existing_template(cve_id):
        _text, reason = approved_template(path, cve_id)
        if not reason:
            return path, ''
    return '', reason


# ----------------------------------------------------------------------------- planning (pure)

def _safe_host(value):
    return bool(value) and bool(HOST_RE.match(value)) and not value.startswith('-')


def _safe_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def local_component_only(cve):
    """A conservative relevance gate for advisories explicitly about local kernel/driver components.

    External service banners cannot establish installed kernel modules or NIC hardware. Do not infer
    that the host is safe; retain the candidate for authenticated/component evidence.
    """
    description = ' '.join(str(getattr(cve, name, '') or '') for name in ('title', 'original_description')).lower()
    return bool(re.search(r'\blocal(?:ly)?\b', description) and
                re.search(r'\b(kernel|driver|module|hardware|nic|kvm|mlx5e|bnxt_en|mmio)\b', description))


def _check(kind, label, argv, display, target, asset, signature, timeout, **params):
    revision = hashlib.sha256(('validation-policy-2:' + repr(argv)).encode()).hexdigest()[:10]
    if kind == 'nuclei_template':
        try:
            with open(params['template'], 'rb') as source:
                revision = hashlib.sha256(revision.encode() + source.read(MAX_INSTALLED_TEMPLATE_BYTES + 1)).hexdigest()[:10]
        except OSError:
            pass
    return {'kind': kind, 'label': label, 'argv': argv, 'display': display, 'target': target, 'asset': asset,
            'service': f'validate:{kind}:{signature[:16]}:{revision}', 'timeout': timeout, 'params': params}


def plan_checks(subject, signature, template=('', '')):
    """``(checks, notes)`` for one finding. ``subject`` is a plain dict (see ``subject_for``), ``template`` the ``(path, reason)`` of
    ``resolve_template`` for a CVE match. A check is ``{kind, label, argv, display, target, asset, service, timeout, params}``: ``argv``
    is what runs (never through a shell) and ``display`` the command a person can repeat. ``notes`` says why a check that could have
    applied was not planned (a template that is not read-only, for instance). Pure: no database, no network."""
    from cveFeed import nmap_scan, templategen
    checks, notes = [], []
    host, kind = subject.get('host') or '', subject['kind']
    if kind == 'cve_match':
        path, why = template
        if path and _safe_host(host):
            argv = [templategen.NUCLEI_BIN, '-t', path, '-u', host, '-ni', '-rl', templategen.RATE_LIMIT, '-timeout', '10',
                    '-retries', '0', '-duc']
            checks.append(_check('nuclei_template', f'nuclei template for {subject["cve_id"]}', argv, shlex.join(argv), host, host,
                                 signature, templategen.RUN_TIMEOUT, template=path, cve_id=subject['cve_id']))
        elif why and why != 'no template covers this CVE':
            notes.append(why)
        if subject.get('local_component_only'):
            notes.append('This advisory requires local kernel, driver or hardware evidence; external service banners cannot validate it.')
        else:
            candidates = []
            if subject.get('source') == 'port':
                candidates.append((subject.get('ip'), subject.get('port')))
            candidates += [(item.get('ip'), item.get('port')) for item in (subject.get('candidate_services') or [])[:4]
                           if isinstance(item, dict)]
            for ip, port in list(dict.fromkeys(candidates))[:4]:
                if not _safe_ip(ip) or not isinstance(port, int) or not 0 < port < 65536:
                    continue
                argv = [nmap_scan.NMAP_BIN, '-sV', '--version-intensity', '5', '-Pn', '-p', str(port), '--host-timeout', '60s', '-oX', '-', ip]
                checks.append(_check('nmap_sv', f'nmap service detection on observed port {port}', argv, shlex.join(argv),
                                     f'{ip}:{port}', f'{ip}:{port}', signature, NMAP_TIMEOUT, ip=ip, port=port))
            if subject.get('source') == 'tech' and subject.get('url'):
                checks.append(_http_check(subject['url'], signature))
            checks += _probe_checks(subject, signature)
    elif kind == 'db_exposure':
        ip, port, label = subject.get('ip'), subject.get('port'), (subject.get('db') or '').lower()
        if ip and _safe_ip(ip) and isinstance(port, int) and 0 < port < 65536:
            if label in DB_EQUIVALENT:
                display = DB_EQUIVALENT[label].format(ip=ip, port=port)
                checks.append(_check('db_probe', f'unauthenticated {label} check', [], display, f'{ip}:{port}', f'{ip}:{port}', signature,
                                     30, ip=ip, port=port, db=label, equivalent=True))
            argv = [nmap_scan.NMAP_BIN, '-sV', '--version-intensity', '5', '-Pn', '-p', str(port), '--host-timeout', '60s', '-oX', '-', ip]
            checks.append(_check('nmap_sv', f'nmap service detection on port {port}', argv, shlex.join(argv), f'{ip}:{port}', f'{ip}:{port}',
                                 signature, NMAP_TIMEOUT, ip=ip, port=port))
    elif kind == 'route_auth' and subject.get('url'):
        checks.append(_http_check(subject['url'], signature))
    return checks, notes


def _probe_checks(subject, signature):
    """One ``fact_probe`` check per planned version or identity probe (``subject['probe_plan']``, chosen by cveFeed.probes.plan_for_host)."""
    from cveFeed import probes
    checks = []
    for entry in subject.get('probe_plan') or []:
        target = entry['target']
        display = probes.display_for(entry['probe'], target)
        argv = probes.nmap_argv(target['ip'], target['port'], target.get('service', '')) if entry['family'] == 'nmap' else ['probe', entry['probe'], target['base']]
        # one step per probe: the step key is (kind, target), and several probes read the same base URL
        where = f"{target['base'].rstrip('/')}/#{entry['probe']}" if target.get('base') else f"{target['ip']}:{target['port']}"
        checks.append(_check('fact_probe', f"Version and identity probe: {entry['label']}", argv, display, where, where, signature + entry['probe'],
                             probes.NMAP_TIMEOUT if entry['family'] == 'nmap' else 90, probe=entry['probe'], probe_target=target,
                             project_id=subject.get('project_id'), domain_id=subject.get('domain_id'), host=subject.get('host'), product=subject.get('product') or ''))
    return checks


def _http_check(url, signature):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not _safe_host(parsed.hostname or ''):
        return None
    argv = ['curl', '-I', '-k', '--max-time', '6', url]
    return _check('http_head', 'HTTP banner check (HEAD, GET only if HEAD is refused)', argv, shlex.join(argv), url, url, signature, 15, url=url)


def _probe_plan(finding, evidence):
    """The version and identity probes for a CVE match: the matched product's own lead first (a version-less match, or a version a probe
    can confirm or refute), then the host's other unversioned products. Chosen by rule, with no AI."""
    from cveFeed import host_context, probes
    from startScan.models import Subdomain
    sub = Subdomain.objects.filter(pk=finding.subdomain_id).prefetch_related('technologies', 'ip_addresses__ports', 'waf').select_related(
        'target_domain').first()
    lead = {'name': finding.matched_product, 'source': finding.source}
    if finding.source == 'port' and evidence.get('port') and evidence.get('ip'):
        lead.update(ip=evidence['ip'], port=evidence['port'])
    edge = host_context.edge_for(sub, sub.target_domain.project_id)['fronted']
    if finding.matched_version:
        # the version is stated, and nmap_sv or the front page already re-read it: only the probes that tell look-alike products apart add anything
        return probes.plan_for_host(sub, [lead], edge_fronted=edge, wanted=probes.IDENTITY_PROBES)
    return probes.plan_for_host(sub, [lead] + probes.leads_for(sub), edge_fronted=edge)


def subject_for(row, finding):
    """The plain dict ``plan_checks`` reads, from a Triage row and its finding: host, CVE id, source, address and port, URL."""
    from cveFeed import route_auth
    subject = {'kind': row.kind, 'host': row.host}
    if row.kind == 'cve_match':
        ev = finding.evidence or {}
        subject.update(cve_id=finding.cve_entry.cve_id, source=finding.source, ip=ev.get('ip'), port=ev.get('port'),
                       product=finding.matched_product, matched_version=finding.matched_version, range=ev.get('range') or {},
                       local_component_only=local_component_only(finding.cve_entry), project_id=row.project_id,
                       domain_id=finding.subdomain.target_domain_id if finding.subdomain is not None else None)
        if finding.subdomain is not None:
            from startScan.models import open_ports
            # Only ports already observed in this host's inventory. Never ask the model for a port or expand target scope.
            candidates = []
            for ip in finding.subdomain.ip_addresses.all():
                for port in open_ports(ip):
                    if _safe_ip(ip.address) and isinstance(port.number, int) and 0 < port.number < 65536:
                        candidates.append({'ip': ip.address, 'port': port.number})
            subject['candidate_services'] = sorted(candidates, key=lambda c: (c['port'], c['ip']))[:4]
        if finding.source == 'tech' and finding.subdomain is not None:
            bases = route_auth.web_bases(finding.subdomain)
            subject['url'] = bases[0] + '/' if bases else None
        if finding.subdomain is not None and not subject['local_component_only']:
            subject['probe_plan'] = _probe_plan(finding, ev)
    elif row.kind == 'db_exposure':
        parsed = urlparse(finding.http_url or '')
        subject.update(ip=parsed.hostname, port=parsed.port, db=(finding.template_id or '').replace('db-exposure-', '', 1))
    elif row.kind == 'route_auth':
        subject['url'] = finding.url
    return subject


# ----------------------------------------------------------------------------- the runners (injectable)

def _trim(value, limit=EVIDENCE_CAP):
    return str(value if value is not None else '')[:limit]


def run_nuclei_template(check):
    """Run the planned template against the one host (see templategen.run_template: -ni, -rl 10, -timeout 10, no retries)."""
    from cveFeed import templategen
    outcome = templategen._run_template_with_retry(check['params']['template'], [check['target']])[0]
    if outcome.get('error'):
        return {'status': 'failed', 'error': outcome['error'], 'summary': outcome['error'], 'outcome': outcome}
    if outcome['vulnerable']:
        hit = outcome.get('hit') or {}
        evidence = {'matched_at': _trim(hit.get('matched-at') or hit.get('host'), 500), 'matcher_name': _trim(hit.get('matcher-name'), 200),
                    'extracted_results': [_trim(e, 200) for e in (hit.get('extracted-results') or [])[:5]],
                    'request': _trim(hit.get('request')), 'response': _trim(hit.get('response'))}
        return {'status': 'hit', 'summary': f'the template matched ({evidence["matcher_name"] or "matcher"})',
                'output_excerpt': _trim(f'matched at {evidence["matched_at"]}', OUTPUT_CAP), 'evidence': evidence, 'outcome': outcome}
    return {'status': 'no_match', 'summary': 'the template did not match', 'outcome': outcome}


def run_nmap_sv(check):
    from cveFeed import nmap_scan
    out = nmap_scan.run_nmap_args(check['argv'][1:], label=check['target'], timeout=check['timeout'])
    port = check['params']['port']
    record = next((p for host in nmap_scan.parse_xml(out) for p in host['ports'] if p['number'] == port), None)
    if record is None or record['state'] != 'open':
        return {'status': 'no_match', 'summary': f'port {port} was not open at the time of the check',
                'output_excerpt': f'port {port} not open'}
    observed = {'product': record['product'], 'version': record['version']}
    text = ' '.join(x for x in (record['product'], record['version'], record['service_extra']) if x)
    return {'status': 'observed', 'summary': f'nmap reports {text or record["service_name"] or "an unidentified service"}'
                                            f' (method {record["method"] or "unknown"})',
            'output_excerpt': _trim(f'{record["service_name"]} {text} {record["cpe"]} method={record["method"]}', OUTPUT_CAP),
            'observed': observed}


def run_http_head(check):
    """HEAD the URL; GET only when the server answers 405. Keeps the status, Server, X-Powered-By and title, never the body."""
    from cveFeed import route_auth
    from reNgine import resources
    url = check['params']['url']
    with resources.heavy_job('route-probe', label=check['target']):
        probe = route_auth.probe_url(url, method='HEAD')
        used = 'HEAD'
        if probe.get('status') == 405:
            probe, used = route_auth.probe_url(url, method='GET'), 'GET'
    server = probe.get('server') or ''
    found = SERVER_RE.match(server)
    summary = f'{used} answered {probe.get("status")}' + (f', Server: {server}' if server else '')
    return {'status': 'observed', 'summary': _trim(summary, 300), 'output_excerpt': _trim(summary + (
        f', X-Powered-By: {probe["powered_by"]}' if probe.get('powered_by') else '') + (
        f', title: {probe["title"]}' if probe.get('title') else ''), OUTPUT_CAP),
        'http': {'status': probe.get('status'), 'method': used},
        'observed': {'product': found.group(1) if found else '', 'version': found.group(2) if found else ''}}


def run_fact_probe(check):
    """Run one catalogued probe (cveFeed.probes) on the host's current row, store what it found as host facts and say it in one line. A
    probe that reads a version gives ``observed`` with that version (``interpret`` then tests it against the finding's range); one that finds
    the product states none, or only an edge, still answers: the version is hidden from outside, which is a result, not a failure."""
    from cveFeed import probes
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    params = check['params']
    sub = (Subdomain.objects.filter(target_domain__project_id=params['project_id'], name=params['host']).filter(latest_scan_q())
           .prefetch_related('technologies', 'ip_addresses__ports', 'waf').select_related('target_domain').order_by('-id').first())
    if sub is None:
        return {'status': 'failed', 'error': 'the host is no longer in the current inventory', 'summary': 'host not found'}
    # a validation re-test reads past the script cache (sending the stored ETag), so a fixed library is seen as fixed now
    found = probes.run_one(params['project_id'], params['domain_id'], sub, {'probe': params['probe'], 'target': params['probe_target']}, fresh=True)
    product = re.sub(r'[^a-z0-9]', '', params.get('product', '').lower())
    versions = [o for o in found if o['kind'] == 'version' and o['outcome'] == 'found' and o['version']]
    pick = next((o for o in versions if product and (product in re.sub(r'[^a-z0-9]', '', o['product'].lower())
                                                      or re.sub(r'[^a-z0-9]', '', o['product'].lower()) in product)), None)
    result = {'status': 'observed', 'summary': f"probe {params['probe']}: {probes.summarize(found)}",
              'output_excerpt': _trim(probes.summarize(found), OUTPUT_CAP), 'probe': {'id': params['probe'], 'found': len(found)}}
    if pick:
        result['observed'] = {'product': pick['product'], 'version': pick['version']}
    return result


def run_db_probe(check):
    from cveFeed import db_exposure
    params = check['params']
    _label, fn = db_exposure.CHECKS[params['db']]
    db_exposure.EVIDENCE.pop((params['ip'], params['port']), None)
    opened = fn(params['ip'], params['port'])
    reply = db_exposure.EVIDENCE.pop((params['ip'], params['port']), '')
    if opened is None:
        return {'status': 'failed', 'error': 'the client library for this check is not installed', 'summary': 'not run'}
    if opened:
        return {'status': 'hit', 'summary': 'the service answered with no credentials' + (f': {reply}' if reply else ''),
                'output_excerpt': _trim(reply, OUTPUT_CAP), 'evidence': {'reply': _trim(reply, 300)}}
    return {'status': 'no_match', 'summary': 'the service did not answer without credentials at the time of the check'}


RUNNERS = {'nuclei_template': run_nuclei_template, 'nmap_sv': run_nmap_sv, 'http_head': run_http_head, 'db_probe': run_db_probe,
           'fact_probe': run_fact_probe}


# ----------------------------------------------------------------------------- outcome rules

STEP_RESULTS = ('hit', 'no_match', 'reaffirmed', 'version_changed', 'observed', 'failed', 'blocked')


def interpret(subject, check, result):
    """Turn an ``observed`` result (nmap or a banner) into ``reaffirmed`` (the live version is still inside the affected range),
    ``version_changed`` (it is not) or plain ``observed``, for a CVE match; a route that still answers anonymously is ``reaffirmed``.
    Returns the result, with its status refined. Pure."""
    if result.get('status') != 'observed':
        return result
    from cveFeed.correlation import PRODUCT_ALIASES, _norm, name_matches_token, parse_version, version_in_range
    out = dict(result)
    if subject['kind'] == 'cve_match':
        observed = (result.get('observed') or {})
        product = _norm(subject.get('product') or '', catalogue=True)
        observed_product = _norm(observed.get('product') or '')
        # A version belongs to the identified product, never to a sibling or an unidentified banner.
        same_product = (name_matches_token(observed_product, product)
                        or product in PRODUCT_ALIASES.get(observed_product, ())
                        or observed_product in PRODUCT_ALIASES.get(product, ()))
        if observed.get('version') and same_product:
            inside = version_in_range(parse_version(observed['version']), subject.get('range') or {})
            if inside is True:
                out.update(status='reaffirmed', summary=result['summary'] + '; that version is inside the affected range')
            elif inside is False:
                out.update(status='version_changed', summary=result['summary'] + '; that version is outside the affected range'
                           f' (the finding recorded {subject.get("matched_version") or "no version"})')
    elif subject['kind'] == 'route_auth' and (result.get('http') or {}).get('status') is not None:
        status = result['http']['status']
        if 200 <= status < 300:
            out.update(status='reaffirmed', summary=result['summary'] + '; the route still answers anonymously')
        else:
            out.update(status='no_match', summary=result['summary'] + '; the route no longer answers 2xx')
    return out


def rollup(steps):
    """The row-level validation status from its steps: hit if any step confirmed it, else failed if any step errored (so it is retried,
    never counted clean), else skipped_blocked if every step was blocked, else observed if checks only gathered metadata."""
    results = [s.get('result') for s in steps]
    if not results:
        return 'none'
    if 'hit' in results:
        return 'hit'
    if 'failed' in results:
        return 'failed'
    if all(r == 'blocked' for r in results):
        return 'skipped_blocked'
    if not any(r in ('no_match', 'version_changed') for r in results):
        return 'observed'
    return 'clean'


def backoff(attempts, now):
    """When a failed check is tried again: 6 hours, doubling, 24 at most; after three failures the next try is a day away."""
    return now + timedelta(hours=min(24, 6 * 2 ** max(0, attempts - 1)))


def raise_class(row, level, why):
    """Raise the row's classification to ``level`` (never lower it) and say why."""
    if triage.rank(level) > triage.rank(row.classification):
        row.classification = level
        row.reason = (f'{why}. ' + (row.reason or ''))[:700]


def _version_only(row):
    """Whether the row's CVE match stands on a version string alone (``match_policy.version_only``): no template hit, no distribution tracker
    listing, no runZero report. Re-reading that same version with another tool is not further evidence."""
    if not row.match_id:
        return False
    from cveFeed import match_policy
    match = row.match
    return match_policy.version_only(getattr(match, 'source', ''), getattr(match, 'evidence', None) or {}, match.version_in_range,
                                     getattr(match, 'template_result', '') or '', getattr(match, 'distro_status', '') or '')


def apply_validation(row, check, result, now=None, save=True):
    """Record one check's result on its Triage row and apply the rules. Never lowers a classification: a hit confirms (for a CVE match
    it also records the template hit as a nuclei-cve finding and sets the match's template_result), a re-affirmed live version raises a
    triaged finding to likely (or to the ceiling, when the match rests on its version string alone), a check that did not reproduce the finding changes nothing but the confidence (so a template that missed
    can never clear a finding with hard evidence), and a failure schedules a retry and is never treated as clean."""
    now = now or timezone.now()
    status = result['status']
    hit_before = row.validation_status == 'hit'
    step = {'kind': check['kind'], 'label': check['label'], 'display': check['display'], 'target': check['target'],
            'ran_at': now.isoformat(), 'result': status, 'summary': _trim(result.get('summary'), 300),
            'output_excerpt': _trim(result.get('output_excerpt'), OUTPUT_CAP), 'error': _trim(result.get('error'), 200)}
    if check['params'].get('equivalent'):
        step['note'] = 'the check runs in-process; the command shown is the equivalent a person can repeat'
    row.validation_steps = [s for s in (row.validation_steps or [])
                            if (s.get('kind'), s.get('target')) != (check['kind'], check['target'])] + [step]
    if status == 'hit':
        raise_class(row, 'confirmed', f'Validated: {step["summary"]}')
        row.validation_evidence = {**(row.validation_evidence or {}), check['kind']: result.get('evidence') or {}}
        if check['kind'] == 'nuclei_template' and row.match_id:
            _record_template_hit(row, check, result)
    elif status == 'failed':
        row.attempts = (row.attempts or 0) + 1
        row.next_attempt_at = backoff(row.attempts, now)
        if row.attempts >= 3:
            row.attempts = 0
    else:
        if status == 'reaffirmed' and row.classification:
            # a live version still inside the range raises a triaged finding to likely, but never above what the evidence supports: a match that
            # stands on its version string alone stays at the ceiling, because reading the same version a second time is not more evidence
            # (v1.3.1 lifted it to likely and the next triage pass put it back, about twelve minutes later)
            level = 'likely'
            if _version_only(row):
                cap, _why = triage.ceiling('cve_match', {'version_only': True})
                level = cap if cap and triage.rank(cap) < triage.rank(level) else level
            raise_class(row, level, f'Validated: {step["summary"]}')
        if status in ('no_match', 'version_changed', 'reaffirmed'):
            row.confidence_adjust = CLEAN_CONFIDENCE_ADJUST if status != 'reaffirmed' else 0.0
        if status in ('no_match', 'version_changed') and row.hard_evidence:
            row.reason = (f'{row.reason or ""} The {check["label"]} did not reproduce it ({step["summary"]}); the hard evidence '
                          f'({"; ".join(row.hard_evidence)}) stands.').strip()[:700]
    row.validation_status = rollup(row.validation_steps)
    # A successful step cannot clear another step's failure. Keep the retry
    # date while the row is failed, and clear it once the failed step resolves.
    if row.validation_status != 'failed':
        row.attempts, row.next_attempt_at = 0, None
    row.validated_at = now
    if save:
        row.save(update_fields=['validation_steps', 'validation_evidence', 'validation_status', 'validated_at', 'attempts',
                                'next_attempt_at', 'confidence_adjust', 'classification', 'reason', 'status', 'verdict', 'signature', 'evidence_key',
                                'hard_evidence', 'updated_at'])
        if status == 'hit' and row.match_id and check['kind'] != 'nuclei_template':
            # a validation hit is hard evidence: the score and snapshots follow, and a match that was version-only before this hit (read
            # with the row's earlier status) and is fire now is paged once. A template hit rescored in _record_template_hit and is
            # announced by notify.template_hits.
            from cveFeed import match_policy, scoring
            match = row.match
            was_version_only = not hit_before and not match_policy.has_hard_evidence(
                match.source, match.evidence, match.template_result or '', match.distro_status or '')
            scoring.evidence_arrived([row.match_id], confirmed=[row.match_id] if was_version_only else ())
    return row


def _record_template_hit(row, check, result):
    """A template hit on a CVE match: the finding is recorded (Vulnerability, source nuclei-cve), the match's template_result becomes
    vulnerable, its legacy verdict follows, and the row's signature moves to the new evidence so the hit is not tested again."""
    from cveFeed import scoring, templategen
    from cveFeed.models import CVEEntry, CVEMatch
    match = CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=row.match_id)
    if not result.get('recorded') and result.get('outcome'):
        cve = CVEEntry.objects.get(pk=match.cve_entry_id)
        templategen.record_outcomes(cve, [result['outcome']], project=row.project_id,
                                    template_id=os.path.basename(check['params']['template']).rsplit('.', 1)[0])
    CVEMatch.objects.filter(pk=match.pk).update(ai_verdict=triage.verdict_for('confirmed'), ai_reason=row.reason[:2000],
                                                updated_at=timezone.now())
    match.refresh_from_db()
    resync(row)
    scoring.rescore_for_matches([match])


def resync(row):
    """Bring the row's signature up to date with its finding after validation changed the evidence (a template hit), so the next
    triage run asks about what the finding is now and does not reset what validation just found."""
    findings = triage.load_findings([row])
    if not findings:
        return
    d = triage.describe(findings[0])
    # the same signature triage.track compares against: a row under an explicit fresh review carries a nonce in it, and a bare
    # signature here would make the next track() see "changed evidence" and reset the hit validation just recorded
    signature = triage.effective_signature(d, row.review_nonce)
    if signature != row.signature:
        row.signature = signature
        row.evidence_key = triage.evidence_key_for(d['kind'], d['signature_fields'], row.review_nonce)
        row.hard_evidence = triage.hard_evidence(d['kind'], d['facts'])[1]
        if row.status == 'triaged':
            row.status, row.verdict = 'pending', None  # the classification stays; the impact text is asked for the new evidence


def record_template_outcomes(cve, outcomes, project, template_path):
    """Feed the template tests auto-fire runs (templategen.run_cve_tests) into the same record: each tested host's Triage rows for this
    CVE get the outcome as a validation step. ``record_outcomes`` has already written the Vulnerability and template_result.

    Only the rows of the host's CURRENT matches are written (``latest_scan_q``): a superseded match's row is history, and writing its
    ``validated_at`` and ``updated_at`` made it look like the freshest record of the finding to the next rescan's twin lookup (issue 338)."""
    from cveFeed import templategen
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import Triage
    if project is None or not outcomes:
        return 0
    by_host = {templategen._host_key(o['host']): o for o in outcomes}
    done = 0
    rows = (Triage.objects.filter(project_id=project, kind='cve_match', match__cve_entry=cve, host__in=list(by_host))
            .filter(latest_scan_q('match__subdomain__')).select_related('match'))
    for row in rows:
        outcome = by_host.get(row.host)
        if outcome is None:
            continue
        argv = [templategen.NUCLEI_BIN, '-t', template_path, '-u', row.host, '-ni', '-rl', templategen.RATE_LIMIT, '-timeout', '10',
                '-retries', '0', '-duc']
        check = _check('nuclei_template', f'nuclei template for {cve.cve_id}', argv, shlex.join(argv), row.host, row.host, row.signature,
                       templategen.RUN_TIMEOUT, template=template_path, cve_id=cve.cve_id)
        result = _result_from_outcome(outcome)
        result['recorded'] = True
        apply_validation(row, check, result)
        done += 1
    return done


def _result_from_outcome(outcome):
    if outcome.get('error'):
        return {'status': 'failed', 'error': outcome['error'], 'summary': outcome['error'], 'outcome': outcome}
    if outcome.get('vulnerable'):
        hit = outcome.get('hit') or {}
        evidence = {'matched_at': _trim(hit.get('matched-at') or hit.get('host'), 500), 'matcher_name': _trim(hit.get('matcher-name'), 200),
                    'extracted_results': [_trim(e, 200) for e in (hit.get('extracted-results') or [])[:5]],
                    'request': _trim(hit.get('request')), 'response': _trim(hit.get('response'))}
        return {'status': 'hit', 'summary': f'the template matched ({evidence["matcher_name"] or "matcher"})',
                'output_excerpt': _trim(f'matched at {evidence["matched_at"]}', OUTPUT_CAP), 'evidence': evidence, 'outcome': outcome}
    return {'status': 'no_match', 'summary': 'the template did not match', 'outcome': outcome}


# ----------------------------------------------------------------------------- running

def _today():
    return timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)


def next_cap_reset():
    """When the per-day validation caps start counting again (just after the next midnight of the day ran_today counts)."""
    return _today() + timedelta(days=1, minutes=5)


def _legacy_ran_today(project_id=None):
    """One-time upgrade-day seed; freshness records are not a usage ledger."""
    from cveFeed.models import ServiceRun
    qs = ServiceRun.objects.filter(service__startswith='validate:', finished_at__gte=_today())
    return (qs.filter(project_id=project_id) if project_id is not None else qs).count()


def ran_today(project_id=None):
    """Reserved check attempts, unaffected by freshness-ledger resets/upserts."""
    from cveFeed.models import ValidationBudget
    scope = 'global' if project_id is None else f'project:{project_id}'
    budget = ValidationBudget.objects.filter(day=_today().date(), scope=scope).first()
    return budget.reserved if budget else _legacy_ran_today(project_id)


def _reserve_validation_check(project_id):
    """Reserve global/project capacity atomically before each actual check.

    The global validation-day row serializes workers. Failures and worker loss
    consume capacity; no network work runs inside the transaction. An accounting
    database failure propagates before the runner, so reservations fail closed.
    """
    from django.db import transaction
    from cveFeed.models import ValidationBudget
    day = _today().date()
    with transaction.atomic():
        global_budget, _ = ValidationBudget.objects.get_or_create(
            day=day, scope='global', defaults={'reserved': _legacy_ran_today})
        global_budget = ValidationBudget.objects.select_for_update().get(pk=global_budget.pk)
        project_budget, _ = ValidationBudget.objects.get_or_create(
            day=day, scope=f'project:{project_id}', defaults={'reserved': lambda: _legacy_ran_today(project_id)})
        if (global_budget.reserved >= cap('VALIDATE_MAX_PER_DAY')
                or project_budget.reserved >= cap('VALIDATE_MAX_PER_PROJECT_DAY')):
            return False
        global_budget.reserved += 1
        project_budget.reserved += 1
        global_budget.save(update_fields=['reserved'])
        project_budget.save(update_fields=['reserved'])
    return True


def _blocked_step(row, check, why, now):
    return {'kind': check['kind'], 'label': check['label'], 'display': check['display'], 'target': check['target'],
            'ran_at': now.isoformat(), 'result': 'blocked', 'summary': why, 'output_excerpt': '', 'error': ''}


def _adopt(row, check):
    """The step a sibling finding (the same host and evidence, another scan's row) already recorded for this check, when the ledger says
    it ran recently: so a second row does not run the check again nor lose the result."""
    from cveFeed.models import Triage
    for other in Triage.objects.filter(project_id=row.project_id, host=row.host, signature=row.signature).exclude(pk=row.pk):
        for step in other.validation_steps or []:
            if (step.get('kind'), step.get('target')) == (check['kind'], check['target']):
                row.validation_steps = [s for s in (row.validation_steps or []) if (s.get('kind'), s.get('target')) != (
                    check['kind'], check['target'])] + [step]
                row.validation_evidence = {**(row.validation_evidence or {}), **(other.validation_evidence or {})}
                if other.validation_status == 'hit':
                    raise_class(row, 'confirmed', f'Validated: {step.get("summary", "")}')
                row.validation_status, row.validated_at = rollup(row.validation_steps), other.validated_at
                return True
    return False


def run_validation(project_id, triage_ids, scan_id=None, runners=None, template_for=None, selected_kinds=None):
    """Plan and run the checks for ``triage_ids`` (rows of ``project_id`` only: a row of another project is never touched), within the
    per-run, per-project and per-day caps and the ledger TTL, honouring the stop flag of ``scan_id``. Returns the counts. Never raises
    for one check's trouble: a failure is recorded on its row and retried later.

    ``runners`` replaces the default check runners (tests); ``template_for(cve_id)`` replaces ``resolve_template``."""
    from cveFeed import ledger, notify
    from cveFeed.models import Triage
    from reNgine import resources
    from startScan.models import Subdomain
    from targetApp.target_types import scannable_hosts
    runners = {**RUNNERS, **(runners or {})}
    template_for = template_for or resolve_template
    if selected_kinds is not None and not set(selected_kinds).issubset(CHECK_KINDS):
        raise ValueError('unknown validation check kind')
    stats = {'rows': 0, 'ran': 0, 'reused': 0, 'blocked': 0, 'no_check': 0, 'failed': 0, 'hits': 0, 'capped': 0, 'stopped': False}
    now = timezone.now()
    rows = list(Triage.objects.filter(pk__in=list(triage_ids), project_id=project_id, kind__in=PLANNED_KINDS))
    rows.sort(key=lambda r: (-len(r.hard_evidence or []), r.pk))
    stats['rows'] = len(rows)
    state = {'run': 0}
    hits = []
    with resources.scan_context(scan_id):
        for row in rows:
            if scan_id is not None and resources.abort_requested(scan_id):
                stats['stopped'] = True
                break
            if row.next_attempt_at and row.next_attempt_at > now:
                continue
            findings = triage.load_findings([row])
            if not findings:
                continue
            finding = findings[0]
            if triage.effective_signature(triage.describe(finding), row.review_nonce) != row.signature:
                continue  # the evidence moved since: triage resets the row and validation follows the new signature
            subject = subject_for(row, finding)
            if not Subdomain.objects.filter(name=row.host, target_domain__project_id=project_id).exists():
                row.validation_status, row.validation_steps = 'skipped_blocked', [{
                    'kind': 'scope', 'label': 'scope check', 'display': '', 'target': row.host, 'ran_at': now.isoformat(),
                    'result': 'blocked', 'summary': 'the host is not part of this project, so nothing was run', 'output_excerpt': '', 'error': ''}]
                row.save(update_fields=['validation_status', 'validation_steps', 'updated_at'])
                stats['blocked'] += 1
                continue
            template = template_for(subject['cve_id']) if row.kind == 'cve_match' else ('', '')
            checks, notes = plan_checks(subject, row.signature, template)
            checks = [c for c in checks if c]
            if selected_kinds is not None:
                checks = [c for c in checks if c['kind'] in selected_kinds]
            if not checks:
                row.validation_status = 'no_check'
                row.validation_steps = [{'kind': 'none', 'label': n, 'display': '', 'target': row.host, 'ran_at': now.isoformat(),
                                         'result': 'blocked', 'summary': n, 'output_excerpt': '', 'error': ''} for n in notes[:1]] \
                    if notes else []
                row.save(update_fields=['validation_status', 'validation_steps', 'updated_at'])
                stats['no_check'] += 1
                try:
                    triage.suggest_local_checks(row)
                except Exception:  # noqa: BLE001 - a suggestion is advisory; it must never break the validation sweep
                    logger.exception('local-check suggestion failed for %s', row.pk)
                continue
            # A failed step of a check the plan no longer holds (a template removed, a port gone) is never run again to replace it, so it would
            # keep the row failed, and due for a retry every day, for ever.
            planned = {(c['kind'], c['target']) for c in checks}
            row.validation_steps = [s for s in (row.validation_steps or [])
                                    if s.get('result') != 'failed' or (s.get('kind'), s.get('target')) in planned]
            for check in checks:
                # a stopped scan or a global pause ends the run before its next check (a check already running under heavy_job is
                # stopped by its watchdog)
                if (scan_id is not None and resources.abort_requested(scan_id)) or resources.global_pause_requested(fail_closed=True):
                    stats['stopped'] = True
                    break
                wanted = list(dict.fromkeys([row.host, check['target']]))
                if len(scannable_hosts(wanted, project=project_id)) != len(wanted):
                    apply_blocked = _blocked_step(row, check, 'the host resolves to an address that must not be scanned, so nothing was run', now)
                    row.validation_steps = [s for s in (row.validation_steps or []) if (s.get('kind'), s.get('target')) != (
                        check['kind'], check['target'])] + [apply_blocked]
                    row.validation_status, row.validated_at = rollup(row.validation_steps), now
                    row.save(update_fields=['validation_steps', 'validation_status', 'validated_at', 'updated_at'])
                    stats['blocked'] += 1
                    continue
                if ledger.fresh(check['service'], [check['asset']], project_id):
                    was_hit = row.validation_status == 'hit'
                    if _adopt(row, check) or any((s.get('kind'), s.get('target')) == (check['kind'], check['target'])
                                                 for s in row.validation_steps or []):
                        row.save(update_fields=['validation_steps', 'validation_evidence', 'validation_status', 'validated_at',
                                                'classification', 'reason', 'updated_at'])
                        if row.validation_status == 'hit' and not was_hit and row.match_id:
                            # a sibling's hit adopted: the heat is read live, the stored score and the snapshots follow here. Not paged:
                            # the sibling's hit was announced when it was found (a template hit by notify.template_hits)
                            from cveFeed import scoring
                            scoring.evidence_arrived([row.match_id])
                        stats['reused'] += 1
                        continue
                if state['run'] >= cap('VALIDATE_MAX_PER_RUN') or not _reserve_validation_check(project_id):
                    stats['capped'] += 1
                    if row.validation_status in ('none', 'no_check'):
                        row.validation_status = 'pending'
                        row.save(update_fields=['validation_status', 'updated_at'])
                    continue
                try:
                    result = interpret(subject, check, runners[check['kind']](check))
                except resources.ScanAborted:
                    stats['stopped'] = True
                    break
                except subprocess.TimeoutExpired:
                    result = {'status': 'failed', 'error': 'the check timed out', 'summary': 'timed out'}
                except Exception as exc:  # noqa: BLE001 - one check failing must not stop the others; it is "failed", never "clean"
                    logger.exception('validation check %s failed for %s', check['kind'], row.host)
                    from cveFeed import activity
                    result = {'status': 'failed', 'summary': 'the check failed to run',
                              'error': activity.diagnostic(f'The {check["label"]}', f'{type(exc).__name__}: {exc}', type(exc).__name__)[:200]}
                state['run'] += 1
                ledger.record(check['service'], [check['asset']], project_id, scan_id, 'failed' if result['status'] == 'failed' else 'done')
                apply_validation(row, check, result)
                stats['ran'] += 1
                if result['status'] == 'failed':
                    stats['failed'] += 1
                if result['status'] == 'hit':
                    stats['hits'] += 1
                    if check['kind'] == 'nuclei_template':
                        hits.append((subject['cve_id'], row.host))
            if stats['stopped']:
                break
    if hits:
        notify.template_hits(hits)  # one message per run, however many hosts
    return stats


def due_ids(project_id, limit=None):
    """Ids of the project's rows whose validation is due, oldest first: never checked, queued over a cap, failed with the retry time
    reached, and anything last checked (or found to have no check) longer ago than the ledger TTL, so a template installed since,
    or a check that can run now, is picked up and a finding is re-validated daily."""
    from django.db.models import Q

    from cveFeed.models import Triage
    from cveFeed.correlation import latest_scan_q
    now = timezone.now()
    stale = now - timedelta(seconds=ledger_ttl())
    due = (Q(validation_status__in=('none', 'pending'))
           | Q(validation_status='failed', next_attempt_at__lte=now)
           | Q(validation_status='failed', next_attempt_at__isnull=True)
           | Q(validation_status__in=('hit', 'clean', 'observed'), validated_at__lt=stale)
           | Q(validation_status__in=('no_check', 'skipped_blocked'), updated_at__lt=stale))
    qs = Triage.objects.filter(project_id=project_id, kind__in=PLANNED_KINDS).filter(
        ~Q(kind='cve_match') | (Q(match__isnull=False) & latest_scan_q('match__subdomain__'))).filter(due).filter(
        Q(next_attempt_at__isnull=True) | Q(next_attempt_at__lte=now))
    return list(qs.order_by('validated_at', 'id').values_list('id', flat=True)[:limit or cap('VALIDATE_MAX_PER_RUN') * 4])


def ledger_ttl():
    from cveFeed import ledger
    return ledger.ttl('validate:x')


def dispatch(rows, scan_id=None):
    """Queue validation, one Celery task per project with only that project's rows (never a cross-project list). Rows of a kind with no
    validated check, and rows already validated for their current evidence, are left out. Returns the number of tasks queued."""
    from cveFeed.tasks import validate_findings
    by_project = {}
    for row in rows:
        if row.kind in PLANNED_KINDS and row.validation_status in ('none', 'pending', 'failed'):
            by_project.setdefault(row.project_id, []).append(row.pk)
    queued = 0
    for project_id, ids in sorted(by_project.items()):
        for start in range(0, len(ids), 200):
            validate_findings.delay(project_id, ids[start:start + 200], scan_id)
            queued += 1
    return queued
