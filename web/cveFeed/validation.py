"""Automatic validation of findings: after triage, CVEngine tries to reproduce a finding itself with a small fixed set of read-only
checks and records exactly what it ran and what came back.

The owner of every target has authorised this, and it stays inside these limits. There is no free-form command: only six kinds of
check exist.

* ``nuclei_template``: an installed template for the CVE, or a generated template that is status valid, still passes the safety gate and
  lives in the generated-templates directory. Either must be read-only by its own text (methods GET, HEAD or OPTIONS, no payloads,
  attack, fuzzing or body, no code, file or out-of-band protocols); anything else is refused ("template not validated").
* ``nmap_sv``: ``nmap -sV`` against the single port the finding names.
* ``http_head``: one HEAD (a GET only when the server answers 405 to HEAD), read by a Sentinel (``page_read``, op ``head``): no cookies, no
  credentials, no redirects, the body never kept.
* ``db_probe``: the existing single credential-less database exposure check.
* ``fact_probe``: a version or identity probe from the catalogue in ``cveFeed.probes`` (a few GETs with the front page's headers, an
  error page signature, a framework script, or a service-version scan of one port), run by a Sentinel (``http_probe``, ``nmap_verify``). It finds the fact an advisory depends on (the
  version, which look-alike product runs, what answers behind a CDN) and records it; it never exploits anything.
* ``script_read``: for a match on a client-side JavaScript library (``cveFeed.detection.client_libraries``), the html-libraries read of every
  web base's front page again, by a Sentinel (``page_read``, op ``libraries``: the pages, then their scripts through ``js_libraries``' vetter and budgets),
  which states the version from the file itself and which copy runs. nmap and a HEAD cannot see a library inside a page, so for such a
  match this replaces them. A version still inside the range is ``reaffirmed`` (never a hit: a version is not an exploitable page), and
  reopens a match an earlier script read closed. Only what is truly false closes the match, through the guarded closure
  (``correlation.close_invalid_correlation``, this host only), never one a person worked: every root permanently redirecting to another
  host, or, for a match made from a file's own body, a fixed running copy where that file and every script that could hold the library
  were read whole in this read and searched end to end, with no loader or module import (``library_outcome``). An absence (the library or its script gone from the page) is left to the next scan. A host the
  server may not read (internal, passive, manual only, a one-host target, the bug bounty gate, script reading off) is left as it is, and
  says why.

Everything is read-only; every host goes through the scannable-host filter and must belong to the finding's project; work is
dispatched per project; no check sends anything to a target from this server (the template, service, banner, database, probe and page checks are
all a Sentinel's, and with no scanner able to take one the check is ``failed``: retried later, never read as clean); each check is kept off the ledger while fresh (CVENGINE_TTL_VALIDATE),
and counts against per-run, per-project and per-day caps. The stop flag is honoured, every check is non-fatal, and an error or a
timeout is "failed" and retried later, never "clean".

What a result does to the classification is deterministic (``apply_validation``): a hit confirms; a check that did not reproduce
the finding never lowers it, and in particular never takes a finding with hard evidence below its floor, because a template can miss
(a WAF, a virtual host, a different path); a failure changes nothing and schedules a retry.
"""
import ipaddress
import json
import hashlib
import logging
import os
import re
import shlex
from datetime import timedelta
from urllib.parse import urljoin, urlparse

import yaml
from django.utils import timezone

from cveFeed import triage
from cveFeed.safeyaml import load_template

logger = logging.getLogger(__name__)

CHECK_KINDS = ('nuclei_template', 'nmap_sv', 'http_head', 'db_probe', 'fact_probe', 'script_read')
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
    'elastic': 'curl -gs --max-time 3 http://{ip}:{port}/',
    'couchdb': 'curl -gs --max-time 3 http://{ip}:{port}/_all_dbs',
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


def _template_check(path, host, cve_id, signature, **params):
    """The ``nuclei_template`` check of one CVE's template against one host: it runs on the built-in scanner (``templategen.run_template``), so it has no
    argv; ``display`` names the template file and the host, for a person reading the step."""
    from cveFeed import templategen
    display = f'template check {os.path.basename(path)} against {host}'
    return _check('nuclei_template', f'template check for {cve_id}', [], display, host, host, signature, templategen.RUN_TIMEOUT,
                  template=path, cve_id=cve_id, **params)


def _sv_argv(ip, port):
    """The service detection command line of an ``nmap_sv`` check, for a person to repeat (a scanner runs it, never this server)."""
    return ['nmap', '-sV', '--version-intensity', '5', '-Pn', '-p', str(port), '--host-timeout', '60s', '-oX', '-', ip]


def plan_checks(subject, signature, template=('', '')):
    """``(checks, notes)`` for one finding. ``subject`` is a plain dict (see ``subject_for``), ``template`` the ``(path, reason)`` of
    ``resolve_template`` for a CVE match. A check is ``{kind, label, argv, display, target, asset, service, timeout, params}``: ``argv``
    is what runs (never through a shell) and ``display`` the command a person can repeat. ``notes`` says why a check that could have
    applied was not planned (a template that is not read-only, for instance). Pure: no database, no network."""
    checks, notes = [], []
    host, kind = subject.get('host') or '', subject['kind']
    if kind == 'cve_match':
        path, why = template
        if path and _safe_host(host):
            checks.append(_template_check(path, host, subject['cve_id'], signature, project_id=subject.get('project_id')))
        elif why and why != 'no template covers this CVE':
            notes.append(why)
        if subject.get('local_component_only'):
            notes.append('This advisory requires local kernel, driver or hardware evidence; external service banners cannot validate it.')
        elif subject.get('library'):
            # a client-side library lives in a page's script files: nmap and a HEAD can never read it, the script read can
            check = _script_read_check(subject, signature)
            if check:
                checks.append(check)
            else:
                notes.append(f'This is a {subject.get("library_product") or "JavaScript library"} match, and the host has no web page to read '
                             'its scripts from.')
        else:
            candidates = []
            if subject.get('source') == 'port':
                candidates.append((subject.get('ip'), subject.get('port')))
            candidates += [(item.get('ip'), item.get('port')) for item in (subject.get('candidate_services') or [])[:4]
                           if isinstance(item, dict)]
            for ip, port in list(dict.fromkeys(candidates))[:4]:
                if not _safe_ip(ip) or not isinstance(port, int) or not 0 < port < 65536:
                    continue
                argv = _sv_argv(ip, port)
                checks.append(_check('nmap_sv', f'nmap service detection on observed port {port}', argv, shlex.join(argv),
                                     f'{ip}:{port}', f'{ip}:{port}', signature, NMAP_TIMEOUT, ip=ip, port=port, project_id=subject.get('project_id')))
            if subject.get('source') == 'tech' and subject.get('url'):
                checks.append(_http_check(subject['url'], signature, subject.get('unattended', True)))
            checks += _probe_checks(subject, signature)
    elif kind == 'db_exposure':
        ip, port, label = subject.get('ip'), subject.get('port'), (subject.get('db') or '').lower()
        if ip and _safe_ip(ip) and isinstance(port, int) and 0 < port < 65536:
            if label in DB_EQUIVALENT:
                display = DB_EQUIVALENT[label].format(ip=ip, port=port)
                checks.append(_check('db_probe', f'unauthenticated {label} check', [], display, f'{ip}:{port}', f'{ip}:{port}', signature,
                                     30, ip=ip, port=port, db=label, equivalent=True))
            argv = _sv_argv(ip, port)
            checks.append(_check('nmap_sv', f'nmap service detection on port {port}', argv, shlex.join(argv), f'{ip}:{port}', f'{ip}:{port}',
                                 signature, NMAP_TIMEOUT, ip=ip, port=port, project_id=subject.get('project_id')))
    elif kind == 'route_auth' and subject.get('url'):
        checks.append(_http_check(subject['url'], signature, subject.get('unattended', True)))
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
                             project_id=subject.get('project_id'), domain_id=subject.get('domain_id'), host=subject.get('host'), product=subject.get('product') or '',
                             unattended=subject.get('unattended', True)))
    return checks


def _script_read_check(subject, signature):
    """The ``script_read`` check of a client-library match: every web base's front page and the scripts it loads, read again by cvENGINE."""
    from cveFeed import js_libraries, probes
    bases = []
    for base in subject.get('bases') or ([subject['url']] if subject.get('url') else []):
        parsed = urlparse(base or '')
        if parsed.scheme in ('http', 'https') and _safe_host(parsed.hostname or ''):
            bases.append(f'{parsed.scheme}://{parsed.netloc}')
    bases = list(dict.fromkeys(bases))
    if not bases:
        return None
    product = subject.get('library_product') or 'JavaScript library'
    where = f'{bases[0]}/#script-read'
    display = ('; '.join(probes.display_for('html-libraries', {'base': base}) for base in bases) +
               f' (then up to {js_libraries.MAX_SCRIPTS_PER_HOST} of the scripts they load, each read for its own version banner)')
    return _check('script_read', f'Script read: the {product} version stated by the script files the page loads', ['probe', 'html-libraries', *bases],
                  display, where, where, signature + 'script-read', 120, bases=bases, project_id=subject.get('project_id'),
                  domain_id=subject.get('domain_id'), host=subject.get('host'), library=subject['library'], product=product,
                  ranges=subject.get('library_ranges') or [], matched_version=subject.get('matched_version') or '',
                  version_source=subject.get('version_source') or '', script_url=subject.get('script_url') or '',
                  seen_urls=subject.get('seen_urls') or [], unattended=subject.get('unattended', True))


def _http_check(url, signature, unattended=True):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not _safe_host(parsed.hostname or ''):
        return None
    argv = ['curl', '-g', '-I', '-k', '--max-time', '6', url]  # the equivalent a person can repeat (-g: brackets and braces in a URL are not curl ranges); the check itself is a Sentinel's page_read
    return _check('http_head', 'HTTP banner check (HEAD, GET only if HEAD is refused)', argv, shlex.join(argv), url, url, signature, 15, url=url, unattended=bool(unattended))


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


def subject_for(row, finding, unattended=True):
    """The plain dict ``plan_checks`` reads, from a Triage row and its finding: host, CVE id, source, address and port, URL. ``unattended`` is
    False for a person's own request (Validate now): the bug bounty gate then holds the run to the program's scope only."""
    from cveFeed import route_auth
    subject = {'kind': row.kind, 'host': row.host, 'unattended': bool(unattended)}
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
        library = library_of(finding)
        if library:
            from cveFeed import detection
            # every file the host was seen to load the library from (the match's own script and the copies its evidence names): a fixed
            # version closes the match only when each of them is read again, whole
            seen = [str(c.get('url'))[:500] for c in (ev.get('copies') or []) if isinstance(c, dict) and c.get('url')]
            subject.update(library=library, library_product=detection._libraries()[library][0],
                           library_ranges=detection.cve_libraries(finding.cve_entry)[library][:10],
                           version_source=str(ev.get('version_source') or ''), script_url=str(ev.get('script_url') or '')[:500],
                           seen_urls=list(dict.fromkeys(u for u in [str(ev.get('script_url') or '')[:500], *seen] if u.startswith('http')))[:8],
                           bases=route_auth.web_bases(finding.subdomain) if finding.subdomain is not None else [])
        elif finding.subdomain is not None and not subject['local_component_only']:
            subject['probe_plan'] = _probe_plan(finding, ev)
    elif row.kind == 'db_exposure':
        parsed = urlparse(finding.http_url or '')
        subject.update(ip=parsed.hostname, port=parsed.port, db=(finding.template_id or '').replace('db-exposure-', '', 1))
    elif row.kind == 'route_auth':
        subject['url'] = finding.url
    return subject


def library_of(match):
    """The ``js_libraries.LIBRARIES`` key of a CVE match made on a client-side JavaScript library from a page (a technology the host's pages
    load, whose advisory names that library: ``detection.client_libraries``), or ''."""
    from cveFeed import detection
    if getattr(match, 'source', '') != 'tech':
        return ''
    key = detection.library_key(match.matched_product)
    return key if key and key in detection.cve_libraries(match.cve_entry) else ''


# ----------------------------------------------------------------------------- the runners (injectable)

def _trim(value, limit=EVIDENCE_CAP):
    return str(value if value is not None else '')[:limit]


def run_nuclei_template(check):
    """Run the planned template against the one host, on the built-in scanner (see ``templategen.run_template``)."""
    from cveFeed import templategen
    outcome = templategen._test_chunk(check['params']['template'], [check['target']], project=check['params'].get('project_id'))[0]
    if outcome.get('vulnerable') and not outcome.get('error'):
        outcome = {**outcome, 'template_evidence': templategen.evidence_of_template(check['params']['template'])}
    return _result_from_outcome(outcome)


def run_nmap_sv(check):
    """Service detection on the one port the finding names, run by a scanner (an ``nmap_verify`` task at intensity 5). With no scanner able to take it
    the check ``failed`` (retried later, never read as clean): it never runs here."""
    from agentapi import sentinel_dispatch
    from reNgine.resources import ScannerUnavailable
    params = check['params']
    port = params['port']
    try:
        target = sentinel_dispatch.nmap_verify_target(params['ip'], [port], intensity=5, host_timeout=60)
        hosts = sentinel_dispatch.try_nmap_verify(sentinel_dispatch._project_of(params.get('project_id')), target)
    except ScannerUnavailable as exc:
        return {'status': 'failed', 'error': str(exc), 'summary': f'not run: no scanner could take this work ({exc.kind})'}
    port = check['params']['port']
    record = next((p for host in hosts for p in host['ports'] if p['number'] == port), None)
    if record is None or record['state'] != 'open':
        return {'status': 'no_match', 'summary': f'port {port} was not open at the time of the check',
                'output_excerpt': f'port {port} not open'}
    observed = {'product': record['product'], 'version': record['version']}
    text = ' '.join(x for x in (record['product'], record['version'], record['service_extra']) if x)
    return {'status': 'observed', 'summary': f'nmap reports {text or record["service_name"] or "an unidentified service"}'
                                            f' (method {record["method"] or "unknown"})',
            'output_excerpt': _trim(f'{record["service_name"]} {text} {record["cpe"]} method={record["method"]}', OUTPUT_CAP),
            'observed': observed}


def _current_host(params):
    """The host's row in the current inventory of the project, or None (a read is made only for a host that is still there)."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    return (Subdomain.objects.filter(target_domain__project_id=params['project_id'], name=params['host']).filter(latest_scan_q())
            .prefetch_related('technologies', 'ip_addresses__ports', 'waf').select_related('target_domain').order_by('-id').first())


def _no_scanner(exc):
    """The result of a check no scanner could take: ``failed`` (retried later, never read as clean). Nothing was sent."""
    return {'status': 'failed', 'error': str(exc), 'summary': f'not run: no scanner could take this work ({getattr(exc, "kind", "")})'}


def run_http_head(check):
    """HEAD the URL; GET only when the server answers 405. Keeps the status, Server, X-Powered-By and title, never the body. Made by a Sentinel
    (``page_read``, op ``head``), under the scope policy of the host: this server sends nothing. ``failed`` when no scanner could take it."""
    from agentapi import probe_dispatch
    from cveFeed import probe_scope
    from dashboard.models import Project
    from reNgine.resources import ScannerUnavailable
    params = check['params']
    url = params['url']
    host = (urlparse(url).hostname or '').lower().rstrip('.')
    params.setdefault('host', host)
    sub = _current_host({**params, 'host': host})
    if sub is None:
        return {'status': 'failed', 'error': 'the host is no longer in the current inventory', 'summary': 'host not found'}
    project = Project.objects.get(pk=params['project_id'])
    read = {'id': f'head:{url}'[:200], 'op': 'head', 'host': host, 'url': url}
    try:
        row = probe_dispatch.try_page_read(project, read, probe_scope.for_page_read(project.pk, sub, unattended=params.get('unattended', True)))
    except ScannerUnavailable as exc:
        return _no_scanner(exc)
    except RuntimeError as exc:
        return {'status': 'failed', 'error': str(exc)[:200], 'summary': 'the scanner could not make the request'}
    probe, used = row['head'], row['head']['method']
    server = probe.get('server') or ''
    found = SERVER_RE.match(server)
    summary = f'{used} answered {probe.get("status")}' + (f', Server: {server}' if server else '')
    return {'status': 'observed', 'summary': _trim(summary, 300), 'output_excerpt': _trim(summary + (
        f', X-Powered-By: {probe["powered_by"]}' if probe.get('powered_by') else '') + (
        f', title: {probe["title"]}' if probe.get('title') else ''), OUTPUT_CAP),
        'http': {'status': probe.get('status'), 'method': used},
        'observed': {'product': found.group(1) if found else '', 'version': found.group(2) if found else ''}}


def run_fact_probe(check):
    """Run one catalogued probe (cveFeed.probes) on a Sentinel (an http probe is an ``http_probe`` task, a port probe an ``nmap_verify`` one), store what
    it found as host facts and say it in one line. A probe that reads a version gives ``observed`` with that version (``interpret`` then tests it against
    the finding's range); one that finds the product states none, or only an edge, still answers: the version is hidden from outside, which is a result,
    not a failure. With no scanner able to take it the check is ``failed``: it never runs here, and is never read as clean."""
    from agentapi import probe_dispatch
    from cveFeed import probes
    from dashboard.models import Project
    from reNgine.resources import ScannerUnavailable
    params = check['params']
    sub = _current_host(params)
    if sub is None:
        return {'status': 'failed', 'error': 'the host is no longer in the current inventory', 'summary': 'host not found'}
    entry = {'probe': params['probe'], 'target': params['probe_target']}
    try:
        if probes.BY_ID[entry['probe']]['family'] == 'nmap':
            found = probes.run_one(params['project_id'], params['domain_id'], sub, entry, fresh=True)  # a service-version scan: the nmap_verify kind, never here
        else:
            project = Project.objects.get(pk=params['project_id'])
            asset = probes.asset_key(sub.name, entry)
            answered = probe_dispatch.try_http_probes(project, None, [(sub, asset, entry)], unattended=params.get('unattended', True))
            found = answered.get(asset)  # try_http_probes raises ScannerUnavailable when no Sentinel took it or its task ended with no result: nothing ran
            if found is None:
                raise ScannerUnavailable('http_probe', 'no scanner returned a result for this probe')
            if isinstance(found, Exception):
                return {'status': 'failed', 'error': str(found)[:200], 'summary': 'the scanner could not run the probe'}
            found = probes.apply_remote(params['project_id'], params['domain_id'], sub, entry, found)
    except ScannerUnavailable as exc:
        return _no_scanner(exc)
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
    """The one credential-less attempt, made by a Sentinel (``db_probe``): this server opens no connection. ``failed`` (never ``no_match``) when no
    scanner answered or the scanner has no client for this database."""
    from agentapi import sentinel_dispatch
    from cveFeed import db_exposure
    from dashboard.models import Project
    params = check['params']
    label, _fn = db_exposure.CHECKS[params['db']]
    project = Project.objects.get(pk=params['project_id'])
    result = sentinel_dispatch.dispatch_or_none(project, 'db_probe', {'address': params['ip'], 'port': params['port'], 'db': db_exposure.DB_KEYS[label]},
                                                host=f'{label} on {params["ip"]}:{params["port"]}', ips=[params['ip']])  # ScannerUnavailable: no scanner can take it
    if result is None or result.get('open') is None:
        return {'status': 'failed', 'error': 'no scanner could run this check', 'summary': 'not run'}
    reply = str(result.get('evidence') or '')
    if result.get('open') is True:
        return {'status': 'hit', 'summary': 'the service answered with no credentials' + (f': {reply}' if reply else ''),
                'output_excerpt': _trim(reply, OUTPUT_CAP), 'evidence': {'reply': _trim(reply, 300)}}
    return {'status': 'no_match', 'summary': 'the service did not answer without credentials at the time of the check'}


def script_read_held_back(project_id, sub, unattended=True):
    """Why the server may not read ``sub``'s pages for a script read, or '': script reading is off, the target is passive or manual only, the
    host is held only under a target set to exactly one other host, it is internal (only a Sentinel inside its network may read it: the server
    never fetches an internal page), its address must not be scanned, the bug bounty gate refuses it (``unattended``: a run the system started
    in a bug bounty project that has not confirmed automated testing; any run: a host outside the program's scope), or the organization
    excluded or archived it."""
    from cveFeed import js_libraries, route_auth
    from cveFeed.archive_rediscovery import archived_names
    from cveFeed.bounty_gate import Gate
    from cveFeed.exclusions import is_excluded
    from targetApp.models import narrowed_names
    from targetApp.target_types import sentinel_only_target
    target, host = getattr(sub, 'target_domain', None), sub.name.lower().rstrip('.')
    if not js_libraries.enabled():
        return 'script reading is turned off (CVENGINE_SCRIPT_BODY_READ=0)'
    held = js_libraries._held_back(target) if target is not None else ''
    if held:
        return f'the target is a {held}: cvENGINE does not read its pages'
    if narrowed_names(project_id, [host]):
        return 'its target is set to one host only: a name under it is not read (host_only_scope)'
    if (target is not None and sentinel_only_target(target.name, project_id)) or sentinel_only_target(host, project_id):
        return ('an internal host: only a Sentinel inside its network may read its pages, and this server never fetches an internal page '
                '(a Sentinel script read is planned for 1.4)')
    if not route_auth.host_allowed(host, project_id):
        return 'the host resolves to an address that must not be scanned'
    bounty = Gate().refusal(project_id, host, unattended=unattended)
    if bounty:
        return f'the bug bounty gate refuses it ({bounty})'
    if is_excluded(project_id, host) or host in archived_names(project_id):
        return 'the organization excluded or archived this host'
    return ''


READ_REUSE_SECONDS = 600  # one fresh read of a host serves every library match of it validated within this window


def _reading_key(project_id, host, bases, library='', seen_urls=()):
    import hashlib
    return 'cvengine:script-read:v2:' + hashlib.sha256(json.dumps([project_id, host, sorted(bases), library, sorted(seen_urls)]).encode()).hexdigest()[:32]


def _current_roots(project_id, host):
    """``[(url, status, location)]`` of the host's current root routes (the route check's, http and https), as HostLibraries reads them."""
    from cveFeed.models import RouteAuth
    return [(row.url, row.http_status, row.redirect_to or '') for row in RouteAuth.objects.filter(
        project_id=project_id, host=host, path='/', retired_at__isnull=True).only('url', 'http_status', 'redirect_to')]


def run_script_read(check):
    """Read every web base's front page and the scripts it loads again, on a Sentinel (``page_read``, op ``libraries``), past every cache, and say what
    that means for the match (``library_outcome``). Nothing is fetched for a host ``script_read_held_back`` refuses, and nothing is ever fetched by this
    server: with no scanner able to take the read the check is ``failed`` (retried later, never read as clean). One read of a host is reused by every
    match of the same library on it for READ_REUSE_SECONDS, so a host with several jQuery CVEs is read once; a person's own request (``unattended`` False:
    Validate now) always reads again. The files the host was seen to load the library from (``seen_urls``: the match's own script, the copies its evidence
    names) that the pages did not load are fetched by the Sentinel too, within what is left of the same script budget, so a fixed version can be weighed
    against them."""
    from django.core.cache import cache
    from agentapi import probe_dispatch
    from cveFeed import probe_scope
    from dashboard.models import Project
    from reNgine.resources import ScannerUnavailable
    params = check['params']
    unattended = params.get('unattended', True)
    sub = _current_host(params)
    if sub is None:
        return {'status': 'failed', 'error': 'the host is no longer in the current inventory', 'summary': 'host not found'}
    held = script_read_held_back(params['project_id'], sub, unattended=unattended)
    if held:
        return {'status': 'blocked', 'summary': f'not read: {held}', 'library': {'held_back': held}}
    bases = params.get('bases') or [params['base']]
    seen_urls = [u for u in params.get('seen_urls') or [] if isinstance(u, str)][:20]
    key = _reading_key(params['project_id'], sub.name.lower(), bases, params['library'], seen_urls)
    reading = None
    if unattended:
        try:
            reading = cache.get(key)
        except Exception:  # noqa: BLE001 - no cache: read again
            reading = None
    reused = reading is not None
    if not reused:
        project = Project.objects.get(pk=params['project_id'])
        host = sub.name.lower().rstrip('.')
        read = {'id': f'libraries:{host}'[:200], 'op': 'libraries', 'host': host, 'bases': [b for b in bases if isinstance(b, str)][:6],
                'library': params['library'], 'seen_urls': seen_urls}
        try:
            reading = probe_dispatch.try_page_read(project, read, probe_scope.for_page_read(project.pk, sub, unattended=unattended))['reading']
        except ScannerUnavailable as exc:
            return _no_scanner(exc)
        except RuntimeError as exc:
            return {'status': 'failed', 'error': str(exc)[:200], 'summary': 'the scanner could not read the page'}
        try:
            cache.set(key, reading, READ_REUSE_SECONDS)
        except Exception:  # noqa: BLE001
            pass
    reading = {**reading, 'extra': dict(reading.get('extra') or {})}
    reading = {**reading, 'roots': _current_roots(params['project_id'], sub.name.lower()), 'reused': reused}
    reading['inventoried_hosts'] = _inventoried(params['project_id'], reading)
    return library_outcome(params, reading)


def _inventoried(project_id, reading):
    """The hosts the read's front pages redirect to that are hosts of this project's current inventory: only a redirect to one of them makes a
    redirect alias (the project's own host, judged on its own; a redirect to anywhere else proves nothing about this host's scripts)."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    targets = {(urlparse(p.get('location') or '').hostname or '').lower().rstrip('.') for p in reading.get('pages') or []
               if p.get('outcome') == 'redirect'} - {''}
    if not targets:
        return []
    return sorted(set(Subdomain.objects.filter(target_domain__project_id=project_id, name__in=sorted(targets)).filter(latest_scan_q())
                      .values_list('name', flat=True)))


def _in_ranges(version, entries):
    """True / False / None (unknown) for ``version`` against the advisory's entries for the library (each a feed range list)."""
    from cveFeed.correlation import parse_version, range_verdict
    ver = parse_version(version)
    if not ver or not entries:
        return None
    results = [range_verdict(ver, ranges)[0] for ranges in entries]
    if any(r is True for r in results):
        return True
    return False if all(r is False for r in results) else None


def _library_records(reading, key):
    """``[(page, record)]``: the record of library ``key`` on every page that was read."""
    return [(page, (page.get('records') or {}).get(key)) for page in reading.get('pages') or []
            if page.get('outcome') == 'read' and (page.get('records') or {}).get(key)]


def _library_evidence(reading, records):
    """The fresh evidence a script read records on its step: what each web base answered and, for the library, the version, where it came
    from, how far it is trusted and every copy with its state."""
    out = {'pages': [{k: page.get(k) for k in ('base', 'outcome', 'status', 'location', 'challenge') if page.get(k) not in (None, '')}
                     for page in reading.get('pages') or []][:6]}
    if reading.get('reused'):
        out['reused'] = True  # the read another match of this host made moments ago
    if records:
        page, record = records[0]
        out.update({'version': record.get('version') or '', 'version_source': record.get('version_source') or '',
                    'version_confidence': record.get('version_confidence') or 0.0, 'script_url': (record.get('script_url') or '')[:300],
                    'copies_unresolved': any(r.get('copies_unresolved') for _p, r in records)})
        out['copies'] = [{'base': p.get('base'), **{k: c.get(k) for k in ('url', 'version', 'source', 'state', 'truncated') if c.get(k) not in (None, '')}}
                         for p, r in records for c in r.get('copies') or [] if isinstance(c, dict)][:8]
    skipped = [(url, why) for page in reading.get('pages') or [] for url, why in page.get('skipped') or []]
    if skipped:
        out['not_read'] = [{'url': url[:300], 'why': why} for url, why in skipped[:8]]
    return out


def _alias_of(params, reading):
    """The host every current root of this host permanently redirects to (301 or 308 to another host, on every web base read now and every
    current root route), or ''. A temporary redirect (302, 307: a login page, a maintenance page) is never an alias."""
    from cveFeed.js_libraries import redirect_alias_of
    host = str(params.get('host') or '').lower().rstrip('.')
    pages = reading.get('pages') or []
    if not pages or any(p.get('outcome') != 'redirect' for p in pages):
        return ''
    roots = [(p.get('final_url') or p.get('base'), p.get('status'), p.get('location') or '') for p in pages]
    roots += [tuple(r) for r in reading.get('roots') or []]
    for url, status, location in roots:
        if status not in (301, 308):
            return ''
        target = (urlparse(urljoin(url or '', location or '')).hostname or '').lower().rstrip('.')
        if not target or target == host:
            return ''
    return redirect_alias_of(roots, host, [p.get('base') for p in pages if p.get('base')] or None)


def _scan_of(reading, url):
    """What a whole read of ``url`` found in this script read (the Sentinel's ``page_read._scanned``), or None when it was not fetched."""
    return (reading.get('scanned') or {}).get(url) or (reading.get('extra') or {}).get(url)


def _whole_versions(scan, key):
    return list(dict.fromkeys(v for k, v, *_how in (scan or {}).get('versions') or [] if k == key))


def _file_doubt(scan, key, product, where):
    """Why one file searched whole leaves the library in doubt, or '': more than one version of it in the one file, its code with a version
    that cannot be told, more matches than are kept, or a licence block no rule names that may be its copy (``js_libraries.rules_out``)."""
    from cveFeed.js_libraries import rules_out
    versions = _whole_versions(scan, key)
    if len(versions) > 1:
        return f'{where} holds more than one {product} version ({", ".join(versions[:4])})'
    if key in (scan.get('unplaceable') or []):
        return f'{where} carries {product} code whose version cannot be told'
    if scan.get('overflow'):
        return f'{where} has more library banners or licence blocks than the read keeps'
    blocks = [b for b in scan.get('blocks') or [] if not rules_out(key, b)]
    if scan.get('blocks_more'):
        blocks = blocks or ['more licence blocks than the read keeps']
    if blocks:
        return f'{where} has a licence block no rule names, which may be a {product} copy ("{(blocks or ["..."])[0][:80]}")'
    if scan.get('loaders'):
        return f'{where} loads scripts at run time ({", ".join(scan["loaders"][:3])}), which the read does not see'
    return ''


def library_outcome(params, reading):
    """The step result of a script read for a match on ``params['library']`` (pure). Only what is truly false is closed, and an absence never
    is (a page that no longer shows a library, the match's own script gone: the next scan's ordinary stale closure decides that):

    - ``reaffirmed``: the copy that runs on a page states, in its own file, a version inside the range (never a hit: the version is on the page,
      the page is not shown to be exploitable);
    - closed (``version_changed`` with a ``close_reason``) in one case only, a redirect alias: every current root of the host answers 301
      or 308 to another host that is one of the project's inventoried hosts (``reading['inventoried_hosts']``), for a match made from a
      script of the front page (``version_source`` body or filename, with its ``script_url``); a version another tool named never closes
      this way (it may be on a deeper route the host still serves). A fixed version the page's files state never closes the match (1.3.3,
      final review): even when the match's own file states one fixed version, every script with a source on every page and every file the
      library was seen in was read whole, searched end to end (``js_libraries.whole_body``) and shows no loader, a page can still load
      another copy at run time that no static read sees (a ``document.write``, an appended script tag, a fetch and eval). Such a read is
      ``observed``, with what the file states;
    - ``observed`` otherwise too: the library gone or moved, a temporary redirect, an older copy that is shadowed, an unread or cut-short file, a
      spent budget, a run-time loader, an error page;
    - ``blocked``: every base was refused or challenged; ``failed``: no base answered, a port this server held, or a server error."""
    from cveFeed.correlation import SCRIPT_READ
    from cveFeed.js_libraries import MAX_SCRIPT_BYTES
    key, product, entries = params['library'], params['product'], params.get('ranges') or []
    pages = reading.get('pages') or []
    records = _library_records(reading, key)
    evidence = _library_evidence(reading, records)

    def result(status, summary, close=''):
        out = {'status': status, 'summary': summary[:300], 'output_excerpt': summary[:OUTPUT_CAP], 'library': evidence}
        if close:
            out['close_reason'] = f'{SCRIPT_READ}. {close} This closes this match only; a later scan that finds the library again matches it again.'
        return out
    alias = _alias_of(params, reading)
    if alias and not (params.get('version_source') in ('body', 'filename') and params.get('script_url')):
        # a version another tool named may come from a deeper route the host still serves (only its front page redirects)
        return result('observed', f'every front page of the host permanently redirects to {alias}, but the {params.get("matched_version") or "matched"} '
                                  'version came from another tool, not from a script of the front page, and may be on a deeper route this host '
                                  'still serves: a redirect alias closes only a match made from the front page\'s own script')
    if alias and alias not in (reading.get('inventoried_hosts') or ()):
        return result('observed', f'every front page of the host permanently redirects to {alias}, which is not one of this project\'s inventoried '
                                  'hosts: a redirect alias closes a match only when its target is a host of the project, judged on its own')
    if alias:
        return result('version_changed', f'every front page of the host permanently redirects to {alias}: its scripts are that host\'s',
                      f'A fresh read shows every front page of this host answers a permanent redirect to {alias} (a redirect alias): it serves no '
                      f'page of its own, so the {product} version recorded for it is the other host\'s, which is judged on its own.')
    if not pages:
        return result('failed', 'the host has no web page to read')
    held = [p for p in pages if p.get('outcome') == 'held']
    if held:  # not run from this server (cveFeed.local_egress): nothing was sent, nothing is concluded, it is tried again later
        return result('failed', f"not run from this server: {held[0].get('error') or 'the port is held'}")
    read = [p for p in pages if p.get('outcome') == 'read']
    if not read:
        outcomes = {p.get('outcome') for p in pages}
        if outcomes <= {'refused', 'challenged'}:
            return result('blocked', 'no front page could be read: ' + '; '.join(
                f"{p['base']} {'was refused by the address gate' if p['outcome'] == 'refused' else 'was challenged by ' + str(p.get('challenge'))}" for p in pages))
        if all(p.get('outcome') == 'unanswered' or (p.get('status') or 0) >= 500 for p in pages):
            return result('failed', f'no front page answered, so the {product} version could not be read again')
        redirects = [p for p in pages if p.get('outcome') == 'redirect']
        if redirects:
            hop = redirects[0]
            how = ('a temporary redirect is not an alias' if hop.get('status') in (302, 303, 307) else
                   'a redirect to the host itself is not an alias' if hop.get('status') in (301, 308) else
                   'the status of the redirect is not known, so it is not taken for an alias')
            return result('observed', f"the front page redirects ({hop.get('status')}) to {hop.get('location')}: {how}, unless every root "
                                      'answers a permanent redirect to another host, and no script was read')
        return result('observed', 'the front page answered ' + ', '.join(str(p.get('status') or p.get('outcome')) for p in pages) +
                      f'; no script was read, so the {product} version could not be read again')
    every_base = len(read) == len(pages)
    # a copy pasted into the page itself (an inline script that states the library, cveFeed.js_libraries.PageScripts.inline) is on the page too
    inline = [(page, {'url': f"{page.get('base')}/ (inline)", 'version': version, 'source': 'body', 'state': 'inline'})
              for page in read for lib, version in page.get('inline') or [] if lib == key]
    # every version of the library any file or page states anywhere in it, searched end to end (a second copy deep in a bundle)
    deep = [(url, v) for url, scan in {**(reading.get('scanned') or {}), **(reading.get('extra') or {})}.items()
            if (scan or {}).get('whole') for v in _whole_versions(scan, key)]
    deep += [(f"{page.get('base')}/", v) for page in read for v in _whole_versions(page.get('page_scan'), key)]
    if not records and not inline and not deep:
        return result('observed', f'no page read now shows {product}; a library a page no longer shows (a maintenance or an access-denied page '
                                  'shows none, a bundle or a loader may hold it) does not close the match: the next scan retires it if it is '
                                  'really gone')
    copies = [(page, c) for page, record in records for c in record.get('copies') or [] if isinstance(c, dict)]
    copies += inline
    for page, record in records:
        effective = next((c for c in record.get('copies') or [] if c.get('state') == 'effective'), None)
        if effective and effective.get('source') == 'body' and _in_ranges(effective.get('version'), entries) is True:
            where = f" (read from the file {effective.get('url')})" if effective.get('url') else ''
            return result('reaffirmed', f"the page loads {product} {effective.get('version')}{where}, the copy that runs; that version is inside "
                                        'the affected range (the version is on the page; whether the page is exploitable depends on how it uses it)')
    inside = [c for _p, c in copies if c.get('source') == 'body' and _in_ranges(c.get('version'), entries) is True]
    if inside:
        states = ', '.join(dict.fromkeys(c.get('state') or 'unresolved' for c in inside))
        return {**result('observed', f'{product} {inside[0].get("version")} inside the affected range is still on the page, as a {states} copy; '
                                     'whether it runs needs a person to look'), 'in_range': True}
    deep_inside = [(url, v) for url, v in deep if _in_ranges(v, entries) is True]
    if deep_inside:
        return {**result('observed', f'{product} {deep_inside[0][1]} inside the affected range is still in {deep_inside[0][0]} (found by '
                                     'searching the whole file); whether it runs needs a person to look'), 'in_range': True}
    blockers = []
    if not (params.get('version_source') == 'body' and params.get('script_url')):
        # the version came from somewhere this read cannot re-read (another tool on another route or in an iframe, a widget bundle the
        # vetter never fetches, a file name or a ?ver= string): what the front page's readable scripts show does not contradict it
        blockers.append(f"the {params.get('matched_version') or 'matched'} version came from "
                        + ('another tool, not from a file this read re-reads' if params.get('version_source') not in ('body', 'filename')
                           else 'a script\'s name, not from a file this read re-reads' if params.get('version_source') == 'filename'
                           else 'a file the match does not name')
                        + ', and a script read closes only a match made from a file it reads again whole')
    capped = [p['base'] for p in read if p.get('capped')]
    if capped:
        blockers.append('the page has more scripts than the read can see, so another copy may be among them')
    if any(p.get('page_truncated') for p in read):
        blockers.append('a front page was cut at the read limit, so a script further in was not seen')
    if any(p.get('inline_unread') for p in read):
        blockers.append('the page has inline code no rule reads, which may be a copy')
    unread = [c for _p, c in copies if c.get('source') != 'body']
    if unread:
        blockers.append(f"the file of a {product} copy ({unread[0].get('url')}) was not read ({unread[0].get('not_read') or 'not read'})")
    if any(r.get('copies_unresolved') for _p, r in records):
        blockers.append('the page does not show which copy runs (' + next((r.get('unresolved_reason') for _p, r in records
                                                                             if r.get('unresolved_reason')), 'copies unresolved') + ')')
    effective = [next((c for c in r.get('copies') or [] if c.get('state') == 'effective'), None) for _p, r in records]
    if not records:
        blockers.append(f'no script file the page loads is {product}: only a copy found inside a page or a bundle states it')
    if any(c is None for c in effective) and not blockers:
        blockers.append(f'no copy of {product} is the one that runs on every page')
    if any(c and c.get('truncated') for c in effective):
        blockers.append(f'the file of the copy that runs was cut at {MAX_SCRIPT_BYTES // 1024} KB, so a second copy further in was not seen')
    if any(_in_ranges(c.get('version'), entries) is None for _p, c in copies if c.get('source') == 'body') or \
            any(_in_ranges(v, entries) is None for _u, v in deep):
        blockers.append('a version a file states cannot be placed against the affected range')
    if not every_base:
        blockers.append('not every web base of the host was read (' + ', '.join(f"{p['base']}: {p.get('outcome')}" for p in pages
                                                                                   if p.get('outcome') != 'read') + ')')
    lazy = [p['base'] for p in read if key in (p.get('lazy') or [])]
    if lazy:
        blockers.append(f'the page adds {product} at run time (a loader or inline code), which the read does not see')
    blockers += _whole_read_blockers(params, reading, read, key, product, entries)
    versions = ', '.join(dict.fromkeys(c.get('version') for c in effective if c))
    if blockers:
        return result('observed', f'the copy that runs states {product} {versions or "no version"}, but ' + '; '.join(dict.fromkeys(blockers))[:400])
    where = f" (read from the file {effective[0].get('url')})" if effective and effective[0] and effective[0].get('url') else ''
    # every script was read whole and none shows a loader, but static reading cannot prove a page loads nothing else at run time (a
    # document.write, an appended script tag, a fetch and eval): the fixed version informs the match, it never closes it (only a redirect
    # alias closes)
    return result('observed', f'the copy that runs states {product} {versions}{where}, outside the affected range, and every script of the '
                              'page was read whole; a page can still load another copy at run time that no static read sees, so the match '
                              f"made on {params.get('matched_version') or 'its version'} stays open")


def _whole_read_blockers(params, reading, read, key, product, entries):
    """Why the fresh read is not whole enough to weigh a fixed version (``library_outcome``; it never closes on one): the match's own file, every script with
    a source on every page (same-host, same-site, CDN, third-party and analytics alike: any of them may carry a copy) and every file the
    library was seen in, each fetched in this read, read whole and free of doubt (``_file_doubt``), every page's own text free of doubt, and
    no run-time loader anywhere."""
    out = []
    own = params.get('script_url') or ''
    if own and params.get('version_source') == 'body':
        scan = _scan_of(reading, own)
        if not scan or not scan.get('whole'):
            out.append(f"the file the match was made on ({own}) was not read whole in this read ({(scan or {}).get('error') or 'not fetched'})")
        else:
            versions = _whole_versions(scan, key)
            if not versions:
                out.append(f'the file the match was made on ({own}) no longer states {product}: that is an absence, which the next scan decides')
            elif any(_in_ranges(v, entries) is not False for v in versions):
                out.append(f'the file the match was made on ({own}) still states {product} {versions[0]}, not outside the affected range')
    wanted = []
    for page in read:
        listed = page.get('entries')
        if listed is None:
            out.append(f"the read of {page.get('base')} does not list its scripts")
            continue
        # EVERY script with a source, whatever its host: a third-party widget the vetter never reads, an analytics tag or a CDN bundle the
        # budget skipped may carry an older copy that runs after the fixed one (the strict whole-page rule of the library provenance)
        wanted += [e['url'] for e in listed if e.get('url')]
    wanted += [u for u in params.get('seen_urls') or [] if u]
    for url in dict.fromkeys(wanted):
        scan = _scan_of(reading, url)
        if not scan or not scan.get('whole'):
            why = (scan or {}).get('error') or next((w for p in read for u, w in p.get('skipped') or [] if u == url), 'not fetched')
            out.append(f'a script that could hold {product} ({url}) was not read whole ({why})')
            break
    for url in dict.fromkeys(wanted):
        scan = _scan_of(reading, url)
        if scan and scan.get('whole'):
            doubt = _file_doubt(scan, key, product, url)
            if doubt:
                out.append(doubt)
                break
    for page in read:
        scan = page.get('page_scan')
        if scan is None:
            out.append(f"the page {page.get('base')}/ was not searched whole")
            continue
        doubt = _file_doubt(scan, key, product, f"the page {page.get('base')}/")
        if doubt:
            out.append(doubt)
    return out


RUNNERS = {'nuclei_template': run_nuclei_template, 'nmap_sv': run_nmap_sv, 'http_head': run_http_head, 'db_probe': run_db_probe,
           'fact_probe': run_fact_probe, 'script_read': run_script_read}


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
    never counted clean), else skipped_blocked if every step was blocked, else observed if checks only gathered metadata. The record of
    the library body read (``LIBRARY_READ``) is not a check that ran here and is left out, so it never moves the status or the schedule."""
    results = [s.get('result') for s in steps if not (isinstance(s, dict) and s.get('kind') == LIBRARY_READ)]
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
    close_reason = result.get('close_reason') if check['kind'] == 'script_read' and result.get('status') == 'version_changed' else ''
    if close_reason and save and row.match_id:
        refusal = _closure_refusal(row)
        if refusal:  # a person worked it, or other evidence vouches for it: the fresh read is recorded, the match is not closed
            result = {**result, 'status': 'observed', 'summary': f"{result.get('summary')}; not closed: {refusal}"}
            close_reason = ''
    status = result['status']
    if check['kind'] == 'script_read' and (status == 'reaffirmed' or result.get('in_range')) and save and row.match_id:
        _reopen_on_script_read(row, result, now)  # an earlier script read closed it; this one reads an affected copy again: open again
    hit_before = row.validation_status == 'hit'
    step = {'kind': check['kind'], 'label': check['label'], 'display': check['display'], 'target': check['target'],
            'ran_at': now.isoformat(), 'result': status, 'summary': _trim(result.get('summary'), 300),
            'output_excerpt': _trim(result.get('output_excerpt'), OUTPUT_CAP), 'error': _trim(result.get('error'), 200)}
    if check['params'].get('equivalent'):
        step['note'] = 'the check runs in-process; the command shown is the equivalent a person can repeat'
    if isinstance(result.get('library'), dict):
        step['library'] = result['library']  # the fresh evidence of a script read: version, where it came from, how far it is trusted, copies
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
            from cveFeed import scoring, threat
            match = row.match
            was_version_only = not hit_before and threat.unproven(match, validation_status='')
            scoring.evidence_arrived([row.match_id], confirmed=[row.match_id] if was_version_only else ())
        elif status == 'reaffirmed' and row.match_id and check['kind'] == 'nuclei_template':
            _record_version_hit(row, check, result)
        if close_reason:
            _close_on_script_read(row, close_reason)
    return row


def _closure_refusal(row):
    """Why a script read must not close the row's match, or '': a person worked it (remediation, an assignee, a comment, an earlier manual
    validation), or the AI, a template, a distribution tracker, runZero or the host itself vouches for it (``match_policy.has_standing``), or
    a validation hit stands for it (``match_policy.has_hard_evidence``)."""
    from cveFeed import match_policy
    from cveFeed.models import CVEMatch
    match = CVEMatch.objects.filter(pk=row.match_id).select_related('cve_entry').first()
    if match is None:
        return 'the match is gone'
    if match.remediation_status != 'open' or match.assignee_id:
        return 'a person worked this match'
    if match_policy.has_standing(match):
        return 'a person or other evidence vouches for this match'
    if match_policy.has_hard_evidence(match.source, match.evidence, match.template_result or '', match.distro_status or '',
                                      row.validation_status):
        return 'hard evidence about this host stands for it (a template, a tracker, the host itself or a validation hit)'
    return ''


def _close_on_script_read(row, reason):
    """Close the row's match as not applicable on a fresh script read, through the guarded closure every deterministic close uses."""
    from cveFeed import correlation
    from cveFeed.models import CVEMatch
    match = CVEMatch.objects.filter(pk=row.match_id).select_related('cve_entry', 'subdomain__target_domain').first()
    if match is None or _closure_refusal(row):
        return False
    closed = correlation.close_invalid_correlation(match, reason[:2000], host_only=True)
    row.refresh_from_db()  # the closure wrote the row's classification: a later check of this run must not save the old one over it
    return closed


def _reopen_on_script_read(row, result, now):
    """Reopen the row's match when an earlier script read closed it (``closed_by_script_read``) and this read finds the library inside the
    affected range again: the copy that runs (``reaffirmed``), or any copy or file of the page (``observed`` with ``in_range``): the closure
    no longer holds. The match takes the fresh read's confidence (an affected copy that may not run no more than SHADOWED_CAP), its verdict
    and the row's classification are cleared, so triage judges it again; the next scan's correlation recomputes the rest. Returns whether it
    reopened."""
    from cveFeed import activity, scoring
    from cveFeed.models import CVEMatch
    match = CVEMatch.objects.filter(pk=row.match_id).select_related('cve_entry').first()
    if match is None or not closed_by_script_read(match):
        return False
    from cveFeed.js_libraries import SHADOWED_CAP
    library = result.get('library') or {}
    confidence = float(library.get('version_confidence') or 0.0)
    if result.get('status') != 'reaffirmed':
        confidence = min(confidence or SHADOWED_CAP, SHADOWED_CAP)
    CVEMatch.objects.filter(pk=match.pk).update(ai_verdict='', ai_reason='', ai_model='', confidence=confidence, updated_at=now)
    match.ai_verdict, match.ai_reason, match.ai_model, match.confidence = '', '', '', confidence
    row.verdict, row.status, row.classification, row.reason = None, 'pending', '', ''
    activity.log('confirm', f'{match.cve_entry.cve_id}: reopened for this asset (a fresh script read finds {product_version(result, library)} '
                 'inside the affected range on the page)', project=row.project_id, cve_id=match.cve_entry.cve_id, match_id=match.pk,
                 finding_id=row.pk, decision='reopened')
    scoring.rescore_for_matches([match])
    return True


def product_version(result, library):
    """The affected version a reopening script read found, for the activity line."""
    if result.get('status') == 'reaffirmed' and library.get('version'):
        return f"{library['version']}, the copy that runs,"
    found = re.search(r'(\d+(?:\.\d+)+) inside the affected range', result.get('summary') or '')
    return f'{found.group(1)}' if found else 'an affected copy'


def closed_by_script_read(match):
    """Whether ``match`` stands closed by a script read (``correlation.SCRIPT_READ``)."""
    from cveFeed.correlation import SCRIPT_READ
    return match.ai_verdict == 'not_affected' and (match.ai_reason or '').startswith(SCRIPT_READ)


def _record_version_hit(row, check, result):
    """A version-class template's hit from a validation check (``reaffirmed``, ``_result_from_outcome``) is recorded on the match like the
    same hit from the template pass (``templategen.record_outcomes``: ``VERSION_ONLY_RESULT``, no finding, never replacing a confirmation),
    so the version it proved is proof on either path: under the KEV heat policy a KEV or exploited match it turns fire is rescored and paged
    once. A result the template pass recorded already (``recorded``) is not written again. Never raises."""
    from cveFeed import templategen
    from cveFeed.models import CVEEntry, CVEMatch
    outcome = result.get('outcome')
    if result.get('recorded') or not outcome or not templategen.is_version_hit(outcome):
        return
    try:
        cve = CVEEntry.objects.get(pk=CVEMatch.objects.filter(pk=row.match_id).values_list('cve_entry_id', flat=True)[0])
        templategen.record_outcomes(cve, [outcome], project=row.project_id,
                                    template_id=os.path.basename(check['params']['template']).rsplit('.', 1)[0])
    except Exception as exc:  # noqa: BLE001 - the validation step is recorded either way
        logger.warning('version-class template hit not recorded on match %s (%s)', row.match_id, type(exc).__name__)


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
        check = _template_check(template_path, row.host, cve.cve_id, row.signature)
        result = _result_from_outcome(outcome)
        result['recorded'] = True
        apply_validation(row, check, result)
        done += 1
    return done


def _result_from_outcome(outcome):
    """A template outcome as a validation step result. A hit of a version-class template (``templategen.template_evidence``) read the
    version again and showed nothing more: it is ``reaffirmed`` (the live version is inside the affected range), never a ``hit``, so it is
    not hard evidence and confirms no row. It proves the version all the same (``apply_validation`` records it on the match): under the KEV
    heat policy a KEV or exploited match turns fire and is paged once; under legacy it lifts no heat and pages nothing."""
    from cveFeed import templategen
    if outcome.get('error'):
        return {'status': 'failed', 'error': outcome['error'], 'summary': outcome['error'], 'outcome': outcome}
    if outcome.get('vulnerable'):
        hit = outcome.get('hit') or {}
        evidence = {'matched_at': _trim(hit.get('matched-at') or hit.get('host'), 500), 'matcher_name': _trim(hit.get('matcher-name'), 200),
                    'extracted_results': [_trim(e, 200) for e in (hit.get('extracted-results') or [])[:5]],
                    'request': _trim(hit.get('request')), 'response': _trim(hit.get('response'))}
        if templategen.is_version_hit(outcome):
            return {'status': 'reaffirmed', 'summary': 'the template matched a version string only; that version is inside the affected '
                                                       'range, and the flaw itself was not shown',
                    'output_excerpt': _trim(f'matched at {evidence["matched_at"]}', OUTPUT_CAP), 'outcome': outcome}
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


LIBRARY_READ = 'library_read'  # the step kind of cvENGINE's own read of a library's served file (``library_step``); never a runnable check


def library_readings(matches):
    """``{match pk: {'page_url', 'read_at', 'how'}}``: for each match, a reading of its host's front page in which the match's ``script_url``
    stated the match's version in its own body (a route check's ``libraries`` record, else the html-libraries probe's). ``how`` is ``banner``
    (the file's comment banner) or ``signature`` (the library's own code). A match with no such reading kept is left out. Two queries for
    any number of matches. Read only."""
    from cveFeed import js_libraries
    from cveFeed.models import ProbeObservation, RouteAuth
    wanted = {}
    for m in matches:
        evidence = m.evidence if isinstance(m.evidence, dict) else {}
        url, version = evidence.get('script_url'), m.matched_version or ''
        key = js_libraries.PRODUCTS.get((m.matched_product or '').strip().lower())
        sub = getattr(m, 'subdomain', None)
        if isinstance(url, str) and url and version and key and sub is not None and sub.target_domain_id:
            wanted[m.pk] = (sub.target_domain.project_id, sub.name.lower(), key, url, version)
    if not wanted:
        return {}
    projects, hosts = {w[0] for w in wanted.values()}, {w[1] for w in wanted.values()}

    def stated(record, url, version):
        for copy in (record.get('copies') or []) if isinstance(record, dict) else []:
            if isinstance(copy, dict) and copy.get('url') == url and copy.get('version') == version and copy.get('source') == 'body':
                return copy
        return None
    routes, probes = {}, {}
    for row in (RouteAuth.objects.filter(project_id__in=projects, host__in=hosts, path='/', checked_at__isnull=False)
                .only('project_id', 'host', 'url', 'checked_at', 'evidence').order_by('-checked_at')):
        routes.setdefault((row.project_id, row.host), []).append(row)
    for row in (ProbeObservation.objects.filter(project_id__in=projects, host__in=hosts, kind='version', probe='html-libraries')
                .only('project_id', 'host', 'url', 'observed_at', 'evidence').order_by('-observed_at')):
        probes.setdefault((row.project_id, row.host), []).append(row)
    out = {}
    for pk, (project, host, key, url, version) in wanted.items():
        for row in routes.get((project, host), []):
            copy = stated(((row.evidence or {}).get('libraries') or {}).get(key), url, version)
            if copy:
                out[pk] = {'page_url': row.url or '', 'read_at': row.checked_at, 'how': copy.get('how') or ''}
                break
        if pk in out:
            continue
        for row in probes.get((project, host), []):
            record = (row.evidence or {}).get('library')
            if isinstance(record, dict) and js_libraries.PRODUCTS.get(str(record.get('product', '')).lower()) == key:
                copy = stated(record, url, version)
                if copy:
                    out[pk] = {'page_url': row.url if str(row.url or '').startswith('http') else '', 'read_at': row.observed_at,
                               'how': copy.get('how') or ''}
                    break
    return out


def library_reading(match):
    """``library_readings`` of one match: ``{}`` when no reading is kept."""
    return library_readings([match]).get(match.pk, {})


def library_read_step(steps):
    """The ``LIBRARY_READ`` step among a row's validation steps, or None."""
    return next((s for s in steps or [] if isinstance(s, dict) and s.get('kind') == LIBRARY_READ), None)


def library_step(match, reading=None):
    """The validation step that records the read of the library's served file which proved ``match``'s version
    (``triage.library_body_proven``) as cvENGINE's own completed check: what was fetched (the script URL), what it stated (the file's banner
    or the library's own code, and the version), which page runs it and when it was read (``reading``, from ``library_readings``; the match's
    creation when none is kept). Its result is ``reaffirmed`` ("still holds"), never a hit: the file proves the version, not a check of the
    flaw. None for a match the file does not prove."""
    from shlex import quote

    from cveFeed import js_libraries
    evidence = match.evidence if isinstance(match.evidence, dict) else {}
    if not triage.library_body_proven(match.source, evidence, match.version_in_range, match.distro_status):
        return None
    reading = reading or {}
    url, version, product = evidence['script_url'], match.matched_version, match.matched_product
    how = reading.get('how') or ('banner' if evidence['version_confidence'] >= js_libraries.CONFIDENCE['banner'] else 'signature')
    stated = (f"the file's own banner states {product} v{version}" if how == 'banner'
              else f"the library's own code in the file names version {version}")
    page = reading.get('page_url') or ''
    span = triage.range_text(evidence.get('range'))
    read_at = reading.get('read_at') or match.created_at
    return {'kind': LIBRARY_READ, 'label': f'Library body read: the {product} version its served file states', 'target': url,
            'display': f'curl -gs {quote(url)} | head -c {js_libraries.HEAD}', 'ran_at': read_at.isoformat() if read_at else '',
            'result': 'reaffirmed', 'error': '', 'output_excerpt': '',
            'summary': _trim(f'Fetched {url}: {stated}; it is the copy {"the page " + page if page else "the page"} runs. {version} is '
                             f'inside the affected range{" " + span if span else ""}.', 300),
            'library': {'version': version, 'version_source': 'body', 'how': how, 'script_url': url, 'page_url': page,
                        'version_confidence': evidence['version_confidence'], 'copy_state': 'effective'}}


def put_library_step(row, step):
    """Put ``step`` (``library_step``, or None to drop one) among ``row``'s validation steps in place of any earlier one. Only the steps
    change: the validation status, its time and the retry schedule are the real checks' (``rollup`` leaves this step out), so the step never
    makes a finding look validated to the schedulers (``due_ids``, ``hot_validation``). Returns whether the steps changed (not saved)."""
    steps = list(row.validation_steps or [])
    if library_read_step(steps) == step:
        return False
    kept = [s for s in steps if not (isinstance(s, dict) and s.get('kind') == LIBRARY_READ)]
    row.validation_steps = kept + ([step] if step else [])
    return True


def record_library_read(row, match, save=True):
    """Record (or drop) the body-read step of ``match`` on its Triage ``row`` (``library_step``, ``put_library_step``). Returns whether it
    changed (and was saved, with ``save``)."""
    changed = put_library_step(row, library_step(match, library_reading(match)))
    if changed and save:
        row.save(update_fields=['validation_steps', 'updated_at'])
    return changed


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


def run_validation(project_id, triage_ids, scan_id=None, runners=None, template_for=None, selected_kinds=None, unattended=True, budget_seconds=None):
    """Plan and run the checks for ``triage_ids`` (rows of ``project_id`` only: a row of another project is never touched), within the
    per-run, per-project and per-day caps and the ledger TTL, honouring the stop flag of ``scan_id``. Returns the counts. Never raises
    for one check's trouble: a failure is recorded on its row and retried later. ``unattended`` is False only for a person's own request
    (Validate now): it reaches every check's subject, so the bug bounty gate holds an automatic run to the project's confirmation and a
    person's own one to the program's scope only.

    ``runners`` replaces the default check runners (tests); ``template_for(cve_id)`` replaces ``resolve_template``.

    ``budget_seconds``: stop starting new findings once this long has passed (after at least one), and say which were left in ``stats['deferred_ids']``.
    A batch is up to 200 findings of network checks, minutes of one worker slot; the sweep's batches filled every slot of the CVE-feed lane while the
    scheduler's own ticks waited behind them (11/10). The task re-queues what was left at the back of the queue, so a tick runs between slices."""
    import time as _time
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
    from targetApp.models import narrowed_names
    narrowed = narrowed_names(project_id, [r.host for r in rows if r.host])  # once for the batch
    started = _time.monotonic()
    handled = 0
    with resources.scan_context(scan_id):
        for index, row in enumerate(rows):
            if scan_id is not None and resources.abort_requested(scan_id):
                stats['stopped'] = True
                break
            if budget_seconds is not None and handled and _time.monotonic() - started > budget_seconds:
                stats['deferred_ids'] = [r.pk for r in rows[index:]]
                break
            handled += 1
            if row.next_attempt_at and row.next_attempt_at > now:
                continue
            findings = triage.load_findings([row])
            if not findings:
                continue
            finding = findings[0]
            if triage.effective_signature(triage.describe(finding), row.review_nonce) != row.signature:
                continue  # the evidence moved since: triage resets the row and validation follows the new signature
            subject = subject_for(row, finding, unattended=unattended)
            if row.host and row.host.strip().lower().rstrip('.') in narrowed:  # held only under a target that is now exactly one host (=example.com)
                row.validation_status, row.validation_steps = 'skipped_blocked', [{
                    'kind': 'scope', 'label': 'scope check', 'display': '', 'target': row.host, 'ran_at': now.isoformat(),
                    'result': 'blocked', 'summary': 'its target is set to this host only, and this name is under it, so nothing was run',
                    'output_excerpt': '', 'error': ''}]
                row.save(update_fields=['validation_status', 'validation_steps', 'updated_at'])
                stats['blocked'] += 1
                continue
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
            # the read of a library's served file that proved its version is cvENGINE's own check: recorded beside the others, never
            # run again here, and never part of the status or the schedule (rollup)
            library = library_step(finding, library_reading(finding)) if row.kind == 'cve_match' else None
            if not checks:
                row.validation_status = 'no_check'
                row.validation_steps = ([{'kind': 'none', 'label': n, 'display': '', 'target': row.host, 'ran_at': now.isoformat(),
                                          'result': 'blocked', 'summary': n, 'output_excerpt': '', 'error': ''} for n in notes[:1]]
                                        if notes else []) + ([library] if library else [])
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
            put_library_step(row, library)
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
                    check['params'].setdefault('project_id', project_id)  # the runners that need a scanner say which project asks
                    result = interpret(subject, check, runners[check['kind']](check))
                except resources.ScanAborted:
                    stats['stopped'] = True
                    break
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
        notify.template_hits(hits, project=project_id)  # one message per run, however many hosts
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
