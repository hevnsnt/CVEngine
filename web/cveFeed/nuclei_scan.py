"""Nuclei over everything discovery found, info severity included, streamed into the findings table.

Targets are every discovered host plus its IPs, and host:port for each open port bbot reported on a
non-default port, so nuclei probes every service rather than just the front door.
"""
import json
import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

NUCLEI_BIN = 'nuclei'
SEVERITIES = 'info,low,medium,high,critical'
DEFAULT_NUCLEI_TIMEOUT = 4 * 3600


def nuclei_timeout():
    """Seconds nuclei may run, from the App Admin timings."""
    try:
        from dashboard.models import SystemTimings
        return SystemTimings.current().nuclei_timeout_hours * 3600
    except Exception:  # noqa: BLE001
        return DEFAULT_NUCLEI_TIMEOUT
DEFAULT_PORTS = (80, 443)
NUCLEI_CHUNK = 100  # targets per nuclei process: a memory kill then only repeats one chunk
BASE_FLAGS = ['-severity', SEVERITIES, '-jsonl', '-silent', '-duc', '-ni', '-nc', '-rl', '150', '-c', '40',
              '-timeout', '10', '-retries', '1', '-etags', 'dos']


# A lighter run for when the normal one was stopped for lack of memory: fewer hosts in parallel, a gentler rate.
LIGHT_FLAGS = {'-rl': '50', '-c': '10'}


TECH_FLAGS = ['-tags', 'tech']
TEMPLATE_POLICY_REV = 'readonly-2'
_APPROVED = {'root': None, 'at': 0, 'value': None}
_APPROVED_LOCK = threading.Lock()


# Templates whose absence quietly removes a whole capability: their exclusion is an error, not a policy statistic.
ESSENTIAL_TEMPLATES = ('http/technologies/tech-detect.yaml',)
NO_TEMPLATES = re.compile(r'no (valid )?templates (were )?(provided|found|loaded)', re.I)
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def _policy_reason(problem):
    """A skip reason without the per-template detail, so equal reasons count together ("forbidden key 'payloads'")."""
    reason = re.sub(r'^template not validated: ', '', str(problem)).strip()
    return re.sub(r'\d+', 'N', reason)[:90]


def _report_policy(revision, count, skipped, essential_skipped):
    """Put the outcome of a template-policy snapshot in the activity and error log, once per snapshot revision for all processes.
    An empty snapshot, or an essential template the policy excluded, is logged as failed; otherwise a done line with the counts."""
    total = count + sum(skipped.values())
    top = ', '.join(f'{reason} ({n})' for reason, n in sorted(skipped.items(), key=lambda kv: -kv[1])[:4])
    message = f'Nuclei template policy approved {count:,} of {total:,} installed templates'
    if skipped:
        message += f'; skipped: {top}'
    failed = not count or bool(essential_skipped)
    if essential_skipped:
        message = (f'Nuclei template policy excludes {", ".join(sorted(essential_skipped))} '
                   f'({"; ".join(sorted(set(essential_skipped.values())))}), so that detection does not run. ' + message)
    (logger.error if failed else logger.info)('%s', message)
    try:
        from django.core.cache import cache
        if not cache.add(f'cvengine:nuclei-policy-logged:{revision}', 1, timeout=7 * 86400):
            return
    except Exception:  # noqa: BLE001 - without the cache every process logs its own snapshot
        pass
    from cveFeed import activity
    activity.log('run_check', message, status='failed' if failed else 'done', approved=count, installed=total,
                 skipped=dict(sorted(skipped.items(), key=lambda kv: -kv[1])[:10]), essential_excluded=essential_skipped)


def _stderr_reason(stream):
    """The line of nuclei's stderr that says why it stopped (its last fatal or error line, else its last line), cleaned."""
    try:
        stream.seek(0, os.SEEK_END)
        stream.seek(max(0, stream.tell() - 8192))
        lines = [ANSI.sub('', line).strip() for line in stream.read().splitlines()]
    except (OSError, ValueError):
        return ''
    lines = [line for line in lines if line]
    pick = next((line for line in reversed(lines) if re.search(r'\[(FTL|ERR)\]|could not|error', line, re.I)), lines[-1] if lines else '')
    return ''.join(c for c in pick if c.isprintable())[:200]


def approved_templates():
    with _APPROVED_LOCK:
        return _approved_templates_locked()


def _approved_templates_locked():
    """Snapshot only installed templates passing the same destination/read-only gate as targeted checks."""
    from cveFeed import templategen, validation
    root = os.path.realpath(templategen.TEMPLATES_ROOT)
    if (_APPROVED['root'] == root and _APPROVED['value'] and os.path.isdir(_APPROVED['value'][0])
            and time.monotonic() - _APPROVED['at'] < 3600):
        return _APPROVED['value']
    if not os.path.isdir(root):
        raise RuntimeError('Nuclei template library is unavailable')
    dest = tempfile.mkdtemp(prefix='cvengine-approved-nuclei-')
    digest = hashlib.sha256(TEMPLATE_POLICY_REV.encode())
    count, skipped, essential_skipped = 0, {}, {}
    try:
        for base, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(base, d)))
            for name in sorted(files):
                if not name.endswith(('.yaml', '.yml')):
                    continue
                path = os.path.join(base, name)
                try:
                    if os.path.islink(path) or os.path.getsize(path) > validation.MAX_INSTALLED_TEMPLATE_BYTES:
                        continue
                    with open(path, 'rb') as source:
                        content = source.read(validation.MAX_INSTALLED_TEMPLATE_BYTES + 1)
                except OSError:
                    continue
                relative = os.path.relpath(path, root)
                problem = ('larger than the template size limit' if len(content) > validation.MAX_INSTALLED_TEMPLATE_BYTES
                           else validation.readonly_problem(content.decode('utf-8', 'replace')))
                if problem:
                    reason = _policy_reason(problem)
                    skipped[reason] = skipped.get(reason, 0) + 1
                    if relative in ESSENTIAL_TEMPLATES:
                        essential_skipped[relative] = reason
                    continue
                target = os.path.join(dest, relative)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, 'wb') as copy:
                    copy.write(content)
                digest.update(relative.encode())
                digest.update(content)
                count += 1
        if not count:
            _report_policy(TEMPLATE_POLICY_REV, 0, skipped, essential_skipped)
            raise RuntimeError('No installed Nuclei templates passed the read-only policy')
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    old = _APPROVED['value']
    revision = digest.hexdigest()[:12]
    _report_policy(revision, count, skipped, essential_skipped)
    if old and old[1] == revision and os.path.isdir(old[0]):
        shutil.rmtree(dest, ignore_errors=True)
        _APPROVED['at'] = time.monotonic()
        return old
    retained = _APPROVED.setdefault('retained', [])
    if old:
        retained.append((old[0], time.monotonic()))
    # A running Nuclei process can use its immutable snapshot for up to four hours.
    for path, created in list(retained):
        if time.monotonic() - created > 6 * 3600:
            shutil.rmtree(path, ignore_errors=True)
            retained.remove((path, created))
    _APPROVED.update(root=root, at=time.monotonic(), value=(dest, revision, count))
    return _APPROVED['value']


def cve_service(cve_id):
    """Coverage key changes when this CVE's selected template or execution policy changes."""
    from cveFeed.validation import resolve_template
    template_path, _ = resolve_template(cve_id)
    try:
        with open(template_path, 'rb') as source:
            revision = hashlib.sha256(TEMPLATE_POLICY_REV.encode() + source.read(200_001)).hexdigest()[:10]
    except OSError:
        revision = hashlib.sha256(TEMPLATE_POLICY_REV.encode()).hexdigest()[:10]
    return f'nuclei-cve:{cve_id}:{revision}'[:64]


def build_flags(tags=None, profile='normal', severities=None, tech=False, templates_dir=None):
    """Pure: the nuclei CLI flags for a run, optionally narrowed to ``tags`` (an iterable of tag names
    already validated against a known-safe allowlist by the caller - see cveFeed.nuclei_templates).
    ``profile='light'`` lowers concurrency and rate for a memory-constrained retry. ``severities`` narrows the severity
    list, and ``tech`` is the light technology-fingerprint pass (the http/technologies templates, info severity)."""
    flags = list(BASE_FLAGS)
    if templates_dir:
        flags += ['-t', templates_dir]
    if severities or tech:
        flags[flags.index('-severity') + 1] = ','.join(severities) if severities else 'info'
    if profile == 'light':
        for flag, value in LIGHT_FLAGS.items():
            flags[flags.index(flag) + 1] = value
        flags += ['-bs', '10']
    if tech:
        flags += TECH_FLAGS
    elif tags:
        flags += ['-tags', ','.join(sorted(tags))]
    return flags


def build_targets(hostnames, ips, ports):
    """Pure: the target list for nuclei. ``ports`` is an iterable of (host, port)."""
    targets = []
    seen = set()

    def add(t):
        if t and t not in seen:
            seen.add(t)
            targets.append(t)
    for h in sorted(hostnames):
        add(h)
    for ip in sorted(ips):
        add(ip)
    for host, port in sorted(ports):
        if port not in DEFAULT_PORTS:
            add(f'{host}:{port}')
    return targets


def host_of(line):
    """Hostname or IP of a nuclei result line (``host`` may be a URL or host:port)."""
    raw = (line.get('host') or line.get('ip') or '').strip()
    if '://' in raw:
        return (urlparse(raw).hostname or '').lower()
    return raw.rsplit(':', 1)[0].strip('[]').lower() if raw.count(':') == 1 else raw.strip('[]').lower()


def stream_nuclei(targets_file, timeout=None, tags=None, profile='normal', severities=None, tech=False):
    """Run nuclei and yield decoded JSON result lines as they arrive. Waits its turn for memory; raises
    reNgine.resources.MemoryKill if it had to be stopped to protect the container (the caller retries lighter)."""
    from reNgine import resources
    try:
        with open(targets_file) as f:
            label = f'{sum(1 for _ in f)} targets'
    except OSError:
        label = 'targets'
    kind = 'nuclei-light' if profile == 'light' or tech else 'nuclei'
    approved_dir, _, _ = approved_templates()
    with resources.heavy_job(kind, label=label) as job, tempfile.TemporaryFile('w+', errors='replace') as stderr:
        proc = subprocess.Popen([NUCLEI_BIN, '-l', targets_file, *build_flags(tags, profile, severities, tech, approved_dir)], stdout=subprocess.PIPE,
                                stderr=stderr, text=True, bufsize=1, start_new_session=True)
        job.attach(proc)
        timed_out = threading.Event()
        def expire():
            timed_out.set()
            resources.terminate_group(proc, grace=5)
        timer = threading.Timer(timeout or nuclei_timeout(), expire)
        timer.start()
        completed = False
        malformed = False
        yielded = 0
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    malformed = True
                    continue
                if isinstance(row, dict):
                    yielded += 1
                    yield row
                else:
                    malformed = True
            completed = True
        finally:
            timer.cancel()
            if proc.poll() is None:
                resources.terminate_group(proc, grace=5)
            proc.wait()
            job.raise_if_killed()
        if completed and timed_out.is_set():
            raise RuntimeError('Nuclei timed out')
        if completed and proc.returncode:
            reason = _stderr_reason(stderr)
            if not yielded and NO_TEMPLATES.search(reason):
                # nuclei exits 1 when the approved library holds no template for these tags: nothing ran, nothing failed
                logger.info('nuclei: no approved template matched %s; nothing to run', ','.join(sorted(tags or [])) or 'this selection')
                return
            logger.error('nuclei exited with status %s: %s', proc.returncode, reason or 'no error output')
            raise RuntimeError(f'Nuclei exited with status {proc.returncode}' + (f': {reason}' if reason else ''))
        if completed and malformed:
            raise RuntimeError('Nuclei returned malformed JSON output')


def scan_targets(scan):
    """Hostnames, IPs and (host, port) pairs discovered for ``scan``."""
    from startScan.models import Subdomain, open_ports
    from targetApp.target_types import is_scannable_ip, resolves_to_blocked
    from cveFeed.exclusions import excluded_names, normalize
    hostnames, ips, ports = set(), set(), set()
    banned = excluded_names(scan.domain.project_id)  # hosts the organization excluded for good: never a target
    from cveFeed.archive_rediscovery import archived_names
    banned = banned | archived_names(scan.domain.project_id)
    for sub in Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses__ports'):
        if banned and normalize(sub.name) in banned:
            continue
        # a discovered name is attacker-controlled DNS: never hand a scanner one that points inside
        if resolves_to_blocked(sub.name):
            continue
        hostnames.add(sub.name)
        for ip in sub.ip_addresses.all():
            if not is_scannable_ip(ip.address):
                continue
            ips.add(ip.address)
            for port in open_ports(ip):
                ports.add((sub.name, port.number))
    return hostnames, ips, ports


def reuse_findings(scan, project, targets):
    """Copy this project's existing findings for the hosts of ``targets`` (scanned recently by another scan) into ``scan``,
    so the scan's findings page is complete. Keyed on name and URL, so a finding is never copied twice. Returns
    (findings copied, hosts they were on)."""
    from startScan.models import Subdomain, Vulnerability
    hosts = {host_of({'host': t}) for t in targets}
    hosts.discard('')
    if not hosts:
        return 0, 0
    mine = {s.name: s for s in Subdomain.objects.filter(scan_history=scan, name__in=hosts)}
    have = set(Vulnerability.objects.filter(scan_history=scan).values_list('name', 'http_url'))
    source = Vulnerability.objects.filter(target_domain__project_id=project, subdomain__name__in=hosts) \
        .exclude(scan_history=scan).select_related('subdomain').order_by('-id')
    copied, copied_hosts = 0, set()
    for vuln in source.iterator(chunk_size=500):
        key = (vuln.name, vuln.http_url)
        if key in have:
            continue
        have.add(key)
        host = vuln.subdomain.name
        tags, refs, cves, cwes = (list(m.all()) for m in (vuln.tags, vuln.references, vuln.cve_ids, vuln.cwe_ids))
        vuln.pk = None
        vuln.scan_history, vuln.target_domain, vuln.subdomain = scan, scan.domain, mine.get(host)
        vuln.endpoint = None
        vuln.save()
        vuln.tags.set(tags)
        vuln.references.set(refs)
        vuln.cve_ids.set(cves)
        vuln.cwe_ids.set(cwes)
        copied += 1
        copied_hosts.add(host)
    return copied, len(copied_hosts)


def run_nuclei(scan_id, stream=stream_nuclei, tags=None, targets=None, severities=None, service_override=None, force=False):
    """Run nuclei over the scan's discovered assets and persist every result. Returns a summary dict.
    ``tags`` narrows the template set to a focused pass (see cveFeed.nuclei_templates); omitted, this
    is the blanket info-severity-and-up pass over every default template. Targets this project's nuclei already covered
    inside the TTL are not scanned again (see cveFeed.ledger): their existing findings are copied into this scan instead.
    ``targets`` replaces the scan's whole target list (the targeted pass runs one group of hosts at a time) and
    ``severities`` narrows what is reported."""
    from cveFeed import activity, ledger
    from cveFeed.models import DiscoveryEvent
    from reNgine.resources import MemoryKill
    from reNgine.definitions import NUCLEI_SEVERITY_MAP
    from reNgine.tasks import parse_nuclei_result, save_vulnerability
    from startScan.models import ScanHistory, Subdomain

    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    domain, project = scan.domain, scan.domain.project_id
    targets = list(targets) if targets is not None else build_targets(*scan_targets(scan))
    if not targets:
        activity.log('run_check', f'Nuclei skipped for {domain.name}: discovery found nothing to scan', project=project)
        return {'targets': 0, 'findings': 0}
    service = service_override or (ledger.nuclei_tag_service(tags) if tags else 'nuclei')
    if stream is stream_nuclei and not service_override:
        service = f'{service}:{approved_templates()[1]}'[:64]
    covered = set() if force else ledger.fresh(service, targets, project)
    todo = [t for t in targets if t not in covered]
    counts = {name: 0 for name in ('info', 'low', 'medium', 'high', 'critical', 'unknown')}
    new = 0
    reused = hosts_reused = 0
    if covered:
        reused, hosts_reused = reuse_findings(scan, project, [t for t in targets if t in covered])
        if reused:
            activity.log('run_check', f'Nuclei on {domain.name}: reused {reused} finding(s) on {hosts_reused} host(s) scanned in '
                         f'the last {ledger.ttl_label(service)}', project=project, scan_id=scan.id)
    if not todo:
        activity.log('run_check', f'Nuclei skipped for {domain.name}: all {len(targets)} targets were scanned in the last '
                     f'{ledger.ttl_label(service)}', project=project, scan_id=scan.id)
        return {'targets': len(targets), 'findings': 0, 'reused': reused, **counts}

    # one lookup table per run instead of two queries per result line
    subs = list(Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses'))
    by_name, by_ip = {}, {}
    for sub in subs:
        by_name.setdefault(sub.name, sub)
        for ip in sub.ip_addresses.all():
            by_ip.setdefault(ip.address, sub)

    profiles = ['normal', 'light'] if stream is stream_nuclei else ['normal']  # injected test streams cannot be lightened
    scanned = []
    # a target another pipeline of this project is scanning right now is left to it
    with ledger.claim_many(f'{service}@{project}', todo) as won:
        won_targets = [t for t in todo if t in set(won)]
        if not won_targets:
            activity.log('run_check', f'Nuclei skipped for {domain.name}: its targets are being scanned by another scan',
                         project=project, scan_id=scan.id)
            return {'targets': len(targets), 'findings': 0, 'reused': reused, **counts}
        message = (f'Nuclei is running a focused pass for {domain.name} ({", ".join(sorted(tags))}), scan #{scan.id}' if tags else
                   f'Nuclei is scanning {len(won_targets)} targets for {domain.name}, info severity and up, scan #{scan.id}')
        if covered:
            message += f' ({len(covered)} already scanned in the last {ledger.ttl_label(service)})'
        running = activity.log('run_check', message, project=project, status='running', scan_id=scan.id)
        try:
            for start in range(0, len(won_targets), NUCLEI_CHUNK):
                chunk = won_targets[start:start + NUCLEI_CHUNK]
                with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as f:
                    f.write('\n'.join(chunk) + '\n')
                    path = f.name
                try:
                    for profile in profiles:
                        kwargs = ({'tags': tags} if tags else {})
                        if severities:
                            kwargs['severities'] = severities
                        if profile != 'normal':
                            kwargs['profile'] = profile
                        try:
                            for line in stream(path, **kwargs):
                                try:
                                    data = parse_nuclei_result(line)
                                except (KeyError, TypeError):
                                    continue
                                host = host_of(line)
                                sub = by_name.get(host) or by_ip.get(host)
                                vuln, created = save_vulnerability(
                                    target_domain=domain, scan_history=scan, subdomain=sub,
                                    http_url=line.get('matched-at') or line.get('host') or host, **data)
                                sev = line.get('info', {}).get('severity', 'unknown')
                                counts[sev if sev in counts else 'unknown'] += 1
                                if created:
                                    new += 1
                                    DiscoveryEvent.objects.create(scan=scan, domain=domain, type='FINDING', label=f"{data['name']} ({sev})",
                                                                  host=host, module='nuclei')
                                    if NUCLEI_SEVERITY_MAP.get(sev, -1) >= 2:  # medium and up deserve a line in the AI feed
                                        activity.log('validate', f"Nuclei confirmed {data['name']} ({sev}) on {host}",
                                                     project=project, severity=sev)
                            break
                        except MemoryKill:
                            if profile == profiles[-1]:
                                raise
                            logger.warning('nuclei was stopped for memory on scan %s; retrying with fewer parallel hosts', scan_id)
                            activity.log('run_check', f'Nuclei ran out of memory on {domain.name}; retrying with fewer parallel hosts',
                                         project=project, scan_id=scan.id)
                finally:
                    os.unlink(path)
                ledger.record(service, chunk, project, scan)
                scanned += chunk
        except Exception as exc:  # noqa: BLE001
            logger.exception('nuclei failed for scan %s', scan_id)
            ledger.record(service, [t for t in won_targets if t not in set(scanned)], project, scan, 'failed')
            activity.settle(running, 'failed', message=f'Nuclei failed for {domain.name}: {exc}')
            return {'targets': len(targets), 'findings': new, 'reused': reused, 'error': str(exc)}
    activity.settle(running, 'done', message=(
        f"Nuclei finished {domain.name}: {new} finding{'s' if new != 1 else ''} "
        f"({counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low, {counts['info']} info)"), **counts)
    return {'targets': len(targets), 'findings': new, 'reused': reused, **counts}


LIGHT_SERVICE = 'nuclei-light'


def tech_name_from(line):
    """The technology a ``http/technologies`` result names. The tech-detect template reports it as the matcher; the others
    are named for it ("Nginx version", "Apache detect"), with an extracted version appended as ``Name:1.2``."""
    info = line.get('info') or {}
    if line.get('template-id') == 'tech-detect' and line.get('matcher-name'):
        name = line['matcher-name']
    else:
        name = re.sub(r'\s+(version|detect|detected|detection|server|fingerprint)$', '', (info.get('name') or '').strip(), flags=re.I)
    name = (name or '').strip()[:100]
    version = next((str(v) for v in line.get('extracted-results') or [] if v and str(v)[0].isdigit()), '')
    return f'{name}:{version[:30]}' if name and version else name


def reuse_technologies(scan, project, hosts):
    """Copy the technologies another scan of this project recorded for ``hosts`` onto this scan's rows for them. Returns how
    many hosts got any."""
    from startScan.models import Subdomain
    mine = {s.name: s for s in Subdomain.objects.filter(scan_history=scan, name__in=hosts).prefetch_related('technologies')
            if not s.technologies.all()}
    if not mine:
        return 0
    source = {}
    for other in Subdomain.objects.filter(target_domain__project_id=project, name__in=list(mine)).exclude(scan_history=scan) \
            .prefetch_related('technologies').order_by('-id').iterator(chunk_size=500):
        if other.name not in source and other.technologies.all():
            source[other.name] = [t.id for t in other.technologies.all()]
    through = Subdomain.technologies.through
    through.objects.bulk_create([through(subdomain_id=mine[name].pk, technology_id=tid) for name, ids in source.items() for tid in ids])
    return len(source)


def run_light_nuclei(scan_id, stream=stream_nuclei, force=False):
    """The light pass: nuclei's HTTP and technology templates over every discovered host, quick and low on memory. Each
    technology it detects is stored on the host, with the same Technology rows bbot fills, so search, the CVE correlation
    and the AI see them. Hosts this project's light pass covered inside the TTL are not scanned again: they take the
    technologies recorded then. Returns ``{'targets', 'technologies', 'hosts', 'techs': {host: [names]}}``."""
    from cveFeed import activity, ledger
    from reNgine.resources import MemoryKill
    from startScan.models import ScanHistory, Subdomain, Technology
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    domain, project = scan.domain, scan.domain.project_id
    targets = build_targets(*scan_targets(scan))
    if not targets:
        activity.log('run_check', f'Nuclei technology pass skipped for {domain.name}: discovery found nothing to scan',
                     project=project, scan_id=scan.id)
        return {'targets': 0, 'technologies': 0, 'hosts': 0, 'techs': {}}
    service = f'{LIGHT_SERVICE}:{approved_templates()[1]}' if stream is stream_nuclei else LIGHT_SERVICE
    covered = set() if force else ledger.fresh(service, targets, project)
    todo = [t for t in targets if t not in covered]
    reused = reuse_technologies(scan, project, {host_of({'host': t}) for t in covered}) if covered else 0
    by_name = {s.name: s for s in Subdomain.objects.filter(scan_history=scan)}
    by_ip = {}
    for sub in by_name.values():
        for ip in sub.ip_addresses.all():
            by_ip.setdefault(ip.address, sub)
    found, scanned = {}, []
    tech_rows, pending = {}, set()  # one Technology lookup per name per run; the host links are written once per chunk
    link = Subdomain.technologies.through

    def flush_links():
        if pending:
            link.objects.bulk_create([link(subdomain_id=s, technology_id=t) for s, t in pending], ignore_conflicts=True)
            pending.clear()
    with ledger.claim_many(f'{service}@{project}', todo) as won:
        won_targets = [t for t in todo if t in set(won)]
        if not won_targets:
            activity.log('run_check', f'Nuclei technology pass for {domain.name}: ' + (
                f'all {len(targets)} targets were scanned in the last {ledger.ttl_label(service)}' if not todo else
                'its targets are being scanned by another scan') + (f', {reused} host(s) reused' if reused else ''),
                project=project, scan_id=scan.id)
            return {'targets': len(targets), 'technologies': 0, 'hosts': 0, 'techs': {}, 'reused': reused}
        message = f'Nuclei is fingerprinting {len(won_targets)} targets for {domain.name}, HTTP and technology templates, scan #{scan.id}'
        if covered:
            message += f' ({len(covered)} already scanned in the last {ledger.ttl_label(service)})'
        running = activity.log('run_check', message, project=project, status='running', scan_id=scan.id)
        try:
            for start in range(0, len(won_targets), NUCLEI_CHUNK):
                chunk = won_targets[start:start + NUCLEI_CHUNK]
                with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as f:
                    f.write('\n'.join(chunk) + '\n')
                    path = f.name
                try:
                    for line in stream(path, **({'tech': True} if stream is stream_nuclei else {})):
                        name = tech_name_from(line)
                        sub = by_name.get(host_of(line)) or by_ip.get(host_of(line))
                        if not (name and sub):
                            continue
                        if name not in tech_rows:
                            tech_rows[name] = Technology.objects.filter(name=name).order_by('id').first() \
                                or Technology.objects.create(name=name)
                        pending.add((sub.pk, tech_rows[name].pk))
                        found.setdefault(sub.name, set()).add(name)
                finally:
                    os.unlink(path)
                    flush_links()  # what a killed chunk already saw is kept
                ledger.record(service, chunk, project, scan)
                scanned += chunk
        except Exception as exc:  # noqa: BLE001 - includes MemoryKill: the pass is best effort, the pipeline carries on
            logger.exception('nuclei technology pass failed for scan %s', scan_id)
            ledger.record(service, [t for t in won_targets if t not in set(scanned)], project, scan, 'failed')
            activity.settle(running, 'failed', message=f'Nuclei technology pass failed for {domain.name}: {exc}')
            return {'targets': len(targets), 'technologies': sum(len(v) for v in found.values()), 'hosts': len(found),
                    'techs': {h: sorted(v) for h, v in found.items()}, 'reused': reused, 'error': str(exc)}
    n = sum(len(v) for v in found.values())
    activity.settle(running, 'done', message=(
        f'Nuclei technology pass on {domain.name}: {n} technolog{"ies" if n != 1 else "y"} on {len(found)} host(s)'
        + (f', {reused} host(s) reused' if reused else '')), technologies=n, hosts=len(found))
    return {'targets': len(targets), 'technologies': n, 'hosts': len(found),
            'techs': {h: sorted(v) for h, v in found.items()}, 'reused': reused}


def _target_strings(sub):
    """The nuclei targets for one host: its name, plus host:port for each open port off the web defaults."""
    from startScan.models import open_ports
    out = [sub.name]
    for ip in sub.ip_addresses.all():
        out += [f'{sub.name}:{p.number}' for p in open_ports(ip) if p.number not in DEFAULT_PORTS]
    return list(dict.fromkeys(out))


def run_cve_checks(scan, subs, provider, cve_runner=None, force=False):
    """For each host of the scan with CVE matches, run the CVE's template (installed, or AI-written and validated) against it.
    Only fire and smoke CVEs, at most MAX_CVES_PER_HOST per host, and a host this project already checked for that CVE inside
    the TTL is left out (unless ``force``: a re-test after a change). Every CVE is its own non-fatal step. Returns ``{'cves': n, 'hosts': n, 'vulnerable': [...]}``."""
    from cveFeed import ledger
    from cveFeed.autofire import HOT_TIERS
    from cveFeed.nuclei_templates import MAX_CVES_PER_HOST
    from cveFeed.models import CVEMatch
    from cveFeed.threat import HEAT_RANK
    if cve_runner is None:
        from cveFeed.templategen import run_cve_tests as cve_runner
    project = scan.domain.project_id
    wanted, tier_of = {}, {}  # cve -> hosts; cve -> heat rank
    per_host = {}
    for m in CVEMatch.objects.filter(subdomain__in=subs).exclude(ai_verdict='not_affected').exclude(distro_status='patched') \
            .select_related('cve_entry', 'subdomain'):
        tier = m.cve_entry.threat_tier
        if tier in HOT_TIERS:
            # at equal heat a match whose version is in the affected range outranks one with no version to check
            per_host.setdefault(m.subdomain.name, []).append(
                (HEAT_RANK.get(tier, 0), m.version_in_range is True, m.cve_entry.cvss or 0, m.cve_entry))
    for host, items in per_host.items():
        for _rank, _in_range, _cvss, cve in sorted(items, key=lambda i: i[:3], reverse=True)[:MAX_CVES_PER_HOST]:
            wanted.setdefault(cve, []).append(host)
    vulnerable, tested, not_tested = [], set(), set()
    for cve, hosts in wanted.items():
        service = cve_service(cve.cve_id)
        done = set() if force else set(ledger.fresh(service, hosts, project))  # one query per CVE, not one per host
        todo = list(hosts) if force else [h for h in hosts if h not in done]
        if not todo:
            continue
        try:
            outcome = cve_runner(cve, todo, provider=provider, project=project)
        except Exception:  # noqa: BLE001 - one CVE failing must not stop the rest
            logger.exception('CVE check %s failed for scan %s', cve.cve_id, scan.id)
            ledger.record(service, todo, project, scan, 'failed')
            not_tested.update(todo)
            continue
        rows = outcome.get('results', []) if isinstance(outcome, dict) else []
        results = {r.get('host'): r for r in rows if isinstance(r, dict) and r.get('host') in todo}
        done_hosts = [h for h in todo if h in results and not results[h].get('error')]
        failed_hosts = [h for h in todo if h not in results or results[h].get('error')]
        if done_hosts:
            ledger.record(service, done_hosts, project, scan)
        if failed_hosts:
            ledger.record(service, failed_hosts, project, scan, 'failed')
            not_tested.update(failed_hosts)
        tested.update(done_hosts)
        vulnerable += [(cve.cve_id, h) for h in done_hosts if results[h].get('vulnerable')]
    return {'cves': len(wanted), 'hosts': len(tested), 'not_tested': len(not_tested), 'vulnerable': vulnerable}


def run_targeted_nuclei(scan_id, stream=stream_nuclei, provider=False, light_techs=None, cve_runner=None,
                        force_cve_checks=False, force=False):
    """The AI-targeted pass. A profile is built for each host from everything gathered (bbot technologies, nmap services,
    the database exposure check, the light pass, CVE matches). The AI picks nuclei tags and severities from the tags the
    installed templates use (the static table is the fallback), hosts that share a choice are scanned together so nuclei
    runs once per group, and each CVE matched to a host gets its own template test. Whatever the ledger says was covered
    recently is not run again, except the CVE checks when ``force_cve_checks`` is set (a re-test after a change). ``provider=False``
    means "ask the configured provider"; None means no AI."""
    from cveFeed import activity
    from cveFeed.nuclei_templates import host_profile, plan_targeting, profile_sources
    from startScan.models import ScanHistory, Subdomain
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    domain, project = scan.domain, scan.domain.project_id
    if provider is False:
        try:
            from reNgine.ai_settings import get_configured_provider
            provider = get_configured_provider()
        except Exception:  # noqa: BLE001 - a misconfigured provider means the static table, not a failed scan
            logger.warning('no usable AI provider for the targeted nuclei pass', exc_info=True)
            provider = None
    hostnames, _ips, _ports = scan_targets(scan)  # the same filter as every other stage: nothing that resolves inside
    subs = [sub for sub in Subdomain.objects.filter(scan_history=scan).prefetch_related(
        'technologies', 'ip_addresses__ports', 'vulnerability_set', 'cve_matches__cve_entry') if sub.name in hostnames]
    if not subs:
        activity.log('run_check', f'Targeted nuclei skipped for {domain.name}: discovery found nothing to scan',
                     project=project, scan_id=scan.id)
        return {'targets': 0, 'findings': 0, 'groups': 0, 'hosts': 0, 'skipped': 0, 'cves': 0}
    by_host = {sub.name: sub for sub in subs}
    light = light_techs or {}
    profiles = {sub.name: host_profile(sub, light.get(sub.name, ())) for sub in subs}
    groups, skipped = plan_targeting(profiles, provider)
    result = {'targets': 0, 'findings': 0, 'groups': len(groups), 'hosts': len(profiles) - len(skipped), 'skipped': len(skipped),
              'reused': 0}
    errors = []
    if skipped:
        activity.log('run_check', f'Targeted nuclei on {domain.name}: {len(skipped)} host(s) with nothing identified to aim at, '
                     f'left to the CVE checks', project=project, scan_id=scan.id)
    for group in groups:
        for host in group['hosts'][:5]:
            sources = ', '.join(profile_sources(profiles[host]))
            activity.log('run_check', f'nuclei targeted scan of {host}: {", ".join(group["tags"][:8])}' +
                         (f' (from {sources})' if sources else ''), project=project, scan_id=scan.id)
        if len(group['hosts']) > 5:
            activity.log('run_check', f'nuclei targeted scan of {len(group["hosts"]) - 5} more host(s) with the same tags',
                         project=project, scan_id=scan.id)
        targets = [t for host in group['hosts'] for t in _target_strings(by_host[host])]
        try:
            out = run_nuclei(scan_id, stream=stream, tags=group['tags'], targets=targets,
                             severities=list(group['severities']) or None, **({'force': True} if force else {}))
        except Exception as exc:  # noqa: BLE001 - one group failing must not stop the others
            logger.exception('targeted nuclei group failed for scan %s', scan_id)
            errors.append(str(exc))
            continue
        result['targets'] += out.get('targets', 0)
        result['findings'] += out.get('findings', 0)
        result['reused'] += out.get('reused', 0)
        if out.get('error'):
            errors.append(out['error'])
    try:
        checks = run_cve_checks(scan, subs, provider, cve_runner, force=force_cve_checks)
    except Exception as exc:  # noqa: BLE001
        logger.exception('CVE checks failed for scan %s', scan_id)
        checks = {'cves': 0, 'hosts': 0, 'vulnerable': []}
        errors.append(str(exc))
    result.update(cves=checks['cves'], cve_hosts=checks['hosts'], vulnerable=checks['vulnerable'])
    if errors:
        result['error'] = errors[0][:290]
    return result
