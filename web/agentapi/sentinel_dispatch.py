"""Dispatch-or-local: the one branch the scan pipeline takes before it runs nmap, naabu, nuclei or testssl.sh itself.

For each of the stages this phase covers, the pipeline asks here first: is there a live, eligible Sentinel for this
project with free capacity and the right capability? If not (the common case today: a project with no Sentinels
registered), every function below is a no-op and returns at once, so the pipeline runs exactly as it did before this
module existed - that is the single most important property here, and it is what the regression test in
``tests.test_sentinel_dispatch`` proves. If there is one, a ``SentinelTask`` is created and this module waits for it to
finish, under two different budgets: a short claim timeout (``_claim_timeout``, default 8s) for any Sentinel to even pick
the task up, and only once one has, the much longer completion timeout (``_dispatch_timeout``, default 90s) for it to
finish the work. A Sentinel that was going to take the task at all almost always claims it within its own poll interval,
so this means a quiet, offline or already-saturated Sentinel costs a scan stage single-digit seconds, not the full
completion budget, before falling back locally - while a Sentinel that did pick the work up keeps the full budget to
actually run it. On success its typed, clipped result is parsed into the *same shape* the local tool's own output already
takes and handed to the *same persistence function* local execution uses (``cveFeed.nmap_scan.persist_inventory``,
``cveFeed.naabu_scan.persist_open_ports``, or - for nuclei - a reconstructed result line fed through the untouched
``cveFeed.nuclei_scan._run_nuclei`` loop via its own ``stream`` seam). On timeout, failure or no Sentinel, the caller falls
back to running the tool locally, exactly as today; the subprocess-running code itself (``nmap_scan.run_nmap_xml``,
``naabu_scan.run_naabu``, ``nuclei_scan.stream_nuclei``) is never touched by this module.

This phase dispatches a whole stage (all of a chunk's addresses, or a chunk's nuclei targets) as a single SentinelTask to
one Sentinel; splitting a stage across multiple Sentinels, or letting several share one project's work, is left to a
follow-up once there is real-world experience with how many Sentinels a project actually registers.
"""
import ipaddress
import os
import time

MAX_ADDRESSES = 64  # kept equal to sentinel_broker.MAX_ADDRESSES: everything beyond this in one stage call is scanned locally
DISPATCH_POLL_INTERVAL = 0.5  # seconds between checks while waiting for a dispatched task to finish
RESOLVE_WORKERS = 16  # matches targetApp.target_types.blocked_names: one bounded parallel pass, never one lookup per target serially
RESOLVE_TIMEOUT = 5  # seconds one target's lookup may take


# The longest a stage waits for a Sentinel that has claimed its task, by kind: a Sentinel that keeps heartbeating a running task is
# doing the work, and a slow tool (nuclei over ten hosts, a full TLS audit) must not be run a second time locally because a short fixed
# wall clock ran out. A Sentinel that stops heartbeating loses its lease on its own (``sentinel_broker.reap_expired``, five minutes) and
# the wait ends then, so the ceiling only bounds a Sentinel that is alive but never finishes.
COMPLETION_CEILING = {'nmap': 900, 'naabu': 600, 'nuclei_light': 900, 'nuclei_targeted': 1800, 'nuclei_deep': 3600, 'testssl': 600,
                      'nmap_udp': 900, 'wpscan': 1800, 'openvas': 3600}
DEFAULT_CEILING = 900
REAP_EVERY = 10  # seconds between checks for a Sentinel whose lease ran out while a stage waits


def _dispatch_timeout(kind=None):
    """Seconds a stage waits for a dispatched Sentinel task to *finish* once a Sentinel has claimed it, before falling back to running
    the tool locally: ``COMPLETION_CEILING`` for the kind. ``CVENGINE_SENTINEL_DISPATCH_TIMEOUT``, when set, replaces every ceiling with
    that one number (an operator who wants scans never to wait long, and the tests)."""
    raw = os.environ.get('CVENGINE_SENTINEL_DISPATCH_TIMEOUT')
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return COMPLETION_CEILING.get(kind, DEFAULT_CEILING)


def _claim_timeout():
    """CVENGINE_SENTINEL_CLAIM_TIMEOUT: seconds a stage waits for *any* Sentinel to even claim a dispatched task before
    giving up on it and falling back to local execution, separate from (and much shorter than) the full completion
    timeout above. A Sentinel that polls ``next_task`` at all almost always claims new work within its own poll
    interval, so a task that is still ``queued`` after this short window is one no eligible Sentinel is going to pick
    up right now (it went offline, hit its concurrency cap, or was never really eligible) - there is no reason to make
    every scan stage eat the full completion timeout just to find that out. Once a Sentinel has claimed the task, this
    no longer applies: the work has already left this process, so the stage keeps waiting up to the completion timeout
    regardless of how long the Sentinel takes to run it. Default 8s."""
    try:
        return max(1, int(os.environ.get('CVENGINE_SENTINEL_CLAIM_TIMEOUT', '8')))
    except ValueError:
        return 8


def any_scanner_for(project, kind):
    from agentapi import sentinel_broker
    return sentinel_broker.any_scanner_for(project, kind)


def _label(host, ips):
    host = (host or '').strip()
    if host:
        return host
    n = len(ips or [])
    return f'{n} address{"es" if n != 1 else ""}' if n else 'its target'


def dispatch_or_none(project, kind, target, host='', ips=None, scan=None, timeout=None, created_by=None, priority=1, redact_target=None):
    """Create one SentinelTask for ``kind`` and wait for it, or return ``None`` at once with no side effect when no live,
    eligible Sentinel exists for ``project`` right now. Returns the task's typed ``result`` dict on success; ``None`` on
    timeout, failure, or no Sentinel - in every one of those cases the caller runs the tool locally instead. The hand-off
    and the check-in each get one ``run_check`` activity line (same kind every other scan-stage line already uses, so
    both the Live page and the Activity page show them with no changes of their own), so it is visible, in one place,
    whenever work actually left this server for a Sentinel and whether it came back.

    ``redact_target``, when given, is called with ``target`` once the task reaches a terminal state (done, failed or
    expired) and its return value replaces the stored ``target`` in the database - for a kind whose target carries a
    secret the Sentinel needed only for this one run (today, only WPScan's API token), so the secret does not sit in
    the database for the rest of the task's retention window once nothing needs it there any more."""
    from agentapi import sentinel_broker
    from agentapi.models import SentinelTask
    from cveFeed import activity
    if not sentinel_broker.any_scanner_for(project, kind):
        return None
    timeout = _dispatch_timeout(kind) if timeout is None else timeout
    task = SentinelTask.objects.create(project=project, scan=scan, kind=kind, target=target, host=(host or '')[:500],
                                       ips=list(ips or [])[:MAX_ADDRESSES], priority=priority, created_by=created_by)
    label = _label(host, ips)
    entry = activity.log('run_check', f'Handed {kind} work for {label} to a Sentinel', project=project, status='running',
                         scan_id=getattr(scan, 'id', None), sentinel_task_id=task.pk)
    deadline = time.monotonic() + timeout
    claim_deadline = time.monotonic() + min(_claim_timeout(), timeout)
    never_claimed = False
    last_reap = time.monotonic()
    while True:
        task.refresh_from_db()
        if task.status in ('done', 'failed', 'expired'):
            break
        now = time.monotonic()
        if now - last_reap >= REAP_EVERY:  # a Sentinel that stopped heartbeating loses its lease here, not only when something else asks
            sentinel_broker.reap_expired()
            last_reap = now
        if task.status == 'queued' and now >= claim_deadline:
            never_claimed = True
            sentinel_broker.expire(task, 'no Sentinel claimed the task in time; the stage fell back to local execution')
            break
        if now >= deadline:
            sentinel_broker.expire(task, 'the dispatch wait timed out; the stage fell back to local execution')
            break
        time.sleep(min(DISPATCH_POLL_INTERVAL, max(0.0, min(claim_deadline, deadline) - now)))
    sentinel = task.agent.name if task.agent_id else None
    if task.status == 'done':
        activity.settle(entry, 'done', message=f'Sentinel {sentinel} checked in {kind} work for {label}' if sentinel
                        else f'A Sentinel checked in {kind} work for {label}')
    elif task.status == 'failed':
        reason = (task.error or (task.result or {}).get('error') or 'no reason given')[:180]
        activity.settle(entry, 'failed', message=(f'Sentinel {sentinel} reported {kind} failed for {label}: {reason}' if sentinel
                        else f'A Sentinel reported {kind} failed for {label}: {reason}'))
    elif never_claimed:
        activity.settle(entry, 'expired', message=f'No Sentinel picked up {kind} work for {label} in time; it ran locally instead')
    else:  # claimed, but not reported back before the completion timeout
        activity.settle(entry, 'expired', message=f'No Sentinel checked in {kind} work for {label} in time; it ran locally instead')
    if redact_target is not None:
        SentinelTask.objects.filter(pk=task.pk).update(target=redact_target(target))
    return task.result if task.status == 'done' else None


# --- nmap: dispatch a chunk of addresses, persist a hit through the exact same function local nmap uses ---------------

def try_nmap(project, scan, targets, org_id=None, timeout=None):
    """``(remaining_targets, totals)``: the addresses a Sentinel fingerprinted (already persisted) are dropped from
    ``remaining_targets``, which the caller then runs through the unchanged local ``scan_in_chunks``/``run_nmap_xml``
    exactly as before. ``totals`` (``{'ports', 'hosts_with_os'}``) is the Sentinel's own contribution, to add to the
    local pass's totals."""
    targets = list(targets)
    zero = {'ports': 0, 'hosts_with_os': 0}
    if not any_scanner_for(project, 'nmap'):
        return targets, zero
    chunk, rest = targets[:MAX_ADDRESSES], targets[MAX_ADDRESSES:]
    result = dispatch_or_none(project, 'nmap', {'addresses': chunk}, ips=chunk, scan=scan, timeout=timeout)
    if result is None:
        return targets, zero
    from cveFeed.nmap_scan import persist_inventory
    inventory = [{'ip': host['ip'], 'os_guess': host.get('os_guess', ''), 'os_accuracy': None, 'ports': host.get('ports', [])}
                 for host in result.get('hosts', []) if host.get('ip')]
    totals = persist_inventory(inventory, org_id=org_id)
    return rest, totals


# --- testssl: one host:port at a time, the Sentinel's raw report items run through the same local evaluate() -----------

def try_testssl(project, host, ip, port, starttls=None, scan=None, timeout=None):
    """A Sentinel's testssl.sh report items for ``host:port`` (raw, in the exact shape ``cveFeed.testssl_scan.evaluate``
    already reads from a local run), or ``None`` when no Sentinel is eligible, on timeout, or on failure - in which case
    the caller runs ``run_testssl`` locally exactly as before. Unlike nmap/naabu/nuclei this is never chunked: a testssl
    run is already one host:port per call, locally or dispatched."""
    if not any_scanner_for(project, 'testssl'):
        return None
    target = {'host': host, 'ip': ip, 'port': port, 'starttls': starttls or ''}
    result = dispatch_or_none(project, 'testssl', target, host=host, ips=[ip], scan=scan, timeout=timeout)
    return (result or {}).get('items') if result is not None else None


# --- nmap -sU: raw XML through the Sentinel, parsed by the exact function a local run's own XML already goes through --

def try_nmap_udp(project, ip_address, scan=None, timeout=None):
    """The parsed ``nmap -sU`` host record for ``ip_address`` from a Sentinel's raw XML report, or ``None`` when no
    Sentinel is eligible, on timeout, or on failure - in which case the caller runs the local ``-sU`` scan exactly as
    before. Unlike every other dispatched kind here, the Sentinel's result is raw XML text, not pre-parsed JSON: UDP's
    own state vocabulary (``open|filtered``, extraports summarisation) and the NSE script output
    ``cveFeed.udp_scan.identify`` reads are read correctly only by ``cveFeed.nmap_scan.parse_xml`` (hardened against a
    custom ENTITY declaration precisely because it now also reads a Sentinel's report, not only this process's own
    nmap output), so that is the one function - local or dispatched - that ever turns the XML into a record. Never
    chunked: one address per task, like testssl."""
    if not any_scanner_for(project, 'nmap_udp'):
        return None
    result = dispatch_or_none(project, 'nmap_udp', {'address': ip_address}, ips=[ip_address], scan=scan, timeout=timeout)
    if result is None:
        return None
    from cveFeed.nmap_scan import parse_xml
    return next((h for h in parse_xml(result.get('xml') or '') if h.get('ip') == ip_address), None)


# --- naabu: an injectable runner wrapping cveFeed.naabu_scan.discover's own seam, untouched otherwise ------------------

def wrap_naabu_runner(project, scan, timeout=None):
    """A ``runner(ips) -> {ip: [open ports]}`` for ``naabu_scan.discover``'s own ``runner`` parameter, or ``None`` when no
    Sentinel is eligible (so ``discover`` uses its unmodified default, ``run_naabu``, exactly as today). The addresses a
    Sentinel actually attempted (its whole chunk, whether or not each had an open port: no entry means none, exactly as
    naabu's own JSON output already means) are never scanned locally too; anything beyond one chunk, or left over on a
    timeout, falls back to the real, unmodified ``naabu_scan.run_naabu``."""
    if not any_scanner_for(project, 'naabu'):
        return None

    def runner(ips):
        from cveFeed.naabu_scan import run_naabu
        ips = list(ips)
        chunk, rest = ips[:MAX_ADDRESSES], ips[MAX_ADDRESSES:]
        result = dispatch_or_none(project, 'naabu', {'addresses': chunk}, ips=chunk, scan=scan, timeout=timeout)
        found = dict((result or {}).get('ports') or {}) if result is not None else run_naabu(chunk)
        if rest:
            found.update(run_naabu(rest))
        return found
    return runner


# --- nuclei (light and targeted): an injectable stream matching cveFeed.nuclei_scan.stream_nuclei's own seam -----------

def _bare_host(target):
    """The hostname or address inside a nuclei target string built by ``nuclei_scan.build_targets`` (a bare host, a bare
    IP, or ``host:port`` for a non-default port)."""
    return target.rsplit(':', 1)[0].strip() if target.count(':') == 1 else target.strip()


def _resolves(host, timeout):
    import socket
    try:
        ipaddress.ip_address(host)
        return True  # a literal address needs no lookup
    except ValueError:
        pass
    try:
        return bool(socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP))
    except (socket.gaierror, UnicodeError, OSError):
        return False


def resolvable_targets(targets, workers=RESOLVE_WORKERS, timeout=RESOLVE_TIMEOUT):
    """The entries of ``targets`` whose host currently resolves, in order: a Sentinel is never handed a target this
    process cannot even look up, which would otherwise dispatch work for nothing and - because the stage that sent it
    marks its whole chunk scanned once the dispatched call returns, not target by target - leave a host that was never
    actually reached looking checked. A stale or deleted DNS record is the common case here (a host that resolved when
    it was first discovered may not resolve months later), not a name a tenant never controlled, so this is a plain
    resolvability check, not ``targetApp.target_types``'s prohibited-range gate: a target already passed that when it
    was added. One bounded parallel pass, like ``target_types.blocked_names``; never one lookup per target serially."""
    from concurrent.futures import ThreadPoolExecutor
    targets = list(targets)
    if not targets:
        return []
    hosts = {t: _bare_host(t) for t in targets}
    unique = sorted(set(hosts.values()))
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(unique))), thread_name_prefix='sentinel-resolve') as pool:
        live = dict(zip(unique, pool.map(lambda h: _resolves(h, timeout), unique)))
    return [t for t in targets if live.get(hosts[t])]

def _finding_to_nuclei_line(finding):
    """One Sentinel-reported nuclei finding, reshaped into the same dict ``reNgine.tasks.parse_nuclei_result`` and
    ``cveFeed.nuclei_scan.host_of`` already read from nuclei's own ``-jsonl`` output. Fields nuclei's full output carries
    that a Sentinel's typed, clipped result never does (the raw request/response transcript, a curl command) are left
    out, not guessed: the untyped nuclei line already tolerates them being absent. ``matcher-name`` is carried through from
    the Sentinel's own ``matcher_name`` field so a tech-detect template hit names a technology the same way
    ``cveFeed.nuclei_scan.tech_name_from`` already reads it from a locally-run nuclei line."""
    return {'host': finding.get('host') or finding.get('matched_at') or '', 'matched-at': finding.get('matched_at') or '',
            'type': 'http', 'template': finding.get('template_id') or '', 'template-id': finding.get('template_id') or '',
            'template-url': [], 'matcher-name': finding.get('matcher_name') or '', 'curl-command': None, 'request': None,
            'response': None, 'extracted-results': finding.get('extracted_results') or [],
            'info': {'name': finding.get('name') or '', 'severity': finding.get('severity') or 'unknown',
                     'description': finding.get('description') or '', 'classification': {}, 'reference': [],
                     'tags': finding.get('tags') or []}}


def wrap_nuclei_stream(scan, kind, timeout=None):
    """A ``stream(targets_file, **kwargs) -> iterable of result-line dicts`` matching ``nuclei_scan.stream_nuclei``'s own
    signature, for ``run_light_nuclei``/``run_targeted_nuclei``'s ``stream`` parameter. Returns the literal, unwrapped
    ``stream_nuclei`` function (not a wrapper around it) when no Sentinel is eligible, so ``_run_nuclei``'s own
    ``stream is stream_nuclei`` identity check, and every other local behaviour, is unaffected."""
    from cveFeed.nuclei_scan import stream_nuclei
    project = scan.domain.project
    if not any_scanner_for(project, kind):
        return stream_nuclei

    def stream(targets_file, **kwargs):
        try:
            with open(targets_file, encoding='utf-8') as handle:
                targets = [line.strip() for line in handle if line.strip()]
        except OSError:
            targets = []
        live = resolvable_targets(targets[:MAX_ADDRESSES])
        if not live:
            # every target in this chunk failed to resolve: a Sentinel would be asked to do nothing, and the local
            # fallback below would too (nuclei cannot reach what cannot be looked up either); run it anyway so the
            # existing "ran, found nothing" accounting is unchanged for a target that would already have gone through
            # stream_nuclei with no Sentinel in play.
            yield from stream_nuclei(targets_file, **kwargs)
            return
        tags = sorted(kwargs.get('tags') or [])
        severities = list(kwargs.get('severities') or [])
        payload = {'targets': live, 'tags': tags, 'severities': severities}
        result = dispatch_or_none(project, kind, payload, ips=[], scan=scan, timeout=timeout)
        if result is None:
            yield from stream_nuclei(targets_file, **kwargs)
            return
        for finding in result.get('findings', []):
            yield _finding_to_nuclei_line(finding)
    return stream


# --- wpscan: a wrapping runner(url, token) -> report, like cveFeed.wpscan_scan's own seam ------------------------------

def wrap_wpscan_runner(project, scan=None, timeout=None):
    """A ``runner(url, token) -> report`` for ``wpscan_scan.run_wpscan``'s own ``runner`` parameter, or the literal,
    unwrapped ``run_wpscan_process`` when no Sentinel is eligible (so ``runner is run_wpscan_process`` identity checks,
    and every other local behaviour, are unaffected). The project's WPScan API token travels with the dispatched task -
    the same blast radius it already has today, since it already leaves this process into a subprocess's environment -
    for this one run only: ``dispatch_or_none``'s ``redact_target`` scrubs it from the stored task once the task is
    done, failed or expired, so it never sits in the database beyond that. A Sentinel's reported outcome is classified
    by the exact same ``cveFeed.wpscan_scan._classify`` a local run's own exit code and report go through, so a
    dispatched site ends up ``NotWordPress``/``Blocked``/a normal report exactly as a local one would."""
    from cveFeed.wpscan_scan import run_wpscan_process
    if not any_scanner_for(project, 'wpscan'):
        return run_wpscan_process

    def runner(url, token):
        from cveFeed.wpscan_scan import _classify
        result = dispatch_or_none(project, 'wpscan', {'url': url, 'token': token}, scan=scan, timeout=timeout,
                                  redact_target=lambda t: {**t, 'token': '***'} if t.get('token') else t)
        if result is None:
            return run_wpscan_process(url, token)
        return _classify(result.get('report'), result.get('returncode', 1), result.get('stderr_tail', ''), token)
    return runner
