"""Dispatch-or-local: the one branch the scan pipeline takes before it runs nmap, naabu, nuclei or testssl.sh itself.

For each of the stages this phase covers, the pipeline asks here first: is there a live, eligible Sentinel for this
project with free capacity and the right capability? If not (the common case today: a project with no Sentinels
registered), every function below is a no-op and returns at once, so the pipeline runs exactly as it did before this
module existed - that is the single most important property here, and it is what the regression test in
``tests.test_sentinel_dispatch`` proves. If there is one, a ``SentinelTask`` is created and this module waits for it to
finish, under two different budgets: a short claim timeout (``_claim_timeout``, default 8s) for any Sentinel to even pick
the task up, and only once one has, the much longer completion timeout (``_dispatch_timeout``, default 90s) for it to
finish the work. A Sentinel with a free slot almost always claims it within its own poll interval, so one that is quiet or
offline costs a scan stage single-digit seconds, not the full completion budget, before falling back locally - while a
Sentinel that did pick the work up keeps the full budget (counted from when it claimed the task, not from when it was
created) to actually run it. **A Sentinel at its concurrency limit is not a missing one**: when every live, eligible Sentinel
is busy the task waits in the queue for a slot, under its own wait budget (``_queue_timeout``) separate from both, and the stage
falls back only when that runs out or the last live Sentinel goes away. On success its typed, clipped result is parsed into the *same shape* the local tool's own output already
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
                      'nmap_udp': 900, 'wpscan': 1800, 'openvas': 3600, 'discover': 1200}
DEFAULT_CEILING = 900
# Added to a kind's ceiling for each target beyond the first (an address of a chunk, a nuclei target): a chunk of 64 addresses takes longer than one.
PER_TARGET_SECONDS = {'nmap': 15, 'naabu': 10, 'nuclei_light': 20, 'nuclei_targeted': 30, 'nuclei_deep': 60}
DEFAULT_QUEUE_SECONDS = 300  # how long a stage waits for a free Sentinel slot when every live, eligible Sentinel is at its limit
REAP_EVERY = 10  # seconds between checks for a Sentinel whose lease ran out while a stage waits


def _dispatch_timeout(kind=None, targets=0):
    """Seconds a stage waits for a dispatched Sentinel task to *finish* once a Sentinel has claimed it, before falling back to running
    the tool locally: ``COMPLETION_CEILING`` for the kind, plus ``PER_TARGET_SECONDS`` for each target beyond the first (so a chunk of many
    addresses is not held to the budget of one), and for OpenVAS the instance's own ``CVENGINE_OPENVAS_MAX_HOURS``.
    ``CVENGINE_SENTINEL_DISPATCH_TIMEOUT``, when set, replaces every ceiling with that one number (an operator who wants scans never to wait
    long, and the tests)."""
    raw = os.environ.get('CVENGINE_SENTINEL_DISPATCH_TIMEOUT')
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    if kind == 'openvas':
        from cveFeed import openvas_scan
        return openvas_scan.max_hours() * 3600 + 600  # the task's own deadline, plus time to report
    base = COMPLETION_CEILING.get(kind, DEFAULT_CEILING)
    return base + PER_TARGET_SECONDS.get(kind, 0) * max(0, int(targets or 0) - 1)


def _queue_timeout(kind=None):
    """CVENGINE_SENTINEL_QUEUE_TIMEOUT: seconds a stage waits for a free slot when every live, eligible Sentinel is at its concurrency limit (default
    300), before the work runs locally instead. It starts when the task is created and is separate from the claim budget (a Sentinel with a free
    slot) and the completion budget (counted from the claim)."""
    try:
        return max(1, int(os.environ.get('CVENGINE_SENTINEL_QUEUE_TIMEOUT', str(DEFAULT_QUEUE_SECONDS))))
    except ValueError:
        return DEFAULT_QUEUE_SECONDS


def budgets():
    """The dispatch budgets as one object, for the Sentinels page: what each wait is, in seconds."""
    return {'claim_seconds': _claim_timeout(), 'queue_seconds': _queue_timeout(),
            'completion_seconds': {kind: _dispatch_timeout(kind) for kind in COMPLETION_CEILING},
            'per_target_seconds': dict(PER_TARGET_SECONDS), 'lease_seconds': int(_run_lease_seconds())}


def _run_lease_seconds():
    from agentapi import sentinel_broker
    return sentinel_broker.RUN_LEASE.total_seconds()


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


def any_scanner_for(project, kind, internal=False):
    from agentapi import sentinel_broker
    return sentinel_broker.any_scanner_for(project, kind, internal)


def _label(host, ips):
    host = (host or '').strip()
    if host:
        return host
    n = len(ips or [])
    return f'{n} address{"es" if n != 1 else ""}' if n else 'its target'


def dispatch_or_none(project, kind, target, host='', ips=None, scan=None, timeout=None, created_by=None, priority=1, redact_target=None,
                     internal=False):
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
    capacity = sentinel_broker.capacity_state(project, kind, internal)
    if capacity['state'] == 'none':
        return None
    targets = len(ips or []) or len((target or {}).get('targets') or (target or {}).get('hosts') or []) if isinstance(target, dict) else len(ips or [])
    timeout = _dispatch_timeout(kind, targets) if timeout is None else timeout
    task = SentinelTask.objects.create(project=project, scan=scan, kind=kind, target=target, host=(host or '')[:500],
                                       ips=list(ips or [])[:MAX_ADDRESSES], priority=priority, created_by=created_by)
    label = _label(host, ips)
    busy = capacity['state'] == 'busy'
    entry = activity.log('run_check', (f'Queued {kind} work for {label}: all {capacity["slots"]} Sentinel slot(s) are in use, waiting for one' if busy
                                       else f'Handed {kind} work for {label} to a Sentinel'),
                         project=project, status='running', scan_id=getattr(scan, 'id', None), sentinel_task_id=task.pk)
    started = time.monotonic()
    queue_budget = _queue_timeout(kind)
    claim_deadline = started + (queue_budget if busy else min(_claim_timeout(), timeout))
    run_deadline = None  # set once a Sentinel holds the task: the completion budget counts from the claim, not from the queueing
    never_claimed = False
    last_reap = started
    while True:
        task.refresh_from_db()
        if task.status in ('done', 'failed', 'expired'):
            break
        now = time.monotonic()
        if now - last_reap >= REAP_EVERY:  # a Sentinel that stopped heartbeating loses its lease here, not only when something else asks
            sentinel_broker.reap_expired()
            last_reap = now
            if task.status == 'queued' and sentinel_broker.capacity_state(project, kind, internal)['state'] == 'none':
                never_claimed = True  # the last live Sentinel went away while the task waited: nothing will take it
                sentinel_broker.expire(task, 'no live Sentinel is left to take the task; the stage fell back to local execution')
                break
        if task.status in ('claimed', 'running') and run_deadline is None:
            run_deadline = now + timeout
        if task.status == 'queued' and now >= claim_deadline:
            if (not busy and now < started + queue_budget
                    and sentinel_broker.capacity_state(project, kind, internal, exclude=task.pk)['state'] == 'busy'):
                busy, claim_deadline = True, started + queue_budget  # another stage took the free slot first: wait for the next one
                continue
            never_claimed = True
            sentinel_broker.expire(task, ('no Sentinel slot freed up in time; the stage fell back to local execution' if busy
                                          else 'no Sentinel claimed the task in time; the stage fell back to local execution'))
            break
        if run_deadline is not None and now >= run_deadline:
            sentinel_broker.expire(task, 'the dispatch wait timed out; the stage fell back to local execution')
            break
        horizon = run_deadline if run_deadline is not None else claim_deadline
        time.sleep(min(DISPATCH_POLL_INTERVAL, max(0.0, horizon - now)))
    sentinel = task.agent.name if task.agent_id else None
    if task.status == 'done':
        activity.settle(entry, 'done', message=f'Sentinel {sentinel} checked in {kind} work for {label}' if sentinel
                        else f'A Sentinel checked in {kind} work for {label}')
    elif task.status == 'failed':
        reason = (task.error or (task.result or {}).get('error') or 'no reason given')[:180]
        activity.settle(entry, 'failed', message=(f'Sentinel {sentinel} reported {kind} failed for {label}: {reason}' if sentinel
                        else f'A Sentinel reported {kind} failed for {label}: {reason}'))
    elif never_claimed:
        activity.settle(entry, 'expired', message=(f'No Sentinel slot freed up for {kind} work for {label} in time; it ran locally instead' if busy
                                                   else f'No Sentinel picked up {kind} work for {label} in time; it ran locally instead'))
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
    from concurrent.futures import ThreadPoolExecutor, wait
    targets = list(targets)
    if not targets:
        return []
    hosts = {t: _bare_host(t) for t in targets}
    unique = sorted(set(hosts.values()))
    n_workers = max(1, min(workers, len(unique)))
    pool = ThreadPoolExecutor(max_workers=n_workers, thread_name_prefix='sentinel-resolve')
    try:
        futures = {h: pool.submit(_resolves, h, timeout) for h in unique}
        # ``getaddrinfo`` cannot be interrupted, so the bound is on the wait: every lookup gets ``timeout`` per round of ``workers`` hosts, and a
        # name still unanswered then counts as not resolving (its thread ends when the resolver gives up), instead of one slow resolver holding
        # the whole stage.
        wait(futures.values(), timeout=timeout * -(-len(unique) // n_workers))
        live = {h: f.done() and not f.cancelled() and f.exception() is None and f.result() for h, f in futures.items()}
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
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


def _nuclei_target(kind, targets, kwargs):
    """The target of a dispatched nuclei task: the targets, the tags and severities this pass would run with locally, and the template policy the
    local run applies. The light pass is nuclei's technology fingerprint (``-tags tech -severity info``): ``run_light_nuclei`` asks for it with a
    ``tech`` flag only the unwrapped local stream takes, so the Sentinel is told the same here, or it would run the whole template library at
    every severity and the stage would time out. ``etags`` are the tags the local run always leaves out (``nuclei_scan.BASE_FLAGS``, ``dos``) and
    ``template_policy`` names the template policy in force (the read-only set, or everything when an administrator allowed it), so the client runs
    nothing this server would not; its ``bundle_sha256`` is the sha256 of the approved template archive the client fetches from
    ``GET /api/v1/sentinel/template-policy/bundle`` (``None`` until that archive exists: it is packed here when the approved snapshot is already
    cached, else on the first policy request)."""
    from agentapi import template_bundle
    from cveFeed import nuclei_scan
    tags, severities = sorted(kwargs.get('tags') or []), list(kwargs.get('severities') or [])
    if kind == 'nuclei_light' or kwargs.get('tech'):
        tags, severities = ['tech'], ['info']
    flags = nuclei_scan.BASE_FLAGS
    etags = flags[flags.index('-etags') + 1].split(',') if '-etags' in flags else []
    rev = nuclei_scan.policy_rev()
    return {'targets': targets, 'tags': tags, 'severities': severities, 'etags': etags,
            'template_policy': {'rev': rev, 'read_only': rev == nuclei_scan.TEMPLATE_POLICY_REV, 'bundle_sha256': template_bundle.sha256_if_ready()}}


def _local_kwargs(kind, kwargs):
    """The keyword arguments the local stream gets when a dispatched stage falls back to it: the light pass keeps its ``tech`` flag, which the
    wrapper in place of ``stream_nuclei`` hid from the caller, so the fallback is the quick fingerprint and not the whole template library."""
    return {**kwargs, 'tech': True} if kind == 'nuclei_light' else kwargs


def wrap_nuclei_stream(scan, kind, timeout=None, internal=False):
    """A ``stream(targets_file, **kwargs) -> iterable of result-line dicts`` matching ``nuclei_scan.stream_nuclei``'s own
    signature, for ``run_light_nuclei``/``run_targeted_nuclei``'s ``stream`` parameter. Returns the literal, unwrapped
    ``stream_nuclei`` function (not a wrapper around it) when no Sentinel is eligible, so ``_run_nuclei``'s own
    ``stream is stream_nuclei`` identity check, and every other local behaviour, is unaffected."""
    from cveFeed.nuclei_scan import stream_nuclei
    project = scan.domain.project
    if internal:  # the target is inside a private network: only a Sentinel there can run it, and there is never a local fallback
        def internal_stream(targets_file, **kwargs):
            if kwargs.get('secret_file'):  # a signed-in pass: a Sentinel is never sent a stored credential, and it must not run signed out and be reported as signed in
                raise RuntimeError('a signed-in nuclei pass cannot run on a Sentinel: the stored sign-in stays on this server')
            try:
                with open(targets_file, encoding='utf-8') as handle:
                    targets = [line.strip() for line in handle if line.strip()]
            except OSError:
                targets = []
            result = dispatch_or_none(project, kind, _nuclei_target(kind, targets[:MAX_ADDRESSES], kwargs), ips=[], scan=scan, internal=True,
                                      timeout=timeout)
            if result is None:
                raise RuntimeError('no Sentinel inside the network answered (one must declare network:internal and cover this project)')
            for finding in result.get('findings', []):
                yield _finding_to_nuclei_line(finding)
        return internal_stream
    if not any_scanner_for(project, kind):
        return stream_nuclei

    def stream(targets_file, **kwargs):
        if kwargs.get('secret_file'):
            # a signed-in pass (cveFeed.auth_nuclei) runs here: the stored credential never goes to a Sentinel, and a dispatched run would be
            # signed out while its findings were labelled as seen while signed in
            yield from stream_nuclei(targets_file, **_local_kwargs(kind, kwargs))
            return
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
            yield from stream_nuclei(targets_file, **_local_kwargs(kind, kwargs))
            return
        result = dispatch_or_none(project, kind, _nuclei_target(kind, live, kwargs), ips=[], scan=scan, timeout=timeout)
        if result is None:
            yield from stream_nuclei(targets_file, **_local_kwargs(kind, kwargs))
            return
        for finding in result.get('findings', []):
            yield _finding_to_nuclei_line(finding)
    return stream


# --- wpscan: a wrapping runner(url, token) -> report, like cveFeed.wpscan_scan's own seam ------------------------------

def wrap_wpscan_runner(project, scan=None, timeout=None, internal=False):
    """A ``runner(url, token) -> report`` for ``wpscan_scan.run_wpscan``'s own ``runner`` parameter, or the literal,
    unwrapped ``run_wpscan_process`` when no Sentinel is eligible (so ``runner is run_wpscan_process`` identity checks,
    and every other local behaviour, are unaffected). The project's WPScan API token travels with the dispatched task -
    the same blast radius it already has today, since it already leaves this process into a subprocess's environment -
    for this one run only: ``dispatch_or_none``'s ``redact_target`` scrubs it from the stored task once the task is
    done, failed or expired, so it never sits in the database beyond that. A Sentinel's reported outcome is classified
    by the exact same ``cveFeed.wpscan_scan._classify`` a local run's own exit code and report go through, so a
    dispatched site ends up ``NotWordPress``/``Blocked``/a normal report exactly as a local one would."""
    from cveFeed.wpscan_scan import run_wpscan_process
    if internal:  # a site inside a declared internal network: only a Sentinel inside it may run WPScan, and there is no local fallback
        from urllib.parse import urlsplit

        def internal_runner(url, token):
            from cveFeed.wpscan_scan import _classify
            host = urlsplit(url).hostname or ''
            result = dispatch_or_none(project, 'wpscan', {'url': url, 'token': token}, host=host, ips=[host], scan=scan, timeout=timeout,
                                      internal=True, redact_target=lambda t: {**t, 'token': '***'} if t.get('token') else t)
            if result is None:
                raise RuntimeError('no Sentinel inside the network ran WPScan (one must declare network:internal and wpscan and cover this project)')
            return _classify(result.get('report'), result.get('returncode', 1), result.get('stderr_tail', ''), token)
        return internal_runner
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
