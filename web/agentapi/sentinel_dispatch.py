"""Dispatch-or-local: the one branch the scan pipeline takes before it runs nmap, naabu or nuclei itself.

For each of the three stages this phase covers, the pipeline asks here first: is there a live, eligible Sentinel for this
project with free capacity and the right capability? If not (the common case today: a project with no Sentinels
registered), every function below is a no-op and returns at once, so the pipeline runs exactly as it did before this
module existed - that is the single most important property here, and it is what the regression test in
``tests.test_sentinel_dispatch`` proves. If there is one, a ``SentinelTask`` is created and this module waits, bounded, for
it to finish; on success its typed, clipped result is parsed into the *same shape* the local tool's own output already
takes and handed to the *same persistence function* local execution uses (``cveFeed.nmap_scan.persist_inventory``,
``cveFeed.naabu_scan.persist_open_ports``, or - for nuclei - a reconstructed result line fed through the untouched
``cveFeed.nuclei_scan._run_nuclei`` loop via its own ``stream`` seam). On timeout, failure or no Sentinel, the caller falls
back to running the tool locally, exactly as today; the subprocess-running code itself (``nmap_scan.run_nmap_xml``,
``naabu_scan.run_naabu``, ``nuclei_scan.stream_nuclei``) is never touched by this module.

This phase dispatches a whole stage (all of a chunk's addresses, or a chunk's nuclei targets) as a single SentinelTask to
one Sentinel; splitting a stage across multiple Sentinels, or letting several share one project's work, is left to a
follow-up once there is real-world experience with how many Sentinels a project actually registers.
"""
import os
import time

MAX_ADDRESSES = 64  # kept equal to sentinel_broker.MAX_ADDRESSES: everything beyond this in one stage call is scanned locally
DISPATCH_POLL_INTERVAL = 0.5  # seconds between checks while waiting for a dispatched task to finish


def _dispatch_timeout():
    """CVENGINE_SENTINEL_DISPATCH_TIMEOUT: seconds a stage waits for a dispatched Sentinel task before falling back to
    running the tool locally. Default 90s: long enough for a Sentinel on an ordinary network to pick up, run and report a
    single chunk, short enough that a quiet or overloaded Sentinel never meaningfully delays a scan."""
    try:
        return max(1, int(os.environ.get('CVENGINE_SENTINEL_DISPATCH_TIMEOUT', '90')))
    except ValueError:
        return 90


def any_scanner_for(project, kind):
    from agentapi import sentinel_broker
    return sentinel_broker.any_scanner_for(project, kind)


def dispatch_or_none(project, kind, target, host='', ips=None, scan=None, timeout=None, created_by=None, priority=1):
    """Create one SentinelTask for ``kind`` and wait for it, or return ``None`` at once with no side effect when no live,
    eligible Sentinel exists for ``project`` right now. Returns the task's typed ``result`` dict on success; ``None`` on
    timeout, failure, or no Sentinel - in every one of those cases the caller runs the tool locally instead."""
    from agentapi import sentinel_broker
    from agentapi.models import SentinelTask
    if not sentinel_broker.any_scanner_for(project, kind):
        return None
    timeout = _dispatch_timeout() if timeout is None else timeout
    task = SentinelTask.objects.create(project=project, scan=scan, kind=kind, target=target, host=(host or '')[:500],
                                       ips=list(ips or [])[:MAX_ADDRESSES], priority=priority, created_by=created_by)
    deadline = time.monotonic() + timeout
    while True:
        task.refresh_from_db()
        if task.status in ('done', 'failed', 'expired'):
            break
        if time.monotonic() >= deadline:
            sentinel_broker.expire(task, 'the dispatch wait timed out; the stage fell back to local execution')
            break
        time.sleep(min(DISPATCH_POLL_INTERVAL, max(0.0, deadline - time.monotonic())))
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

def _finding_to_nuclei_line(finding):
    """One Sentinel-reported nuclei finding, reshaped into the same dict ``reNgine.tasks.parse_nuclei_result`` and
    ``cveFeed.nuclei_scan.host_of`` already read from nuclei's own ``-jsonl`` output. Fields nuclei's full output carries
    that a Sentinel's typed, clipped result never does (the raw request/response transcript, a curl command) are left
    out, not guessed: the untyped nuclei line already tolerates them being absent."""
    return {'host': finding.get('host') or finding.get('matched_at') or '', 'matched-at': finding.get('matched_at') or '',
            'type': 'http', 'template': finding.get('template_id') or '', 'template-id': finding.get('template_id') or '',
            'template-url': [], 'matcher-name': '', 'curl-command': None, 'request': None, 'response': None,
            'extracted-results': finding.get('extracted_results') or [],
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
        tags = sorted(kwargs.get('tags') or [])
        severities = list(kwargs.get('severities') or [])
        payload = {'targets': targets[:MAX_ADDRESSES], 'tags': tags, 'severities': severities}
        result = dispatch_or_none(project, kind, payload, ips=[], scan=scan, timeout=timeout)
        if result is None:
            yield from stream_nuclei(targets_file, **kwargs)
            return
        for finding in result.get('findings', []):
            yield _finding_to_nuclei_line(finding)
    return stream
