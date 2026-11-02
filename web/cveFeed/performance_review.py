"""The three-hour review of scanner capacity, now a report only.

It used to move the scanner admission caps itself (a step kept in Redis, confirmed by an AI call). The auto-tuner (cveFeed.autotune) owns
those numbers now, in every mode: Auto moves them, Suggest recommends, Off leaves them to the person who tunes by hand. This review still
measures the window and works out what it would have done (``safe_candidate``), which the three-hour assessment review keeps with its record;
it no longer changes anything and no longer asks the AI. ``failure_cause`` and ``CAPACITY_PATTERN`` are shared with the auto-tuner's
measurements.
"""
import json
import logging
from collections import Counter
from datetime import timedelta

from django.db.models import Count, Q
from django.utils import timezone

from reNgine import resources

logger = logging.getLogger(__name__)
KINDS = ('nmap', 'bbot-standard', 'bbot-passive', 'nuclei', 'template-test', 'route-probe')
# Only stage names that identify the scanner kind can support a per-tool
# failure adjustment. Generic discovery errors cannot justify lowering an
# unrelated scanner's concurrency.
STAGE_KINDS = {'nmap_scan': 'nmap', 'nuclei_light_scan': 'nuclei',
               'nuclei_targeted_scan': 'nuclei', 'route_auth_scan': 'route-probe'}
# What a failed stage's stored message says about its cause (the texts the scanners raise: see resources.MemoryBusy, the nmap and Nuclei
# wrappers, route_auth). Only a failure that points at load can justify a lower admission cap; one that points at configuration (a missing
# template library, a policy refusal, an invalid argument, a missing key) will fail again at any concurrency, and a message that says
# neither is not acted on.
CAPACITY_PATTERN = (r'waited too long for memory|timed out|timeout|exceeded its total time budget|out of memory|cannot allocate memory|'
                    r'too many open files|resource temporarily unavailable|exited with status (-9|-11|137|139)( |:|$)|killed')
CONFIGURATION_PATTERN = (r'unavailable|not installed|not found|no such file|passed the read-only policy|permission denied|invalid|'
                         r'unknown flag|unrecognized|missing|api key|unauthori[sz]ed|forbidden|not scanned:|is excluded|prohibited|'
                         r'is not allowed|not permitted|unsupported')
COOLDOWN = 6 * 3600
KEY = 'cvengine:adaptive:decision'  # the last step the review applied, before the auto-tuner took over (read for its rollback rule)


def failure_cause(message):
    """``capacity``, ``configuration`` or ``other`` for a failed stage's stored message. A message that matches both reads as capacity
    (the stage ran out of something), because lowering a cap on a misjudged configuration error costs less than missing a real overload."""
    import re
    text = str(message or '')
    if re.search(CAPACITY_PATTERN, text, re.I):
        return 'capacity'
    if re.search(CONFIGURATION_PATTERN, text, re.I):
        return 'configuration'
    return 'other'


def summarize(samples, now):
    """Use a real two-hour span inside the three-hour window, not a single live snapshot."""
    valid = [s for s in samples if now - 3 * 3600 <= float(s.get('t', 0)) <= now and
             (s.get('memory') or {}).get('total_mb')]
    if len(valid) < 120 or max(s['t'] for s in valid) - min(s['t'] for s in valid) < 2 * 3600:
        return None
    free = sorted(max(0, min(1, s['memory'].get('available_mb', 0) / s['memory']['total_mb'])) for s in valid)
    waits, running = Counter(), Counter()
    for sample in valid:
        waits.update(sample.get('waiting_by_kind') or {})
        running.update(sample.get('running_by_kind') or {})
    return {'samples': len(valid), 'span_minutes': round((max(s['t'] for s in valid) - min(s['t'] for s in valid)) / 60),
            'free_p10': round(free[max(0, len(free)//10 - 1)], 3),
            'waiting': {kind: waits[kind] for kind in KINDS}, 'running': {kind: running[kind] for kind in KINDS}}


def safe_candidate(metrics, *, memory_kills=0, scanner_failures=0, scanner_runs=0, stage_outcomes=None, provider_throttles=0,
                   caps=None, bounds=None, previous=None, now=0):
    """Pure policy gate: one gradual change, with rollback after a harmful increase."""
    if metrics is None:
        return {'kind': 'none', 'direction': 'none', 'reason': 'Insufficient two-hour resource telemetry'}
    caps = caps or {}
    bounds = bounds or {}
    pressure = memory_kills > 0 or metrics['free_p10'] < 0.18
    stage_outcomes = stage_outcomes or {}

    def share(kind, key='capacity_failures'):
        counts = stage_outcomes[kind]
        return counts.get(key, 0) / counts['runs']

    def eligible(kind, counts):
        return kind in KINDS and counts['runs'] >= 10

    # a kind is lowered for the failures that point at load only: its other failures leave the cap alone (see CAPACITY_PATTERN)
    failing = sorted((kind for kind, counts in stage_outcomes.items() if eligible(kind, counts) and share(kind) > 0.15),
                     key=lambda kind: (share(kind), stage_outcomes[kind]['capacity_failures']), reverse=True)
    misconfigured = sorted((kind for kind, counts in stage_outcomes.items()
                            if eligible(kind, counts) and share(kind, 'configuration_failures') > 0.15 and kind not in failing))
    if previous and now - previous.get('at', 0) < COOLDOWN and not pressure and not failing:
        return {'kind': 'none', 'direction': 'none', 'reason': 'Capacity cooldown is active'}
    if pressure:
        if previous and previous.get('direction') == 'up' and caps.get(previous.get('kind'), 0) > previous.get('previous', 0):
            kind = previous['kind']
            return {'kind': kind, 'direction': 'down', 'reason': 'Rollback: memory pressure rose after capacity increase'}
        kinds = sorted(KINDS, key=lambda k: metrics['running'].get(k, 0), reverse=True)
        for kind in kinds:
            if metrics['running'].get(kind, 0) and caps.get(kind, 0) > bounds[kind][0]:
                return {'kind': kind, 'direction': 'down', 'reason': 'Measured memory pressure'}
        return {'kind': 'none', 'direction': 'none', 'reason': 'Pressure detected but all observed active kinds are at their minimum'}
    if failing:
        for kind in failing:
            if kind in bounds and caps.get(kind, 0) > bounds[kind][0]:
                reason = ('Rollback: scanner errors rose after capacity increase' if previous and
                          previous.get('kind') == kind and previous.get('direction') == 'up' and
                          caps[kind] > previous.get('previous', 0) else 'Measured failures in this scanner kind')
                return {'kind': kind, 'direction': 'down', 'reason': reason}
        return {'kind': 'none', 'direction': 'none', 'reason': 'Failing scanner kinds are at their minimum'}
    if misconfigured:
        return {'kind': 'none', 'direction': 'none',
                'reason': f'{misconfigured[0]} failures look like configuration, not capacity; the cap is unchanged'}
    if provider_throttles:
        return {'kind': 'none', 'direction': 'none', 'reason': 'Provider throttling was observed; no capacity increase'}
    if scanner_runs < 10 or scanner_failures:
        return {'kind': 'none', 'direction': 'none', 'reason': 'Too few successful scanner outcomes for a safe increase'}
    if metrics['free_p10'] < 0.4:
        return {'kind': 'none', 'direction': 'none', 'reason': 'Memory headroom is too small for an increase'}
    for kind in sorted(KINDS, key=lambda k: metrics['waiting'].get(k, 0), reverse=True):
        if metrics['waiting'].get(kind, 0) >= 20 and caps.get(kind, 0) < bounds[kind][1]:
            return {'kind': kind, 'direction': 'up', 'reason': 'Sustained queued work with low pressure and successful scans'}
    return {'kind': 'none', 'direction': 'none', 'reason': 'No sustained eligible wait or operator maximum reached'}


def review(now=None):
    from cveFeed.models import AIUsage
    from cveFeed.scan_control import pause_requested
    from startScan.models import ScanActivity

    now = now or timezone.now()
    if pause_requested():
        return {'status': 'no_change', 'reason': 'Scanning is paused'}
    store = resources.get_store()
    client = getattr(store, 'r', None)
    if client is None:
        return {'status': 'no_change', 'reason': 'Shared Redis admission control unavailable'}
    since = now - timedelta(hours=3)
    try:
        samples = resources.adaptive_history(since.timestamp())
        metrics = summarize(samples, now.timestamp())
        scanner_kind = (Q(name__icontains='nmap') | Q(name__icontains='nuclei') |
                        Q(name__icontains='bbot') | Q(name__icontains='discovery') |
                        Q(name='route_auth_scan'))
        recent = ScanActivity.objects.filter(scanner_kind, time__gte=since)
        scanner_runs = recent.filter(status__in=(0, 2)).count()
        scanner_failures = recent.filter(status=0).count()
        stage_outcomes = {}
        failed = Q(status=0)
        for row in recent.filter(name__in=STAGE_KINDS, status__in=(0, 2)).values('name').annotate(
                runs=Count('id'), failures=Count('id', filter=failed),
                capacity=Count('id', filter=failed & Q(error_message__iregex=CAPACITY_PATTERN)),
                configuration=Count('id', filter=failed & ~Q(error_message__iregex=CAPACITY_PATTERN)
                                    & Q(error_message__iregex=CONFIGURATION_PATTERN))):
            kind = STAGE_KINDS[row['name']]
            counts = stage_outcomes.setdefault(kind, {'runs': 0, 'failures': 0, 'capacity_failures': 0, 'configuration_failures': 0})
            counts['runs'] += row['runs']
            counts['failures'] += row['failures']
            counts['capacity_failures'] += row['capacity']
            counts['configuration_failures'] += row['configuration']
        memory_kills = max((s.get('memory_kills_3h', 0) for s in samples), default=0)
        throttles = AIUsage.objects.filter(started_at__gte=since, error_category__in=('rate_limit', 'provider_rate_limit')).count()
        previous = json.loads(client.get(KEY) or '{}')
        caps = {kind: resources.max_concurrent(kind) for kind in KINDS}
        bounds = {kind: resources.adaptive_bounds(kind) for kind in KINDS}
        candidate = safe_candidate(metrics, memory_kills=memory_kills, scanner_failures=scanner_failures,
            scanner_runs=scanner_runs, stage_outcomes=stage_outcomes, provider_throttles=throttles, caps=caps, bounds=bounds,
            previous=previous, now=now.timestamp())
        record = {'status': 'no_change', 'reason': candidate['reason'], 'metrics': metrics,
                  'scanner_runs': scanner_runs, 'scanner_failures': scanner_failures,
                  'stage_outcomes': stage_outcomes,
                  'memory_kills': memory_kills, 'provider_throttles': throttles,
                  'active_caps_before': caps, 'bounds': bounds}
        if previous.get('metrics') and metrics:
            record['previous_adjustment_outcome'] = {
                'kind': previous.get('kind'), 'previous_direction': previous.get('direction'),
                'free_p10_before': previous['metrics'].get('free_p10'),
                'free_p10_now': metrics['free_p10'], 'scanner_failures_now': scanner_failures,
                'memory_kills_now': memory_kills}
        if candidate['kind'] == 'none':
            return record
        # Report only: the auto-tuner moves the scanner limits (cveFeed.autotune), so two tuners never pull the same number.
        return {**record, 'candidate': candidate, 'note': 'scanner limits are moved by auto-tuning (Settings, configMaxxing), not by this review'}
    except Exception as exc:
        logger.error('three-hour performance review failed (%s)', type(exc).__name__)
        return {'status': 'no_change', 'reason': 'Performance telemetry or AI review failed; admission caps unchanged'}
