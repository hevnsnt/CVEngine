"""The maintainer report (REST ``GET tuning/report``, MCP ``get_maintainer_report``): what the instance maintainer saw and did in the last 24 hours, in one
answer a person or an agent can read without calling five things. Read-only, for an App Admin, and instance health only: numbers, check titles and
setting names, never a host name, an address, a project or a finding.

Nothing here is measured again for the report. The signals are the ones the checks read (``agentapi.maintainer_signals.collect``, summarised by
``cveFeed.maintainer_checks.brief`` exactly as the operations snapshot does), the alerts are ``reviewer.open_alerts`` (so ``stale`` and the link to the decision
that answered each are the strip's own), and the decisions are ``autotune.serialize``. The size is bounded: at most ``MAX_DECISIONS`` decisions, each with its
reason and outcome sentence cut short, and the totals say how many there were.
"""
from datetime import timedelta

from django.db.models import Count, Q
from django.utils import timezone

WINDOW_HOURS = 24
MAX_DECISIONS = 50
MAX_ALERTS = 20
ALERT_KEYS = ('id', 'code', 'severity', 'title', 'stale', 'age_minutes', 'decision_id')
DECISION_KEYS = ('id', 'at', 'setting', 'label', 'old_value', 'new_value', 'source', 'actor', 'action', 'applied', 'pressure', 'phase', 'reason',
                 'resolution', 'resolved_by', 'outcome', 'outcome_detail', 'verify_at', 'verified_at', 'alerts', 'undoes')


def _signals():
    """The summary of the signals the checks read, as the operations snapshot sends it (``maintainer_checks.brief``)."""
    from agentapi import maintainer_signals, system_status
    from cveFeed import maintainer_checks
    depths = client = None
    try:
        client = system_status._broker_client()
        depths = system_status._queues()
    except Exception:  # noqa: BLE001 - the queue and Redis signals then say unknown
        depths = None
    collected = maintainer_signals.collect(depths, client)
    return maintainer_checks.brief(collected.get('signals'))['signals']


def _sentinels():
    from cveFeed import fleet
    try:
        facts = fleet.fleet_facts()
    except Exception:  # noqa: BLE001
        return {'live': None, 'live_remote': None, 'slots': None}
    return {'live': facts.get('live_sentinels'), 'live_remote': facts.get('live_remote'), 'slots': facts.get('slots')}


def _alerts():
    from cveFeed import reviewer
    return [{k: a.get(k) for k in ALERT_KEYS} for a in reviewer.open_alerts()[:MAX_ALERTS]]


def _decisions(since):
    from cveFeed import autotune
    from cveFeed.models import TuningDecision
    window = TuningDecision.objects.filter(created_at__gte=since)
    tally = window.aggregate(
        total=Count('pk'), helped=Count('pk', filter=Q(outcome='helped')), no_effect=Count('pk', filter=Q(outcome='no_effect')),
        regressed=Count('pk', filter=Q(outcome='regressed')), unknown=Count('pk', filter=Q(outcome='unknown')), reverted=Count('pk', filter=Q(outcome='reverted')),
        pending=Count('pk', filter=Q(applied=True, outcome='', verify_at__isnull=False)), recommended=Count('pk', filter=Q(applied=False)))
    total = tally.pop('total')
    shown = []
    for d in window.select_related('actor').order_by('-created_at', '-pk')[:MAX_DECISIONS]:
        item = autotune.serialize(d)
        item = {k: item[k] for k in DECISION_KEYS}
        item['reason'] = (item['reason'] or '')[:200]
        item['outcome_detail'] = (item['outcome_detail'] or '')[:200] or None
        shown.append(item)
    return shown, total, tally


def report(now=None):
    from cveFeed import autotune
    now = now or timezone.now()
    status = autotune.status()
    decisions, total, counts = _decisions(now - timedelta(hours=WINDOW_HOURS))
    return {
        'at': now.isoformat(), 'window_hours': WINDOW_HOURS,
        'tuning': {'mode': status.get('mode'), 'effective_mode': status.get('effective_mode'), 'killed': bool(status.get('killed')),
                   'agent_policy': status.get('agent_policy'), 'pinned': status.get('pinned') or []},
        'signals': _signals(), 'sentinels': _sentinels(), 'alerts': _alerts(),
        'decisions': decisions, 'decisions_total': total, 'decisions_shown': len(decisions), 'counts': counts,
    }
