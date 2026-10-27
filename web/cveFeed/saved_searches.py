"""Saved searches with alerts: a host search a person keeps (the Hosts page syntax) that is re-run on a schedule and reports
what changed.

``evaluate_due`` is the beat task's body: it takes the searches whose time has come (oldest first, a bounded number per run,
and it stops early when its time budget is spent) and ``evaluate`` runs each one through the same code path the interactive search
uses (``agentapi.services``), so a saved search finds exactly what the Hosts page finds. Three rules keep it safe:

- Rights are the owner's, checked when the search runs. A search whose owner left the project (or was deactivated) is switched
  off with a reason, never run with the rights it was saved under.
- A host is one machine, however many names it has: matches are told apart by the same host key the Hosts page uses (the project
  plus the set of IP addresses), so ``example.test`` and ``www.example.test`` on one server are one match, not two.
- The first evaluation only records the baseline. Alerts begin with the second, so saving a search never floods a channel with
  every host that already matched. A search matching more than MAX_MATCHES hosts is "too broad": it is not alerted on until it
  is narrowed, because a set that big shifts all the time and cannot be compared cheaply.

One message per search per evaluation goes out through ``notify.saved_search`` (Settings, Notifications), plus one line in the
activity feed. Work is bounded everywhere: BATCH searches per run, a database timeout per search, SAMPLE hosts per message.
"""
import hashlib
import logging
import time
from datetime import timedelta

from django.db import DatabaseError, connection, transaction
from django.utils import timezone

from agentapi.services import ApiError, check_search, search_host_rows
from cveFeed import activity, notify
from cveFeed.counts import with_host_key
from cveFeed.models import SavedSearch
from tenancy import roles

logger = logging.getLogger(__name__)

BATCH = 25  # searches evaluated per beat run; the rest wait for the next one
BUDGET_SECONDS = 300  # no new search is started after this long in one run
STATEMENT_TIMEOUT_MS = 20000  # one search's queries may not hold the database longer than this
LOCK_SECONDS = 120
MAX_NAMES = 5  # new or departed hosts named in the activity line (the notification lists its own sample)


def _next_run(search, now):
    return now + timedelta(minutes=SavedSearch.FREQUENCIES.get(search.frequency, SavedSearch.FREQUENCIES['daily']))


def host_digest(host_key):
    """A short stable id for a host key: what is stored per matched host instead of the (long, address-id based) key."""
    return hashlib.sha1(host_key.encode()).hexdigest()[:12]


def current_matches(project, terms):
    """``({digest: host name} highest score first, too_broad)`` for the hosts that match now: one row per host, found with the
    interactive search's own query. Reads at most MAX_MATCHES + 1 rows; the extra one is how "too broad" is known."""
    limit = SavedSearch.MAX_MATCHES + 1
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute('SET LOCAL statement_timeout = %s', [STATEMENT_TIMEOUT_MS])
        rows = list(with_host_key(search_host_rows(project, terms)).order_by('-score', 'name').values_list('host_key', 'name')[:limit])
    found = {host_digest(key): name for key, name in rows[:SavedSearch.MAX_MATCHES]}
    return found, len(rows) > SavedSearch.MAX_MATCHES


def access_problem(search):
    """Why the owner may no longer run this search, or ''. Checked at every evaluation against the owner's rights as they are now."""
    owner = search.owner
    if not owner.is_active:
        return 'the owner of this search is deactivated'
    if not roles.effective_role(owner, search.project):
        return 'the owner of this search no longer has access to the project'
    return ''


def _save(search, **fields):
    """Write an evaluation's outcome, unless the search was edited meanwhile (its query changed, so the outcome describes a
    search that no longer exists)."""
    return SavedSearch.objects.filter(pk=search.pk, query=search.query).update(**fields)


def _disable(search, reason, now):
    _save(search, enabled=False, last_status='disabled', last_error=reason[:200], last_run_at=now)
    activity.log('saved_search', f'Saved search {search.name!r} was switched off: {reason}', project=search.project_id, search_id=search.pk)
    return {'status': 'disabled', 'reason': reason}


def _fail(search, what, now):
    # the message can hold paths or SQL, so only its type is stored; the full text goes to the worker log under a diagnostic id
    message = activity.diagnostic(f'Saved search {search.name!r}', what)
    _save(search, last_status='error', last_error='the search could not be run; see the activity feed', last_run_at=now,
          next_run_at=_next_run(search, now))
    activity.log('saved_search', message, project=search.project_id, status='failed', search_id=search.pk)
    return {'status': 'error'}


def _plural(n, noun):
    return f'{n} {noun}{"" if n == 1 else "s"}'


def evaluate(search, now=None):
    """Run one saved search now and report what changed. Returns ``{status, count, new_count, gone_count, baseline, alerted, new}``
    (``new``: up to five names) or ``{status: 'disabled' | 'error' | 'busy'}``. The caller decides whether the search is due. Two
    evaluations of one search never overlap (a run-now during the beat run): both would diff against the same baseline and alert twice."""
    from django.core.cache import cache
    key = f'cvengine:saved-search:{search.pk}'
    if not cache.add(key, 1, timeout=LOCK_SECONDS):
        return {'status': 'busy'}
    try:
        return _evaluate(search, now or timezone.now())
    finally:
        cache.delete(key)


def _evaluate(search, now):
    problem = access_problem(search)
    if problem:
        return _disable(search, problem, now)
    try:
        terms = check_search(search.query)
    except ApiError as exc:  # a filter changed its rules since the search was saved
        return _disable(search, f'the query is no longer valid ({exc.message})', now)
    try:
        found, too_broad = current_matches(search.project, terms)
    except DatabaseError as exc:  # a timeout or a lost connection: try again at the next time, never loop on it
        return _fail(search, f'{type(exc).__name__}: {exc}', now)
    due = {'last_run_at': now, 'next_run_at': _next_run(search, now), 'last_error': ''}
    if too_broad:
        _save(search, last_status='too_broad', last_match_count=SavedSearch.MAX_MATCHES + 1, **due)
        if search.last_status != 'too_broad':
            activity.log('saved_search', f'Saved search {search.name!r} matches more than {SavedSearch.MAX_MATCHES} hosts: narrow it to get alerts',
                         project=search.project_id, search_id=search.pk)
        return {'status': 'too_broad', 'count': SavedSearch.MAX_MATCHES + 1, 'new_count': 0, 'gone_count': 0, 'baseline': False, 'alerted': False, 'new': []}
    before = search.matched or {}
    baseline = search.baseline_at is None
    new = [name for key, name in found.items() if key not in before]
    gone = [name for key, name in before.items() if key not in found]
    count = len(found)
    reached = bool(search.threshold) and count >= search.threshold and (baseline or search.last_match_count < search.threshold)
    alert = {'new': new if search.alert_new else [], 'gone': gone if search.alert_gone else [], 'reached': reached}
    alerted = False
    if baseline:
        activity.log('saved_search', f'Saved search {search.name!r} started: {_plural(count, "host")} match now; alerts begin with the next check',
                     project=search.project_id, search_id=search.pk, count=count)
    elif alert['new'] or alert['gone'] or reached:
        alerted = _alert(search, alert, count)
    _save(search, matched=found, last_match_count=count, last_status='ok', baseline_at=search.baseline_at or now,
          **({'last_alert_at': now} if alerted else {}), **due)
    return {'status': 'ok', 'count': count, 'new_count': len(new), 'gone_count': len(gone), 'baseline': baseline, 'alerted': alerted, 'new': new[:MAX_NAMES]}


def _alert(search, alert, count):
    """One notification and one activity line for what this evaluation found. True when a channel was tried."""
    parts = []
    if alert['new']:
        parts.append(f'{_plural(len(alert["new"]), "new host")} ({", ".join(alert["new"][:MAX_NAMES])}{", ..." if len(alert["new"]) > MAX_NAMES else ""})')
    if alert['gone']:
        parts.append(f'{_plural(len(alert["gone"]), "host")} no longer match')
    if alert['reached']:
        parts.append(f'{count} matches reach the threshold of {search.threshold}')
    activity.log('saved_search', f'Saved search {search.name!r}: {"; ".join(parts)}', project=search.project_id, search_id=search.pk, count=count)
    return notify.saved_search(search, alert['new'], alert['gone'], count, alert['reached'])


def evaluate_due(now=None):
    """The beat task's body: evaluate the searches that are due, oldest first, at most BATCH of them and only while the time
    budget lasts. One search failing never stops the others."""
    now = now or timezone.now()
    started = time.monotonic()
    due = SavedSearch.objects.filter(enabled=True, next_run_at__lte=now).select_related('owner', 'project').order_by('next_run_at', 'id')[:BATCH]
    results = {'evaluated': 0, 'alerted': 0, 'disabled': 0, 'errors': 0}
    for search in due:
        if time.monotonic() - started > BUDGET_SECONDS:
            break
        try:
            outcome = evaluate(search, now)
        except Exception:  # noqa: BLE001 - a bug in one search must not stop the rest, and its next_run_at must still move on
            logger.exception('saved search %s failed', search.pk)
            _fail(search, 'unexpected error', now)
            outcome = {'status': 'error'}
        results['evaluated'] += 1
        results['alerted'] += bool(outcome.get('alerted'))
        results['disabled'] += outcome['status'] == 'disabled'
        results['errors'] += outcome['status'] == 'error'
    return results
