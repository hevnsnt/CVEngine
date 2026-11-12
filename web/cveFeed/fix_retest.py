"""Retest on fix: a finding marked fixed is checked again, and only a check that ran says it is gone.

(Not ``cveFeed.retest``, which re-tests hosts that just changed.) When a person, the API or an agent marks a CVE match, scanner finding or
hygiene finding fixed, ``status_changed`` queues a retest of the SAME check that produced the finding's proof (the ``hit`` or ``reaffirmed``
steps of its Triage row). It runs on a Sentinel, through the runners and the daily budget the validation dispatch already has
(``cveFeed.validation.RUNNERS``, ``_reserve_validation_check``): nothing new scans, and nothing runs on this server. The result is one of:

* ``verified_fixed``: the check ran, the host answered, and it no longer reproduces the finding.
* ``still_reproduces``: it does. The finding is reopened at once, the new exchange is kept as its proof, and the activity feed and the
  notification channels say so.
* ``not_verified``: it could not be told (no Sentinel, the host did not answer, the check failed, the check is gone). The finding stays fixed,
  not verified, with the reason, and is tried again with back-off, never more than once a day. A host that could not be reached is never read
  as fixed: before a result of "does not reproduce" is believed, a Sentinel must have connected to the finding's address (``_reachable``).
* ``no_check``: the finding has no stored check or evidence to repeat. It says "marked fixed, cannot be re-checked automatically" and is
  never shown as verified.

The newest result is kept on the finding's Triage row (``retest_state`` and friends: every list already joins it, so no list pays a query for
it); each try, with its Sentinel, time and evidence, is a ``FixRetest`` row. A status that a person changes afterwards starts the state over.
Periodic re-verification of findings that are verified fixed is not done.
"""
import contextlib
import logging
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

VERIFYING, VERIFIED, REPRODUCES, NOT_VERIFIED, NO_CHECK = 'verifying', 'verified_fixed', 'still_reproduces', 'not_verified', 'no_check'
STATES = (VERIFYING, VERIFIED, REPRODUCES, NOT_VERIFIED, NO_CHECK)
LABELS = {VERIFYING: 'Fixed, verifying', VERIFIED: 'Verified fixed', REPRODUCES: 'Still reproduces, reopened',
          NOT_VERIFIED: 'Fixed, not verified', NO_CHECK: 'Marked fixed, cannot be re-checked automatically'}
NO_CHECK_REASON = 'no stored check or evidence to repeat'
NOT_YET = 'not re-checked yet'
REPRODUCED = ('hit', 'reaffirmed')  # the step results that are a check reproducing the finding
GONE = ('no_match', 'version_changed')  # the step results that are a check not reproducing it
ALIVE_KINDS = ('nuclei_template', 'nmap_sv', 'db_probe', 'fact_probe')  # a "no match" of these does not show that the host answered
MAX_TRIES = 6  # after this many tries that could not tell, it is left for a person's Retest now
MAX_DELAY_DAYS = 7
FILTERS = ('verified_fixed', 'unverified_fixed', 'reopened')  # the Findings status facets this adds (``counts.retest_q``)
KIND_OF = {'cve_match': 'match', 'route_auth': 'route', 'hygiene': 'hygiene'}  # Triage.kind -> the finding kind of the audit trail (else vulnerability)


def retry_delay(tries):
    """When a retest that could not tell is tried again: a day after the first try, then doubling (2, 4 days), at most a week. Never sooner than a day."""
    return timedelta(days=min(MAX_DELAY_DAYS, 2 ** max(0, tries - 1)))


# ---------------------------------------------------------------------------------------------------------------- reading the state

def proof_checks(triage):
    """The checks that produced this finding's proof, as ``[{kind, label, display, target}]``: the steps of its validation that reproduced it
    (a ``hit``, else a ``reaffirmed`` live version). ``[]`` when there is none: a kind with no validated check, or no check that ever reproduced it."""
    from cveFeed import validation
    if triage is None or triage.kind not in validation.PLANNED_KINDS:
        return []
    steps = [s for s in (triage.validation_steps or []) if isinstance(s, dict) and s.get('kind') in validation.CHECK_KINDS]
    for results in (('hit',), ('reaffirmed',)):
        found = [s for s in steps if s.get('result') in results]
        if found:
            return [{'kind': s['kind'], 'label': str(s.get('label') or '')[:200], 'display': str(s.get('display') or '')[:500],
                     'target': str(s.get('target') or '')[:500]} for s in found]
    return []


def summary(remediation_status, triage):
    """What the finding shows about its retest, from the finding's remediation status and its Triage row (None: it has none), with no query:
    ``{state, label, text, at, sentinel, reason, can_retest}``. ``state`` is '' for a finding that was never marked fixed (or was changed by
    hand since), else one of ``STATES``. ``text`` is the sentence a person reads: "Verified fixed on 2026-11-12", "Fixed, not verified: the
    host did not answer". ``can_retest`` is true for a fixed finding that has a check to repeat."""
    fixed = remediation_status == 'fixed'
    stored = getattr(triage, 'retest_state', '') or ''
    reason = getattr(triage, 'retest_reason', '') or ''
    if fixed:
        if triage is None:
            state, reason = NO_CHECK, NO_CHECK_REASON
        elif stored in (VERIFYING, VERIFIED, NOT_VERIFIED, NO_CHECK):
            state = stored
        elif proof_checks(triage):
            state, reason = NOT_VERIFIED, NOT_YET  # marked fixed before retests existed (or reset): checkable, not checked
        else:
            state, reason = NO_CHECK, NO_CHECK_REASON
    elif stored == REPRODUCES and remediation_status in ('open', 'in_progress'):
        state = REPRODUCES
    else:
        return {'state': '', 'label': '', 'text': '', 'at': None, 'sentinel': '', 'reason': '', 'can_retest': False}
    at = getattr(triage, 'retest_at', None) if triage is not None else None
    sentinel = getattr(triage, 'retest_sentinel', '') or ''
    label = LABELS[state]
    day = at.strftime('%Y-%m-%d') if at else ''
    if state in (VERIFIED, REPRODUCES):
        text = f'{label} on {day}' if day else label
    elif state == NOT_VERIFIED:
        text = f'{label}: {reason or NOT_YET}'
    else:
        text = label
    return {'state': state, 'label': label, 'text': text, 'at': at.isoformat() if at else None, 'sentinel': sentinel, 'reason': reason,
            'can_retest': bool(fixed and triage is not None and (stored in (VERIFYING, VERIFIED, NOT_VERIFIED) or proof_checks(triage)))}


# ---------------------------------------------------------------------------------------------------------------- asking for one

def _stored_checks(triage):
    """The checks of the newest retest of this finding that recorded any: the proof as it stood when the finding was marked fixed (a later
    validation sweep can replace a step once the host stops reproducing, and the proof must not go with it)."""
    if triage is None or not getattr(triage, 'pk', None):
        return []
    from cveFeed.models import FixRetest
    for checks in FixRetest.objects.filter(triage_id=triage.pk).order_by('-id').values_list('check_run', flat=True)[:5]:
        if (checks or {}).get('checks'):
            return checks['checks']
    return []


def _set_state(triage, state, reason='', at=None, sentinel=''):
    triage.retest_state, triage.retest_reason, triage.retest_at, triage.retest_sentinel = state, reason[:300], at, sentinel[:120]
    triage.save(update_fields=['retest_state', 'retest_reason', 'retest_at', 'retest_sentinel', 'updated_at'])


def request(triage, user=None, source='automatic', now=None):
    """Queue a retest of this fixed finding on the validation queue (a Sentinel runs it), or say it cannot be re-checked: ``(FixRetest | None, state)``.
    One at a time per finding: a retest already queued or running answers ``(that one, 'verifying')``. A finding with no check to repeat is
    stored as ``no_check`` and nothing is queued."""
    from cveFeed.models import FixRetest
    now = now or timezone.now()
    checks = proof_checks(triage) or _stored_checks(triage)
    if not checks:
        _set_state(triage, NO_CHECK, NO_CHECK_REASON, now)
        return None, NO_CHECK
    try:
        with transaction.atomic():
            active = FixRetest.objects.select_for_update().filter(triage=triage, status__in=('queued', 'running')).first()
            if active is not None:
                return active, VERIFYING
            tries = FixRetest.objects.filter(triage=triage, outcome=NOT_VERIFIED).count() + 1 if source == 'retry' else 1
            job = FixRetest.objects.create(triage=triage, project_id=triage.project_id, source=source, requested_by=user, attempts=tries,
                                           check_run={'checks': checks})
            _set_state(triage, VERIFYING, '', None, '')
    except IntegrityError:  # two requests at once: the other one stands
        return FixRetest.objects.filter(triage=triage, status__in=('queued', 'running')).first(), VERIFYING
    _enqueue(job)
    return job, VERIFYING


def _enqueue(job):
    from cveFeed import activity
    from cveFeed.tasks import retest_fixed_finding
    try:
        retest_fixed_finding.apply_async(args=[job.pk], priority=3)
    except Exception:  # noqa: BLE001 - a broker that refuses: it is tried again later
        logger.warning('retest %s could not be queued', job.pk, exc_info=True)
        _settle_not_verified(job, 'the retest could not be queued', None, '', timezone.now())
        return
    activity.log('validate', f'Retest queued for finding #{job.triage_id}: re-running the check that proved it', project=job.project_id,
                 finding_id=job.triage_id, job_id=job.pk, source=job.source)


def status_changed(obj, before, after):
    """The hook of every status change (``agentapi.services._apply_remediation``: a person, the API, an agent). Marked fixed starts a retest; a change
    away from fixed starts the state over. Never raises: a finding is marked fixed whatever happens here."""
    try:
        from django.core.exceptions import ObjectDoesNotExist
        try:
            triage = obj.triage
        except ObjectDoesNotExist:
            return None
        if after == 'fixed' and before != 'fixed':
            return request(triage, getattr(obj, 'remediation_by', None), 'automatic')
        if after != 'fixed' and triage.retest_state:
            _set_state(triage, '', '', None, '')
    except Exception:  # noqa: BLE001
        logger.warning('retest hook failed for %r', obj, exc_info=True)
    return None


def status_changed_many(changes, after, now=None):
    """``status_changed`` for many findings at once (``agentapi.services.bulk_update_finding_status``): ``changes`` is ``[(finding, status before)]``, every finding
    now at ``after``. Each gets what ``status_changed`` gives it (a retest queued with its activity line, or ``no_check`` stored, or the state started over), in a
    fixed number of queries instead of five or more each. Never raises."""
    try:
        from django.core.exceptions import ObjectDoesNotExist
        now = now or timezone.now()
        wanted, reset = {}, {}
        for obj, before in changes:
            try:
                triage = obj.triage
            except ObjectDoesNotExist:
                continue
            if after == 'fixed' and before != 'fixed':
                wanted.setdefault(triage.pk, (triage, getattr(obj, 'remediation_by', None)))
            elif after != 'fixed' and triage.retest_state:
                reset.setdefault(triage.pk, triage)
        if reset:
            for triage in reset.values():
                triage.retest_state, triage.retest_reason, triage.retest_at, triage.retest_sentinel, triage.updated_at = '', '', None, '', now
            _save_states(list(reset.values()))
        if wanted:
            _request_many(list(wanted.values()), now)
    except Exception:  # noqa: BLE001
        logger.warning('retest hook failed for a batch of findings', exc_info=True)


_STATE_FIELDS = ['retest_state', 'retest_reason', 'retest_at', 'retest_sentinel', 'updated_at']


def _save_states(triages):
    from cveFeed.models import Triage
    Triage.objects.bulk_update(triages, _STATE_FIELDS)


def _stored_checks_many(triage_ids):
    """``{triage id: checks}`` of ``_stored_checks`` for these findings, in one query (only those that have some)."""
    from cveFeed.models import FixRetest
    seen, out = {}, {}
    for triage_id, checks in FixRetest.objects.filter(triage_id__in=triage_ids).order_by('triage_id', '-id').values_list('triage_id', 'check_run'):
        seen[triage_id] = seen.get(triage_id, 0) + 1
        if triage_id not in out and seen[triage_id] <= 5 and (checks or {}).get('checks'):
            out[triage_id] = checks['checks']
    return out


def _request_many(asked, now):
    """``request(triage, user, 'automatic')`` for each ``(triage, user)`` of ``asked``, queries shared: the checks to repeat, the retests already running, the rows
    created and the states stored are one query each, and the activity lines one insert. A retest that cannot be created with the others (two requests at once) is
    asked for by itself, as ``request`` does."""
    from cveFeed.models import AgentActivity, FixRetest
    checks = {}
    for triage, _user in asked:
        found = proof_checks(triage)
        if found:
            checks[triage.pk] = found
    missing = [t.pk for t, _ in asked if t.pk not in checks]
    checks.update(_stored_checks_many(missing) if missing else {})
    nothing = [t for t, _ in asked if t.pk not in checks]
    for triage in nothing:
        triage.retest_state, triage.retest_reason, triage.retest_at, triage.retest_sentinel, triage.updated_at = NO_CHECK, NO_CHECK_REASON, now, '', now
    if nothing:
        _save_states(nothing)
    todo = [(t, u) for t, u in asked if t.pk in checks]
    if not todo:
        return
    running = set(FixRetest.objects.filter(triage_id__in=[t.pk for t, _ in todo], status__in=('queued', 'running')).values_list('triage_id', flat=True))
    todo = [(t, u) for t, u in todo if t.pk not in running]  # one at a time per finding: a retest already queued stands
    if not todo:
        return
    try:
        with transaction.atomic():
            jobs = FixRetest.objects.bulk_create([FixRetest(triage=t, project_id=t.project_id, source='automatic', requested_by=u, attempts=1,
                                                            check_run={'checks': checks[t.pk]}) for t, u in todo])
            for triage, _user in todo:
                triage.retest_state, triage.retest_reason, triage.retest_at, triage.retest_sentinel, triage.updated_at = VERIFYING, '', None, '', now
            _save_states([t for t, _ in todo])
    except IntegrityError:  # two requests at once: each finding is asked for by itself, the other one's stands
        for triage, user in todo:
            request(triage, user, 'automatic', now)
        return
    from cveFeed.tasks import retest_fixed_finding
    lines = []
    for job in jobs:
        try:
            retest_fixed_finding.apply_async(args=[job.pk], priority=3)
        except Exception:  # noqa: BLE001 - a broker that refuses: it is tried again later
            logger.warning('retest %s could not be queued', job.pk, exc_info=True)
            _settle_not_verified(job, 'the retest could not be queued', None, '', timezone.now())
            continue
        lines.append(AgentActivity(kind='validate', message=f'Retest queued for finding #{job.triage_id}: re-running the check that proved it', status='done',
                                   project_id=job.project_id, cve_id='', detail={'finding_id': job.triage_id, 'job_id': job.pk, 'source': job.source},
                                   finished_at=timezone.now()))
    if lines:
        try:
            AgentActivity.objects.bulk_create(lines)
        except Exception:  # noqa: BLE001 - the feed is telemetry, as ``activity.log``
            logger.warning('could not record the retest activity', exc_info=True)


# ---------------------------------------------------------------------------------------------------------------- running one

@contextlib.contextmanager
def recording_sentinels():
    """Collect the Sentinels (agent ids) whose answers the dispatch returned inside the block: ``sentinel_dispatch.Result`` appends to the list."""
    from agentapi import sentinel_dispatch
    seen = []
    token = sentinel_dispatch.RECORDER.set(seen)
    try:
        yield seen
    finally:
        sentinel_dispatch.RECORDER.reset(token)


def _sentinel_names(agent_ids):
    from agentapi.models import Agent
    ids = [i for i in dict.fromkeys(agent_ids) if i]
    return ', '.join(Agent.objects.filter(pk__in=ids).order_by('pk').values_list('name', flat=True))[:120] if ids else ''


def _planned(row, finding, wanted):
    """``(subject, chosen, missing)``: the planned checks (``validation.plan_checks``) that are one of ``wanted`` (the kind and target of each proof
    check), and the wanted ones that are no longer planned (a template removed, a port gone)."""
    from cveFeed import validation
    subject = validation.subject_for(row, finding, unattended=False)
    template = validation.resolve_template(subject['cve_id']) if row.kind == 'cve_match' else ('', '')
    checks, _notes = validation.plan_checks(subject, row.signature, template)
    keys = {(w['kind'], w['target']) for w in wanted}
    chosen = [c for c in checks if c and (c['kind'], c['target']) in keys]
    have = {(c['kind'], c['target']) for c in chosen}
    return subject, chosen, [w for w in wanted if (w['kind'], w['target']) not in have]


def _endpoints(subject, check):
    """``[(ip, port)]`` whose connection shows that the host answered: the check's own address and port, else the services the host was seen with."""
    params = check.get('params') or {}
    if params.get('ip') and params.get('port'):
        return [(params['ip'], int(params['port']))]
    if subject.get('ip') and subject.get('port'):
        return [(subject['ip'], int(subject['port']))]
    return [(c['ip'], int(c['port'])) for c in (subject.get('candidate_services') or []) if c.get('ip') and c.get('port')][:4]


def _reachable(project, subject, check, scan=None):
    """True when a Sentinel connected to the host (``probe_dispatch.try_alive``); False when none did; None when there was no address to try. A
    "does not reproduce" from a check whose answer does not show that the host was there (``ALIVE_KINDS``) is only believed after this."""
    from agentapi import probe_dispatch
    endpoints = _endpoints(subject, check)
    if not endpoints:
        return None
    asks = [{'id': f'{ip}:{port}', 'host': subject.get('host') or ip, 'ip': ip, 'port': port, 'scheme': 'https' if port in (443, 8443) else 'http'}
            for ip, port in endpoints]
    return any(probe_dispatch.try_alive(project, scan, asks).values())


def _result_summary(check, result):
    return {'check': check['kind'], 'label': check['label'], 'result': result.get('status'), 'summary': str(result.get('summary') or '')[:300],
            **({'evidence': result['evidence']} if result.get('evidence') else {}),
            **({'output_excerpt': str(result['output_excerpt'])[:400]} if result.get('output_excerpt') else {})}


def decide(results):
    """``(outcome, reason)`` from the results of the repeated checks (``[(check, result, reachable)]``): still_reproduces when any reproduces it,
    verified_fixed when every one ran, did not reproduce it and (where it matters) the host answered, else not_verified with the plain reason."""
    if any(r.get('status') in REPRODUCED for _c, r, _a in results):
        return REPRODUCES, ''
    for check, result, alive in results:
        status = result.get('status')
        if status == 'failed':
            why = str(result.get('error') or result.get('summary') or 'the check failed')
            if 'no scanner could take' in why:
                return NOT_VERIFIED, 'no Sentinel could take the check'
            return NOT_VERIFIED, why[:200]
        if status == 'blocked':
            return NOT_VERIFIED, str(result.get('summary') or 'the check was blocked by scope or policy')[:200]
        if status not in GONE:
            return NOT_VERIFIED, 'the check ran but could not tell if it still reproduces'
        if check['kind'] in ALIVE_KINDS and alive is not True:
            return NOT_VERIFIED, 'the host did not answer' if alive is False else 'could not confirm that the host answered'
    return VERIFIED, ''


def run(job_id):
    """Run one queued retest: repeat each proof check on a Sentinel, decide, store the outcome with the time, the Sentinel and the evidence, and
    reopen the finding when it still reproduces. Never raises for one check's trouble (it is ``not_verified`` and tried again)."""
    from cveFeed import activity, ledger, validation
    from cveFeed.models import FixRetest, Triage
    from reNgine import resources
    now = timezone.now()
    if not FixRetest.objects.filter(pk=job_id, status='queued').update(status='running', started_at=now):
        return {'skipped': 'not queued'}
    job = FixRetest.objects.get(pk=job_id)
    row = Triage.objects.select_related('match__cve_entry', 'match__subdomain__target_domain', 'vulnerability__subdomain',
                                        'vulnerability__target_domain', 'route', 'hygiene').get(pk=job.triage_id, project_id=job.project_id)
    progress = activity.log('validate', f'Retest {job.pk} running for finding #{row.pk}', project=job.project_id, status='running',
                            finding_id=row.pk, job_id=job.pk)
    finding = row.finding
    if finding is None or getattr(finding, 'remediation_status', '') != 'fixed':
        FixRetest.objects.filter(pk=job.pk).update(status='done', reason='the finding is no longer marked fixed', finished_at=now)
        activity.settle(progress, 'done', f'Retest {job.pk} skipped: the finding is no longer marked fixed')
        return {'skipped': 'not fixed'}
    wanted = (job.check_run or {}).get('checks') or []
    results, sentinels = [], []
    try:
        with recording_sentinels() as seen:
            subject, chosen, missing = _planned(row, finding, wanted)
            if missing or not chosen:
                outcome, reason = NOT_VERIFIED, 'the check that proved it is no longer available'
            else:
                project = _project_of(job.project_id)
                for check in chosen:
                    if resources.global_pause_requested(fail_closed=True):
                        results.append((check, {'status': 'failed', 'error': 'scanning is paused'}, None))
                        break
                    check['params'].setdefault('project_id', job.project_id)
                    if not validation._reserve_validation_check(job.project_id):
                        results.append((check, {'status': 'failed', 'error': 'the daily check limit was reached'}, None))
                        break
                    try:
                        result = validation.interpret(subject, check, validation.RUNNERS[check['kind']](check))
                    except Exception as exc:  # noqa: BLE001 - one check failing is "could not retest", never "fixed"
                        logger.warning('retest check %s failed for %s', check['kind'], row.host, exc_info=True)
                        result = {'status': 'failed', 'error': f'the check failed to run ({type(exc).__name__})'}
                    alive = None
                    if result.get('status') in GONE and check['kind'] in ALIVE_KINDS:
                        try:
                            alive = _reachable(project, subject, check)
                        except Exception as exc:  # noqa: BLE001 - no Sentinel for the connect either: the host is unconfirmed
                            logger.info('retest reachability check failed for %s: %s', row.host, type(exc).__name__)
                    ledger.record(check['service'], [check['asset']], job.project_id, None, 'failed' if result.get('status') == 'failed' else 'done')
                    results.append((check, result, alive))
                outcome, reason = decide(results)
            sentinels = list(seen)
    except Exception as exc:  # noqa: BLE001 - a broken retest never marks anything fixed
        logger.warning('retest %s failed', job.pk, exc_info=True)
        outcome, reason = NOT_VERIFIED, f'the retest failed ({type(exc).__name__})'
    return _finish(job, row, finding, outcome, reason, results, _sentinel_names(sentinels), progress)


def _project_of(project_id):
    from dashboard.models import Project
    return Project.objects.get(pk=project_id)


def _finish(job, row, finding, outcome, reason, results, names, progress):
    from cveFeed import activity
    from cveFeed.models import FixRetest
    now = timezone.now()
    evidence = {'results': [_result_summary(c, r) for c, r, _a in results]}
    first_hit = next((r for _c, r, _a in results if r.get('status') in REPRODUCED), None)
    if first_hit is not None:
        evidence['summary'] = first_hit.get('summary') or ''
        evidence['exchange'] = first_hit.get('evidence') or {}
    if outcome == NOT_VERIFIED:
        return _settle_not_verified(job, reason, evidence, names, now, progress)
    FixRetest.objects.filter(pk=job.pk).update(status='done', outcome=outcome, reason=reason, sentinel=names, evidence=evidence,
                                               finished_at=now, next_attempt_at=None)
    where = f' on Sentinel {names}' if names else ''
    if outcome == VERIFIED:
        _set_state(row, VERIFIED, '', now, names)
        _audit(row, finding, VERIFIED, names)
        activity.settle(progress, 'done', f'Retest {job.pk}: verified fixed (finding #{row.pk}); the check ran{where}', outcome=VERIFIED, sentinel=names)
        return {'outcome': VERIFIED, 'sentinel': names}
    _reopen(row, finding, evidence, names, now)
    activity.settle(progress, 'done', f'Retest {job.pk}: still reproduces, so finding #{row.pk} was reopened{where}', outcome=REPRODUCES, sentinel=names)
    return {'outcome': REPRODUCES, 'sentinel': names}


def _settle_not_verified(job, reason, evidence, names, now, progress=None):
    """A retest that could not tell: stored as such, the finding stays fixed and not verified, and the next try is a day or more away."""
    from cveFeed import activity
    from cveFeed.models import FixRetest, Triage
    tries = max(job.attempts or 1, 1)
    retry_at = now + retry_delay(tries) if tries < MAX_TRIES else None
    FixRetest.objects.filter(pk=job.pk).update(status='done', outcome=NOT_VERIFIED, reason=reason[:300], sentinel=names, evidence=evidence or {},
                                               finished_at=now, next_attempt_at=retry_at)
    row = Triage.objects.get(pk=job.triage_id)
    _set_state(row, NOT_VERIFIED, reason if retry_at else f'{reason}; gave up after {tries} tries, use Retest now', now, names)
    if progress is not None:
        activity.settle(progress, 'done', f'Retest {job.pk}: could not retest finding #{row.pk} ({reason}); it stays fixed, not verified',
                        outcome=NOT_VERIFIED, retry_at=retry_at.isoformat() if retry_at else None)
    return {'outcome': NOT_VERIFIED, 'reason': reason, 'retry_at': retry_at.isoformat() if retry_at else None}


def _audit(row, finding, outcome, names, extra=None):
    from cveFeed.models import FindingAuditEvent
    try:
        FindingAuditEvent.objects.create(project_id=row.project_id, finding_kind=KIND_OF.get(row.kind, 'vulnerability'), finding_id=finding.pk,
                                         event='retest', actor=None, before={'status': 'fixed'}, after={'retest': outcome, 'sentinel': names, **(extra or {})})
    except Exception:  # noqa: BLE001 - the audit trail never costs a finding its result
        logger.warning('retest audit failed for %s', finding.pk, exc_info=True)


def _reopen(row, finding, evidence, names, now):
    """The finding still reproduces: open it again (a status change by the engine, with a note that says why), keep the new exchange as its proof,
    and tell the people who watch (the activity line is the caller's; the notification channels are told here)."""
    from cveFeed import notify
    from cveFeed.models import FindingAuditEvent
    note = 'Reopened automatically: a retest after it was marked fixed still reproduces it' + (f' (Sentinel {names})' if names else '') + '.'
    finding.remediation_status, finding.remediation_updated_at, finding.remediation_by = 'open', now, None
    finding.remediation_note = note[:2000]
    finding.save(update_fields=['remediation_status', 'remediation_updated_at', 'remediation_by', 'remediation_note'])
    fresh = {r['check']: r['evidence'] for r in evidence['results'] if r.get('evidence')}
    if fresh:
        row.validation_evidence = {**(row.validation_evidence or {}), **fresh}
        row.validation_status, row.validated_at = 'hit', now
        row.save(update_fields=['validation_evidence', 'validation_status', 'validated_at', 'updated_at'])
    _set_state(row, REPRODUCES, evidence.get('summary') or '', now, names)
    FindingAuditEvent.objects.create(project_id=row.project_id, finding_kind=KIND_OF.get(row.kind, 'vulnerability'), finding_id=finding.pk, event='status',
                                     actor=None, before={'status': 'fixed'}, after={'status': 'open', 'note': note})
    _audit(row, finding, REPRODUCES, names, {'summary': (evidence.get('summary') or '')[:200]})
    try:
        from agentapi import services
        from cveFeed.views import bump_stats_revision
        transaction.on_commit(bump_stats_revision)
        host = services._host_of(finding)
        if host:
            services._rescore_hosts([host])
        notify.fix_not_holding(row.host, _title_of(row, finding))
    except Exception:  # noqa: BLE001 - the reopening stands whether or not the channels answered
        logger.warning('retest follow-up failed for %s', finding.pk, exc_info=True)


def _title_of(row, finding):
    if row.kind == 'cve_match':
        return finding.cve_entry.cve_id
    return getattr(finding, 'name', None) or getattr(finding, 'title', None) or row.kind


# ---------------------------------------------------------------------------------------------------------------- the retries

def sweep(limit=20, now=None):
    """Queue the retests that could not tell and whose time has come (``next_attempt_at``), for findings that are still fixed, at most ``limit`` per
    call. ``retry_delay`` is a day at the least, so a finding is tried at most once a day."""
    from cveFeed.models import FixRetest
    now = now or timezone.now()
    queued = 0
    due = list(FixRetest.objects.filter(outcome=NOT_VERIFIED, next_attempt_at__lte=now, status='done').order_by('next_attempt_at')
               .select_related('triage')[:limit * 3])
    for old in due:
        if queued >= limit:
            break
        t = old.triage
        FixRetest.objects.filter(pk=old.pk).update(next_attempt_at=None)  # this try's turn is used up whatever follows
        newest = FixRetest.objects.filter(triage=t).order_by('-id').first()
        finding = t.finding
        if newest.pk != old.pk or t.retest_state != NOT_VERIFIED or finding is None or getattr(finding, 'remediation_status', '') != 'fixed':
            continue  # superseded: a newer try or a status change already stands
        job, _state = request(t, None, 'retry', now)
        queued += 1 if job is not None else 0
    return {'queued': queued}
