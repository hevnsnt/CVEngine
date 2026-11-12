"""The automatic lifecycle of an AI-written scan template: draft -> valid | invalid | expired, with no person in it.

A draft (``templategen.job_answer``) has passed the static gate and a Sentinel's syntax check once. This module takes it the rest of
the way, in order, and a draft becomes ``valid`` (the only status ``validation.approved_template`` will hand to a host) only when every
gate passes:

1. static gate again (``templategen.static_check``: protocols, destinations, request count, read-only methods, real matchers);
2. the scanner's syntax check and the benign loopback control on a Sentinel (``nuclei_validate``, mode ``validate``);
3. a fixture: the AI (stage ``template_validation``) sees only the CVE data and writes the response an affected host and a fixed host
   give; ``templatefixture`` evaluates the template's matchers offline, and they must match the affected response and must NOT match the
   fixed one, a benign page or a 404;
4. the AI's second-pass critique of the template, the fixture and the offline results (same stage): it must agree;
5. promotion: the file is written under GENERATED_DIR, ``path`` and ``positive_fixture_*`` are recorded, status becomes ``valid``.

A failed gate marks the row ``invalid`` with a plain reason. A gate that could not run because of the system (no Sentinel can take
``nuclei_validate``, AI off) makes the draft wait without using a try; a gate that failed in a way that may pass next time (the AI's answer
was unreadable, its fixture did not match) is retried up to ``MAX_ATTEMPTS`` times with back-off. A draft still pending after
``expiry_days()`` days is closed as ``expired``. Nothing here runs a template on a host and nothing here asks a person to do anything.
"""
import datetime
import json
import logging
import os
import re

from django.utils import timezone

from cveFeed import activity, templatefixture, templategen

logger = logging.getLogger(__name__)

KIND = STAGE = 'template_validation'
MAX_ATTEMPTS = 3
BACKOFF = (datetime.timedelta(minutes=15), datetime.timedelta(hours=1), datetime.timedelta(hours=4))
WAIT_SYSTEM = datetime.timedelta(minutes=30)  # a Sentinel or the AI is missing: look again in half an hour, no try used
BATCH = 10
DEFAULT_EXPIRY_DAYS = 7
STUCK_AFTER = datetime.timedelta(hours=6)  # a draft pending longer than this with the same blocker is a real problem the system cannot fix itself
LOCK = 'cvengine:template-validation'

FIXTURE_SYSTEM_BODY = (
    'Reply with ONLY one JSON object, no prose: {"vulnerable": {"status": 200, "headers": {"Server": "..."}, "body": "..."}, '
    '"not_affected": {"status": 200, "headers": {}, "body": "..."}}. "vulnerable" is the HTTP response (at most a few hundred characters of '
    'body) that a host running an affected release gives to an ordinary read-only request, as the advisory describes it: a version banner or '
    'page text that appears only in affected releases. "not_affected" is the response of a fixed release of the same product to the same '
    'request. Use only what the CVE data says. If the data does not say what an affected host shows, reply {"vulnerable": null, '
    '"not_affected": null}.')
CRITIQUE_SYSTEM_BODY = (
    'You are given the template, the two responses it was tested on and the results of the offline test. Reply with ONLY one JSON object, no '
    'prose: {"verdict": "agree" or "disagree", "reasons": ["one plain sentence each"]}. Answer agree only if all of these hold: the template '
    'only reads (no change of state, no exploit payload), it talks only to the scanned host, its matchers show the flaw or the affected '
    'version this CVE names (not a banner every server of the kind shows), and it would not flag a fixed or unrelated host. Otherwise answer '
    'disagree and say why in plain words.')


def expiry_days():
    try:
        return max(1, int(os.environ.get('CVENGINE_TEMPLATE_DRAFT_EXPIRY_DAYS', '')))
    except ValueError:
        return DEFAULT_EXPIRY_DAYS


def _system(body):
    from reNgine import ai_prompts
    return ai_prompts.compose(STAGE, body + ' ' + templategen.UNTRUSTED_NOTICE)


def _model(job):
    return templategen._job_model(job)


def _json(text):
    """The first JSON object in a model reply (fenced or bare), or None."""
    text = (text or '').strip()
    fence = re.search(r'```(?:json)?\s*\n(.*?)```', text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    start, end = text.find('{'), text.rfind('}')
    if start < 0 or end <= start:
        return None
    try:
        value = json.loads(text[start:end + 1])
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _save(tmpl, **fields):
    for key, value in fields.items():
        setattr(tmpl, key, value)
    tmpl.save(update_fields=list(fields))


def _say(tmpl, message):
    activity.log('validate', message, cve_id=tmpl.cve_entry.cve_id)


# ----------------------------------------------------------------------------- the three ways a row leaves 'draft'

def reject(tmpl, reason):
    """Close the draft as invalid, with the plain reason a person reads on the AI usage page."""
    reason = ' '.join(str(reason).split())[:400]
    _save(tmpl, status=tmpl.STATUS_INVALID, validation_reason=reason, validated_at=timezone.now(), validation_stage='', validation_next_at=None,
          validation_output=(tmpl.validation_output + '\nautomatic validation: ' + reason).strip()[:6000])
    _say(tmpl, f'The AI-written check for {tmpl.cve_entry.cve_id} was rejected by automatic validation: {reason}')
    return 'invalid'


def _retry(tmpl, reason, now=None):
    """A gate failed in a way that can pass next time: use one try, back off, give up after MAX_ATTEMPTS."""
    now = now or timezone.now()
    attempts = tmpl.validation_attempts + 1
    if attempts >= MAX_ATTEMPTS:
        _save(tmpl, validation_attempts=attempts)
        return reject(tmpl, f'{reason} (tried {attempts} times)')
    _save(tmpl, validation_attempts=attempts, validation_next_at=now + BACKOFF[attempts - 1], validation_reason=f'trying again later: {reason}')
    return 'retry'


def _wait(tmpl, reason, now=None):
    """The system cannot run a gate right now: the draft waits, no try is used (the expiry window still runs)."""
    now = now or timezone.now()
    _save(tmpl, validation_next_at=now + WAIT_SYSTEM, validation_reason=f'waiting: {reason}')
    return 'waiting'


def expire_stale(now=None):
    """Drafts still pending after ``expiry_days()`` days are closed as expired, not validated: the queue cannot grow without bound."""
    from cveFeed.models import GeneratedTemplate
    now = now or timezone.now()
    cutoff = now - datetime.timedelta(days=expiry_days())
    expired = 0
    for tmpl in GeneratedTemplate.objects.filter(status=GeneratedTemplate.STATUS_DRAFT, validation_started_at__lt=cutoff).select_related('cve_entry'):
        last = (tmpl.validation_reason or 'no gate could run').replace('waiting: ', '').replace('trying again later: ', '')
        reason = f'expired, not validated: still pending after {expiry_days()} days ({last})'[:400]
        _save(tmpl, status=GeneratedTemplate.STATUS_EXPIRED, validation_reason=reason, validated_at=now, validation_stage='', validation_next_at=None,
              validation_output=(tmpl.validation_output + '\nautomatic validation: ' + reason).strip()[:6000])
        _say(tmpl, f'The AI-written check for {tmpl.cve_entry.cve_id} expired and was closed without being validated: {reason}')
        expired += 1
    return expired


def promote(tmpl, job, now=None):
    """Every gate passed: write the file, record the fixture evidence, mark the row valid."""
    now = now or timezone.now()
    ok, why = templategen.static_check(tmpl.yaml, expected_cve_id=tmpl.cve_entry.cve_id)
    if not ok:
        return reject(tmpl, f'static check: {why}')
    template_id = tmpl.template_id or str((templategen.load_template(tmpl.yaml) or {}).get('id', ''))
    try:
        path = templategen.save_template_file(template_id, tmpl.yaml)
    except FileExistsError:
        path = os.path.join(templategen.GENERATED_DIR, f'{template_id}.yaml')
        try:
            with open(path, encoding='utf-8') as handle:
                same = handle.read() == tmpl.yaml
        except OSError:
            same = False
        if not same:
            return reject(tmpl, 'a different check with the same id is already installed for this CVE')
    except (OSError, RuntimeError, ValueError) as exc:
        return _retry(tmpl, f'the validated check could not be saved ({exc})', now)
    source = (f'AI fixture and offline matcher test, benign controls, the syntax check on a Sentinel, second-pass critique by {_model(job)}')[:300]
    _save(tmpl, template_id=template_id, path=path, status=tmpl.STATUS_VALID, positive_fixture_verified_at=now, positive_fixture_source=source,
          validation_reason='passed every automatic gate', validated_at=now, validation_stage='', validation_next_at=None,
          validation_output=(tmpl.validation_output + '\nautomatic validation: passed every gate').strip()[:6000])
    _say(tmpl, f'The AI-written check for {tmpl.cve_entry.cve_id} passed every automatic gate and may now be run on hosts')
    return 'valid'


# ----------------------------------------------------------------------------- the gates

def _sentinel_gate(tmpl, now):
    """Static gate and the Sentinel's syntax check with the benign control. Returns the outcome string when the draft is settled or must
    wait, or None when it passes."""
    from agentapi import sentinel_dispatch
    from reNgine.resources import ScannerUnavailable
    ok, why = templategen.static_check(tmpl.yaml, expected_cve_id=tmpl.cve_entry.cve_id)
    if not ok:
        return reject(tmpl, f'static check: {why}')
    try:
        valid, output, fixture_ok, note = sentinel_dispatch.try_nuclei_validate(tmpl.yaml, None)
    except ScannerUnavailable as exc:
        return _wait(tmpl, f'no Sentinel can run template checks ({exc.kind}) right now', now)
    if not valid:
        return reject(tmpl, f'the scanner did not accept the template: {" ".join((output or "no output").split())[:200]}')
    if fixture_ok is False:
        return reject(tmpl, 'it matched a benign page on the Sentinel, so it would flag hosts that are not affected')
    if fixture_ok is None:
        return _retry(tmpl, 'the Sentinel did not run the benign control', now)
    return None


def _ask(tmpl, phase, now):
    """Queue the AI job of ``phase`` (fixture or critique) for the reviewer container."""
    from cveFeed import ai_jobs
    if not ai_jobs.ai_on():
        return _wait(tmpl, 'the AI provider is not turned on', now)
    cve = templategen.cve_info_for(tmpl.cve_entry)
    safe = {k: templategen._clean_value(v, 4000 if isinstance(v, str) else 500) for k, v in cve.items()}
    if phase == 'fixture':
        system = _system(FIXTURE_SYSTEM_BODY)
        parts = [ai_jobs.text('Describe the responses of an affected and of a fixed host for this CVE:'), ai_jobs.fence('CVE', safe)]
    else:
        system = _system(CRITIQUE_SYSTEM_BODY)
        parts = [ai_jobs.text('Review this template for this CVE:'), ai_jobs.fence('CVE', safe), ai_jobs.fence('TEMPLATE', tmpl.yaml),
                 ai_jobs.fence('RESPONSES', {'affected_host': tmpl.fixture['vulnerable'], 'fixed_host': tmpl.fixture['not_affected'],
                                              'offline_test': 'the matchers match the affected response and do not match the fixed one, a benign page or a 404'})]
    try:
        ai_jobs.enqueue('template_validation', 'template_validation', system=system, parts=parts, options={'redact_reply': False},
                        context={'template': tmpl.pk, 'phase': phase}, dedupe=f'tmplval:{tmpl.pk}:{phase}', priority=8)
    except ValueError as exc:
        return _retry(tmpl, f'the AI question could not be queued ({exc})', now)
    _save(tmpl, validation_stage=f'waiting:{phase}', validation_next_at=None, validation_reason=f'waiting for the AI ({phase})')
    return 'asked'


def step(tmpl, now=None):
    """Advance one draft by one gate. Returns 'valid', 'invalid', 'asked', 'waiting', 'retry' or 'busy'."""
    from cveFeed.models import AIJob
    now = now or timezone.now()
    stage = tmpl.validation_stage
    if stage.startswith('waiting:'):
        if AIJob.objects.filter(kind=KIND, dedupe__startswith=f'tmplval:{tmpl.pk}:', status__in=AIJob.OPEN).exists():
            return 'busy'
        _save(tmpl, validation_stage=stage.split(':', 1)[1])  # the job ended without an applied answer (expired, lost): that was a try
        return _retry(tmpl, 'the AI job ended without an answer', now)
    if stage in ('', 'syntax'):  # 'syntax': a draft whose first check (templategen.job_answer) never finished; the same check again
        outcome = _sentinel_gate(tmpl, now)
        if outcome:
            return outcome
        _save(tmpl, validation_stage='fixture')
        stage = 'fixture'
    if stage in ('fixture', 'critique'):
        if stage == 'critique' and not (tmpl.fixture and tmpl.fixture.get('vulnerable') and tmpl.fixture.get('not_affected')):
            _save(tmpl, validation_stage='fixture')
            stage = 'fixture'
        return _ask(tmpl, stage, now)
    return _retry(tmpl, f'unknown stage {stage!r}', now)


def run_pending(now=None, limit=BATCH):
    """The five-minute task: stamp new drafts, expire stale ones, advance the due ones. Calls no AI itself (it queues jobs for the reviewer
    container) and runs no template."""
    from django.core.cache import cache

    from cveFeed.models import GeneratedTemplate
    now = now or timezone.now()
    out = {'stamped': 0, 'expired': 0, 'valid': 0, 'invalid': 0, 'asked': 0, 'waiting': 0, 'retry': 0, 'busy': 0}
    if not cache.add(LOCK, 1, timeout=600):
        return {**out, 'skipped': 'another run is in progress'}
    try:
        out['stamped'] = GeneratedTemplate.objects.filter(status=GeneratedTemplate.STATUS_DRAFT, validation_started_at__isnull=True).update(validation_started_at=now)
        out['expired'] = expire_stale(now)
        due = GeneratedTemplate.objects.filter(status=GeneratedTemplate.STATUS_DRAFT).exclude(validation_next_at__gt=now) \
            .select_related('cve_entry').order_by('validation_started_at', 'id')[:limit]
        for tmpl in due:
            try:
                outcome = step(tmpl, now)
            except Exception:  # noqa: BLE001 - one broken draft never stops the others
                logger.exception('automatic validation of generated template %s failed', tmpl.pk)
                outcome = _retry(tmpl, 'an unexpected error stopped the check', now)
            out[outcome] = out.get(outcome, 0) + 1
    finally:
        cache.delete(LOCK)
    return out


# ----------------------------------------------------------------------------- what the AI answered (ai_jobs handler)

def _template(job):
    from cveFeed.models import GeneratedTemplate
    tmpl = GeneratedTemplate.objects.filter(pk=(job.context or {}).get('template')).select_related('cve_entry').first()
    return tmpl if tmpl is not None and tmpl.status == GeneratedTemplate.STATUS_DRAFT else None


def job_answer(job, text):
    tmpl = _template(job)
    if tmpl is None:
        return None
    phase = (job.context or {}).get('phase')
    now = timezone.now()
    _save(tmpl, validation_stage=phase if phase in ('fixture', 'critique') else '')
    data = _json(text)
    if data is None:
        _retry(tmpl, 'the AI answer could not be read', now)
    elif phase == 'fixture':
        _fixture_answer(tmpl, data, now)
    else:
        _critique_answer(tmpl, job, data, now)
    return None


def _fixture_answer(tmpl, data, now):
    if data.get('vulnerable') is None and data.get('not_affected') is None:
        return reject(tmpl, 'the CVE data does not say what an affected host shows, so the check cannot be tested')
    affected, fixed = templatefixture.clean_fixture(data.get('vulnerable')), templatefixture.clean_fixture(data.get('not_affected'))
    if affected is None or fixed is None:
        return _retry(tmpl, 'the AI did not give both a usable affected and a fixed response', now)
    try:
        hit = templatefixture.matches(tmpl.yaml, affected)
        wrong = [name for name, response in (('the fixed release', fixed), ('a benign page', templatefixture.BENIGN), ('a 404 page', templatefixture.NOT_FOUND))
                 if templatefixture.matches(tmpl.yaml, response)]
    except templatefixture.Unsupported as exc:
        return reject(tmpl, f'it uses a matcher that cannot be tested offline ({exc})')
    if wrong:
        return reject(tmpl, f'it also matches {" and ".join(wrong)}, so it would flag hosts that are not affected')
    if not hit:
        return _retry(tmpl, 'the template did not match the response an affected host gives', now)
    _save(tmpl, fixture={'vulnerable': affected, 'not_affected': fixed}, validation_stage='critique', validation_next_at=None)
    return _ask(tmpl, 'critique', now)


def _critique_answer(tmpl, job, data, now):
    verdict = str(data.get('verdict', '')).strip().lower()
    if verdict == 'agree':
        return promote(tmpl, job, now)
    if verdict == 'disagree':
        reasons = [str(r) for r in (data.get('reasons') or []) if isinstance(r, str)] if isinstance(data.get('reasons'), list) else []
        return reject(tmpl, 'the AI second pass disagreed: ' + (' '.join(reasons)[:300] or 'no reason given'))
    return _retry(tmpl, 'the AI second pass gave no clear verdict', now)


def job_failure(job, category, detail):
    tmpl = _template(job)
    if tmpl is None:
        return
    phase = (job.context or {}).get('phase')
    _save(tmpl, validation_stage=phase if phase in ('fixture', 'critique') else '')
    why = 'the AI declined to answer' if category == 'refused' else f'the AI call failed ({category})'
    _retry(tmpl, why)


def job_expired(job):
    job_failure(job, 'expired', {})


# ----------------------------------------------------------------------------- what the owner sees and what the reviewer reports

def summary(now=None):
    """Counts and the plain reasons of rejections, for the AI usage page and the headline: {valid, pending, rejected, expired, reasons}."""
    from django.db.models import Count

    from cveFeed.models import GeneratedTemplate as G
    now = now or timezone.now()
    counts = dict(G.objects.values_list('status').annotate(n=Count('id')))
    reasons = {}
    for row in G.objects.filter(status__in=(G.STATUS_INVALID, G.STATUS_EXPIRED), created_at__gte=now - datetime.timedelta(days=30)) \
            .values('validation_reason', 'validation_output'):
        output_lines = (row['validation_output'] or '').strip().splitlines()
        reason = (row['validation_reason'] or '').strip() or (output_lines[0] if output_lines else 'no reason recorded')
        reason = re.sub(r'\s*\(tried \d+ times\)$', '', reason)[:160]
        reasons[reason] = reasons.get(reason, 0) + 1
    top = sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
    return {'valid': counts.get(G.STATUS_VALID, 0), 'pending': counts.get(G.STATUS_DRAFT, 0), 'rejected': counts.get(G.STATUS_INVALID, 0),
            'expired': counts.get(G.STATUS_EXPIRED, 0), 'reasons': [{'reason': r, 'count': n} for r, n in top]}


def problem(now=None):
    """A real problem the system cannot fix itself, as ``{code, title, detail, facts}``, or None. Never asks anyone to review a template."""
    from django.db.models import Q

    from cveFeed import ai_jobs
    from cveFeed.models import GeneratedTemplate as G
    now = now or timezone.now()
    old = G.objects.filter(status=G.STATUS_DRAFT).filter(validation_started_at__lte=now - STUCK_AFTER).count()
    if old:
        from agentapi import sentinel_dispatch
        from reNgine.resources import ScannerUnavailable
        try:
            sentinel_dispatch.nuclei_validate_ready(None)
        except ScannerUnavailable:
            from cveFeed import fleet as fleet_lib
            facts = {'pending': old, **{k: v for k, v in fleet_lib.fleet_facts(now).items() if k in ('live_sentinels', 'builtin_scanner', 'builtin_live')}}
            lead = f'{old} AI-written check(s) are waiting because no Sentinel that runs template checks is online. '
            tail = f'They are tested by themselves as soon as a Sentinel that runs template checks is available, and closed as expired if none is within {expiry_days()} days.'
            if facts['builtin_scanner'] and not facts['builtin_live']:
                fix = ' Fix: start the built-in Sentinel or bring it up to date on the Sentinels page.'
            elif facts['builtin_scanner']:
                fix = ' Fix: bring the built-in Sentinel up to date on the Sentinels page.'
            elif facts['live_sentinels']:  # remote Sentinels only: there is no built-in one to start, and nothing to do on this side
                lead = (f"{old} AI-written check(s) are waiting: this install's {fleet_lib.sentinels_text(facts['live_sentinels'])} {'is' if facts['live_sentinels'] == 1 else 'are all'} remote and none of "
                        f"{'it' if facts['live_sentinels'] == 1 else 'them'} runs template checks yet. ")
                fix = ' Nothing needs starting here.'
            else:
                fix = ' Fix: bring a Sentinel online (see the Sentinels page).'
            return {'code': 'no_sentinel', 'title': 'AI-written checks cannot be tested yet', 'detail': lead + tail + fix, 'facts': facts}
        if not ai_jobs.ai_on():
            return {'code': 'ai_off', 'title': 'AI-written checks cannot be tested yet',
                    'detail': f'{old} AI-written check(s) are waiting because the AI provider is not turned on, and the second-pass review needs it. '
                              'Fix: turn the AI provider on in Settings, AI.',
                    'facts': {'pending': old}}
    week = now - datetime.timedelta(days=7)
    bad = G.objects.filter(status__in=(G.STATUS_INVALID, G.STATUS_EXPIRED)).filter(
        Q(validated_at__gte=week) | Q(validated_at__isnull=True, created_at__gte=week)).count()
    good = G.objects.filter(status=G.STATUS_VALID, validated_at__gte=week).count()
    if bad >= 5 and not good:
        top = summary(now)['reasons']
        why = top[0]['reason'] if top else 'no reason recorded'
        return {'code': 'all_rejected', 'title': 'Every AI-written check was rejected this week',
                'detail': f'{bad} AI-written checks were rejected or expired in the last seven days and none passed. The most common reason: {why}. '
                          'What you can do: check that the CVE feed carries product and version data for the CVEs that were tried, and that a Sentinel '
                          'that runs template checks is online. If the reason is a refused or empty AI answer, the AI Model Usage page shows the '
                          'refusals. A different model is not the usual cure.',
                'facts': {'rejected': bad, 'top_reason': why}}
    return None
