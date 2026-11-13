"""Questions an administrator answers after an update (and in the setup wizard of a new install), so that an update never switches on, by itself, something
that costs money or changes what is scanned (owner, 2026-11-13).

The rule: a feature that spends the administrator's money, or changes what is scanned, ships OFF (or in its no-cost mode) and stays there until a person
answers the question about it. Features that already existed and that a person switched on keep working: nothing here turns anything off.

Adding a question in a later release is one entry in ``QUESTIONS``: a ``Question`` with its choices, the safe default, ``applies`` (does it matter on this
install), ``decided`` (did a person already choose it somewhere else, in which case it is never asked) and ``apply`` (carries an answer out through the same
Settings handler the Settings page uses, so the validation, the limits and the audit entry are the Settings page's own). Nothing writes a model field
around those handlers. The AI question is a list of lines (``AI_LINES``): the host review is one more line there when it lands.

What is stored: ``cveFeed.SetupAnswer``, one row per question, written only by a person's answer (``later`` is "decide later"). No migration writes one.
Who sees it: App Admins. ``dashboard`` sends one to the page once per session while a question has no row at all; the status strip keeps a reminder while any
question is open; the Settings API (``setup_questions``) lists and answers, and the MCP bridge lists but never answers (a person switches a paid feature on).
"""
import json

from django.db import transaction
from django.test import RequestFactory
from django.utils import timezone

LATER = 'later'
SESSION_KEY = 'setup_questions_redirected'
PAGE = '/cve/update-questions/'


class QuestionError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def _call(handler, user, values):
    """Run a Settings handler as ``user`` with ``values`` as its body: the page's own validation, limits and audit entry apply."""
    from cveFeed import settings_api
    request = RequestFactory().generic('PUT', '/cve/api/settings/question/', json.dumps(values), content_type='application/json')
    request.user = user
    try:
        return handler(request)
    except settings_api.SettingsError as exc:
        raise QuestionError(exc.status, exc.message)


# --- the AI question -----------------------------------------------------------------------------------------------------------------------------------

def _reviewer_row():
    from cveFeed.models import ReviewerSettings
    return ReviewerSettings.objects.order_by('pk').first()


def _review_line_facts():
    """The cost facts of the AI lines, stated once under the question."""
    from cveFeed import reviewer
    from cveFeed.models import ReviewerSettings
    row = _reviewer_row() or ReviewerSettings()
    return [f'Finding review: at most {row.review_daily_max:,} findings a day, one provider call each.',
            f'Server health check: {len(reviewer.ops_hours(row))} calls a day.']


def _apply_reviewer(user, mode):
    from cveFeed import settings_api
    _call(settings_api.reviewer_put, user, {'enabled': mode != 'off', 'auto_close': mode == 'act'})


def _host_review_facts():
    from cveFeed import reviewer
    from cveFeed.models import ReviewerSettings
    row = _reviewer_row() or ReviewerSettings()
    return [f'Host review: the AI reads every open finding of a host that changed, one provider call per host, at most {row.host_review_daily_max:,} a day, and suggests one '
            f'next step. It may start at most {row.host_review_auto_per_project_day:,} safe read-only steps per project a day, and only in a project a person set to automatic.']


def _apply_host_review(user, mode):
    """Off leaves it off; Recommend only and Act on safe steps switch it on with every project on recommend: only a person sets a project to automatic (the host
    card, or Settings > AI model), never an answer on this page."""
    from cveFeed import settings_api
    _call(settings_api.reviewer_put, user, {'host_review_enabled': mode != 'off'})


# (title, the cost facts of the line as a list of sentences, apply(user, mode)): a later release adds its AI feature here, and the three choices cover it.
AI_LINES = (
    ('AI finding review and server health check', _review_line_facts, _apply_reviewer),
    ('AI host review', _host_review_facts, _apply_host_review),
)
NEW_LINES = {2: ('AI host review',)}  # the lines each version of the AI question added: an answer given before is asked again for them


def _ai_applies():
    try:
        from cveFeed import reviewer
        if reviewer.provider_row() is not None:
            return True, ''
    except Exception:  # noqa: BLE001 - a question that cannot be worked out is not asked
        pass
    return False, 'No AI model is connected, so there is nothing to switch on. You can turn AI validation on later in Settings > AI model.'


def _ai_decided():
    row = _reviewer_row()
    if not (row is not None and row.updated_by_id):  # every save of the reviewer settings records who made it
        return False
    from cveFeed.models import SetupAnswer
    # the host review line is new: a person who saved the AI settings before it existed has not decided it, and an update never switches it on for them
    return bool(row.host_review_enabled or SetupAnswer.objects.filter(key='ai_validation', version__gte=2).exists())


def _ai_current():
    row = _reviewer_row()
    if row is None or not row.enabled:
        return 'off'
    return 'act' if row.auto_close else 'recommend'


def _ai_facts():
    return [fact for _title, facts, _apply in AI_LINES for fact in facts()] + ['Your AI provider bills every call.']


def _ai_choices():
    return [
        {'value': 'off', 'label': 'Off', 'tag': 'Nothing is billed', 'effect': 'No AI review. You can turn it on later.'},
        {'value': 'recommend', 'label': 'Recommend only',
         'effect': 'The AI gives a verdict on each finding and each host and a person decides. It never closes or changes a finding, and every host review waits for you to press Start.'},
        {'value': 'act', 'label': 'Act on safe steps',
         'effect': 'As Recommend, and the AI may also close a finding as a false positive when it is sure and the evidence is not hard proof. Host reviews stay on recommend in every project: '
                   'only a person sets a project to automatic, on the host card or in Settings > AI model.'},
    ]


def _ai_apply(user, value, since=None):
    """Carry out an answer. ``since`` is the version of the answer being replaced, when there is one that is older than the question: only the lines added after it
    are applied, so a person who is asked again about the host review changes nothing about the finding review they answered before."""
    newer = {title for version, titles in NEW_LINES.items() if since is not None and version > since for title in titles}
    for title, _facts, apply in AI_LINES:
        if since is None or title in newer:
            apply(user, value)


# --- the scanner question ------------------------------------------------------------------------------------------------------------------------------

def _scan_decided():
    from cveFeed import scanner_plan
    if scanner_plan.chosen():
        return True
    try:
        from dashboard.models import SetupWizard
        row = SetupWizard.objects.order_by('id').first()
        return bool(row is not None and 'plan' in ((row.data or {}).get('steps') or {}))  # the wizard of a new install asked it as its step "Where it runs"
    except Exception:  # noqa: BLE001
        return False


# The answer is the scanner plan itself (cveFeed.scanner_plan, the words of Settings > Sentinels > Which scanners run): internal = the built-in scanner only,
# external = your own Sentinels only (the built-in scanner is removed), both. "External" with no live Sentinel of your own would leave nothing to scan with, so the
# plan stays as it is until the first one checks in (``settle``).
def _scan_choices():
    from cveFeed import scanner_plan
    effects = {
        'internal': 'Internal: the built-in scanner on this server runs the checks. Nothing changes if this is what runs now.',
        'external': 'External: only Sentinels you install on your own machines run the checks, so the built-in scanner is removed, which frees its memory.',
        'both': 'Internal and external: your own Sentinels first, the built-in scanner on this server as the backup.',
    }
    now = scanner_plan.current_plan()
    return [{'value': o['value'], 'label': o['base'], 'effect': effects[o['value']], **({'tag': 'Keeps what runs now'} if o['value'] == now else {})}
            for o in scanner_plan.decision()['options']]


def _live_sentinels():
    from cveFeed import scanner_plan
    try:
        return scanner_plan.externals_live()
    except Exception:  # noqa: BLE001 - not knowing is treated as none: the plan is then not removed
        return 0


def _scan_apply(user, value):
    from cveFeed import scanner_plan, settings_api
    if value == scanner_plan.current_plan():
        return  # what runs now: nothing is changed, nothing restarts
    if value == 'external' and not _live_sentinels():
        return  # no Sentinel of your own yet: the built-in scanner stays until the first one checks in (settle)
    _call(settings_api.scanner_plan_post, user, {'plan': value})


def _scan_current():
    from cveFeed import scanner_plan
    return scanner_plan.current_plan()


def _scan_waiting(row):
    """True while an "inside only" answer waits for the first Sentinel of your own."""
    from cveFeed import scanner_plan
    return bool(row and row.answer == 'external' and scanner_plan.current_plan() != 'external' and scanner_plan._pending(scanner_plan.PENDING_PLAN) != 'external')


def _first_project_slug():
    try:
        from dashboard.models import Project
        return Project.objects.order_by('id').values_list('slug', flat=True).first()
    except Exception:  # noqa: BLE001
        return None


def _scan_next(row):
    """What to do next after an answer that uses Sentinels (``external`` or ``both``), or ``None``."""
    if not row or row.answer not in ('external', 'both'):
        return None
    slug = _first_project_slug()
    steps = [{'text': 'Install a Sentinel inside your network', 'url': '/cve/sentinels/'},
             {'text': 'Tell cvENGINE which internal ranges to scan (only if you scan inside your network)', 'url': f'/cve/{slug}/sentinels/' if slug else '/cve/sentinels/'}]
    from cveFeed import scanner_plan
    lines = ['The server restarts briefly only if the built-in scanner is switched on or off by this.'] if row.answer != scanner_plan.current_plan() or _scan_waiting(row) else []
    if _scan_waiting(row):
        lines.insert(0, 'No Sentinel of your own has checked in yet, so nothing was switched off. The built-in scanner keeps running until the first one does; then your choice is applied.')
    return {'steps': steps, 'notes': lines, 'waiting': _scan_waiting(row)}


def settle(user=None):
    """Apply an "inside only" answer that was waiting for a Sentinel, once one of your own is live. Idempotent; the status strip's poll calls it."""
    from cveFeed.admin_api import audit
    from cveFeed.models import SetupAnswer
    try:
        row = SetupAnswer.objects.filter(key='scan_from', answer='external').first()
        if not _scan_waiting(row) or not _live_sentinels():
            return False
        from cveFeed import scanner_plan
        prior = scanner_plan.current_plan()
        scanner_plan.request('external')
        if user is not None and getattr(user, 'pk', None):
            audit(user, 'scanner_plan.changed', 'external', previous=prior, via='setup question, first Sentinel checked in')
        return True
    except Exception:  # noqa: BLE001 - a poll is never worth a failed page
        return False


# --- the credential checks question ---------------------------------------------------------------------------------------------------------------------

def _cred_current():
    from cveFeed import validation
    return 'on' if validation.credential_checks_allowed() else 'off'


def _cred_decided():
    """A person already turned them on in Settings > Scan policy: that is a choice. "Off" is what the update set, so it is not one until a person answers."""
    return _cred_current() == 'on'


def _cred_choices():
    return [
        {'value': 'off', 'label': 'No', 'tag': 'Keeps what this update set',
         'effect': 'Checks that send credentials stay off. Findings that came from those checks (default logins) are no longer re-confirmed.'},
        {'value': 'on', 'label': 'Yes',
         'effect': 'Turns on the checks that try vendor default logins and send fixed credentials to your hosts. Use it only on hosts you are allowed to log in to.'},
    ]


def _cred_apply(user, value):
    from cveFeed import settings_api
    _call(settings_api.scan_policy_put, user, {'allow_credential_checks': value == 'on'})


# What the page says about the update itself, as information only (nothing to answer).
NOTES = ('Every host is checked once more with nuclei after this update, because the check set changed. Nothing needs to be done.',)


class Question:
    def __init__(self, key, since, title, text, choices, safe_default, applies, decided, apply, current, link, link_text, facts=None, version=1):
        self.key, self.since, self.title, self.text, self.choices, self.facts, self.version = key, since, title, text, choices, facts, version
        self.safe_default, self.applies, self.decided, self.apply, self.current = safe_default, applies, decided, apply, current
        self.link, self.link_text = link, link_text


QUESTIONS = (
    Question('scan_from', '1.4.0', 'Which scanners will you use?',
             'The built-in scanner runs on this server (internal). Sentinels are scanners you install on your own machines (external), and one placed inside your '
             'network also sees what an outsider cannot.',
             _scan_choices, _scan_current, lambda: (True, ''), _scan_decided, _scan_apply, _scan_current, '/cve/sentinels/', 'Settings > Sentinels'),
    Question('ai_validation', '1.4.0', 'Do you want AI validation?',
             'An AI model can double-check your findings and watch the health of the server. It stays off until you say otherwise. Features you already turned '
             'on in an earlier release are not touched.',
             _ai_choices, lambda: 'off', _ai_applies, _ai_decided, _ai_apply, _ai_current, '/cve/settings/#ai', 'Settings > AI model', facts=_ai_facts, version=2),
    Question('credential_checks', '1.4.0', 'Run checks that send credentials?',
             'Some checks try vendor default logins and send fixed credentials (a default password, an API key) to your hosts to see whether they are accepted. '
             'This update turned them off, and they stay off until you say yes.',
             _cred_choices, lambda: 'off', lambda: (True, ''), _cred_decided, _cred_apply, _cred_current, '/cve/settings/#scan_policy', 'Settings > Scan policy'),
)
BY_KEY = {q.key: q for q in QUESTIONS}


def _answers():
    from cveFeed.models import SetupAnswer
    return {a.key: a for a in SetupAnswer.objects.all()}


def _describe(q, answers):
    applies, why = q.applies()
    row = answers.get(q.key)
    new_lines = []
    if row is not None and row.version < q.version:  # answered before the question gained a line: it is asked again, for the new line only
        new_lines = [line for version, lines in NEW_LINES.items() if q.key == 'ai_validation' and version > row.version for line in lines]
        row = None
    if not applies:
        state = 'not_applicable'
    elif q.decided() and not (row and row.answer != LATER):
        state = 'decided'  # a person already chose it elsewhere (Settings, the installer, the update dialog)
    elif row and row.answer != LATER:
        state = 'answered'
    elif row:
        state = 'later'
    else:
        state = 'pending'
    safe = q.safe_default() if callable(q.safe_default) else q.safe_default
    out = {'key': q.key, 'since': q.since, 'title': q.title, 'text': q.text, 'state': state, 'link': q.link, 'link_text': q.link_text,
           'applies': applies, 'why_not': why, 'safe_default': safe, 'current': q.current() if applies else 'off',
           'answer': row.answer if row else None, 'answered_by': row.answered_by.username if row and row.answered_by_id else None,
           'answered_at': row.answered_at.isoformat() if row else None}
    out['choices'] = [{**c, 'safe': c['value'] == safe} for c in q.choices()] if applies else []
    out['facts'] = q.facts() if applies and q.facts else []
    out['new_lines'] = new_lines if applies else []
    if applies and new_lines:  # asked again for the new line only: the words, the facts and the choices are about it alone
        out['title'] = 'AI host review: one new question'
        out['text'] = 'Your earlier answer about finding review and the server health check is kept as it is. This is only about the new AI host review.'
        out['facts'] = [f for title, facts, _apply in AI_LINES if title in new_lines for f in facts()] + ['Your AI provider bills every call.']
        out['choices'] = [{'value': 'off', 'label': 'Keep the host review off', 'safe': True, 'tag': 'Nothing is billed', 'effect': 'The host review stays off. Your finding review is not changed.'},
                          {'value': 'recommend', 'label': 'Switch the host review on', 'safe': False,
                           'effect': 'The AI reviews hosts that changed and suggests a next step; a person starts it. Every project stays on recommend, and a false positive from the host review is never closed by itself. '
                                     'Your finding review is not changed.'}]
    if q.key == 'scan_from':
        out['next'] = _scan_next(row)
    return out


def snapshot():
    """Every question with its state: ``pending`` (nobody answered), ``later`` (decide later), ``answered``, ``decided`` (chosen elsewhere) or
    ``not_applicable`` (counts as off). ``open`` is what the reminder counts; ``pending`` is what sends an administrator to the page."""
    answers = _answers()
    questions = [_describe(q, answers) for q in QUESTIONS]
    pending = sum(1 for q in questions if q['state'] == 'pending')
    later = sum(1 for q in questions if q['state'] == 'later')
    return {'questions': questions, 'pending': pending, 'later': later, 'open': pending + later, 'url': PAGE, 'notes': list(NOTES),
            'safe_default': 'A feature that costs money or changes what is scanned stays off until you answer.'}


def reminder():
    """The line the status strip keeps for an App Admin while a question is open, or None. Never raises: a reminder is not worth a failed page."""
    try:
        n = snapshot()['open']
    except Exception:  # noqa: BLE001
        return None
    if not n:
        return None
    return {'open': n, 'url': PAGE, 'text': f'{n} question{"s" if n != 1 else ""} about this update {"is" if n == 1 else "are"} waiting.'}


def should_redirect(request):
    """Whether this dashboard request goes to the page: an App Admin, a plain page load, at most once per session, only while a question has no answer
    at all (so "decide later" ends it). The API, static files, health and the updater are other routes and are never sent here."""
    user = request.user
    if request.method != 'GET' or not (user.is_authenticated and user.is_superuser) or request.GET.get('skip') == '1':
        return False
    try:
        if request.session.get(SESSION_KEY) or not snapshot()['pending']:
            return False
        request.session[SESSION_KEY] = True
    except Exception:  # noqa: BLE001 - the dashboard always opens
        return False
    return True


def _record(user, key, answer):
    from cveFeed.models import SetupAnswer
    SetupAnswer.objects.update_or_create(key=key, defaults={'answer': answer, 'answered_by': user, 'answered_at': timezone.now(), 'version': BY_KEY[key].version})


def answer(user, key, value):
    """Record an answer: ``value`` is one of the question's choices, or ``later``. A choice is carried out first (through the Settings handler, so a value
    the page would refuse is refused here) and recorded only when that worked."""
    from cveFeed.admin_api import audit
    q = BY_KEY.get(key)
    if q is None:
        raise QuestionError(404, 'no such question')
    if not (user.is_authenticated and user.is_superuser):
        raise QuestionError(403, 'App Admin only')
    applies, why = q.applies()
    if not applies:
        raise QuestionError(409, why)
    if value != LATER and value not in [c['value'] for c in q.choices()]:
        raise QuestionError(400, 'that is not one of the choices')
    from cveFeed.models import SetupAnswer
    earlier = SetupAnswer.objects.filter(key=key).values_list('version', flat=True).first()
    stale = earlier is not None and earlier < q.version  # answered before the question gained a line: only the new line is carried out
    with transaction.atomic():
        if value != LATER:
            if stale and key == 'ai_validation':
                _ai_apply(user, value, since=earlier)
            else:
                q.apply(user, value)
        _record(user, key, value)
    audit(user, 'setup.question', key, answer=value)
    return snapshot()


def answer_many(user, answers):
    """Save every answer of the page in one go: all are checked first, so a refused one saves nothing."""
    if not isinstance(answers, dict) or not answers:
        raise QuestionError(400, 'send answers: {key: choice}')
    if not (user.is_authenticated and user.is_superuser):
        raise QuestionError(403, 'App Admin only')
    for key, value in answers.items():
        q = BY_KEY.get(key)
        if q is None:
            raise QuestionError(404, 'no such question')
        if not q.applies()[0]:
            raise QuestionError(409, q.applies()[1])
        if not isinstance(value, str) or (value != LATER and value not in [c['value'] for c in q.choices()]):
            raise QuestionError(400, 'that is not one of the choices')
    out = None
    for key, value in answers.items():
        out = answer(user, key, value)
    return out


def defer_all(user):
    """"Decide later" for the whole page: every question nobody answered is recorded as ``later``; nothing is switched on."""
    from cveFeed.admin_api import audit
    if not (user.is_authenticated and user.is_superuser):
        raise QuestionError(403, 'App Admin only')
    done = []
    for q in snapshot()['questions']:
        if q['state'] == 'pending':
            _record(user, q['key'], LATER)
            done.append(q['key'])
    if done:
        audit(user, 'setup.question', ','.join(done), answer=LATER)
    return snapshot()
