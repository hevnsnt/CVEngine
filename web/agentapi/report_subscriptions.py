"""Email reports (REST and MCP): a weekly or monthly summary of a project or a whole organization, sent by email (cveFeed.report_digests).

Who may do what (docs/REPORTING.md, docs/TENANCY.md): anyone who can read a project may see its email reports; an organization's are seen by people with an
organization role (a person added to some of its projects only gets a 404). A project's are created, changed, paused, tested and deleted by a write role
(an audit role and a read-only token never); an organization's by an Org Admin or an App Admin. Anyone who may manage a scope may change any subscription
in it, and saving makes them its ``owner``: the email is made with the owner's access, worked out again at every send.

The model is unscoped (a whole-organization report has no project), so every read here checks the caller's access to the subscription's scope explicitly.
"""
import datetime
import re

from django.core.cache import cache
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone

from agentapi import report_scope
from agentapi.services import ApiError, _user_brief
from cveFeed import mailer, report_digest, report_digests, report_schedule
from cveFeed.models import ReportDelivery, ReportSubscription
from tenancy import audit, throttle

FIELDS = ('name', 'project', 'org', 'recipients', 'cadence', 'weekday', 'day_of_month', 'send_time', 'timezone', 'attach', 'enabled', 'confirm_opted_out')
SCHEDULE_FIELDS = ('cadence', 'weekday', 'day_of_month', 'send_time', 'timezone')
TEST_SECONDS, TEST_PER_HOUR = 60, 10
_CONTROL = re.compile(r'[\x00-\x1f\x7f]+')
_TIME = re.compile(r'^([01]\d|2[0-3]):(00|15|30|45)$')
PREVIEW_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'; sandbox"


def _iso(value):
    return value.isoformat() if value else None


# --- access ----------------------------------------------------------------------------------------------------------------

def _scope_of(ctx, sub):
    return report_scope.resolve(ctx, project=sub.project.slug if sub.project_id else None, org=sub.org.slug if sub.org_id else None)


def _refusal(scope, ctx):
    if ctx.token is not None and getattr(ctx.token, 'read_only', False):
        return 'this token is read only'
    if scope.kind == 'org':
        return 'only an Org Admin can manage email reports of a whole organization'
    return 'audit role is read only'


def _get(ctx, subscription_id, manage=False):
    """``(subscription, scope)``: 404 when the caller cannot view its scope (the same answer as a missing one), 403 when they can view but not manage."""
    sub = ReportSubscription._base_manager.select_related('project__org', 'org', 'owner', 'created_by').filter(pk=subscription_id).first()
    if sub is None:
        raise ApiError(404, 'email report not found')
    try:
        scope = _scope_of(ctx, sub)
    except ApiError:
        raise ApiError(404, 'email report not found')
    if not report_scope.can_view_subscriptions(ctx.user, scope):
        raise ApiError(404, 'email report not found')
    if manage and not report_scope.can_manage(ctx.user, scope, ctx.token):
        raise ApiError(403, _refusal(scope, ctx))
    return sub, scope


def _named_scope(ctx, params):
    """The scope named by ``project`` or ``org`` in ``params`` (read access, and the right to see its email reports), or None when neither is named."""
    project, org = params.get('project') or None, params.get('org') or None
    if not project and not org:
        return None
    scope = report_scope.resolve(ctx, project=project, org=org)
    if not report_scope.can_view_subscriptions(ctx.user, scope):
        raise ApiError(404, 'organization not found' if org else 'project not found')
    return scope


# --- the view of a subscription ---------------------------------------------------------------------------------------------

def _last_test(sub):
    d = ReportDelivery.objects.filter(subscription=sub, test=True).order_by('-id').first()
    if d is None:
        return None
    return {'status': d.status, 'at': _iso(d.finished_at or d.created_at), 'to': d.recipients[0]['email'] if d.recipients else '', 'error': d.error}


def _view(sub, can_manage):
    scope = ({'kind': 'project', 'slug': sub.project.slug, 'name': sub.project.name, 'org': sub.project.org.slug if sub.project.org_id else ''}
             if sub.project_id else {'kind': 'org', 'slug': sub.org.slug, 'name': sub.org.name})
    return {'id': sub.pk, 'name': sub.name, 'scope': scope, 'recipients': list(sub.recipients), 'opted_out': list(sub.opted_out or []), 'cadence': sub.cadence,
            'weekday': sub.weekday, 'day_of_month': sub.day_of_month, 'send_time': f'{sub.send_time:%H:%M}', 'timezone': sub.timezone, 'attach': sub.attach,
            'enabled': sub.enabled, 'schedule': report_schedule.summary(sub), 'next_run_at': _iso(sub.next_run_at), 'last_sent_at': _iso(sub.last_sent_at),
            'last_status': sub.last_status, 'last_error': sub.last_error, 'owner': _user_brief(sub.owner), 'created_by': _user_brief(sub.created_by),
            'created': _iso(sub.created_at), 'updated': _iso(sub.updated_at), 'can_manage': can_manage, 'last_test': _last_test(sub)}


def _views(ctx, subs):
    """Each subscription as ``_view`` shows it, with ``can_manage`` worked out once per scope."""
    cache_, out = {}, []
    for sub in subs:
        key = ('p', sub.project_id) if sub.project_id else ('o', sub.org_id)
        if key not in cache_:
            try:
                cache_[key] = report_scope.can_manage(ctx.user, _scope_of(ctx, sub), ctx.token)
            except ApiError:
                cache_[key] = False
        out.append(_view(sub, cache_[key]))
    return out


# --- validation ------------------------------------------------------------------------------------------------------------

def _int(body, key, low, high):
    value = body[key]
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ApiError(400, f'{key} must be a whole number from {low} to {high}')
    return value


def _clean(body, creating):
    """The validated fields of ``body``: a 400 for anything unknown, mistyped or out of range."""
    if not isinstance(body, dict):
        raise ApiError(400, 'body must be a JSON object')
    unknown = sorted(set(body) - set(FIELDS))
    if unknown:
        raise ApiError(400, f'unknown field(s): {", ".join(str(k) for k in unknown)}')
    if not creating and ('project' in body or 'org' in body):
        raise ApiError(400, 'the scope of an email report cannot change; create a new one')
    out = {}
    if creating or 'name' in body:
        name = body.get('name')
        if not isinstance(name, str):
            raise ApiError(400, 'name is required')
        name = ' '.join(_CONTROL.sub(' ', name).split())[:ReportSubscription.MAX_NAME]
        if not name:
            raise ApiError(400, 'name is required')
        out['name'] = name
    if creating or 'recipients' in body:
        raw = body.get('recipients')
        if not isinstance(raw, list) or any(not isinstance(r, str) for r in raw):
            raise ApiError(400, 'recipients must be a list of email addresses')
        emails = list(dict.fromkeys(r.strip().lower() for r in raw if r.strip()))
        bad = [e for e in emails if not mailer.EMAIL_RE.match(e)]
        if bad:
            raise ApiError(400, f'not an email address: {bad[0][:80]}')
        if not 1 <= len(emails) <= ReportSubscription.MAX_RECIPIENTS:
            raise ApiError(400, f'give from 1 to {ReportSubscription.MAX_RECIPIENTS} recipients')
        out['recipients'] = emails
    if 'cadence' in body:
        if body['cadence'] not in ReportSubscription.CADENCES:
            raise ApiError(400, f'cadence must be one of: {", ".join(ReportSubscription.CADENCES)}')
        out['cadence'] = body['cadence']
    if 'weekday' in body:
        out['weekday'] = _int(body, 'weekday', 0, 6)
    if 'day_of_month' in body:
        out['day_of_month'] = _int(body, 'day_of_month', 1, 28)
    if 'send_time' in body:
        text = body['send_time']
        if not isinstance(text, str) or not _TIME.match(text):
            raise ApiError(400, 'send_time must be HH:MM, on the quarter hour (00, 15, 30 or 45)')
        out['send_time'] = datetime.time(int(text[:2]), int(text[3:]))
    if 'timezone' in body:
        try:
            report_schedule.zone(body['timezone'])
        except ValueError:
            raise ApiError(400, 'timezone must be an IANA time zone name such as Europe/London')
        out['timezone'] = body['timezone']
    if 'attach' in body:
        if body['attach'] not in ReportSubscription.ATTACH:
            raise ApiError(400, f'attach must be one of: {", ".join(ReportSubscription.ATTACH)}')
        out['attach'] = body['attach']
    for key in ('enabled', 'confirm_opted_out'):
        if key in body:
            if not isinstance(body[key], bool):
                raise ApiError(400, f'{key} must be true or false')
            out[key] = body[key]
    return out


def _opted_out_check(emails, opted_out, confirmed):
    """Adding back an address that used the unsubscribe link needs ``confirm_opted_out``; returns the opt-out list without the addresses added back."""
    gone = {o['email']: o for o in opted_out or []}
    again = [e for e in emails if e in gone]
    if again and not confirmed:
        when = str(gone[again[0]].get('at', ''))[:10]
        raise ApiError(400, f'{again[0]} unsubscribed on {when}; send confirm_opted_out to add it back')
    return [o for o in opted_out or [] if o['email'] not in emails]


def _next_run(sub, now):
    return report_schedule.next_slot(sub, now) if sub.enabled else None


# --- routes ----------------------------------------------------------------------------------------------------------------

def list_subscriptions(ctx, params):
    scope = _named_scope(ctx, params)
    if scope is not None:
        query = Q(project_id=scope.project.pk) if scope.kind == 'project' else Q(org_id=scope.org.pk)
    else:  # everything the caller can see
        listed = report_scope.list_scopes(ctx)['scopes']
        from dashboard.models import Org, Project
        projects = list(Project._base_manager.filter(slug__in=[s['slug'] for s in listed if s['kind'] == 'project' and s['can_view_subscriptions']]).values_list('pk', flat=True))
        orgs = list(Org.objects.filter(slug__in=[s['slug'] for s in listed if s['kind'] == 'org' and s['can_view_subscriptions']]).values_list('pk', flat=True))
        query = Q(project_id__in=projects) | Q(org_id__in=orgs)
    subs = ReportSubscription._base_manager.filter(query).select_related('project__org', 'org', 'owner', 'created_by').order_by('name', 'id')
    out = {'results': _views(ctx, subs), 'limits': report_scope.limits(), 'mail_ready': mailer.ready()}
    if scope is not None:
        out['can_create'] = report_scope.can_manage(ctx.user, scope, ctx.token)
    return out


def get_subscription(ctx, subscription_id):
    sub, scope = _get(ctx, subscription_id)
    return _view(sub, report_scope.can_manage(ctx.user, scope, ctx.token))


def create_subscription(ctx, body):
    from dashboard.models import Org, Project
    if not isinstance(body, dict):
        raise ApiError(400, 'body must be a JSON object')
    scope = report_scope.resolve(ctx, project=body.get('project') or None, org=body.get('org') or None)
    if not report_scope.can_view_subscriptions(ctx.user, scope):
        raise ApiError(404, 'organization not found' if scope.kind == 'org' else 'project not found')
    if not report_scope.can_manage(ctx.user, scope, ctx.token):
        raise ApiError(403, _refusal(scope, ctx))
    fields = _clean({k: v for k, v in body.items() if k not in ('project', 'org')}, creating=True)
    confirmed = fields.pop('confirm_opted_out', False)
    owner_key = {'project': scope.project} if scope.kind == 'project' else {'org': scope.org}
    now = timezone.now()
    with transaction.atomic():
        # the project or organization row is the lock that keeps two creations from both slipping under a cap
        (Project if scope.kind == 'project' else Org).objects.select_for_update().get(pk=(scope.project or scope.org).pk)
        if ReportSubscription._base_manager.filter(**owner_key).count() >= ReportSubscription.MAX_PER_SCOPE:
            raise ApiError(400, f'{scope.label} already has {ReportSubscription.MAX_PER_SCOPE} email reports; delete one first')
        if ReportSubscription._base_manager.filter(owner=ctx.user).count() >= ReportSubscription.MAX_PER_OWNER:
            raise ApiError(400, f'you already run {ReportSubscription.MAX_PER_OWNER} email reports; delete one first')
        sub = ReportSubscription(**owner_key, owner=ctx.user, created_by=ctx.user, **fields)
        _opted_out_check(sub.recipients, [], confirmed)
        sub.next_run_at = _next_run(sub, now)
        sub.save()
    audit.record(ctx.user, 'report.subscription.create', f'{scope.label}: {sub.name}', org=scope.org.pk if scope.kind == 'org' else scope.project.org_id,
                 subscription=sub.pk, scope=scope.kind, recipients=sub.recipients, schedule=report_schedule.summary(sub), attach=sub.attach)
    sub = ReportSubscription._base_manager.select_related('project__org', 'org', 'owner', 'created_by').get(pk=sub.pk)
    return _view(sub, True), 201


def update_subscription(ctx, subscription_id, body):
    sub, scope = _get(ctx, subscription_id, manage=True)
    fields = _clean(body, creating=False)
    if not fields:
        raise ApiError(400, f'nothing to change: send one or more of {", ".join(f for f in FIELDS if f not in ("project", "org"))}')
    confirmed = fields.pop('confirm_opted_out', False)
    now = timezone.now()
    with transaction.atomic():
        locked = ReportSubscription._base_manager.select_for_update().get(pk=sub.pk)
        was_enabled, schedule_before = locked.enabled, tuple(getattr(locked, f) for f in SCHEDULE_FIELDS)
        if 'recipients' in fields:
            locked.opted_out = _opted_out_check(fields['recipients'], locked.opted_out, confirmed)
        for key, value in fields.items():
            setattr(locked, key, value)
        locked.owner = ctx.user  # the report runs with the access of the last person who saved it
        if locked.enabled and (not was_enabled or tuple(getattr(locked, f) for f in SCHEDULE_FIELDS) != schedule_before or locked.next_run_at is None):
            locked.next_run_at = _next_run(locked, now)
            if not was_enabled:
                locked.last_status, locked.last_error = '', ''
        elif not locked.enabled:
            locked.next_run_at = None
        locked.save()
    audit.record(ctx.user, 'report.subscription.update', f'{scope.label}: {locked.name}', org=scope.org.pk if scope.kind == 'org' else scope.project.org_id,
                 subscription=locked.pk, scope=scope.kind, changed=sorted(fields), recipients=locked.recipients)
    sub = ReportSubscription._base_manager.select_related('project__org', 'org', 'owner', 'created_by').get(pk=sub.pk)
    return _view(sub, True)


def delete_subscription(ctx, subscription_id):
    sub, scope = _get(ctx, subscription_id, manage=True)
    audit.record(ctx.user, 'report.subscription.delete', f'{scope.label}: {sub.name}', org=scope.org.pk if scope.kind == 'org' else scope.project.org_id,
                 subscription=sub.pk, scope=scope.kind, recipients=sub.recipients)
    sub.delete()
    return {'deleted': True}


def test_subscription(ctx, subscription_id):
    """Queue one test email of the report to the caller's own address (never to the recipients)."""
    sub, scope = _get(ctx, subscription_id, manage=True)
    email = (ctx.user.email or '').strip()
    if not mailer.EMAIL_RE.match(email):
        raise ApiError(400, 'your account has no valid email address to send the test to')
    if not mailer.ready():
        raise ApiError(409, 'outgoing mail is not set up (Settings, Email)')
    if not cache.add(f'cvengine:report-test:{sub.pk}', 1, timeout=TEST_SECONDS):
        raise ApiError(429, f'a test was sent a moment ago; try again in {TEST_SECONDS} seconds')
    key = f'cvengine:report-test-user:{ctx.user.pk}'
    throttle.count(key, 3600)
    if throttle.exceeded(key, TEST_PER_HOUR + 1):
        raise ApiError(429, f'you can send {TEST_PER_HOUR} test emails an hour; try again later')
    from cveFeed.tasks import send_report_test
    send_report_test.apply_async(args=[sub.pk, ctx.user.pk], queue='report_queue')
    audit.record(ctx.user, 'report.subscription.test', f'{scope.label}: {sub.name}', org=scope.org.pk if scope.kind == 'org' else scope.project.org_id,
                 subscription=sub.pk, scope=scope.kind, to=email)
    return {'status': 'queued', 'to': email}, 202


def _preview(ctx, sub, scope, fmt):
    """The email as it would be made now for the period ending now, built with the viewer's own access (nothing is sent)."""
    fmt = (fmt or 'html').lower()
    if fmt not in ('html', 'text', 'json'):
        raise ApiError(400, 'format must be html, text or json')
    now = timezone.now()
    digest = report_digest.build(scope, report_schedule.trailing(sub, now), now, sub.cadence, now, tz=sub.timezone)
    subject, text, html = report_digest.render(digest, sub if sub.pk else None, ctx.user.email or 'you@example.org',
                                               report_digests._unsubscribe_url(sub, 'x@example.org', test=True), owner_name=ctx.user.get_full_name() or ctx.user.username)
    if fmt == 'html':
        response = HttpResponse(html, content_type='text/html; charset=utf-8')
        response['Content-Security-Policy'] = PREVIEW_CSP  # the page's own policy forbids framing; this one lets the Reporting page frame it, with no script
        response['X-Content-Type-Options'] = 'nosniff'
        response['Cache-Control'] = 'private, no-store'
        return response
    return {'subject': subject, 'text': text, 'digest': digest}


def preview_subscription(ctx, subscription_id, params):
    sub, scope = _get(ctx, subscription_id)
    return _preview(ctx, sub, scope, params.get('format'))


def digest_preview(ctx, params):
    """The preview of unsaved settings: ``project`` or ``org``, ``cadence`` (weekly or monthly), optionally ``timezone``."""
    scope = _named_scope(ctx, params)
    if scope is None:
        raise ApiError(400, 'give a project or an organization')
    cadence = params.get('cadence') or 'weekly'
    if cadence not in ReportSubscription.CADENCES:
        raise ApiError(400, f'cadence must be one of: {", ".join(ReportSubscription.CADENCES)}')
    tz = params.get('timezone') or 'UTC'
    try:
        report_schedule.zone(tz)
    except ValueError:
        raise ApiError(400, 'timezone must be an IANA time zone name such as Europe/London')
    sub = ReportSubscription(name='Preview', cadence=cadence, timezone=tz)
    return _preview(ctx, sub, scope, params.get('format'))


def _delivery_view(d):
    states = [r.get('status') for r in d.recipients]
    return {'id': d.pk, 'test': d.test, 'status': d.status, 'period_start': _iso(d.period_start), 'period_end': _iso(d.period_end), 'attempts': d.attempts,
            'attachment': d.attachment, 'error': d.error, 'created': _iso(d.created_at), 'finished': _iso(d.finished_at),
            'next_retry_at': _iso(d.next_retry_at), 'sent': states.count('sent'), 'failed': len(states) - states.count('sent'),
            'recipients': [{'email': r.get('email'), 'status': r.get('status'), 'error': r.get('error', '')} for r in d.recipients]}


def list_deliveries(ctx, subscription_id):
    sub, _ = _get(ctx, subscription_id)
    return {'results': [_delivery_view(d) for d in ReportDelivery.objects.filter(subscription=sub).order_by('-id')[:20]]}
