"""Sending the email reports: which are due, the one send of each period, retries, and the unsubscribe links (docs/REPORTING.md).

``send_due`` is the body of the 15-minute beat task ``send_report_digests``. A period is never sent twice, whatever fails:

- a subscription is claimed with a compare-and-set on ``next_run_at`` (the slot is moved first, then the email is made), so two workers cannot both take it;
- a ``ReportDelivery`` row is unique per (subscription, period start), so a repeated claim cannot make a second email;
- a send that was interrupted part-way (the worker died) is marked ``unknown`` after two hours and is never retried by itself;
- a server that was down for weeks sends only the latest period once: the next slot is worked out from now, not from the missed one.

Only a failure that cannot have delivered anything (the connection could not be made, a time-out before the message was accepted) is retried, for the
recipients it failed for, at most twice. A refused address is never retried. The email is made with the access of the subscription's ``owner``, worked out
again at every send: when they can no longer manage the scope the subscription switches itself off and says why.

Nothing here contacts a host: the digest reads stored results (``cveFeed.report_digest``).
"""
import hashlib
import logging
import os
import re
import secrets
import time
from datetime import timedelta

from django.core import signing
from django.db import IntegrityError, transaction
from django.db.models import F
from django.urls import reverse
from django.utils import timezone

from agentapi import report_scope
from cveFeed import mailer, report_digest, report_export, report_schedule
from cveFeed.models import ReportDelivery, ReportSubscription

logger = logging.getLogger(__name__)

BATCH = 20
BUDGET_SECONDS = 900
STUCK_AFTER = timedelta(hours=2)
RETRY_DELAYS = (timedelta(minutes=30), timedelta(hours=2))
MAX_ATTEMPTS = 3
KEEP_DELIVERIES = 50
SALT = 'cvengine.report-unsubscribe'
MIME = {'pdf': 'application/pdf', 'csv': 'text/csv'}
NO_MAIL = 'outgoing mail is not set up (Settings, Email)'


# --- access and bookkeeping -----------------------------------------------------------------------------------------------------

def _scope_name(sub):
    return sub.project.name if sub.project_id else sub.org.name


def _scope(sub, user=None):
    """The ReportScope of ``sub`` as ``user`` (default: its owner) can read it now, or None."""
    user = user or sub.owner
    if user is None:
        return None
    return report_scope.for_worker(user, 'project' if sub.project_id else 'org', project_id=sub.project_id, org_id=sub.org_id)


def access_problem(sub):
    """``(sentence, scope)``: why the owner can no longer run ``sub`` (the sentence), or ``('', scope)`` when they can."""
    owner = sub.owner
    if owner is None:
        return 'the person it ran as was removed; someone with access must save it again', None
    if not owner.is_active:
        return 'the person it ran as is disabled; someone with access must save it again', None
    scope = _scope(sub)
    if scope is None or not report_scope.can_manage(owner, scope):
        return f'the owner of this email report no longer has access to {_scope_name(sub)}', None
    return '', scope


def _audit(sub, action, actor_name='email reports', **detail):
    from dashboard.models import AuditLog
    org_id = sub.org_id or (sub.project.org_id if sub.project_id else None)
    AuditLog.objects.create(actor=None, actor_name=actor_name[:150], action=action, target=f'{_scope_name(sub)}: {sub.name}'[:300], org_id=org_id,
                            detail={'subscription': sub.pk, 'scope': 'project' if sub.project_id else 'org', **detail})


def disable(sub, reason, now=None):
    """Switch ``sub`` off for ``reason`` (a short sentence); it stays off until someone with access saves it again."""
    now = now or timezone.now()
    ReportSubscription._base_manager.filter(pk=sub.pk).update(enabled=False, next_run_at=None, last_status='disabled', last_error=reason[:200], updated_at=now)
    _audit(sub, 'report.subscription.disabled', reason=reason)


def prune(sub):
    """Keep the newest KEEP_DELIVERIES deliveries of ``sub``."""
    keep = list(ReportDelivery.objects.filter(subscription=sub).order_by('-id').values_list('id', flat=True)[:KEEP_DELIVERIES])
    if len(keep) == KEEP_DELIVERIES:
        ReportDelivery.objects.filter(subscription=sub).exclude(id__in=keep).delete()


# --- unsubscribe links ---------------------------------------------------------------------------------------------------------

def _hash(email):
    return hashlib.sha256(email.lower().encode('utf-8')).hexdigest()[:20]


def unsubscribe_token(sub, email):
    """The signed token of one recipient's unsubscribe link. Rotating ``sub.unsubscribe_key`` voids every link already sent."""
    return signing.dumps({'s': sub.pk, 'r': _hash(email), 'k': sub.unsubscribe_key[:12]}, salt=SALT, compress=True)


def read_unsubscribe_token(token):
    """``(subscription, email)`` for a valid token, else None: the subscription must exist, its key must match and one of its recipients must match."""
    try:
        data = signing.loads(str(token)[:600], salt=SALT)
        sub = ReportSubscription._base_manager.select_related('project__org', 'org').filter(pk=int(data['s'])).first()
    except (signing.BadSignature, KeyError, TypeError, ValueError):
        return None
    if sub is None or not secrets.compare_digest(str(data.get('k', '')), sub.unsubscribe_key[:12]):
        return None
    email = next((e for e in sub.recipients if _hash(e) == data.get('r')), None)
    return (sub, email) if email else None


def _unsubscribe_url(sub, email, test=False):
    return f'{mailer.base_url()}{reverse("report_unsubscribe", args=["test" if test else unsubscribe_token(sub, email)])}'


# --- building one email --------------------------------------------------------------------------------------------------------

def _attachment(scope, sub, now):
    """``(tuple for the message or None, info for the email, delivery code, bytes)``: the full report as a file, unless it is over the size cap or
    could not be made (the email is sent either way and says which)."""
    if sub.attach == 'none':
        return None, None, '', 0
    limit = report_scope.attach_max_mb()
    directory = report_export.report_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, secrets.token_hex(24) + '.' + sub.attach)
    try:
        report_export.build_file(scope, 'findings', sub.attach, False, path, now)
        size = os.path.getsize(path)
        if size > limit * 1024 * 1024:
            return None, {'state': 'too_large', 'kind': sub.attach, 'mb': f'{size / 1024 / 1024:.1f}', 'limit_mb': limit}, 'too_large', size
        name = f"cvengine-report-{re.sub(r'[^A-Za-z0-9._-]+', '-', scope.slug)}-{now:%Y%m%d}.{sub.attach}"
        with open(path, 'rb') as fh:
            content = fh.read()
        return (name, content, MIME[sub.attach]), {'state': 'attached', 'kind': sub.attach, 'filename': name}, sub.attach, size
    except Exception:  # noqa: BLE001 - a report that could not be made never stops the email
        logger.warning('could not build the attachment of email report %s', sub.pk, exc_info=True)
        return None, {'state': 'failed', 'kind': sub.attach}, 'failed', 0
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _owner_name(sub):
    owner = sub.owner
    return (owner.get_full_name() or owner.username) if owner else ''


def _list_id(sub):
    name = re.sub(r'[^\x20-\x7e]|["<>]', '', sub.name).strip() or 'cvENGINE email report'
    return f'"{name}" <sub-{sub.pk}.reports.{mailer._instance(mailer.row()).replace(":", ".")}>'


def _send(delivery, sub, digest, attachment, emails, test=False):
    """Make and send one message per address of ``emails`` over one connection, and record each one's outcome on ``delivery`` (not saved here)."""
    cfg = mailer.row()
    tuple_, info, code, size = attachment
    messages = []
    for email in emails:
        url = _unsubscribe_url(sub, email, test=test)
        subject, text, html = report_digest.render(digest, sub, email, url, attachment=info, owner_name=_owner_name(sub))
        messages.append(mailer.digest_message(cfg, email, ('[Test] ' + subject) if test else subject, text, html, url, _list_id(sub), tuple_))
    results = mailer.send_many(messages, cfg)
    by_email = {r['email']: r for r in delivery.recipients}
    for email, (ok, error, transient) in zip(emails, results):
        by_email[email].update(status='sent' if ok else ('failed' if transient else 'refused'), error=error[:200], transient=bool(transient and not ok))
    delivery.attachment, delivery.attachment_bytes = code, size


def _finish(delivery, sub, now, scope):
    """Work out the delivery's status from its recipients, schedule a retry for transient failures, and tell the subscription."""
    states = [r['status'] for r in delivery.recipients]
    sent = states.count('sent')
    delivery.status = 'sent' if sent == len(states) else 'partial' if sent else 'failed'
    retry = [r for r in delivery.recipients if r['status'] == 'failed' and r.get('transient')]
    delivery.next_retry_at = now + RETRY_DELAYS[min(delivery.attempts, len(RETRY_DELAYS)) - 1] if retry and delivery.attempts < MAX_ATTEMPTS and not delivery.test else None
    delivery.finished_at = now
    first_error = next((r['error'] for r in delivery.recipients if r['error']), '')
    delivery.error = first_error if delivery.status != 'sent' else ''
    delivery.save()
    if delivery.test:
        return
    failed = len(states) - sent
    update = {'last_status': delivery.status, 'last_error': delivery.error[:200] if delivery.status != 'sent' else ''}
    if sent:
        update['last_sent_at'] = now
    if delivery.status == 'partial':
        update['last_error'] = f'{failed} of {len(states)} failed: {first_error}'[:200]
    ReportSubscription._base_manager.filter(pk=sub.pk).update(**update)
    if scope.kind == 'project':
        from cveFeed import activity
        activity.log('report_digest', f"Email report {sub.name!r} sent to {sent} recipient{'' if sent == 1 else 's'}", project=scope.project.pk)
    else:  # a project-less activity row is visible system-wide and would show the organization's name: the audit log is the record
        _audit(sub, 'report.subscription.sent', sent=sent, failed=failed, period=delivery.period_start.date().isoformat())


def _digest(scope, sub, start, end, now):
    return report_digest.build(scope, start, end, sub.cadence, now, tz=sub.timezone)


def deliver_period(sub, now):
    """Send the period that ends at ``sub.next_run_at`` (once), then prune. Returns the outcome word: sent, partial, failed, skipped, disabled or ''
    when another worker already took the period."""
    period_end = sub.next_run_at
    period_start = report_schedule.previous_slot(sub, period_end)
    claimed = ReportSubscription._base_manager.filter(pk=sub.pk, enabled=True, next_run_at=period_end).update(
        next_run_at=report_schedule.next_slot(sub, max(now, period_end)))  # moved first: from now, so a long outage sends only the latest period
    if not claimed:
        return ''
    problem, scope = access_problem(sub)
    if problem:
        disable(sub, problem, now)
        return 'disabled'
    if not mailer.ready():
        try:
            with transaction.atomic():
                ReportDelivery.objects.create(subscription=sub, period_start=period_start, period_end=period_end, status='skipped', error=NO_MAIL, finished_at=now)
        except IntegrityError:
            return ''
        ReportSubscription._base_manager.filter(pk=sub.pk).update(last_status='skipped', last_error=NO_MAIL)
        prune(sub)
        return 'skipped'
    emails = list(sub.recipients)
    try:
        with transaction.atomic():
            delivery = ReportDelivery.objects.create(subscription=sub, period_start=period_start, period_end=period_end, status='sending',
                                                     recipients=[{'email': e, 'status': 'pending', 'error': '', 'transient': False} for e in emails])
    except IntegrityError:
        return ''  # the period was handled already
    try:
        digest = _digest(scope, sub, period_start, period_end, now)
    except Exception:  # noqa: BLE001 - a database error while reading: retry later, say so
        logger.exception('could not build email report %s', sub.pk)
        for r in delivery.recipients:
            r.update(status='failed', error='the report could not be built; it will be tried again', transient=True)
        _finish(delivery, sub, now, scope)
        return delivery.status
    delivery.summary = {k: digest['headline'][k] for k in ('open_findings', 'exposed_hosts', 'new_findings', 'fixed')}
    _send(delivery, sub, digest, _attachment(scope, sub, now), emails)
    _finish(delivery, sub, now, scope)
    prune(sub)
    return delivery.status


# --- the beat ------------------------------------------------------------------------------------------------------------------

def expire_stuck(now):
    """A delivery still ``sending`` after STUCK_AFTER lost its worker part-way: it may or may not have reached anyone, so it is ``unknown`` and never retried."""
    n = ReportDelivery.objects.filter(status='sending', created_at__lt=now - STUCK_AFTER).update(
        status='unknown', finished_at=now, error='interrupted while sending; not retried so nobody gets it twice')
    for delivery in ReportDelivery.objects.filter(status='unknown', finished_at=now).select_related('subscription'):
        if not delivery.test:
            ReportSubscription._base_manager.filter(pk=delivery.subscription_id).update(last_status='unknown', last_error=delivery.error)
    return n


def retry_failed(now):
    """Send again to the recipients whose failure was transient, for deliveries due a retry. Returns how many deliveries were retried."""
    done = 0
    due = ReportDelivery.objects.filter(status__in=('failed', 'partial'), test=False, next_retry_at__lte=now, attempts__lt=MAX_ATTEMPTS).select_related(
        'subscription__project__org', 'subscription__org', 'subscription__owner')
    for d in due:
        claimed = ReportDelivery.objects.filter(pk=d.pk, attempts=d.attempts, status=d.status).update(status='sending', attempts=F('attempts') + 1, next_retry_at=None)
        if not claimed:
            continue
        d.refresh_from_db()
        sub = d.subscription
        try:
            problem, scope = access_problem(sub)
            wanted = [r['email'] for r in d.recipients if r['status'] == 'failed' and r.get('transient')]
            if problem or not wanted or not mailer.ready():
                d.status = 'partial' if any(r['status'] == 'sent' for r in d.recipients) else 'failed'
                d.save(update_fields=['status'])
                continue
            digest = _digest(scope, sub, d.period_start, d.period_end, now)
            _send(d, sub, digest, _attachment(scope, sub, now), wanted)
            _finish(d, sub, now, scope)
            done += 1
        except Exception:  # noqa: BLE001 - one delivery's failure never stops the rest
            logger.exception('retry of email report delivery %s failed', d.pk)
            ReportDelivery.objects.filter(pk=d.pk, status='sending').update(status='unknown', finished_at=now, error='interrupted while sending; not retried so nobody gets it twice')
    return done


def send_due(now=None):
    """The beat body: expire stuck sends, retry transient failures, then send each subscription whose slot has come (at most BATCH, within
    BUDGET_SECONDS). One failure never stops the rest; ``next_run_at`` has moved before the send is tried. Returns the counts."""
    now = now or timezone.now()
    started = time.monotonic()
    counts = {'sent': 0, 'partial': 0, 'failed': 0, 'skipped': 0, 'disabled': 0}
    expire_stuck(now)
    retry_failed(now)
    due = ReportSubscription._base_manager.filter(enabled=True, next_run_at__lte=now).select_related('project__org', 'org', 'owner').order_by('next_run_at', 'id')[:BATCH]
    for sub in due:
        if time.monotonic() - started > BUDGET_SECONDS:
            break
        try:
            outcome = deliver_period(sub, now)
        except Exception:  # noqa: BLE001
            logger.exception('email report %s failed', sub.pk)
            outcome = 'failed'
        if outcome in counts:
            counts[outcome] += 1
    return counts


# --- a test send -----------------------------------------------------------------------------------------------------------------

def send_test(sub, user, now=None):
    """Send ``sub``'s email for the period that ends now to ``user`` only (subject starting "[Test] "), with the same content and attachment as a real
    one. A delivery row records it (``test``), outside the one-per-period rule. Returns the delivery."""
    now = now or timezone.now()
    scope = _scope(sub, user)
    start = report_schedule.trailing(sub, now)
    delivery = ReportDelivery.objects.create(subscription=sub, period_start=start, period_end=now, test=True, requested_by=user, status='sending',
                                             recipients=[{'email': user.email, 'status': 'pending', 'error': '', 'transient': False}])
    if not mailer.ready():
        delivery.recipients[0].update(status='failed', error=NO_MAIL)
        _finish(delivery, sub, now, scope)
        return delivery
    try:
        digest = _digest(scope, sub, start, now, now)
        _send(delivery, sub, digest, _attachment(scope, sub, now), [user.email], test=True)
    except Exception:  # noqa: BLE001
        logger.exception('test send of email report %s failed', sub.pk)
        delivery.recipients[0].update(status='failed', error='the report could not be built')
    _finish(delivery, sub, now, scope)
    return delivery


def send_test_by_id(subscription_id, user_id):
    """The task body of a test send: the person must still be able to manage the scope, and must have a valid address."""
    from django.contrib.auth.models import User
    sub = ReportSubscription._base_manager.select_related('project__org', 'org', 'owner').filter(pk=subscription_id).first()
    user = User.objects.filter(pk=user_id, is_active=True).first()
    if sub is None or user is None or not mailer.EMAIL_RE.match(user.email or ''):
        return {'status': 'skipped'}
    scope = _scope(sub, user)
    if scope is None or not report_scope.can_manage(user, scope):
        return {'status': 'skipped'}
    return {'status': send_test(sub, user).status}
