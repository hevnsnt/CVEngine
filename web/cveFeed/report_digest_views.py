"""The unsubscribe page an email report links to (and the target of the mail program's one-click Unsubscribe).

The signed token in the address is the only credential (``report_digests.read_unsubscribe_token``), so the route is open to anyone who holds a link and
exempt from the CSRF check (an RFC 8058 one-click request carries no CSRF token). A GET only shows a confirmation and changes nothing, so a mail scanner
that opens every link does not unsubscribe anyone; a POST removes the address. A bad, forged or stale token gets one plain answer, whatever is wrong with it.
"""
import logging
from datetime import timezone as dt_timezone

from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from cveFeed import report_digests
from cveFeed.models import ReportSubscription
from tenancy import throttle

logger = logging.getLogger(__name__)
PER_MINUTE = 30


def _page(request, state, status=200, **context):
    response = render(request, 'cveFeed/unsubscribe.html', {'state': state, **context}, status=status)
    response['Cache-Control'] = 'no-store'
    response['Referrer-Policy'] = 'no-referrer'
    return response


def _mask(email):
    local, _, domain = email.partition('@')
    return f'{local[:1]}•••@{domain}'


def _limited(request):
    from reNgine.client_ip import client_ip
    key = f'report-unsub:{client_ip(request) or "unknown"}'  # the client, not the proxy every request comes from (review r3 S2)
    throttle.count(key, 60)
    return throttle.exceeded(key, PER_MINUTE + 1)


@csrf_exempt
@never_cache
@require_http_methods(['GET', 'POST'])
def unsubscribe(request, token):
    if _limited(request):
        return HttpResponse('Too many requests. Try again in a minute.', status=429, content_type='text/plain; charset=utf-8')
    if token == 'test':  # the link of a test send explains itself and changes nothing
        return _page(request, 'test')
    found = report_digests.read_unsubscribe_token(token)
    if found is None:
        return _page(request, 'invalid', status=404)
    sub, email = found
    scope = sub.project.name if sub.project_id else sub.org.name
    if request.method == 'GET':
        return _page(request, 'confirm', name=sub.name, scope=scope, masked=_mask(email))
    with transaction.atomic():
        locked = ReportSubscription._base_manager.select_for_update().get(pk=sub.pk)
        if email not in locked.recipients:  # a second click, or two at once
            return _page(request, 'done', name=sub.name, scope=scope)
        locked.recipients = [e for e in locked.recipients if e != email]
        locked.opted_out = [*locked.opted_out, {'email': email, 'at': timezone.now().astimezone(dt_timezone.utc).isoformat()}]
        update = ['recipients', 'opted_out', 'updated_at']
        if not locked.recipients:
            locked.enabled, locked.next_run_at, locked.last_error = False, None, 'every recipient unsubscribed'
            update += ['enabled', 'next_run_at', 'last_error']
        locked.save(update_fields=update)
    report_digests._audit(locked, 'report.subscription.unsubscribe', actor_name=email, email=email)
    return _page(request, 'done', name=sub.name, scope=scope)
