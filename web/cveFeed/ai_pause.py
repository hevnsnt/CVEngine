"""The AI provider's "usage limit reached" refusal (Anthropic pausing an organisation's API requests until a date): one admin alert that names it.

The AI reviewer container sees the refusal's message and sends it with the failed job (``provider_message``, only when it is this refusal, cut to
``MESSAGE_MAX``); ``ai_jobs.submit`` calls ``raise_alert``. One row stays open while the pause lasts (``code`` is unique among open rows) and is
refreshed by each refusal; the next answered job resolves it (``resolve_alert``). The reviewer meanwhile waits hours, not 15 minutes, between tries."""
import hashlib
import logging
import re

from django.utils import timezone

logger = logging.getLogger(__name__)

CODE = 'ai_provider_paused'
MESSAGE_MAX = 300
USAGE_LIMIT = re.compile(r'usage limit|regain access', re.I)
RESUME = re.compile(r'(?:regain access|resume|available again|reset)s?\s+(?:on|at|after|by)\s+([^.\n]{4,60})', re.I)
TITLE = 'The AI provider paused API requests (usage limit reached)'


def is_usage_limit(message):
    return bool(USAGE_LIMIT.search(str(message or '')))


def resume_text(message):
    """The resume date the provider's message carries (as it wrote it), or ''."""
    found = RESUME.search(str(message or ''))
    return found.group(1).strip() if found else ''


def _detail(message, resume):
    when = f' The provider says access returns {resume}.' if resume else ' The message names no resume date.'
    return ('The AI provider refused the AI reviewer\'s calls: its usage limit for this organisation is reached, so no AI work runs until the limit '
            f'is raised or resets.{when} Refused calls are not billed and do not count as failed attempts; the reviewer retries every few hours.\n'
            f'Provider message: {str(message)[:MESSAGE_MAX]}')


def raise_alert(message, now=None):
    """Open (or refresh) the one alert for the pause. Never raises: a report must not fail the job's answer. Returns the alert or None."""
    try:
        from cveFeed import reviewer
        from cveFeed.models import AdminAlert
        now = now or timezone.now()
        resume = resume_text(message)
        digest = hashlib.sha1(f'{CODE}|{resume}'.encode()).hexdigest()[:20]
        facts = {'resume': resume, 'message': str(message)[:MESSAGE_MAX]}
        alert = AdminAlert.objects.filter(code=CODE, resolved_at__isnull=True).first()
        if alert is None:
            return AdminAlert.objects.create(code=CODE, severity='warning', title=TITLE, detail=_detail(message, resume), facts=facts, digest=digest,
                                             first_seen=now, last_seen=now, **reviewer.carried_dismissal(CODE, digest, 'warning', now))
        alert.detail, alert.facts, alert.digest, alert.last_seen = _detail(message, resume), facts, digest, now
        alert.save(update_fields=['detail', 'facts', 'digest', 'last_seen'])
        return alert
    except Exception:  # noqa: BLE001
        logger.warning('AI pause: could not record the alert', exc_info=True)
        return None


def resolve_alert(now=None):
    """A job was answered: the pause is over. Returns how many alerts it resolved."""
    try:
        from cveFeed.models import AdminAlert
        return AdminAlert.objects.filter(code=CODE, resolved_at__isnull=True).update(resolved_at=now or timezone.now())
    except Exception:  # noqa: BLE001
        logger.warning('AI pause: could not resolve the alert', exc_info=True)
        return 0
