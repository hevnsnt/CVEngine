"""Audit rows for credential events. An Org Admin reads the rows tagged with their organizations, so an event about a user is
written once for each organization the user belongs to; with none, once without an organization (App Admins only)."""
import logging

from dashboard.models import AuditLog
from tenancy import roles

logger = logging.getLogger(__name__)


def record(actor, action, target='', org=None, **detail):
    AuditLog.objects.create(actor=actor, actor_name=getattr(actor, 'username', '') or '', action=action, target=str(target)[:300],
                            org_id=getattr(org, 'pk', org), detail=detail)


def record_for_user(actor, action, user, target=None, **detail):
    """One row per organization of ``user``, so each organization's admins see their own users' credential events."""
    name = user.username if target is None else target
    org_ids = sorted(roles.user_org_ids(user)) or [None]
    for org_id in org_ids:
        record(actor, action, name, org=org_id, **detail)


def record_for_user_quietly(actor, action, user, **detail):
    """For events recorded in the middle of a security decision (a lockout): the record is best effort, and a failing database write
    must never stop the counter or the refusal that comes with it."""
    try:
        record_for_user(actor, action, user, **detail)
    except Exception:  # noqa: BLE001
        logger.warning('could not record %s for %s', action, getattr(user, 'username', '?'), exc_info=True)
