"""Audit rows for credential events. An Org Admin reads the rows tagged with their organizations, so an event about a user is
written once for each organization the user belongs to; with none, once without an organization (App Admins only)."""
import contextlib
import contextvars
import logging

from dashboard.models import AuditLog
from tenancy import roles

logger = logging.getLogger(__name__)

# The API token behind the request being served (set by the MCP and REST entry points for the length of one call). An audit row written meanwhile says
# so in its detail, next to the token owner's name: "the agent called X, running as <owner>" is not the same as "<owner> did X".
_token = contextvars.ContextVar('audit_token', default=None)


@contextlib.contextmanager
def acting_as(ctx):
    """Mark every audit row written inside the block as made through ``ctx``'s API token (nothing when the call carries no token)."""
    handle = _token.set(getattr(ctx, 'token', None))
    try:
        yield
    finally:
        _token.reset(handle)


def token_detail():
    """``{'via_token': {...}}`` for the token being served (its name and, when a registered agent holds it, the agent's id and name), else ``{}``. Never raises:
    an audit row is written whether or not the agent can be looked up."""
    token = _token.get()
    if token is None or getattr(token, 'scope', 'full') == 'sentinel':  # a Sentinel's own routine rows already name it (``agent_id``); the mark is for an agent acting as a user
        return {}
    return {'via_token': describe_token(token)}


def describe_token(token):
    """``{'name', 'agent_id', 'agent_name'}`` of an API token (the agent keys only when a registered agent holds it)."""
    info = {'name': str(getattr(token, 'name', '') or '')[:100]}
    try:
        from agentapi.models import Agent
        agent = Agent.objects.filter(token=token).only('id', 'name').first() if getattr(token, 'pk', None) else None
        if agent is not None:
            info.update(agent_id=agent.pk, agent_name=agent.name)
    except Exception:  # noqa: BLE001
        logger.debug('audit: the agent behind the token could not be read', exc_info=False)
    return info


def record(actor, action, target='', org=None, **detail):
    AuditLog.objects.create(actor=actor, actor_name=getattr(actor, 'username', '') or '', action=action, target=str(target)[:300],
                            org_id=getattr(org, 'pk', org), detail={**detail, **token_detail()})


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
