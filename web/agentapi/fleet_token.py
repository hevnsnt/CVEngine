"""The scanner fleet's Sentinel identity on a hosted server (hosted/README.md): one external Sentinel Agent and the token it signs in with.

Hosted servers are scanned by a fleet of external Sentinels that the operator runs. ``manage.py ensure_fleet_token`` (hosted mode only) gives the fleet
its credential: an ``Agent`` (``kind='scanner'``) with one ``ApiToken`` of the ``sentinel`` scope, which can call the Sentinel endpoints and nothing else
(``agentapi.auth.request_allowed``). It is deliberately the least a Sentinel can be:

* ``network`` is ``external`` and ``network:internal`` is in neither its capabilities nor its limits, so it is never offered work for a declared internal
  range (``sentinel_broker.effective_capabilities`` grants that capability only to a Sentinel whose network is internal);
* its capabilities are the task kinds an external Sentinel may run, never the built-in scanner's own kinds (``sentinel_broker.BUILTIN_KINDS``), and the
  same list is the administrator's limit on it, so the fleet cannot widen what it may do by registering with a longer list;
* the token is the only secret: it is returned once (the command prints it), and only its hash is stored, like every API token.

The Agent is found by its token's name (``TOKEN_NAME``), which only this module sets on a ``sentinel``-scope token: a Sentinel that enrolled itself under
the same display name is never adopted or rotated. Running again rotates the token (the old one stops working at once); ``revoke`` ends the identity
for good; ``disable`` and ``enable`` suspend and resume it (a suspended fleet is refused at the door and holds no task).
"""
import os
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

NAME = 'cvENGINE Scanner Fleet'
TOKEN_NAME = 'fleet:cvl'
DISABLED_NOTE = 'disabled by the hosted control plane (suspended)'
REVOKED_NOTE = 'revoked by the hosted control plane'
DEFAULT_CONCURRENCY = 8
OFF = ('', '0', 'false', 'no', 'off')


class FleetError(Exception):
    """A refusal with a message for the operator; the command prints it to stderr and exits non-zero."""


def hosted_enabled():
    """Hosted mode is on only when ``CVENGINE_HOSTED`` is set to something other than 0, false, no or off (unset: off)."""
    return os.environ.get('CVENGINE_HOSTED', '').strip().lower() not in OFF


def capabilities():
    """The kinds the fleet may run: every task kind except the built-in scanner's, and never ``network:internal``."""
    from agentapi import sentinel_broker, sentinel_contract
    return [kind for kind in sentinel_contract.KINDS if kind not in sentinel_broker.BUILTIN_KINDS]


def fleet_agent(lock=False):
    """The fleet's Agent (newest first), or ``None``."""
    from agentapi.auth import SCOPE_SENTINEL
    from agentapi.models import Agent
    rows = Agent.objects.filter(kind='scanner', token__name=TOKEN_NAME, token__scope=SCOPE_SENTINEL).select_related('token', 'token__user').order_by('-id')
    return (rows.select_for_update(of=('self', 'token')) if lock else rows).first()


def owner(username=None):
    """The user the fleet's token belongs to: ``username``, or the oldest active App Admin (the one the hosted setup created)."""
    from django.contrib.auth.models import User
    rows = User.objects.filter(is_active=True, is_superuser=True)
    if username:
        user = rows.filter(username=username).first()
        if user is None:
            raise FleetError(f'there is no active App Admin named "{username}"')
        return user
    user = rows.order_by('id').first()
    if user is None:
        raise FleetError('there is no active App Admin yet to own the fleet token: create the admin account first')
    return user


def _summary(agent, state, token=None):
    out = {'state': state, 'agent_id': agent.pk, 'name': agent.name, 'status': agent.status, 'network': agent.network,
           'capabilities': list(agent.capabilities or []), 'token_prefix': agent.token.prefix + '...' + (agent.token.suffix or '')}
    if token is not None:
        out['token'] = token
    return out


def ensure(username=None, max_concurrent=DEFAULT_CONCURRENCY, now=None):
    """Create the fleet Agent and token, or rotate the token of the one that exists. Returns the summary, with ``token`` (the raw secret, shown once)."""
    from agentapi import agent_broker
    from agentapi.auth import SCOPE_SENTINEL, create_token
    from agentapi.models import Agent
    from agentapi.sentinel_broker import SENTINEL_TOKEN_TTL
    from dashboard.models import ApiToken
    from tenancy import audit
    if not 1 <= int(max_concurrent) <= agent_broker.MAX_CONCURRENT_CAP:
        raise FleetError(f'max_concurrent must be a whole number from 1 to {agent_broker.MAX_CONCURRENT_CAP}')
    now = now or timezone.now()
    caps = capabilities()
    with transaction.atomic():
        agent = fleet_agent(lock=True)
        user = agent.token.user if agent and not username else owner(username)
        if agent is not None and not user.is_active:
            user = owner(username)
        token, raw = create_token(user, TOKEN_NAME, scope=SCOPE_SENTINEL, expires_at=now + SENTINEL_TOKEN_TTL)
        if agent is None:
            agent = Agent.objects.create(token=token, name=NAME, kind='scanner', scope={'orgs': [], 'projects': [], 'hosts': [], 'instance': True},
                                         capabilities=caps, network='external', limits={'capabilities': caps}, max_concurrent=int(max_concurrent),
                                         status='active', status_note='', status_changed_at=now)
            state = 'created'
        else:
            old = agent.token
            agent.token = token
            agent.capabilities = caps  # a rotation also puts back the least-privilege shape if anything widened it
            agent.network = 'external'
            agent.limits = {'capabilities': caps}
            agent.max_concurrent = int(max_concurrent)
            agent.status, agent.status_note, agent.status_changed_at = 'active', '', now
            agent.save()
            ApiToken.objects.filter(pk=old.pk).update(revoked=True)  # the old secret stops working in the same transaction
            state = 'rotated'
        audit.record_for_user(user, 'agent.register', user, target=agent.name, agent_id=agent.pk, kind='scanner', via='fleet-token', state=state,
                              network='external', capabilities=len(caps))
    return _summary(Agent.objects.select_related('token').get(pk=agent.pk), state, raw)


def revoke(now=None):
    """End the fleet identity: the token is revoked, the Agent is ``revoked`` and gives its tasks back. Nothing to revoke is not an error."""
    from agentapi.agent_broker import release_agent_tasks
    from agentapi.models import Agent
    from dashboard.models import ApiToken
    from tenancy import audit
    now = now or timezone.now()
    with transaction.atomic():
        agent = fleet_agent(lock=True)
        if agent is None:
            return {'state': 'absent'}
        release_agent_tasks(agent, REVOKED_NOTE)
        ApiToken.objects.filter(pk=agent.token_id).update(revoked=True)
        Agent.objects.filter(pk=agent.pk).update(status='revoked', status_note=REVOKED_NOTE, status_changed_at=now)
        audit.record_for_user(None, 'agent.revoke', agent.token.user, target=agent.name, agent_id=agent.pk, kind='scanner', reason='fleet token revoked')
    return _summary(Agent.objects.select_related('token').get(pk=agent.pk), 'revoked')


def disable(now=None):
    """Suspend the fleet: the token stops authenticating and the Agent holds no task. ``enable`` undoes it. Nothing to disable is an error."""
    from agentapi.agent_broker import release_agent_tasks
    from agentapi.models import Agent
    from dashboard.models import ApiToken
    from tenancy import audit
    now = now or timezone.now()
    with transaction.atomic():
        agent = fleet_agent(lock=True)
        if agent is None:
            raise FleetError('there is no fleet token to disable: run ensure_fleet_token first')
        if agent.status == 'revoked':
            raise FleetError('the fleet token was revoked: run ensure_fleet_token (without options) to issue a new one')
        before = agent.status
        release_agent_tasks(agent, DISABLED_NOTE)
        ApiToken.objects.filter(pk=agent.token_id).update(revoked=True)
        Agent.objects.filter(pk=agent.pk).update(status='suspended', status_note=DISABLED_NOTE, status_changed_at=now)
        audit.record_for_user(None, 'agent.status', agent.token.user, target=agent.name, agent_id=agent.pk, before={'status': before},
                              after={'status': 'suspended'}, note=DISABLED_NOTE)
    return _summary(Agent.objects.select_related('token').get(pk=agent.pk), 'disabled')


def enable(now=None):
    """Resume a fleet ``disable`` suspended: the same token works again. A revoked fleet, or a token that has expired, needs a new token instead."""
    from agentapi.models import Agent
    from dashboard.models import ApiToken
    from tenancy import audit
    now = now or timezone.now()
    with transaction.atomic():
        agent = fleet_agent(lock=True)
        if agent is None:
            raise FleetError('there is no fleet token to enable: run ensure_fleet_token first')
        if agent.status == 'revoked':
            raise FleetError('the fleet token was revoked: run ensure_fleet_token (without options) to issue a new one')
        if agent.token.expires_at is not None and agent.token.expires_at <= now + timedelta(seconds=1):
            raise FleetError('the fleet token has expired: run ensure_fleet_token (without options) to issue a new one')
        if agent.status == 'suspended' and agent.status_note != DISABLED_NOTE:
            raise FleetError('the fleet was suspended by an administrator, not by --disable: change that in the web interface')
        before = agent.status
        ApiToken.objects.filter(pk=agent.token_id).update(revoked=False)
        Agent.objects.filter(pk=agent.pk).update(status='active', status_note='', status_changed_at=now)
        audit.record_for_user(None, 'agent.status', agent.token.user, target=agent.name, agent_id=agent.pk, before={'status': before},
                              after={'status': 'active'}, note='enabled by the hosted control plane')
    return _summary(Agent.objects.select_related('token').get(pk=agent.pk), 'enabled')
