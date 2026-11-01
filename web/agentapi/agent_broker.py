"""The agent broker: who the agents are, what work exists for them, and which agent gets it.

An agent (an API token that registered itself) declares a scope and capabilities. Work is queued for CVE matches as ``AgentTask`` rows
with the capabilities it needs. An agent asks for its next task and the broker gives it the best one it is eligible for: its scope
(organizations, projects, hosts) covers the host, its user still has a write role there, its capabilities and operating systems satisfy
the task, and it has room under its concurrent limit. A task is leased: it goes back to the queue when the lease runs out, which is what
happens when an agent stops heartbeating, is suspended or revoked, or its scope shrinks.

Everything an agent reports is untrusted data: it is typed, clipped and stored, never executed, and never used to build a command.
"""
import time
from contextlib import contextmanager
from datetime import timedelta

from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.db.models import Count, F, Q
from django.utils import timezone

from agentapi import agent_scope as scope_lib
from agentapi import agent_tasks
from agentapi import services as svc
from agentapi.models import ACTIVE_TASK_STATUSES, Agent, AgentTask
from agentapi.services import ApiError, AssetFilter
from tenancy import audit, roles, throttle

LIVE_WINDOW = timedelta(minutes=3)  # an agent not heard from for this long is offline and gets no new work
OFFER_LEASE = timedelta(minutes=2)  # a claimed task must be accepted (or reported) within this
RUN_LEASE = timedelta(minutes=5)  # an accepted task is kept by heartbeats, each extending it by this
MAX_RUNTIME = timedelta(hours=4)  # heartbeats stop extending a task this long after it was accepted
BACKOFF = timedelta(seconds=30)
HEARTBEAT_SECONDS = 60
DEFER_FOR = timedelta(seconds=60)  # a busy agent leaves a task to a less busy one for this long, then takes it: an agent that heartbeats but never polls must not hold work for ever
MAX_WAIT = 20  # seconds a get_next_task call may hold a web thread
MAX_WAITERS = 6  # concurrent holders, so long polls can never take every web thread (16 by default)
MAX_WAITERS_PER_USER = 2  # and one user, however many tokens it mints, cannot hold more than this of them
MAX_AGENTS_PER_USER = 10
MAX_SCAN = 5000  # queued rows one claim looks through, in pages of CANDIDATES, before it says there is nothing for this agent
USER_RATE_FACTOR = 3  # a user's tokens together may make this many times one token's calls
MAX_ATTEMPTS_PER_DAY = 5  # tasks for one match and kind in a day, so a loop of queue, fail, queue cannot grow the audit trail without bound
RETENTION_DAYS = 30  # finished agent tasks are deleted after this (the audit log keeps the trail)
MAX_CONCURRENT_CAP = 10
MAX_ACTIVE_PER_PROJECT = 2000
MAX_QUEUE_BATCH = 200
CANDIDATES = 200
MAX_SUMMARY = 1000
MAX_CHECK_OUTPUT = 2000
MAX_CHECKS = 20
MAX_NOTE = 200
RATES = {'register': (30, 3600), 'heartbeat': (120, 60), 'claim': (60, 60), 'report': (120, 60), 'release': (120, 60), 'queue': (30, 60)}
ADMIN_STATUSES = ('active', 'suspended', 'revoked')
INHERITED_SUSPENSION_NOTE = 'another agent of this user is suspended or revoked; an administrator must reinstate this one'  # migration 0008 matches it
STATUS_ORDER = ('queued', 'assigned', 'running', 'completed', 'failed', 'cancelled')


# --- agent identity ---------------------------------------------------------------------------

def _need_token(ctx, write=True):
    if not ctx.token:
        raise ApiError(400, 'an agent is registered on an API token; call this with a token')
    if write:
        svc.require_write_token(ctx)
    return ctx.token


def _hit(name, limit, window):
    """Count one call against a window and say whether it is within ``limit``. One INCR, so concurrent callers cannot all pass the check."""
    cache.add(name, 0, window)
    try:
        used = cache.incr(name)
    except ValueError:  # the key expired between the add and the incr
        cache.set(name, 1, window)
        used = 1
    return used <= limit


def _limit(token, action):
    """Count one call of ``action`` against the token's window and against its user's, so minting more tokens buys no more calls; 429 past
    either. The token is keyed by its hash, not an id."""
    limit, window = RATES[action]
    if not (_hit(f'agentapi:{action}:{token.key_hash[:16]}', limit, window)
            and _hit(f'agentapi:{action}:user:{token.user_id}', limit * USER_RATE_FACTOR, window)):
        raise ApiError(429, f'too many {action} calls: at most {limit} per {window} seconds')


def _limit_user(user, action):
    limit, window = RATES[action]
    if not _hit(f'agentapi:{action}:user:{user.pk}', limit, window):
        raise ApiError(429, f'too many {action} calls: at most {limit} per {window} seconds')


def _whole(value, name, low=0, high=None):
    """``value`` as a whole number, or a 400: a bool, a float, a huge or infinite number and a list are the caller's mistake, never a crash."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or abs(value) == float('inf') or int(value) != value:
        raise ApiError(400, f'{name} must be a whole number')
    value = int(value)
    if value < low or (high is not None and value > high):
        raise ApiError(400, f'{name} must be at least {low}' + (f' and at most {high}' if high is not None else ''))
    return value


def _agent_of(ctx, usable=True, write=True):
    """The caller's registered agent. ``usable`` also refuses a revoked one (a suspended one may still ask where it stands)."""
    token = _need_token(ctx, write)
    agent = Agent.objects.filter(token=token).select_related('token__user').first()
    if agent is None:
        raise ApiError(404, 'this token has no registered agent: call register_agent first')
    if usable and agent.status == 'revoked':
        raise ApiError(403, 'this agent was revoked by an administrator')
    return agent


def _touch(agent, now=None):
    agent.last_seen = now or timezone.now()
    Agent.objects.filter(pk=agent.pk).update(last_seen=agent.last_seen)


def _parse_registration(body, creating):
    try:
        out = {}
        if 'name' in body or creating:
            out['name'] = scope_lib.clean_name(body.get('name'))
        if 'kind' in body or creating:
            out['kind'] = scope_lib.clean_kind(body.get('kind'))
        if 'scope' in body:
            out['scope'] = scope_lib.clean_scope(body['scope'])
        for key, clean in (('capabilities', scope_lib.clean_capabilities), ('os', scope_lib.clean_os), ('tools', scope_lib.clean_tools)):
            if key in body:
                out[key] = clean(body[key])
        if 'max_concurrent' in body:
            value = body['max_concurrent']
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_CONCURRENT_CAP:
                raise scope_lib.ScopeError(f'max_concurrent must be a whole number from 1 to {MAX_CONCURRENT_CAP}')
            out['max_concurrent'] = value
    except scope_lib.ScopeError as exc:
        raise ApiError(400, str(exc))
    return out


def _authorise(user, scope):
    bad_orgs, bad_projects, bad_instance = scope_lib.authorise(user, scope)
    if bad_instance:
        raise ApiError(403, 'scope.instance (every organization and project on this server) needs the App Admin role')
    if bad_orgs or bad_projects:
        parts = [f'{label}: {", ".join(names[:10])}' for label, names in (('organizations', bad_orgs), ('projects', bad_projects)) if names]
        raise ApiError(403, f'you cannot claim responsibility for {"; ".join(parts)} (not found, or your account has no access)')


def register(ctx, body):
    """Register the caller's token as an agent, or update its registration; the same call is both and repeating it changes nothing. Fields
    left out keep their value. The scope is checked against what the token's user can reach."""
    token = _need_token(ctx)
    if not isinstance(body, dict):
        raise ApiError(400, 'body must be an object')
    _limit(token, 'register')
    agent = Agent.objects.filter(token=token).first()
    if agent and agent.status == 'revoked':
        raise ApiError(403, 'this agent was revoked by an administrator')
    fields = _parse_registration(body, creating=agent is None)
    if 'scope' in fields:
        _authorise(ctx.user, fields['scope'])
    if agent is None and Agent.objects.filter(token__user=ctx.user, token__revoked=False).count() >= MAX_AGENTS_PER_USER:
        raise ApiError(429, f'a user may have at most {MAX_AGENTS_PER_USER} registered agents; unregister one first')
    created = agent is None
    if created:
        status, note = _initial_status(ctx.user)
        agent = Agent(token=token, status=status, status_note=note, **fields)
        changed = sorted(fields)
        try:
            with transaction.atomic():
                agent.save()
        except IntegrityError:  # two first registrations of one token raced: the other one won, this call is the update
            return register(ctx, body)
    else:
        changed = [k for k, v in fields.items() if getattr(agent, k) != v]
        for key in changed:
            setattr(agent, key, fields[key])
        if changed:
            agent.save()
    if 'scope' in fields and token.assets != fields['scope']['hosts']:
        token.assets = fields['scope']['hosts']  # the remediation work list narrows to the same hosts, and stops doing so when they are cleared
        token.save(update_fields=['assets'])
    _touch(agent)
    if changed:
        audit.record_for_user(ctx.user, 'agent.register' if created else 'agent.update', ctx.user, target=agent.name,
                              agent_id=agent.pk, kind=agent.kind, changed=changed, scope=agent.scope, capabilities=agent.capabilities)
        released = release_ineligible(agent) if not created else 0
    else:
        released = 0
    out = agent_dict(agent, detail=True)
    out.update(created=created, changed=changed, released_tasks=released, warnings=_warnings(agent))
    return out


def _initial_status(user):
    """``(status, note)`` of a new registration. A user who has an agent suspended or revoked does not get round it with a new token: the new
    agent starts suspended. Otherwise an administrator's agent is active at once and anyone else's waits for approval, because an agent
    can take work, and report it fixed, in every project its user writes to."""
    if Agent.objects.filter(token__user=user, status__in=('suspended', 'revoked')).exists():
        return 'suspended', INHERITED_SUSPENSION_NOTE
    return ('active', '') if roles.is_admin_anywhere(user) else ('pending', '')


def _warnings(agent):
    scope = agent.scope or {}
    out = []
    if not scope.get('orgs') and not scope.get('projects'):
        out.append('the scope names no organization or project, so no work will be assigned; add orgs or projects (hosts narrow it further)')
    if agent.status == 'pending':
        out.append('this agent is waiting for an administrator to approve it: no work is assigned until then')
    elif agent.status != 'active':
        out.append(f'this agent is {agent.status}: no work is assigned until an administrator reinstates it')
    if not agent.capabilities:
        out.append('no capabilities are declared, so no work can match')
    return out


def unregister(ctx):
    """Remove the caller's registration. Not open to a suspended or revoked agent: deleting the row would wipe the administrator's decision."""
    agent = _agent_of(ctx, usable=False)
    if agent.status not in ('active', 'pending'):
        raise ApiError(403, f'this agent is {agent.status}; only an administrator can change that')
    release_agent_tasks(agent, 'agent unregistered', actor=ctx.user)
    audit.record_for_user(ctx.user, 'agent.unregister', ctx.user, target=agent.name, agent_id=agent.pk)
    agent.delete()
    return {'unregistered': True}


def heartbeat(ctx, body=None):
    """Say the agent is alive. Extends the lease of every task it is running and answers where each stands, so an agent learns at once that
    a lease was lost (a suspended agent, a task cancelled by a person)."""
    agent = _agent_of(ctx)
    _limit(agent.token, 'heartbeat')
    now = timezone.now()
    _touch(agent, now)
    reap_expired(now)
    _sentinel().reap_expired(now)
    release_ineligible(agent)  # a role downgraded, a project left or a limit tightened since the claim ends the lease now, not in four hours
    leases = []
    for task in AgentTask.objects.filter(agent=agent, status__in=('assigned', 'running')).order_by('id'):
        if task.status == 'running' and agent.status == 'active':
            lease = min(now + RUN_LEASE, (task.accepted_at or now) + MAX_RUNTIME)
            if AgentTask.objects.filter(pk=task.pk, agent=agent, status='running', lease_expires_at__gte=now).update(lease_expires_at=lease):
                task.lease_expires_at = lease
        leases.append({'task_id': task.pk, 'status': task.status, 'lease_expires_at': svc._iso(task.lease_expires_at)})
    # A Sentinel (kind='scanner') is an Agent like any other: one heartbeat call extends both its remediation/validation
    # AgentTask leases above and its scan-stage SentinelTask leases here, so leasing never needs a second heartbeat loop.
    leases.extend(_sentinel().extend_leases(agent, now))
    return {'agent': {'id': agent.pk, 'status': agent.status}, 'server_time': now.isoformat(), 'heartbeat_every_seconds': HEARTBEAT_SECONDS,
            'offline_after_seconds': int(LIVE_WINDOW.total_seconds()), 'leases': leases}


def _sentinel():
    """Lazy import: ``agentapi.sentinel_broker`` imports this module for its shared constants, so importing it back at module
    load time here would be circular. Called only inside a function body, after both modules have finished loading."""
    from agentapi import sentinel_broker
    return sentinel_broker


# --- effective rights ---------------------------------------------------------------------------

class Eff:
    """What an agent may do right now: its registration cut down to what its user can reach, and to the administrator's limits."""

    def __init__(self, agent, now):
        token, limits = agent.token, agent.limits or {}
        user = token.user
        self.agent, self.user, self.now = agent, user, now
        self.problem = self._problem(agent, token, user, now)
        caps = set(agent.capabilities or [])
        if limits.get('capabilities') is not None:
            caps &= set(limits['capabilities'])
        self.caps = caps
        self.os = set(agent.os or [])
        self.projects = scope_lib.project_slugs_in_scope(user, agent.scope or {}, limits.get('projects')) if not self.problem else set()
        patterns = (agent.scope or {}).get('hosts') or []
        self.hosts = AssetFilter(patterns) if patterns else None
        self.max_concurrent = min(agent.max_concurrent, limits.get('max_concurrent') or MAX_CONCURRENT_CAP)
        self.roles = {}

    @staticmethod
    def _problem(agent, token, user, now):
        if agent.status == 'pending':
            return 'the agent is waiting for an administrator to approve it'
        if agent.status != 'active':
            return f'the agent is {agent.status}'
        if token.revoked or (token.expires_at and token.expires_at <= now):
            return 'its token is revoked or expired'
        if not user.is_active:
            return 'its user is disabled'
        if token.read_only:
            return 'its token is read only'
        from tenancy.middleware import TenancyMiddleware
        if TenancyMiddleware.must_enrol_mfa(user):
            return 'its user has to set up two-step sign-in first'
        return ''

    @property
    def live(self):
        return bool(self.agent.last_seen and self.now - self.agent.last_seen <= LIVE_WINDOW)

    def can_write(self, project):
        if project.pk not in self.roles:
            self.roles[project.pk] = roles.effective_role(self.user, project) not in (None, roles.AUDIT)
        return self.roles[project.pk]

    def refusal(self, task):
        """None when this agent may take ``task``, else ``(code, detail)``: scope, role, os or capability."""
        if task.project.slug not in self.projects:
            return 'scope', 'the project is outside this agent\'s scope'
        if self.hosts is not None and not self.hosts.matches([task.host.lower()], task.ips or []):
            return 'scope', 'the host is outside this agent\'s scope'
        if not self.can_write(task.project):
            return 'role', 'the agent\'s user has no write role in the project'
        missing = scope_lib.missing_requirements(task.required_capabilities, self.caps)
        if missing:
            return 'capability', ', '.join(missing)
        if self.os and task.os_family and task.os_family not in self.os:
            return 'os', f'the agent does not act on {task.os_family} hosts'
        return None


def effective(agent, now=None):
    return Eff(agent, now or timezone.now())


def _effs_for(projects, now):
    """The Eff of every active agent whose scope names one of ``projects`` (or its organization): the only agents that could matter to work
    there, found in SQL, so a call never builds the rights of every agent on the instance."""
    named = Q()
    for project in projects:
        named |= Q(scope__projects__contains=[project.slug])
        if project.org_id:
            named |= Q(scope__orgs__contains=[project.org.slug])
    if not named:
        return []
    agents = Agent.objects.filter(named, status='active', token__revoked=False).select_related('token__user')[:CANDIDATES]
    return [e for e in (Eff(a, now) for a in agents) if not e.problem]


def explain(task, effs):
    """Why no agent can take this queued task right now, or None when one could. Names no agent: only the host and the missing capability."""
    covering = [e for e in effs if (e.refusal(task) or ('', ''))[0] not in ('scope', 'role')]
    if not covering:
        return f'no agent covers host {task.host}'
    live = [e for e in covering if e.live]
    if not live:
        return f'the agents covering host {task.host} are offline (none seen in the last {int(LIVE_WINDOW.total_seconds() // 60)} minutes)'
    if any(e.refusal(task) is None for e in live):
        return None
    codes = [e.refusal(task) for e in live]
    missing = sorted({c[1] for c in codes if c[0] == 'capability'})
    if missing:
        return f'no live agent covering host {task.host} has capability {" and ".join(missing)}'
    return f'no live agent covering host {task.host} acts on {task.os_family} hosts'


# --- queueing ---------------------------------------------------------------------------------

def _open(match):
    """Whether a match is still work: not fixed, not accepted, not ruled out and not out of the affected range."""
    return (match.remediation_status in ('open', 'in_progress') and match.ai_verdict != 'not_affected' and match.version_in_range is not False)


def _match_with_host(match_id):
    from cveFeed.models import CVEMatch
    return CVEMatch.objects.select_related('cve_entry__detection', 'subdomain').prefetch_related('subdomain__ip_addresses__ports') \
        .filter(pk=match_id).first()


def queue_work(ctx, slug, kind, match_ids=None, mode=None, tier=None, host=None, limit=MAX_QUEUE_BATCH):
    """Queue validation or remediation work for CVE matches of one project: the listed ``match_ids``, or the open matches that fit ``tier``
    and ``host`` (a substring), up to ``limit``. Each task records what it needs; work that is already queued is left alone. The answer
    says what was queued, what was skipped and why, and which queued tasks no live agent can take."""
    project, _ = svc.get_one_project(ctx, slug, write=True)
    if not isinstance(kind, str) or kind not in AgentTask.KINDS:
        raise ApiError(400, f'kind must be one of {", ".join(AgentTask.KINDS)}')
    _limit_user(ctx.user, 'queue')
    limit = min(MAX_QUEUE_BATCH, _whole(limit, 'limit', 1))
    for value, label in ((mode, 'mode'), (host, 'host')):
        if value is not None and not isinstance(value, str):
            raise ApiError(400, f'{label} must be a string')
    if match_ids is not None and (not isinstance(match_ids, list) or not match_ids or len(match_ids) > MAX_QUEUE_BATCH
                                  or not all(isinstance(i, int) and not isinstance(i, bool) for i in match_ids)):
        raise ApiError(400, f'match_ids must be a list of 1 to {MAX_QUEUE_BATCH} whole numbers')
    if tier is not None and (not isinstance(tier, str) or tier not in agent_tasks.PRIORITY):
        raise ApiError(400, 'tier must be fire, smoke or ice')
    active = AgentTask.objects.filter(project=project, status__in=ACTIVE_TASK_STATUSES).count()
    if active >= MAX_ACTIVE_PER_PROJECT:
        raise ApiError(429, f'this project already has {MAX_ACTIVE_PER_PROJECT} agent tasks waiting or in progress')
    qs = svc._matches_qs(project).select_related('cve_entry__detection', 'subdomain').prefetch_related('subdomain__ip_addresses__ports')
    if match_ids is not None:
        qs = qs.filter(pk__in=match_ids)
    else:
        qs = qs.exclude(ai_verdict='not_affected').exclude(version_in_range=False).filter(remediation_status__in=('open', 'in_progress'))
        qs = qs.exclude(triage__classification__in=svc.FALSE_POSITIVES)
        if host:
            qs = qs.filter(subdomain__name__icontains=str(host)[:200])
    created, skipped = [], []
    candidates = list(qs[:limit])
    found = {m.pk for m in candidates}
    skipped.extend({'match_id': i, 'reason': 'match not found in this project'} for i in (match_ids or []) if i not in found)
    for match in candidates:
        reason = _queue_one(ctx, project, match, kind, mode, tier, created)
        if reason:
            skipped.append({'match_id': match.pk, 'reason': reason})
    effs = _effs_for([project], timezone.now())
    stuck = [{'task_id': t.pk, 'host': t.host, 'reason': r} for t in created if (r := explain(t, effs))]
    return {'queued': [task_brief(t) for t in created], 'skipped': skipped, 'unassignable': stuck}


def _queue_one(ctx, project, match, kind, mode, tier, created):
    """Queue one match; returns why it was skipped, or None after adding the task to ``created``."""
    if not _open(match) or not match.subdomain_id:
        return 'the finding is closed or has no host'
    match_tier = agent_tasks.tier_of(match)
    if tier and match_tier != tier:
        return f'its tier is {match_tier}, not {tier}'
    if AgentTask.objects.filter(match=match, kind=kind, created_at__gte=timezone.now() - timedelta(days=1)).count() >= MAX_ATTEMPTS_PER_DAY:
        return f'{MAX_ATTEMPTS_PER_DAY} tasks for it were already queued in the last day'
    try:
        task_mode, needs = agent_tasks.describe(match, kind, mode)
    except ApiError as exc:
        return exc.message
    sub = match.subdomain
    try:
        with transaction.atomic():
            task = AgentTask.objects.create(
                project=project, match=match, kind=kind, mode=task_mode, required_capabilities=needs, host=sub.name[:500],
                os_family=agent_tasks.host_os_family(sub), ips=agent_tasks.host_ips(sub), priority=agent_tasks.PRIORITY.get(match_tier, 1),
                created_by=ctx.user)
    except IntegrityError:
        return 'already queued or in progress'
    audit.record(ctx.user, 'agent.task.queue', _target(task), org=project.org_id, task_id=task.pk, kind=kind, mode=task_mode, host=task.host,
                 required=needs, cve=match.cve_entry.cve_id)
    created.append(task)
    return None


def _target(task):
    return f'task #{task.pk} {task.kind} {task.host}'[:300]


# --- leases ---------------------------------------------------------------------------------------

def _requeue(task, reason, refund=False, actor=None, action='agent.task.expire', backoff=True):
    """Take ``task`` back from its agent: to the queue, or to failed when its attempts are used up. ``refund`` gives the attempt back (the
    agent did nothing wrong). False when another call changed the task first."""
    now = timezone.now()
    attempts = max(task.attempts - 1, 0) if refund else task.attempts
    status = 'failed' if attempts >= task.max_attempts else 'queued'
    changes = {'status': status, 'agent': None, 'lease_expires_at': None, 'attempts': attempts, 'error': reason[:300], 'accepted_at': None,
               'not_before': now + BACKOFF if backoff and status == 'queued' else None, 'finished_at': now if status == 'failed' else None}
    won = AgentTask._base_manager.filter(pk=task.pk, status=task.status, agent_id=task.agent_id).update(**changes)
    if won:
        project = task.project
        audit.record(actor, action, _target(task), org=project.org_id, task_id=task.pk, agent_id=task.agent_id, reason=reason, now=status)
    return bool(won)


def reap_expired(now=None):
    """Return every task whose lease ran out to the queue. Called by every broker call, so no scheduler has to run."""
    now = now or timezone.now()
    expired = AgentTask._base_manager.filter(status__in=('assigned', 'running'), lease_expires_at__lt=now).select_related('project')[:CANDIDATES]
    return sum(_requeue(t, 'the lease expired without a report', refund=False) for t in list(expired))


def release_agent_tasks(agent, reason, actor=None):
    """Give back every task an agent holds (suspended, revoked, unregistered). Not counted against the task's attempts.
    Also releases any SentinelTask the same agent holds (a Sentinel is an Agent too), so a suspend or revoke takes effect
    on both queues at once, immediately, with no separate code path a reviewer could miss."""
    held = AgentTask._base_manager.filter(agent=agent, status__in=('assigned', 'running')).select_related('project')
    return (sum(_requeue(t, reason, refund=True, actor=actor, action='agent.task.release', backoff=False) for t in list(held))
            + _sentinel().release_agent_tasks(agent, reason, actor=actor))


def release_ineligible(agent):
    """After a registration or limit change: give back the tasks (and SentinelTasks) the agent may no longer hold."""
    eff = effective(agent)
    held = AgentTask._base_manager.filter(agent=agent, status__in=('assigned', 'running')).select_related('project')
    return (sum(_requeue(t, 'the agent no longer covers this work', refund=True, action='agent.task.release', backoff=False)
               for t in list(held) if eff.problem or eff.refusal(t))
            + _sentinel().release_ineligible(agent))


def prune_tasks(now=None, days=None):
    """Delete finished, failed and cancelled tasks older than the retention. The audit log keeps who did what; the rows would only pile up."""
    import os
    now = now or timezone.now()
    try:
        days = days or max(1, int(os.environ.get('CVENGINE_AGENT_TASK_RETENTION_DAYS', '')))
    except ValueError:
        days = RETENTION_DAYS
    old = AgentTask._base_manager.filter(status__in=('completed', 'failed', 'cancelled'), finished_at__lt=now - timedelta(days=days))
    deleted = 0
    while True:
        ids = list(old.values_list('pk', flat=True)[:5000])
        if not ids:
            return deleted
        deleted += AgentTask._base_manager.filter(pk__in=ids).delete()[0]


def release_for_tokens(token_ids):
    for agent in Agent.objects.filter(token_id__in=list(token_ids)):
        release_agent_tasks(agent, 'the agent\'s token was revoked')


# --- claiming ---------------------------------------------------------------------------------------

@contextmanager
def _waiter_slot(wanted, token):
    """Whether this caller may hold a web thread for a long poll: the instance, the token's user and the token each have a cap, so one
    user cannot take every slot by minting tokens. Yields False when a cap is reached, and the caller answers at once."""
    if not wanted:
        yield False
        return
    caps = (('agentapi:waiters', MAX_WAITERS), (f'agentapi:waiters:user:{token.user_id}', MAX_WAITERS_PER_USER),
            (f'agentapi:waiters:{token.key_hash[:16]}', 1))
    taken, within = [], True
    try:
        for key, cap in caps:
            cache.add(key, 0, 120)
            try:
                used = cache.incr(key)
            except ValueError:
                cache.set(key, 1, 120)
                used = 1
            taken.append(key)
            if used > cap:
                within = False
                break
        yield within
    finally:
        for key in taken:
            try:
                cache.decr(key)
            except ValueError:
                pass


def _better_placed(eff, task, effs, counts):
    """Whether another live agent with free room and less on its plate could take ``task``: it is left for them, so one agent that polls
    fastest does not end up with all the work. Only for DEFER_FOR: after that the busy agent that is asking takes it."""
    mine = counts.get(eff.agent.pk, 0)
    return any(o.agent.pk != eff.agent.pk and o.live and counts.get(o.agent.pk, 0) < min(mine, o.max_concurrent) and o.refusal(task) is None
               for o in effs)


def _still_needed(task):
    match = _match_with_host(task.match_id)
    if match is None or not _open(match):
        AgentTask._base_manager.filter(pk=task.pk, status='queued').update(status='cancelled', error='the finding is no longer open',
                                                                          finished_at=timezone.now())
        return None
    return match


def _claimable(eff, kinds, now):
    """The queued tasks this agent's registration can possibly take, in hand-out order. The operating system and the capabilities are
    settled in SQL (a task's requirement lists are few distinct values, so the agent's satisfiable ones are looked up first), so a run of
    tasks the agent cannot do never fills the window it looks through; only the host scope is left to Python."""
    qs = AgentTask.objects.filter(status='queued', kind__in=kinds, project__slug__in=eff.projects) \
        .filter(Q(not_before__isnull=True) | Q(not_before__lte=now))
    if eff.os:
        qs = qs.filter(Q(os_family='') | Q(os_family__in=eff.os))
    wanted = list(qs.order_by().values_list('required_capabilities', flat=True).distinct())
    satisfiable = [needs for needs in wanted if not scope_lib.missing_requirements(needs, eff.caps)]
    return qs.filter(required_capabilities__in=satisfiable).select_related('project__org').order_by('-priority', 'created_at', 'id') \
        if satisfiable else AgentTask.objects.none()


def _try_claim(agent, kinds, now, effs_cache):
    eff = effective(agent, now)
    if eff.problem:
        raise ApiError(403, f'no work can be assigned: {eff.problem}')
    with transaction.atomic():
        Agent.objects.select_for_update().get(pk=agent.pk)  # one claim at a time per agent, so the concurrent limit holds
        counts = dict(AgentTask._base_manager.filter(status__in=('assigned', 'running')).values_list('agent_id').annotate(n=Count('id')))
        if counts.get(agent.pk, 0) >= eff.max_concurrent:
            return None, f'at capacity ({counts[agent.pk]} of {eff.max_concurrent} tasks in progress)'
        queued, seen = _claimable(eff, kinds, now), set()
        while len(seen) < MAX_SCAN:
            page = list(queued.exclude(pk__in=seen)[:CANDIDATES])
            if not page:
                break
            seen.update(t.pk for t in page)
            for task in page:
                claimed = _offer(agent, eff, task, counts, now, effs_cache)
                if claimed:
                    return claimed, ''
        return None, 'no eligible work is queued'


def _offer(agent, eff, task, counts, now, effs_cache):
    """Lease ``task`` to the agent if it may take it and nobody else has: ``(task, match)``, or None."""
    if eff.refusal(task):
        return None
    if counts.get(agent.pk, 0):
        if task.project_id not in effs_cache:
            effs_cache[task.project_id] = _effs_for([task.project], now)
        if now - task.created_at < DEFER_FOR and _better_placed(eff, task, effs_cache[task.project_id], counts):
            return None
    match = _still_needed(task)
    if match is None:
        return None
    won = AgentTask.objects.filter(pk=task.pk, status='queued').update(
        status='assigned', agent=agent, attempts=F('attempts') + 1, claimed_at=now, accepted_at=None, lease_expires_at=now + OFFER_LEASE,
        error='', not_before=None)
    if not won:
        return None
    task.refresh_from_db()
    audit.record(agent.token.user, 'agent.task.claim', _target(task), org=task.project.org_id, task_id=task.pk, agent_id=agent.pk,
                 agent=agent.name, attempt=task.attempts)
    return task, match


def next_task(ctx, body=None):
    """Hand the caller the best task it is eligible for, leased to it, or say there is none. ``wait`` (seconds, at most MAX_WAIT) holds
    the call open until work appears, which is how an agent long-polls: the MCP transport here has no server push."""
    body = body or {}
    agent = _agent_of(ctx)
    kinds = body.get('kinds') or list(AgentTask.KINDS)
    if not isinstance(kinds, list) or not all(isinstance(k, str) and k in AgentTask.KINDS for k in kinds):
        raise ApiError(400, f'kinds must be a list drawn from {", ".join(AgentTask.KINDS)}')
    wait = min(MAX_WAIT, _whole(body.get('wait', 0), 'wait'))
    _limit(agent.token, 'claim')
    deadline = time.monotonic() + wait
    effs_cache = {}
    with _waiter_slot(wait > 0, agent.token) as slot:
        deadline = deadline if slot else 0
        while True:
            now = timezone.now()
            _touch(agent, now)
            reap_expired(now)
            claimed, why = _try_claim(agent, kinds, now, effs_cache)
            if claimed or time.monotonic() >= deadline:
                break
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
            agent.refresh_from_db()
            if agent.status != 'active':
                raise ApiError(403, f'no work can be assigned: the agent is {agent.status}')
    if not claimed:
        return {'task': None, 'reason': why, 'retry_after_seconds': 5 if wait == 0 else 1}
    task, match = claimed
    return {'task': agent_tasks.payload(task, match), 'reason': ''}


def _ensure_eligible(agent, task):
    """Hand ``task`` back and answer 409 when the agent no longer may hold it: its user's role, its scope, a limit or its status changed
    since the claim. Checked on accept and on report, so a demoted or limited agent cannot finish work it was leased before."""
    if task.status not in ('assigned', 'running'):
        return
    eff = effective(agent)
    if eff.problem or eff.refusal(task):
        _requeue(task, 'the agent no longer covers this work', refund=True, action='agent.task.release', backoff=False)
        raise ApiError(409, 'the task was taken back: this agent no longer covers it')


def accept_task(ctx, task_id):
    agent = _agent_of(ctx)
    _limit(agent.token, 'claim')
    now = timezone.now()
    _touch(agent, now)
    reap_expired(now)
    task = AgentTask.objects.select_related('project').filter(pk=_int(task_id)).first()
    if task is None or task.agent_id != agent.pk:
        raise ApiError(404, 'task not found')
    _ensure_eligible(agent, task)
    if task.status == 'running':
        return {'task': task_brief(task), 'accepted': True}
    won = AgentTask.objects.filter(pk=task.pk, agent=agent, status='assigned', lease_expires_at__gte=now).update(
        status='running', accepted_at=now, lease_expires_at=now + RUN_LEASE)
    if not won:
        raise ApiError(409, 'the task is no longer assigned to this agent (its lease expired or it was cancelled)')
    task.refresh_from_db()
    audit.record(ctx.user, 'agent.task.accept', _target(task), org=task.project.org_id, task_id=task.pk, agent_id=agent.pk, agent=agent.name)
    match = _match_with_host(task.match_id)
    return {'task': agent_tasks.payload(task, match) if match else task_brief(task), 'accepted': True}


def get_task(ctx, task_id):
    """One of the caller's own tasks with its payload."""
    agent = _agent_of(ctx, write=False)
    task = AgentTask.objects.select_related('project').filter(pk=_int(task_id), agent=agent).first()
    match = _match_with_host(task.match_id) if task else None
    if task is None or match is None:
        raise ApiError(404, 'task not found')
    return agent_tasks.payload(task, match)


def _int(value):
    if isinstance(value, bool):
        raise ApiError(400, 'task_id must be an integer')
    return svc._int_param(value, 'task_id')


# --- results ----------------------------------------------------------------------------------------

def _text(value, limit):
    from reNgine.ai_providers import clean_text
    return clean_text(value, limit) if isinstance(value, str) else ''


def clean_result(kind, body):
    """The typed, clipped result of a task from an agent's report. Free text is cleaned and capped and never interpreted."""
    outcome = body.get('outcome')
    if outcome != 'error' and outcome not in agent_tasks.OUTCOMES[kind]:
        raise ApiError(400, f'outcome must be one of {", ".join(agent_tasks.OUTCOMES[kind])} or error')
    checks = body.get('checks') or []
    if not isinstance(checks, list) or len(checks) > MAX_CHECKS:
        raise ApiError(400, f'checks must be a list of at most {MAX_CHECKS} entries')
    clean_checks = []
    for item in checks:
        if not isinstance(item, dict) or item.get('result') not in agent_tasks.CHECK_RESULTS:
            raise ApiError(400, f'each check needs a result of {", ".join(agent_tasks.CHECK_RESULTS)}')
        clean_checks.append({'id': _text(item.get('id'), 40), 'result': item['result'], 'output': _text(item.get('output'), MAX_CHECK_OUTPUT)})
    return {'outcome': outcome, 'summary': _text(body.get('summary'), MAX_SUMMARY), 'checks': clean_checks,
            'retryable': bool(body.get('retryable', True)) if outcome == 'error' else None}


def _comment(project, match, user, text):
    from cveFeed.models import FindingAuditEvent, FindingComment
    comment = FindingComment.objects.create(project=project, finding_kind='match', finding_id=match.pk, author=user, text=text[:svc.MAX_COMMENT_LENGTH])
    FindingAuditEvent.objects.create(project=project, finding_kind='match', finding_id=match.pk, event='comment', actor=user, before={},
                                      after={'comment_id': comment.id, 'text': comment.text[:200]})


def _apply_result(task, agent, user, result):
    """What a finished task does to its finding: a comment saying what the agent found, and for a fix the same status change a person or
    ``update_remediation_status`` makes. A validation verdict never edits the finding: people and the triage decide from the evidence."""
    match = _match_with_host(task.match_id)
    if match is None:
        return
    summary = result['summary'] or 'no summary'
    _comment(task.project, match, user, f'Agent {agent.name} ({task.kind}, {task.mode}): {result["outcome"]}. {summary}')
    if task.kind == 'remediate' and result['outcome'] == 'fixed':
        before = match.remediation_status
        svc._apply_remediation(match, 'fixed', f'Fixed by agent {agent.name}: {summary}', user)
        svc._record_status_change(task.project, 'match', match.pk, before, 'fixed', user)


def report_result(ctx, task_id, body):
    """The agent's final word on a task it holds. A failure it marks retryable goes back to the queue until its attempts run out."""
    agent = _agent_of(ctx)
    if not isinstance(body, dict):
        raise ApiError(400, 'body must be an object')
    _limit(agent.token, 'report')
    now = timezone.now()
    _touch(agent, now)
    reap_expired(now)
    held = AgentTask.objects.select_related('project').filter(pk=_int(task_id), agent=agent).first()
    if held is not None:
        _ensure_eligible(agent, held)
    with transaction.atomic():
        task = AgentTask.objects.select_for_update(of=('self',)).select_related('project').filter(pk=_int(task_id)).first()
        if task is None or task.agent_id != agent.pk:
            raise ApiError(404, 'task not found')
        result = clean_result(task.kind, body)
        if task.status in ('completed', 'failed'):
            same = (task.result or {}).get('outcome') == result['outcome']
            if same:
                return {'task': task_brief(task), 'duplicate': True}
            raise ApiError(409, f'the task already finished as {task.status}')
        if task.status not in ('assigned', 'running') or not task.lease_expires_at or task.lease_expires_at < now:
            raise ApiError(409, 'the task is no longer assigned to this agent (its lease expired or it was cancelled)')
        if result['outcome'] == 'error':
            return _fail(task, agent, ctx.user, result)
        AgentTask.objects.filter(pk=task.pk).update(status='completed', result=result, finished_at=now, lease_expires_at=None, error='')
        _apply_result(task, agent, ctx.user, result)
        audit.record(ctx.user, 'agent.task.complete', _target(task), org=task.project.org_id, task_id=task.pk, agent_id=agent.pk, agent=agent.name,
                     outcome=result['outcome'])
    task.refresh_from_db()
    return {'task': task_brief(task), 'duplicate': False}


def _fail(task, agent, user, result):
    reason = result['summary'] or 'the agent reported an error'
    AgentTask.objects.filter(pk=task.pk).update(result=result)
    if result['retryable']:
        _requeue(task, reason, actor=user, action='agent.task.fail')
    else:
        AgentTask.objects.filter(pk=task.pk).update(status='failed', error=reason[:300], finished_at=timezone.now(), lease_expires_at=None)
        audit.record(user, 'agent.task.fail', _target(task), org=task.project.org_id, task_id=task.pk, agent_id=agent.pk, reason=reason[:300],
                     now='failed')
    task.refresh_from_db()
    return {'task': task_brief(task), 'duplicate': False}


def release_task(ctx, task_id, reason=''):
    """The agent gives a task back (it cannot do it after all). It returns to the queue without counting against the task, after a short pause."""
    agent = _agent_of(ctx)
    _limit(agent.token, 'release')
    reap_expired()
    task = AgentTask.objects.select_related('project').filter(pk=_int(task_id), agent=agent).first()
    if task is None:
        raise ApiError(404, 'task not found')
    if task.status not in ('assigned', 'running') or not _requeue(task, _text(reason, 200) or 'released by the agent', refund=True,
                                                                  actor=ctx.user, action='agent.task.release'):
        raise ApiError(409, 'the task is not held by this agent')
    task.refresh_from_db()
    return {'task': task_brief(task)}


# --- reading ----------------------------------------------------------------------------------------

def task_brief(task):
    match = task.match
    agent = task.agent
    return {'id': task.pk, 'project': task.project.slug, 'kind': task.kind, 'mode': task.mode, 'status': task.status, 'host': task.host,
            'finding': {'kind': 'match', 'id': task.match_id, 'cve': match.cve_entry.cve_id if match else None},
            'priority': task.priority, 'required_capabilities': task.required_capabilities, 'os_family': task.os_family,
            'agent': {'id': agent.pk, 'name': agent.name, 'kind': agent.kind} if agent else None, 'attempts': task.attempts,
            'max_attempts': task.max_attempts, 'lease_expires_at': svc._iso(task.lease_expires_at), 'created': svc._iso(task.created_at),
            'finished': svc._iso(task.finished_at), 'error': task.error, 'result': task.result or None}


def _task_rows(qs):
    return qs.select_related('project__org', 'match__cve_entry', 'agent')


def my_assignments(ctx, params=None):
    agent = _agent_of(ctx, write=False)
    params = params or {}
    reap_expired()
    qs = AgentTask.objects.filter(agent=agent)
    qs = qs.filter(status=params['status']) if params.get('status') else qs.filter(status__in=('assigned', 'running'))
    return svc.paginate(_task_rows(qs).order_by('-id'), params, task_brief)


def list_tasks(ctx, slug, params):
    """Agent tasks of one project (or every project the caller can see, with ``_all``), newest first."""
    project, _ = svc.get_project(ctx, slug)
    reap_expired()
    qs = svc._scoped(AgentTask.objects.all(), project, 'project')
    if params.get('status') == 'active':  # waiting for an agent, or leased to one
        qs = qs.filter(status__in=ACTIVE_TASK_STATUSES)
    for param, field in (('status', 'status'), ('kind', 'kind')):
        if params.get(param) and params[param] != 'active':
            qs = qs.filter(**{field: str(params[param])[:20]})
    if params.get('agent_id'):
        qs = qs.filter(agent_id=svc._int_param(params['agent_id'], 'agent_id'))
    if params.get('host'):
        qs = qs.filter(host__icontains=str(params['host'])[:200])
    return svc.paginate(_task_rows(qs).order_by('-id'), params, task_brief)


def list_unassignable(ctx, slug, params):
    """Queued tasks no live agent can take, each with the reason. Names no agent."""
    project, _ = svc.get_project(ctx, slug)
    reap_expired()
    qs = svc._scoped(AgentTask.objects.filter(status='queued'), project, 'project')
    tasks = list(_task_rows(qs).order_by('-priority', 'created_at')[:MAX_QUEUE_BATCH])
    effs = _effs_for({t.project_id: t.project for t in tasks}.values(), timezone.now())
    rows = []
    for task in tasks:
        reason = explain(task, effs)
        if reason:
            rows.append({**task_brief(task), 'reason': reason})
    return {'count': len(rows), 'results': rows, 'note': 'an assignable task may still wait: every capable agent can be busy'}


def cancel_task(ctx, slug, task_id):
    project, _ = svc.get_one_project(ctx, slug, write=True)
    task = AgentTask.objects.select_related('project', 'agent').filter(pk=svc._int_param(task_id, 'task_id'), project=project).first()
    if task is None:
        raise ApiError(404, 'task not found')
    won = AgentTask.objects.filter(pk=task.pk, status=task.status, status__in=ACTIVE_TASK_STATUSES).update(
        status='cancelled', agent=None, lease_expires_at=None, finished_at=timezone.now(), error='cancelled by a person')
    if not won:
        raise ApiError(409, 'the task already finished')
    audit.record(ctx.user, 'agent.task.cancel', _target(task), org=project.org_id, task_id=task.pk, agent_id=task.agent_id)
    task.refresh_from_db()
    return task_brief(task)


# --- agents: listing and administration ---------------------------------------------------------------

def agent_dict(agent, detail=False, counts=None, viewer=None):
    now = timezone.now()
    token = agent.token
    live = bool(agent.last_seen and now - agent.last_seen <= LIVE_WINDOW)
    counts = counts if counts is not None else {}
    out = {'id': agent.pk, 'name': agent.name, 'kind': agent.kind, 'status': agent.status, 'status_note': agent.status_note, 'live': live,
           'last_seen': svc._iso(agent.last_seen), 'registered': svc._iso(agent.registered_at), 'owner': token.user.username,
           'token': {'id': token.pk, 'name': token.name, 'prefix': token.prefix}, 'scope': agent.scope, 'capabilities': agent.capabilities,
           'os': agent.os, 'tools': agent.tools, 'max_concurrent': agent.max_concurrent, 'limits': agent.limits,
           'tasks': {'open': counts.get('assigned', 0) + counts.get('running', 0), 'completed': counts.get('completed', 0),
                     'failed': counts.get('failed', 0)}}
    if agent.kind == 'scanner':  # cheap (stored JSON only), so the list shows a Sentinel that cannot update itself
        from agentapi import sentinel_settings
        out['version'] = (agent.info or {}).get('version')
        out['version_label'] = out['version'] or 'unknown (built without the updater)'  # a Sentinel installed with plain docker compose reports the build's commit; one with neither says so
        out['self_update'] = sentinel_settings.effective(agent)['self_update']
        out['updater'] = sentinel_settings.updater_state(agent)
        from agentapi import sentinel_version
        out['version_state'] = sentinel_version.state(agent, out['self_update'])  # current, behind or unknown, from the cached check of the latest client
        # slots: its concurrency limit, what it holds now and by kind (stored rows only, so the list stays cheap)
        held = counts.get('_held_by_kind', {})
        limit = min(agent.max_concurrent, (agent.limits or {}).get('max_concurrent') or agent.max_concurrent)
        out['slots'] = {'max': limit, 'in_use': sum(held.values()), 'free': max(0, limit - sum(held.values())), 'by_kind': held}
    if detail:
        if agent.kind == 'scanner':
            out['settings'] = sentinel_settings.detail(agent)
            out['update'] = {**((agent.info or {}).get('update') or {}), 'requested_at': svc._iso(agent.update_requested_at)}
        eff = effective(agent, now)
        out['effective'] = {'capabilities': sorted(eff.caps), 'projects': sorted(eff.projects), 'max_concurrent': eff.max_concurrent,
                            'can_receive_work': not eff.problem and bool(eff.projects) and bool(eff.caps), 'problem': eff.problem}
        if agent.kind == 'scanner':
            out['queued_for_it'] = _sentinel().queued_for(agent)  # what waits in the queue that this Sentinel could take, by kind
    return _redacted(out, viewer, agent)


def _redacted(out, viewer, agent):
    """``out`` for an administrator looking at someone else's agent: the organizations and projects of other tenants (the user may belong to
    more than one) are left out of what it is responsible for, with the host list, which could name their assets."""
    if viewer is None or viewer.is_superuser or agent.token.user_id == viewer.pk:
        return out
    from dashboard.models import Org, Project
    org_ids = roles.managed_org_ids(viewer)
    orgs = set(Org.objects.filter(pk__in=org_ids).values_list('slug', flat=True))
    projects = set(Project.objects.filter(org_id__in=org_ids).values_list('slug', flat=True))
    scope = out['scope'] or {}
    shown = {'orgs': [o for o in scope.get('orgs', []) if o in orgs], 'projects': [p for p in scope.get('projects', []) if p in projects]}
    hidden = len(shown['orgs']) < len(scope.get('orgs', [])) or len(shown['projects']) < len(scope.get('projects', []))
    out['scope'] = {**shown, 'hosts': [] if hidden else scope.get('hosts', [])}
    out['scope_redacted'] = hidden
    if 'projects' in (out['limits'] or {}):
        out['limits'] = {**out['limits'], 'projects': [p for p in out['limits']['projects'] if p in projects]}
    if 'effective' in out:
        out['effective'] = {**out['effective'], 'projects': [p for p in out['effective']['projects'] if p in projects]}
    return out


_SENTINEL_STATUS_BUCKET = {'queued': 'queued', 'claimed': 'assigned', 'running': 'running', 'done': 'completed',
                           'failed': 'failed', 'expired': 'cancelled'}


def _counts(agent_ids):
    """Task counts by bucket (queued/assigned/running/completed/failed/cancelled) for each agent id, from both AgentTask
    and, for a Sentinel (kind='scanner'), SentinelTask: the one admin surface (list_agents, get_agent) shows both kinds
    of work without a reader needing to know which queue an agent uses."""
    out = {}
    for agent_id, status, n in AgentTask.objects.filter(agent_id__in=agent_ids).values_list('agent_id', 'status').annotate(n=Count('id')):
        out.setdefault(agent_id, {})[status] = n
    for agent_id, status, n in _sentinel().task_status_counts(agent_ids):
        bucket = _SENTINEL_STATUS_BUCKET.get(status, status)
        bucket_counts = out.setdefault(agent_id, {})
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + n
    for agent_id, kinds in _sentinel().slot_usage(agent_ids).items():  # the tasks a Sentinel holds now, by kind, for its slots
        out.setdefault(agent_id, {})['_held_by_kind'] = kinds
    return out


def my_agent(ctx):
    _need_token(ctx, write=False)
    return identity(ctx)


def identity(ctx):
    """What whoami adds for a token: its registered agent with scope, capabilities and open assignments, or how to register."""
    if not ctx.token:
        return None
    agent = Agent.objects.filter(token=ctx.token).select_related('token__user').first()
    if agent is None:
        return {'registered': False, 'hint': 'call register_agent with a name, kind, scope (orgs, projects, hosts) and capabilities'}
    reap_expired()
    held = _task_rows(AgentTask.objects.filter(agent=agent, status__in=('assigned', 'running'))).order_by('id')
    return {'registered': True, **agent_dict(agent, detail=True, counts=_counts([agent.pk]).get(agent.pk)), 'warnings': _warnings(agent),
            'assignments': [task_brief(t) for t in held]}


def _manageable(actor):
    """Agents ``actor`` may see and administer: all for an App Admin, those of users in organizations they administer, and their own."""
    qs = Agent.objects.select_related('token__user')
    if actor.is_superuser:
        return qs
    org_ids = roles.managed_org_ids(actor)
    users = roles.users_in_orgs(org_ids).values('pk') if org_ids else None
    return qs.filter(Q(token__user=actor) | Q(token__user__in=users)) if users is not None else qs.filter(token__user=actor)


def list_agents(ctx, params):
    qs = _manageable(ctx.user)
    for param in ('status', 'kind'):
        if params.get(param):
            qs = qs.filter(**{param: params[param]})
    if params.get('q'):
        qs = qs.filter(Q(name__icontains=str(params['q'])[:100]) | Q(token__user__username__icontains=str(params['q'])[:100]))
    page = svc.paginate(qs.order_by('name', 'id'), params, lambda a: a)
    counts = _counts([a.pk for a in page['results']])
    page['results'] = [agent_dict(a, counts=counts.get(a.pk), viewer=ctx.user) for a in page['results']]
    return page


def get_agent(ctx, agent_id):
    agent = _manageable(ctx.user).filter(pk=svc._int_param(agent_id, 'agent_id')).first()
    if agent is None:
        raise ApiError(404, 'agent not found')
    # A Sentinel's (kind='scanner') work is SentinelTask, not AgentTask: same admin call, the matching history.
    recent = (_sentinel().recent_tasks(agent, ctx.user) if agent.kind == 'scanner'
             else [task_brief(t) for t in _task_rows(AgentTask.objects.filter(agent=agent)).order_by('-id')[:20]])
    return {**agent_dict(agent, detail=True, counts=_counts([agent.pk]).get(agent.pk), viewer=ctx.user), 'warnings': _warnings(agent),
            'recent_tasks': recent}


def _clean_limits(value):
    if not isinstance(value, dict) or set(value) - {'capabilities', 'projects', 'max_concurrent'}:
        raise ApiError(400, 'limits must be an object with capabilities, projects and max_concurrent (each may be null for no limit)')
    out = {}
    try:
        if value.get('capabilities') is not None:
            out['capabilities'] = scope_lib.clean_capabilities(value['capabilities'])
        if value.get('projects') is not None:
            out['projects'] = scope_lib.clean_scope({'projects': value['projects']})['projects']
    except scope_lib.ScopeError as exc:
        raise ApiError(400, str(exc))
    cap = value.get('max_concurrent')
    if cap is not None:
        if isinstance(cap, bool) or not isinstance(cap, int) or not 1 <= cap <= MAX_CONCURRENT_CAP:
            raise ApiError(400, f'max_concurrent must be a whole number from 1 to {MAX_CONCURRENT_CAP}')
        out['max_concurrent'] = cap
    return out


def update_agent(ctx, agent_id, body):
    """An administrator approves, limits, suspends or revokes an agent: ``status`` (active, suspended, revoked), ``note`` and ``limits``.
    A suspended or revoked agent loses its leases at once; a tighter limit releases what it no longer allows."""
    svc.require_write_token(ctx)
    agent = _manageable(ctx.user).filter(pk=svc._int_param(agent_id, 'agent_id')).first()
    if agent is None or not roles.can_manage_user(ctx.user, agent.token.user):
        raise ApiError(404, 'agent not found')
    if agent.token.user_id == ctx.user.pk and not ctx.user.is_superuser:
        raise ApiError(403, 'an administrator cannot approve, limit or reinstate their own agent; ask another administrator')
    if not roles.can_manage_credentials(ctx.user, agent.token.user):
        raise ApiError(403, 'this user also belongs to organizations you do not administer; ask an App Admin')
    if not isinstance(body, dict) or not set(body) & {'status', 'note', 'limits', 'settings', 'update'} or set(body) - {'status', 'note', 'limits', 'settings', 'update'}:
        raise ApiError(400, 'send status, note, limits, settings and/or update')
    if ('settings' in body or 'update' in body) and agent.kind != 'scanner':
        raise ApiError(400, 'settings and updates are managed for Sentinels (kind=scanner) only')
    if 'update' in body and body['update'] != 'now':
        raise ApiError(400, 'update must be "now"')
    before = {'status': agent.status, 'limits': agent.limits}
    if 'status' in body:
        if body['status'] not in ADMIN_STATUSES:
            raise ApiError(400, f'status must be one of {", ".join(ADMIN_STATUSES)}')
        agent.status = body['status']
    if 'limits' in body:
        agent.limits = _clean_limits(body['limits'])
    note = _text(body['note'], MAX_NOTE) if 'note' in body else None
    if agent.status != before['status'] and note in (None, agent.status_note) and (
            agent.status == 'active' or agent.status_note == INHERITED_SUSPENSION_NOTE):
        # Approving or reinstating clears the reason the agent was held back, so an active agent is not shown with it; the automatic "another
        # agent of this user is suspended ..." note goes with any change of status. An administrator's own reason stays when the agent is
        # suspended or revoked. (The admin dialog sends the note field back unchanged with every action, which counts as no new note.)
        agent.status_note = ''
    elif note is not None:
        agent.status_note = note
    agent.status_by = ctx.user
    agent.save()
    if 'settings' in body:
        from agentapi import sentinel_settings
        sentinel_settings.set_managed(agent, body['settings'], ctx.user)
    if 'update' in body:
        from agentapi import sentinel_settings
        sentinel_settings.request_update(agent, ctx.user)
    released = release_agent_tasks(agent, f'the agent is {agent.status}', actor=ctx.user) if agent.status != 'active' else release_ineligible(agent)
    audit.record_for_user(ctx.user, 'agent.status' if 'status' in body else 'agent.limits', agent.token.user, target=agent.name, agent_id=agent.pk,
                          before=before, after={'status': agent.status, 'limits': agent.limits}, note=agent.status_note, released_tasks=released)
    out = get_agent(ctx, agent.pk)
    out['released_tasks'] = released
    return out
