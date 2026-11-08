"""Registered agents and the work the broker hands them (agentapi.agent_broker, agentapi.sentinel_broker).

An ``Agent`` is the registered identity of one API token: who it says it is, what it is responsible for and what it can do.
An ``AgentTask`` is one unit of validation or remediation work for a CVE match, leased to an agent until it reports back.
A ``SentinelTask`` is one unit of scan-stage work (nmap, naabu, a nuclei pass) for a scan, leased to a ``kind='scanner'``
Agent (a "Sentinel") the same way, but shaped around what a scanner needs rather than a CVE match. A ``SentinelEnrollment``
is the one-time secret an administrator hands a new Sentinel so its first ``register`` call can create its own ``Agent`` row.
"""
import uuid

from django.db import models
from django.db.models.functions import Now
from django.utils import timezone

from agentapi import sentinel_contract

ACTIVE_TASK_STATUSES = ('queued', 'assigned', 'running')
SENTINEL_ACTIVE_STATUSES = ('queued', 'claimed', 'running')


class Agent(models.Model):
    KINDS = ('remediation', 'validation', 'scanner', 'reporter', 'human')
    STATUSES = ('pending', 'active', 'suspended', 'revoked')

    token = models.OneToOneField('dashboard.ApiToken', on_delete=models.CASCADE, related_name='agent')
    name = models.CharField(max_length=100)
    kind = models.CharField(max_length=16, default='remediation')
    # What the agent asked to be responsible for: {orgs: [slug], projects: [slug], hosts: [pattern]}. It is intersected with what the
    # token's user can reach every time work is handed out, so a user who loses a project loses the agent's claim to it at once.
    scope = models.JSONField(default=dict, blank=True)
    capabilities = models.JSONField(default=list, blank=True)
    # Whether a Sentinel sits inside a private network. Decided by this server (the enrollment an administrator provisioned it from, or an
    # administrator's later change), never by the Sentinel: ``network:internal`` in ``capabilities`` is only what the Sentinel claims, and
    # work for a declared internal range goes to a Sentinel whose ``network`` is ``internal`` (``sentinel_broker.effective_capabilities``).
    network = models.CharField(max_length=10, default='external', db_default='external')
    os = models.JSONField(default=list, blank=True)  # operating system families the agent can act on; empty means any
    tools = models.JSONField(default=list, blank=True)  # free-form tool names the agent has (nmap, curl, ansible ...)
    max_concurrent = models.PositiveSmallIntegerField(default=2)
    status = models.CharField(max_length=10, default='pending')  # pending until an administrator approves it (see agent_broker._initial_status)
    # An administrator's narrowing: {capabilities: [..] | null, projects: [slug] | null, max_concurrent: int | null}.
    limits = models.JSONField(default=dict, blank=True)
    # A Sentinel's settings (``agentapi.sentinel_broker.SETTINGS``), kept twice so the most recent change wins whichever side made it:
    # ``managed_settings`` is what an administrator set from cvENGINE, ``reported_settings`` what the Sentinel's own configuration said
    # (its environment). Each entry is ``{value, at}`` (plus ``by`` when managed); ``at`` is this server's clock when the value last changed.
    managed_settings = models.JSONField(default=dict, blank=True)
    # What a Sentinel reports about itself: its client ``version`` and the state of its host-side updater (``update``: status, phase, detail, at).
    # ``update_requested_at`` is an administrator's "update now"; it clears once the Sentinel reports it is running a different version or a failed attempt.
    info = models.JSONField(default=dict, blank=True)
    update_requested_at = models.DateTimeField(null=True, blank=True)
    reported_settings = models.JSONField(default=dict, blank=True)
    status_note = models.CharField(max_length=200, blank=True, default='')
    status_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    # When ``status`` last changed (registration, or an administrator's ``update_agent``): how old a suspension or revocation is, for the rule
    # that holds a user's new agents back while another of theirs is suspended or revoked (``agent_broker.suspension_culprit``).
    status_changed_at = models.DateTimeField(null=True, blank=True)
    # Set when that rule suspended this agent at registration (no administrator decided it), with the agent it named. Such an agent is never
    # itself a reason to hold the next one back, and any status an administrator sets clears both.
    status_inherited = models.BooleanField(default=False, db_default=False)
    held_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    last_seen = models.DateTimeField(null=True, blank=True)
    registered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name', 'id']

    def __str__(self):
        return f'{self.name} ({self.kind})'


class AgentTask(models.Model):
    KINDS = ('validate', 'remediate')
    STATUSES = ('queued', 'assigned', 'running', 'completed', 'failed', 'cancelled')

    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE, related_name='+')
    match = models.ForeignKey('cveFeed.CVEMatch', on_delete=models.CASCADE, related_name='agent_tasks')
    kind = models.CharField(max_length=12)
    mode = models.CharField(max_length=12, blank=True, default='')  # validate: local | network | guided; remediate: package | config
    # Derived from the work when it is queued. Each entry is a capability, or several joined by '|' of which one is enough.
    required_capabilities = models.JSONField(default=list, blank=True)
    host = models.CharField(max_length=500, blank=True, default='')  # the host's name at queue time, for scope matching and display
    os_family = models.CharField(max_length=10, blank=True, default='')  # linux | windows | macos | bsd | '' when unknown
    ips = models.JSONField(default=list, blank=True)  # the host's addresses at queue time, so a CIDR in an agent's scope can be matched
    priority = models.PositiveSmallIntegerField(default=1)  # 3 fire, 2 smoke, 1 ice
    status = models.CharField(max_length=10, default='queued')
    agent = models.ForeignKey(Agent, on_delete=models.SET_NULL, null=True, blank=True, related_name='tasks')
    attempts = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField(default=3)
    not_before = models.DateTimeField(null=True, blank=True)  # a released or failed task waits out a short backoff
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error = models.CharField(max_length=300, blank=True, default='')
    created_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-priority', 'created_at', 'id']
        indexes = [models.Index(fields=['status', 'lease_expires_at'], name='agenttask_lease_idx'),
                   models.Index(fields=['project', 'status'], name='agenttask_project_idx')]
        constraints = [models.UniqueConstraint(fields=['match', 'kind'], condition=models.Q(status__in=ACTIVE_TASK_STATUSES),
                                               name='one_active_agent_task_per_match_kind')]


def new_trace_id():
    """The id one SentinelTask carries from the stage that queues it, through the Sentinel that runs it, to the audit rows and activity lines about it."""
    return uuid.uuid4().hex


class SentinelTask(models.Model):
    """One unit of scan-stage work: run this tool against this server-constructed target, leased to a ``kind='scanner'`` Agent (a
    Sentinel) until it reports back. ``target`` and ``result`` are each a small typed, clipped record (see
    ``agentapi.sentinel_broker.TARGET_SCHEMA`` / ``clean_result``); neither is ever built from, or interpreted as, a command."""
    KINDS = sentinel_contract.KINDS  # one list: the contract's ``kind_since``
    STATUSES = ('queued', 'claimed', 'running', 'done', 'failed', 'expired')

    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE, related_name='+')
    scan = models.ForeignKey('startScan.ScanHistory', on_delete=models.CASCADE, related_name='sentinel_tasks', null=True, blank=True)
    kind = models.CharField(max_length=20)
    target = models.JSONField(default=dict, blank=True)  # server-constructed: addresses/ports for nmap and naabu, host/templates for nuclei
    host = models.CharField(max_length=500, blank=True, default='')  # for scope matching and display, as AgentTask.host
    ips = models.JSONField(default=list, blank=True)  # addresses named by this task, for scope matching against an agent's host patterns
    priority = models.PositiveSmallIntegerField(default=1)
    status = models.CharField(max_length=10, default='queued')
    agent = models.ForeignKey(Agent, on_delete=models.SET_NULL, null=True, blank=True, related_name='sentinel_tasks')
    attempts = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField(default=1)  # a dispatched stage falls back to local execution rather than retrying
    not_before = models.DateTimeField(null=True, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error = models.CharField(max_length=300, blank=True, default='')
    # Signed-in work (docs/SCANNER-ARCHITECTURE.md, decision 4). ``secret_ref`` names the stored credential the task needs ("authcred:<id>", an
    # ``AuthCredential``), never its value: a task that carries one is offered only to the built-in scanner, which redeems it once through
    # ``sentinel_broker.read_secret``. ``secret_read_at`` is the compare-and-set that makes that read single use. Nothing sets ``secret_ref`` yet.
    secret_ref = models.CharField(max_length=40, null=True, blank=True)
    secret_read_at = models.DateTimeField(null=True, blank=True)
    trace_id = models.CharField(max_length=32, default=new_trace_id, db_default='', db_index=False)  # rows from before it existed read ''
    # A streamed kind (``sentinel_contract.STREAMED``: bbot_discovery) posts numbered batches while it runs (``SentinelPartial``): the seq of the last
    # batch the server took. A batch at or below it is a retry of one already stored; the next must be exactly one more.
    partial_seq = models.PositiveIntegerField(default=0, db_default=0)
    created_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-priority', 'created_at', 'id']
        indexes = [models.Index(fields=['status', 'lease_expires_at'], name='sentineltask_lease_idx'),
                   models.Index(fields=['project', 'status'], name='sentineltask_project_idx'),
                   models.Index(fields=['scan', 'kind'], name='sentineltask_scan_kind_idx')]

    def save(self, *args, **kwargs):
        """A new task is checked against the organization's do-not-scan address list before it is written, whoever creates it: the one place a kind added
        later cannot go around (``agentapi.address_guard``). Raises ``reNgine.resources.AddressExcluded``; nothing is stored."""
        if self._state.adding and self.project_id:
            from agentapi import address_guard
            refusal = address_guard.dispatch_refusal(self.project_id, self.kind, self.target, self.host, self.ips, scan=self.scan if self.scan_id else None)
            if refusal:
                from reNgine.resources import AddressExcluded
                raise AddressExcluded(self.kind, refusal)
        super().save(*args, **kwargs)

    def __str__(self):
        return f'sentinel task #{self.pk} {self.kind} ({self.status})'


class SentinelPartial(models.Model):
    """One batch of partial results a streamed task posted while it ran (``sentinel_broker.report_partial``), typed and clipped by
    ``sentinel_broker.clean_partial``, waiting for the stage that dispatched the task (``sentinel_dispatch.dispatch_stream``) to persist it. That
    stage reads the batches in ``seq`` order and deletes each once it is stored, so a row lives for seconds; what is left when a stage went away
    goes with its task (cascade, and the task's retention)."""
    task = models.ForeignKey(SentinelTask, on_delete=models.CASCADE, related_name='partials')
    seq = models.PositiveIntegerField()
    body = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['task', 'seq']
        constraints = [models.UniqueConstraint(fields=['task', 'seq'], name='sentinelpartial_task_seq_uniq')]

    def __str__(self):
        return f'partial {self.seq} of sentinel task #{self.task_id}'


class StageRun(models.Model):
    """A scan stage (or a sweep) that handed work to Sentinels and gave its Celery worker back while it waits (``agentapi.stage_runs``, docs/
    SCANNER-ARCHITECTURE.md, "Asynchronous stages"). ``kind`` is the registered adapter that continues it, ``stage`` the stage it waits in, ``context``
    what that adapter needs to carry on (JSON: ids and flags, never a credential), ``task_ids`` the SentinelTasks it waits on and ``tasks`` the state of
    each wait (its budgets, as wall-clock times, and whether its activity line was closed). ``state``: ``running`` (a worker is on it, until
    ``lease_until``), ``waiting`` (no worker: Sentinels hold its tasks), ``ready`` (every task ended; the completion callback is queued), ``done``,
    ``failed`` or ``cancelled``. ``deadline`` is when the waiting run must next be looked at (a claim or completion budget ends then)."""
    STATES = ('running', 'waiting', 'ready', 'done', 'failed', 'cancelled')
    OPEN_STATES = ('running', 'waiting', 'ready')

    kind = models.CharField(max_length=64, db_default='')
    stage = models.CharField(max_length=64, blank=True, default='', db_default='')
    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE, null=True, blank=True, related_name='+')
    scan = models.ForeignKey('startScan.ScanHistory', on_delete=models.CASCADE, null=True, blank=True, related_name='+')
    context = models.JSONField(default=dict, blank=True, db_default={})
    task_ids = models.JSONField(default=list, blank=True, db_default=[])
    tasks = models.JSONField(default=dict, blank=True, db_default={})
    state = models.CharField(max_length=12, default='running', db_default='running')
    queue = models.CharField(max_length=40, blank=True, default='', db_default='')
    rounds = models.PositiveIntegerField(default=0, db_default=0)
    deadline = models.DateTimeField(null=True, blank=True)
    lease_until = models.DateTimeField(null=True, blank=True)
    waiting_since = models.DateTimeField(null=True, blank=True)
    woke_at = models.DateTimeField(null=True, blank=True)
    resumed_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    history = models.JSONField(default=list, blank=True, db_default=[])  # per wait: seconds waited and the callback latency, for the metrics
    error = models.CharField(max_length=300, blank=True, default='', db_default='')
    created_at = models.DateTimeField(default=timezone.now, db_default=Now())
    updated_at = models.DateTimeField(auto_now=True, db_default=Now())

    class Meta:
        ordering = ['created_at', 'id']
        indexes = [models.Index(fields=['state', 'deadline'], name='stagerun_state_idx'),
                   models.Index(fields=['scan', 'state'], name='stagerun_scan_idx')]

    def __str__(self):
        return f'stage run #{self.pk} {self.kind} ({self.state})'


class SentinelEnrollment(models.Model):
    """A one-time, short-lived secret an org admin or App Admin generates for one project (or organization): when a Sentinel's
    first ``register`` call presents it, the server creates the Agent row (kind='scanner') pre-scoped to it, owned by the
    administrator who generated it, and marks it pending approval exactly like any other new agent (see
    ``agent_broker._initial_status``). Only the hash is stored; the raw secret is shown once, in the enroll response."""
    token_hash = models.CharField(max_length=64, unique=True)
    prefix = models.CharField(max_length=12)
    org = models.ForeignKey('dashboard.Org', on_delete=models.CASCADE, null=True, blank=True, related_name='+')
    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE, null=True, blank=True, related_name='+')
    created_by = models.ForeignKey('auth.User', on_delete=models.CASCADE, related_name='+')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    network = models.CharField(max_length=10, default='external', db_default='external')  # what the administrator chose when provisioning: external or internal
    used_at = models.DateTimeField(null=True, blank=True)
    used_by_agent = models.ForeignKey(Agent, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    builtin = models.BooleanField(default=False, db_default=False)  # the install's own scanner (agentapi.builtin_scanner): minted by the server, never by a person
    # The API token the redeemed secret minted (scope 'sentinel'): what ties a Sentinel to the scope it was enrolled for, so it can narrow it but
    # never widen it, even after its Agent row was removed and registered again.
    token = models.OneToOneField('dashboard.ApiToken', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')

    class Meta:
        ordering = ['-created_at', 'id']
        indexes = [models.Index(fields=['expires_at'], name='sentinelenroll_expiry_idx')]

    def __str__(self):
        return f'enrollment {self.prefix}... for {self.project or self.org}'


class SentinelDefaults(models.Model):
    """The one row of instance-wide defaults for Sentinels (``pk=1``): what a Sentinel does when neither an administrator nor its own
    configuration set a value. ``self_update`` is ``off``, ``manual`` (it updates only when an administrator presses Update now) or
    ``automatic``; empty means "follow the instance's own Automatic or Manual update choice" (``cveFeed.updater.read_mode``)."""
    self_update = models.CharField(max_length=10, blank=True, default='')
    # The capability policy defaults (``agentapi.sentinel_policy``): ``{kind: {'mode': 'allow'|'deny'|'prefer', 'max_concurrent': int|None}}`` applied to a
    # Sentinel with no policy of its own for a kind. ``builtin_kinds`` is for the install's own scanner (``None``: nothing was ever chosen, so the shipped
    # default applies: OpenVAS denied; ``{}``: an administrator chose no defaults), ``external_kinds`` for every other Sentinel (empty: all declared kinds allowed).
    builtin_kinds = models.JSONField(null=True, blank=True, default=None)
    external_kinds = models.JSONField(blank=True, default=dict, db_default={})  # db_default: the code still running during an update inserts without it
    changed_by = models.CharField(max_length=150, blank=True, default='')
    changed_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def current(cls):
        return cls.objects.get_or_create(pk=1)[0]

    def __str__(self):
        return f'sentinel defaults (self-update: {self.self_update or "follows the instance"})'
