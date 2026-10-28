"""Registered agents and the work the broker hands them (agentapi.agent_broker, agentapi.sentinel_broker).

An ``Agent`` is the registered identity of one API token: who it says it is, what it is responsible for and what it can do.
An ``AgentTask`` is one unit of validation or remediation work for a CVE match, leased to an agent until it reports back.
A ``SentinelTask`` is one unit of scan-stage work (nmap, naabu, a nuclei pass) for a scan, leased to a ``kind='scanner'``
Agent (a "Sentinel") the same way, but shaped around what a scanner needs rather than a CVE match. A ``SentinelEnrollment``
is the one-time secret an administrator hands a new Sentinel so its first ``register`` call can create its own ``Agent`` row.
"""
from django.db import models

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
    os = models.JSONField(default=list, blank=True)  # operating system families the agent can act on; empty means any
    tools = models.JSONField(default=list, blank=True)  # free-form tool names the agent has (nmap, curl, ansible ...)
    max_concurrent = models.PositiveSmallIntegerField(default=2)
    status = models.CharField(max_length=10, default='pending')  # pending until an administrator approves it (see agent_broker._initial_status)
    # An administrator's narrowing: {capabilities: [..] | null, projects: [slug] | null, max_concurrent: int | null}.
    limits = models.JSONField(default=dict, blank=True)
    status_note = models.CharField(max_length=200, blank=True, default='')
    status_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
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


class SentinelTask(models.Model):
    """One unit of scan-stage work: run this tool against this server-constructed target, leased to a ``kind='scanner'`` Agent (a
    Sentinel) until it reports back. ``target`` and ``result`` are each a small typed, clipped record (see
    ``agentapi.sentinel_broker.TARGET_SCHEMA`` / ``clean_result``); neither is ever built from, or interpreted as, a command."""
    KINDS = ('nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep', 'testssl', 'nmap_udp', 'wpscan')
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
    created_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-priority', 'created_at', 'id']
        indexes = [models.Index(fields=['status', 'lease_expires_at'], name='sentineltask_lease_idx'),
                   models.Index(fields=['project', 'status'], name='sentineltask_project_idx'),
                   models.Index(fields=['scan', 'kind'], name='sentineltask_scan_kind_idx')]

    def __str__(self):
        return f'sentinel task #{self.pk} {self.kind} ({self.status})'


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
    used_at = models.DateTimeField(null=True, blank=True)
    used_by_agent = models.ForeignKey(Agent, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')

    class Meta:
        ordering = ['-created_at', 'id']
        indexes = [models.Index(fields=['expires_at'], name='sentinelenroll_expiry_idx')]

    def __str__(self):
        return f'enrollment {self.prefix}... for {self.project or self.org}'
