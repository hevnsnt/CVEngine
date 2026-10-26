from reNgine.crypto_fields import ENCRYPTED_COLUMN_LENGTH, EncryptedCharField, EncryptedJSONField
from django.db import models
from reNgine.definitions import *
from django.contrib.auth.models import User


class SearchHistory(models.Model):
	user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE, related_name='search_history')
	query = models.CharField(max_length=1000)

	def __str__(self):
		return self.query


class Org(models.Model):
	"""Top of the tenancy hierarchy: Organization -> Project.

	(Named Org in code because targetApp.Organization already means a group of targets.)
	"""
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	slug = models.SlugField(unique=True)
	require_mfa = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return self.name


class Project(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	slug = models.SlugField(unique=True)
	insert_date = models.DateTimeField()
	org = models.ForeignKey(Org, on_delete=models.SET_NULL, null=True, blank=True, related_name='projects')

	def __str__(self):
		return self.slug

	def clean(self):
		from django.core.exceptions import ValidationError
		from tenancy.roles import ALL_PROJECTS, is_reserved_project
		if is_reserved_project(self.slug):
			raise ValidationError({'slug': f'"{ALL_PROJECTS}" is reserved for the all-projects view'})

	def save(self, *args, **kwargs):
		# the reserved slug of the all-projects view can never name a real project, whichever code path creates it
		from tenancy.roles import ALL_PROJECTS, is_reserved_project
		if is_reserved_project(self.slug):
			raise ValueError(f'"{ALL_PROJECTS}" is reserved for the all-projects view and cannot be a project slug')
		super().save(*args, **kwargs)


class OpenAiAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH)

	def __str__(self):
		return 'OpenAI API key (the value is never shown)'
	

class OllamaSettings(models.Model):
	id = models.AutoField(primary_key=True)
	selected_model = models.CharField(max_length=500)
	use_ollama = models.BooleanField(default=True)

	def __str__(self):
		return self.selected_model


class AIProviderSettings(models.Model):
	"""Single-row config for the model-agnostic AI layer (see reNgine/ai_providers.py).

	The API key lives here (Postgres), set via the settings UI, never in git or .env.
	"""
	PROVIDER_CHOICES = [('anthropic', 'Anthropic'), ('openai', 'OpenAI'), ('openrouter', 'OpenRouter'), ('ollama', 'Ollama'), ('vllm', 'vLLM')]
	id = models.AutoField(primary_key=True)
	provider = models.CharField(max_length=32, choices=PROVIDER_CHOICES, default='anthropic')
	model = models.CharField(max_length=200, blank=True, default='')
	api_key = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH, blank=True, default='')
	base_url = models.CharField(max_length=500, blank=True, default='')
	enabled = models.BooleanField(default=False)
	# Auto-fire: on a new FIRE/SMOKE CVE the AI picks targets and starts scans.
	auto_fire = models.BooleanField(default=False)
	auto_fire_engine_id = models.IntegerField(null=True, blank=True)  # scanEngine.EngineType id
	auto_fire_max_scans = models.IntegerField(default=200)  # hosts tested per CVE (the column keeps its old name)
	# How many times a day the model may be asked to plan validation checks (each is a paid request): in total, and for one project.
	plan_daily_total = models.PositiveIntegerField(default=200)
	plan_daily_per_project = models.PositiveIntegerField(default=20)
	verified_at = models.DateTimeField(null=True, blank=True)
	verified_provider = models.CharField(max_length=32, blank=True, default='')
	verified_model = models.CharField(max_length=200, blank=True, default='')

	def __str__(self):
		return f'{self.provider}:{self.model or "default"}'


class NetlasAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH)

	def __str__(self):
		return 'Netlas API key (the value is never shown)'
	

class ChaosAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH)

	def __str__(self):
		return 'Chaos API key (the value is never shown)'
	

class HackerOneAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	username = models.CharField(max_length=500)
	key = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH)

	def __str__(self):
		return self.username


class InAppNotification(models.Model):
	project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=True)
	notification_type = models.CharField(max_length=10, choices=NOTIFICATION_TYPES, default='system')
	status = models.CharField(max_length=10, choices=NOTIFICATION_STATUS_TYPES, default='info')
	title = models.CharField(max_length=255)
	description = models.TextField()
	icon = models.CharField(max_length=50) # mdi icon class name
	is_read = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)
	redirect_link = models.URLField(max_length=255, blank=True, null=True)
	open_in_new_tab = models.BooleanField(default=False)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		if self.notification_type == 'system':
			return f"System wide notif: {self.title}"
		else:
			return f"Project wide notif: {self.project.name}: {self.title}"
		
	@property
	def is_system_wide(self):
		# property to determine if the notification is system wide or project specific
		return self.notification_type == 'system'


class UserPreferences(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	bug_bounty_mode = models.BooleanField(default=True)
	
	def __str__(self):
		return f"{self.user.username}'s preferences"

ROLE_ADMIN, ROLE_USER, ROLE_AUDIT, ROLE_PENTESTER = 'admin', 'user', 'audit', 'pentester'
ROLE_CHOICES = [
	(ROLE_ADMIN, 'Admin (change settings)'),
	(ROLE_USER, 'User (add, scan, reports)'),
	(ROLE_AUDIT, 'Audit (read only)'),
	(ROLE_PENTESTER, 'Pentester (bug bounty workflow)'),
]


class OrgMembership(models.Model):
	"""A role across every project in an organization."""
	user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='org_memberships')
	org = models.ForeignKey(Org, on_delete=models.CASCADE, related_name='memberships')
	role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_AUDIT)

	class Meta:
		unique_together = ('user', 'org')

	def __str__(self):
		return f'{self.user} is {self.role} in {self.org}'


class ProjectMembership(models.Model):
	"""A role in one project; overrides the user's org-level role for that project."""
	user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='project_memberships')
	project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='memberships')
	role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_AUDIT)

	class Meta:
		unique_together = ('user', 'project')

	def __str__(self):
		return f'{self.user} is {self.role} in {self.project}'


class UserProfile(models.Model):
	"""Per-user flags: bug bounty opt-in and TOTP MFA state."""
	user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='tenancy_profile')
	bugbounty_enabled = models.BooleanField(default=False)
	mfa_enabled = models.BooleanField(default=False)
	mfa_secret = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH, blank=True, default='')  # the TOTP seed: encrypted at rest
	recovery_codes = models.JSONField(default=list, blank=True)  # keyed hashes of unused codes (tenancy.mfa)
	mfa_last_step = models.BigIntegerField(default=0)  # last accepted TOTP step, blocks code replay
	onboarded = models.BooleanField(default=False)  # finished the first-run wizard
	must_change_password = models.BooleanField(default=False)  # set when an admin issued a temporary password

	def __str__(self):
		return f'profile of {self.user}'


class ApiToken(models.Model):
	"""Bearer token for agents (REST /api/v1 and MCP /mcp/). Only a hash is stored.

	A token acts as its user: same org/project memberships, same roles. read_only
	narrows it further (GET and read-only MCP tools only).
	"""
	user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_tokens')
	name = models.CharField(max_length=100)
	key_hash = models.CharField(max_length=64, unique=True)
	prefix = models.CharField(max_length=12)  # shown in the UI to tell tokens apart
	read_only = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)
	last_used_at = models.DateTimeField(null=True, blank=True)
	expires_at = models.DateTimeField(null=True, blank=True)
	revoked = models.BooleanField(default=False)
	# Hosts, IPs or CIDRs this agent has registered as its responsibility (narrows /work).
	assets = models.JSONField(default=list, blank=True)

	def __str__(self):
		return f'{self.name} ({self.prefix}...) for {self.user}'


class SystemTimings(models.Model):
	"""Single-row, App Admin editable timings. Saving applies them to the beat schedule; workers read the
	timeouts at the start of each run."""
	cve_sync_minutes = models.PositiveIntegerField(default=30)       # how often the cve.now feed is read
	hygiene_hour_utc = models.PositiveSmallIntegerField(default=3)   # daily certificate/TLS/email sweep
	ct_watch_minutes = models.PositiveIntegerField(default=20)       # how often every target is re-checked against crt.sh
	discovery_timeout_hours = models.PositiveSmallIntegerField(default=6)
	nuclei_timeout_hours = models.PositiveSmallIntegerField(default=4)

	@classmethod
	def current(cls):
		return cls.objects.first() or cls()


class IpAccessControl(models.Model):
	"""Single-row App Admin toggle. When enabled, IpAllowlistMiddleware blocks every request (web UI,
	admin, agent API, everything) whose connecting IP does not match an IpAllowlistEntry."""
	enabled = models.BooleanField(default=False)

	@classmethod
	def current(cls):
		return cls.objects.first() or cls()


class IpAllowlistEntry(models.Model):
	"""One allowed IP or CIDR (e.g. "203.0.113.4" or "203.0.113.0/24", IPv4 or IPv6)."""
	cidr = models.CharField(max_length=64)
	label = models.CharField(max_length=200, blank=True, default='')
	created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
	created_at = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return f'{self.cidr} ({self.label})' if self.label else self.cidr


class AbuseStrike(models.Model):
	"""One rejected request that carried an attack payload (command or SQL injection, path traversal, ...).
	Strikes add up per user and per IP; enough of them inside the window trigger an automatic ban."""
	user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
	username = models.CharField(max_length=150, blank=True, default='')
	ip = models.CharField(max_length=64, blank=True, default='')
	weight = models.PositiveSmallIntegerField(default=1)
	category = models.CharField(max_length=40)
	field = models.CharField(max_length=80, blank=True, default='')
	sample = models.CharField(max_length=200, blank=True, default='')  # truncated, for the admin to judge
	path = models.CharField(max_length=200, blank=True, default='')
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-created_at']


class AbuseBan(models.Model):
	"""An automatic (or manual) block of an IP address. An account ban is just ``User.is_active = False`` plus
	revoked tokens, recorded here too so an admin can see why. Lift a ban by setting ``lifted`` (admin UI)."""
	ip = models.CharField(max_length=64, blank=True, default='', db_index=True)
	user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
	username = models.CharField(max_length=150, blank=True, default='')
	reason = models.CharField(max_length=300)
	created_at = models.DateTimeField(auto_now_add=True)
	expires_at = models.DateTimeField(null=True, blank=True)  # null = until an admin lifts it
	lifted = models.BooleanField(default=False)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		return f'{self.ip or self.username}: {self.reason}'


class AuditLog(models.Model):
	"""Who changed what in administration: accounts, memberships, organizations, projects, timings."""
	actor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
	actor_name = models.CharField(max_length=150, blank=True, default='')
	action = models.CharField(max_length=60)
	target = models.CharField(max_length=300, blank=True, default='')
	org = models.ForeignKey(Org, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
	detail = models.JSONField(default=dict, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-id']

	def __str__(self):
		return f'{self.actor_name} {self.action} {self.target}'


class ApiCredential(models.Model):
	"""An API key for an external OSINT/recon service (Shodan, Censys, ...), scoped to one organization or
	one project. Fed into bbot at discovery time (see cveFeed.api_credentials) so its passive modules for
	that service activate; a project's own key overrides its organization's for the same service.

	Exactly one of org/project is set. Both are nullable FKs, and Postgres never treats two NULLs as equal,
	so unique_together on (org, service) and (project, service) each only constrains the rows that actually
	use that column, which is what lets many projects each hold their own row for the same service.
	"""
	org = models.ForeignKey(Org, on_delete=models.CASCADE, null=True, blank=True, related_name='api_credentials')
	project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=True, related_name='api_credentials')
	service = models.CharField(max_length=40)  # a key in cveFeed.api_credentials.SERVICES
	value = EncryptedJSONField(default=dict)  # e.g. {"api_key": "..."} or {"api_id": "...", "api_secret": "..."}
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		constraints = [
			models.CheckConstraint(
				check=(models.Q(org__isnull=False, project__isnull=True) | models.Q(org__isnull=True, project__isnull=False)),
				name='apicredential_exactly_one_scope'),
		]
		unique_together = [('org', 'service'), ('project', 'service')]

	def __str__(self):
		return f'{self.service} for {self.org or self.project}'
