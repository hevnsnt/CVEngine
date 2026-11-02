from django.apps import apps
from django.db import models
from dashboard.models import Project
from targetApp.alias_note import ALIAS_MAX, NOTE_MAX


class HistoricalIP(models.Model):
	id = models.AutoField(primary_key=True)
	ip = models.CharField(max_length=150)
	location = models.CharField(max_length=500)
	owner = models.CharField(max_length=500)
	last_seen = models.CharField(max_length=500)

	def __str__(self):
		return self.ip


class RelatedDomain(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=250)

	def __str__(self):
		return self.name


class Registrar(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, null=True, blank=True)
	phone = models.CharField(max_length=150, null=True, blank=True)
	email = models.CharField(max_length=350, null=True, blank=True)
	url = models.CharField(max_length=1000, null=True, blank=True)

	def __str__(self):
		return self.name


class DomainRegistration(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, null=True, blank=True)
	organization = models.CharField(max_length=500, null=True, blank=True)
	address = models.CharField(max_length=500, null=True, blank=True)
	city = models.CharField(max_length=100, null=True, blank=True)
	state = models.CharField(max_length=100, null=True, blank=True)
	zip_code = models.CharField(max_length=100, null=True, blank=True)
	country = models.CharField(max_length=100, null=True, blank=True)
	email = models.CharField(max_length=500, null=True, blank=True)
	phone = models.CharField(max_length=150, null=True, blank=True)
	fax = models.CharField(max_length=150, null=True, blank=True)
	id_str = models.CharField(max_length=500, null=True, blank=True)

	def __str__(self):
		return self.name


class WhoisStatus(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)

	def __str__(self):
		return self.name


class NameServer(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)

	def __str__(self):
		return self.name


class DNSRecord(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	type = models.CharField(max_length=50)

	def __str__(self):
		return self.name


class DomainInfo(models.Model):
	id = models.AutoField(primary_key=True)
	dnssec = models.BooleanField(default=False)
	# dates
	created = models.DateTimeField(null=True, blank=True)
	updated = models.DateTimeField(null=True, blank=True)
	expires = models.DateTimeField(null=True, blank=True)
	# geolocation
	geolocation_iso = models.CharField(max_length=10, null=True, blank=True)
	# registrar
	registrar = models.ForeignKey(Registrar, blank=True, on_delete=models.CASCADE, null=True)
	# registrant
	registrant = models.ForeignKey(
		DomainRegistration,
		blank=True,
		null=True,
		on_delete=models.CASCADE,
		related_name='registrant'
	)
	# admin
	admin = models.ForeignKey(
		DomainRegistration,
		blank=True,
		null=True,
		on_delete=models.CASCADE,
		related_name='admin'
	)
	# tech
	tech = models.ForeignKey(
		DomainRegistration,
		blank=True,
		null=True,
		on_delete=models.CASCADE,
		related_name='tech'
	)
	# status
	status = models.ManyToManyField(WhoisStatus, blank=True)
	# ns
	name_servers = models.ManyToManyField(NameServer, blank=True)
	dns_records = models.ManyToManyField(DNSRecord, blank=True)
	# whois server
	whois_server = models.CharField(max_length=150, null=True, blank=True)
	# associated/similer domains
	related_domains = models.ManyToManyField(RelatedDomain, blank=True, related_name='associated_domains')
	related_tlds = models.ManyToManyField(RelatedDomain, blank=True, related_name='related_tlds')
	similar_domains = models.ManyToManyField(RelatedDomain, blank=True, related_name='similar_domains')
	# historical ips
	historical_ips = models.ManyToManyField(HistoricalIP, blank=True, related_name='similar_domains')

	def __str__(self):
		return str(self.id)


class Domain(models.Model):
	id = models.AutoField(primary_key=True)
	# Unique per organization, not across the instance: two organizations may each track example.com, and neither can see, detect or
	# block the other's record. ``org`` is the project's organization, kept in step by save().
	name = models.CharField(max_length=300, db_index=True)
	org = models.ForeignKey('dashboard.Org', on_delete=models.CASCADE, null=True, blank=True, related_name='+', editable=False)
	h1_team_handle = models.CharField(max_length=100, blank=True, null=True)
	ip_address_cidr = models.CharField(max_length=100, blank=True, null=True)
	description = models.TextField(blank=True, null=True)
	# what a person calls this target and a few lines about it (targetApp.alias_note): shown beside the name, never in place of it
	alias = models.CharField(max_length=ALIAS_MAX, blank=True, default='', db_default='')
	note = models.CharField(max_length=NOTE_MAX, blank=True, default='', db_default='')
	insert_date = models.DateTimeField(null=True)
	start_scan_date = models.DateTimeField(null=True)
	request_headers = models.JSONField(null=True, blank=True)
	domain_info = models.ForeignKey(DomainInfo, on_delete=models.CASCADE, null=True, blank=True)
	project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=False)
	# How far this target's scope reaches: 'auto' uses the shared-domain list (a tenant under a provider's domain is host-only,
	# an owned name may be promoted to its apex), 'host' is exactly this host (never its parent domain, and no name under it is
	# discovered, kept or scanned under this target), 'parent' treats the registrable domain as owned. Chosen when the target is added
	# (``=example.com`` in Add targets, or ``scope_mode``) or later (POST targets/<id>/scope).
	SCOPE_AUTO, SCOPE_HOST, SCOPE_PARENT = 'auto', 'host', 'parent'
	SCOPE_MODES = ((SCOPE_AUTO, 'auto'), (SCOPE_HOST, 'host'), (SCOPE_PARENT, 'parent'))
	scope_mode = models.CharField(max_length=8, choices=SCOPE_MODES, default=SCOPE_AUTO)
	# How this target is discovered each time something starts discovery on its own (the work conductor, the assessment review, a move):
	# the mode chosen when it was added, or later. 'manual' is "just add it, do not scan yet": nothing automatic ever scans it, only a person
	# who picks a mode. The database default keeps every row from before the column on 'standard', what they were always scanned with.
	DISCOVERY_STANDARD, DISCOVERY_DEEP, DISCOVERY_PASSIVE, DISCOVERY_MANUAL = 'standard', 'deep', 'passive', 'manual'
	DISCOVERY_MODES = ((DISCOVERY_STANDARD, 'standard'), (DISCOVERY_DEEP, 'deep'), (DISCOVERY_PASSIVE, 'passive'), (DISCOVERY_MANUAL, 'manual'))
	discovery_mode = models.CharField(max_length=8, choices=DISCOVERY_MODES, default=DISCOVERY_STANDARD, db_default=DISCOVERY_STANDARD)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['org', 'name'], condition=models.Q(org__isnull=False), name='uniq_domain_org_name'),
			models.UniqueConstraint(fields=['project', 'name'], condition=models.Q(org__isnull=True), name='uniq_domain_project_name'),
		]

	def save(self, *args, **kwargs):
		# read from the database, not the cached project: a new project is placed in its organization just after it is saved
		if self.project_id:
			from dashboard.models import Project
			org_id = Project._base_manager.filter(pk=self.project_id).values_list('org_id', flat=True).first()
			if org_id != self.org_id:
				self.org_id = org_id
				if kwargs.get('update_fields') is not None and 'org' not in kwargs['update_fields']:
					kwargs['update_fields'] = [*kwargs['update_fields'], 'org']
		super().save(*args, **kwargs)

	def is_host_scoped(self):
		"""True when only this host (never its parent domain) is in scope: scope_mode 'host', or 'auto' for a tenant of a
		shared provider domain (see targetApp.shared_domains)."""
		if self.scope_mode == self.SCOPE_HOST:
			return True
		if self.scope_mode == self.SCOPE_PARENT:
			return False
		from targetApp.shared_domains import effective_apex
		return effective_apex(self.name)[1]

	def exact_host_only(self):
		"""True when the target was set to 'host' (``=example.com`` at add time, or the scope selector): exactly this host. No name under it
		is enumerated, kept under this target or scanned through it. An 'auto' tenant of a shared provider domain is host scoped too
		(bbot strict scope, never its parent), but keeps its own tree as before: only an explicit 'host' narrows it to the one name."""
		return self.scope_mode == self.SCOPE_HOST

	def includes_host(self, name):
		"""Whether ``name`` belongs under this target: the target itself, or a name under it (dot boundary) unless the target is exactly
		one host (``exact_host_only``). An address target holds only itself."""
		target = (self.name or '').strip().lower().rstrip('.')
		host = str(name or '').strip().lower().rstrip('.')
		if not host or not target:
			return False
		if host == target:
			return True
		return not self.exact_host_only() and host.endswith('.' + target)

	def get_recent_scan_id(self):
		ScanHistory = apps.get_model('startScan.ScanHistory')
		obj = ScanHistory.objects.filter(domain__id=self.id).order_by('-id')
		if obj:
			return obj[0].id

	def __str__(self):
		return str(self.name)


def in_target_scope_q(prefix=''):
	"""A filter for Subdomain rows (``prefix`` reaches the Subdomain from another model, e.g. ``'subdomain__'``) that leaves out every name
	under a target set to exactly one host (``Domain.exact_host_only``): a row kept from before the target was narrowed is never swept or
	scanned through it. The target's own name, and every row of any other target, pass unchanged."""
	from django.db.models import F, Q
	return ~Q(**{prefix + 'target_domain__scope_mode': Domain.SCOPE_HOST}) | Q(**{prefix + 'name__iexact': F(prefix + 'target_domain__name')})


def narrowed_names(project_id, names):
	"""The names among ``names`` that ``project_id`` holds only as rows under a target set to exactly one host (``in_target_scope_q``
	leaves every row of theirs out): a sweep that starts from something other than the inventory (an old screenshot, say) skips them. Empty,
	at the cost of one query, for a project with no such target."""
	names = {str(n).strip().lower().rstrip('.') for n in names if n}
	if not names or not Domain._base_manager.filter(project_id=project_id, scope_mode=Domain.SCOPE_HOST).exists():
		return set()
	from django.db.models.functions import Lower
	from startScan.models import Subdomain
	rows = Subdomain.objects.filter(target_domain__project_id=project_id).annotate(lname=Lower('name')).filter(lname__in=names)
	return set(rows.exclude(in_target_scope_q()).values_list('lname', flat=True)) - set(rows.filter(in_target_scope_q()).values_list('lname', flat=True))


def org_domains(project):
	"""Every Domain in the organization ``project`` (an object or an id) belongs to (unscoped), or just the project's own when it has no organization. A
	domain name is unique within this set, never across the instance."""
	from dashboard.models import Project
	project_id = getattr(project, 'pk', project)
	org_id = Project._base_manager.filter(pk=project_id).values_list('org_id', flat=True).first()
	if org_id:
		return Domain._base_manager.filter(org_id=org_id)
	return Domain._base_manager.filter(project_id=project_id)
