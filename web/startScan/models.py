from urllib.parse import urlparse
from django.apps import apps
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models import Value
from django.db.models.functions import Coalesce, MD5 as Md5
from django.utils import timezone
from reNgine.definitions import (CELERY_TASK_STATUSES,
								 NUCLEI_REVERSE_SEVERITY_MAP)
from reNgine.utilities import *
from scanEngine.models import EngineType
from targetApp.models import Domain


class hybrid_property:
	def __init__(self, func):
		self.func = func
		self.name = func.__name__
		self.exp = None

	def __get__(self, instance, owner):
		if instance is None:
			return self
		return self.func(instance)

	def __set__(self, instance, value):
		pass

	def expression(self, exp):
		self.exp = exp
		return self


class ScanHistory(models.Model):
	id = models.AutoField(primary_key=True)
	start_scan_date = models.DateTimeField()
	scan_status = models.IntegerField(choices=CELERY_TASK_STATUSES, default=-1)
	results_dir = models.CharField(max_length=100, blank=True)
	domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	scan_type = models.ForeignKey(EngineType, on_delete=models.CASCADE)
	celery_ids = ArrayField(models.CharField(max_length=100), blank=True, default=list)
	tasks = ArrayField(models.CharField(max_length=200), null=True)
	stop_scan_date = models.DateTimeField(null=True, blank=True)
	used_gf_patterns = models.CharField(max_length=500, null=True, blank=True)
	error_message = models.CharField(max_length=300, blank=True, null=True)
	emails = models.ManyToManyField('Email', related_name='emails', blank=True)
	employees = models.ManyToManyField('Employee', related_name='employees', blank=True)
	dorks = models.ManyToManyField('Dork', related_name='dorks', blank=True)
	initiated_by = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='initiated_scans', blank=True, null=True)
	aborted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='aborted_scans')
	# The bbot mode this scan was queued to run in ('' for a scan queued before it was recorded). A queued scan whose worker message was lost is sent
	# again in this mode (cveFeed.reaper), so a passive scan is never recovered as a standard one.
	discovery_mode = models.CharField(max_length=16, blank=True, default='', db_default='')

	class Meta:
		indexes = [
			models.Index(fields=['scan_status', 'id'], name='scan_status_id_idx'),
			models.Index(fields=['domain', 'scan_status'], name='scan_domain_status_idx'),
			models.Index(fields=['domain', 'start_scan_date'], name='scan_domain_started_idx'),
		]

	def __str__(self):
		return self.domain.name

	def get_subdomain_count(self):
		return Subdomain.objects.filter(scan_history__id=self.id).count()

	def get_subdomain_change_count(self):
		last_scan = (
			ScanHistory.objects
			.filter(id=self.id)
			.filter(tasks__overlap=['subdomain_discovery'])
			.order_by('-start_scan_date')
		)
		scanned_host_q1 = (
			Subdomain.objects
			.filter(target_domain__id=self.domain.id)
			.exclude(scan_history__id=last_scan[0].id)
			.values('name')
		)
		scanned_host_q2 = (
			Subdomain.objects
			.filter(scan_history__id=last_scan[0].id)
			.values('name')
		)
		new_subdomains = scanned_host_q2.difference(scanned_host_q1).count()
		removed_subdomains = scanned_host_q1.difference(scanned_host_q2).count()
		return [new_subdomains, removed_subdomains]


	def get_endpoint_count(self):
		return (
			EndPoint.objects
			.filter(scan_history__id=self.id)
			.count()
		)

	def get_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.count()
		)

	def get_unknown_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=-1)
			.count()
		)

	def get_info_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=0)
			.count()
		)

	def get_low_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=1)
			.count()
		)

	def get_medium_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=2)
			.count()
		)

	def get_high_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=3)
			.count()
		)

	def get_critical_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=4)
			.count()
		)

	def get_completed_ago(self):
		if self.stop_scan_date:
			return self.get_time_ago(self.stop_scan_date)

	def get_total_scan_time_in_sec(self):
		if self.stop_scan_date:
			return (self.stop_scan_date - self.start_scan_date).seconds

	def get_elapsed_time(self):
		return self.get_time_ago(self.start_scan_date)

	def get_time_ago(self, time):
		duration = timezone.now() - time
		days, seconds = duration.days, duration.seconds
		hours = days * 24 + seconds // 3600
		minutes = (seconds % 3600) // 60
		seconds = seconds % 60
		if not hours and not minutes:
			return f'{seconds} seconds'
		elif not hours:
			return f'{minutes} minutes'
		elif not minutes:
			return f'{hours} hours'
		return f'{hours} hours {minutes} minutes'


class Subdomain(models.Model):
	# TODO: Add endpoint property instead of replicating endpoint fields here
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
	name = models.CharField(max_length=1000)
	is_imported_subdomain = models.BooleanField(default=False)
	is_important = models.BooleanField(default=False, null=True, blank=True)
	http_url = models.CharField(max_length=10000, null=True, blank=True)
	screenshot_path = models.CharField(max_length=1000, null=True, blank=True)
	screenshot_hash = models.CharField(max_length=16, blank=True, default='')  # 64-bit difference hash (cveFeed.shots)
	http_header_path = models.CharField(max_length=1000, null=True, blank=True)
	discovered_date = models.DateTimeField(blank=True, null=True)
	cname = models.CharField(max_length=5000, blank=True, null=True)
	is_cdn = models.BooleanField(default=False, blank=True, null=True)
	cdn_name = models.CharField(max_length=200, blank=True, null=True)
	http_status = models.IntegerField(default=0)
	content_type = models.CharField(max_length=100, null=True, blank=True)
	response_time = models.FloatField(null=True, blank=True)
	webserver = models.CharField(max_length=1000, blank=True, null=True)
	content_length = models.IntegerField(default=0, blank=True, null=True)
	page_title = models.CharField(max_length=1000, blank=True, null=True)
	technologies = models.ManyToManyField('Technology', related_name='technologies', blank=True)
	ip_addresses = models.ManyToManyField('IPAddress', related_name='ip_addresses', blank=True)
	directories = models.ManyToManyField('DirectoryScan', related_name='directories', blank=True)
	waf = models.ManyToManyField('Waf', related_name='waf', blank=True)
	attack_surface = models.TextField(null=True, blank=True)
	# host score (cveFeed.scoring): 0 to 100, with the ordered {label, points} lines that add up to it
	score = models.IntegerField(default=0)
	score_detail = models.JSONField(default=list, blank=True)
	scored_at = models.DateTimeField(null=True, blank=True)

	class Meta:
		indexes = [
			models.Index(fields=['target_domain', 'name'], name='sub_domain_name_idx'),
			models.Index(fields=['scan_history', 'name'], name='sub_scan_name_idx'),
			models.Index(fields=['target_domain', '-score'], name='sub_domain_score_idx'),
		]

	def __str__(self):
		return str(self.name)

	@property
	def get_endpoint_count(self):
		endpoints = EndPoint.objects.filter(subdomain__name=self.name, subdomain__target_domain_id=self.target_domain_id)
		if self.scan_history:
			endpoints = endpoints.filter(scan_history=self.scan_history)
		return endpoints.count()

	@property
	def get_info_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=0)
			.count()
		)

	@property
	def get_low_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=1)
			.count()
		)

	@property
	def get_medium_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=2)
			.count()
		)

	@property
	def get_high_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=3)
			.count()
		)

	@property
	def get_critical_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=4)
			.count()
		)

	@property
	def get_total_vulnerability_count(self):
		return self.get_vulnerabilities.count()

	@property
	def get_vulnerabilities(self):
		vulns = Vulnerability.objects.filter(subdomain__name=self.name, subdomain__target_domain_id=self.target_domain_id)
		if self.scan_history:
			vulns = vulns.filter(scan_history=self.scan_history)
		return vulns

	@property
	def get_vulnerabilities_without_info(self):
		vulns = Vulnerability.objects.filter(subdomain__name=self.name, subdomain__target_domain_id=self.target_domain_id).exclude(severity=0)
		if self.scan_history:
			vulns = vulns.filter(scan_history=self.scan_history)
		return vulns

	@property
	def get_directories_count(self):
		subdomains = (
			Subdomain.objects
			.filter(id=self.id)
		)
		dirscan = (
			DirectoryScan.objects
			.filter(directories__in=subdomains)
		)
		return (
			DirectoryFile.objects
			.filter(directory_files__in=dirscan)
			.distinct()
			.count()
		)

	@property
	def get_subscan_count(self):
		return (
			SubScan.objects
			.filter(subdomain__id=self.id)
			.distinct()
			.count()
		)


class SubScan(models.Model):
	id = models.AutoField(primary_key=True)
	type = models.CharField(max_length=100, blank=True, null=True)
	start_scan_date = models.DateTimeField()
	status = models.IntegerField()
	celery_ids = ArrayField(models.CharField(max_length=100), blank=True, default=list)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
	subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE)
	stop_scan_date = models.DateTimeField(null=True, blank=True)
	error_message = models.CharField(max_length=300, blank=True, null=True)
	engine = models.ForeignKey(EngineType, on_delete=models.CASCADE, blank=True, null=True)
	subdomain_subscan_ids = models.ManyToManyField('Subdomain', related_name='subdomain_subscan_ids', blank=True)

	def get_completed_ago(self):
		if self.stop_scan_date:
			return get_time_taken(timezone.now(), self.stop_scan_date)

	def get_total_time_taken(self):
		if self.stop_scan_date:
			return get_time_taken(self.stop_scan_date, self.start_scan_date)

	def get_elapsed_time(self):
		return get_time_taken(timezone.now(), self.start_scan_date)

	def get_task_name_str(self):
		taskmap = {
			'subdomain_discovery': 'Subdomain discovery',
			'dir_file_fuzz': 'Directory and File fuzzing',
			'port_scan': 'Port Scan',
			'fetch_url': 'Fetch URLs',
			'vulnerability_scan': 'Vulnerability Scan',
			'screenshot': 'Screenshot',
			'waf_detection': 'Waf Detection',
			'osint': 'Open-Source Intelligence'
		}
		return taskmap.get(self.type, 'Unknown')

class EndPoint(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	source = models.CharField(max_length=200, null=True, blank=True)
	http_url = models.CharField(max_length=30000)
	content_length = models.IntegerField(default=0, null=True, blank=True)
	page_title = models.CharField(max_length=30000, null=True, blank=True)
	http_status = models.IntegerField(default=0, null=True, blank=True)
	content_type = models.CharField(max_length=100, null=True, blank=True)
	discovered_date = models.DateTimeField(blank=True, null=True)
	response_time = models.FloatField(null=True, blank=True)
	webserver = models.CharField(max_length=1000, blank=True, null=True)
	is_default = models.BooleanField(null=True, blank=True, default=False)
	matched_gf_patterns = models.CharField(max_length=10000, null=True, blank=True)
	techs = models.ManyToManyField('Technology', related_name='techs', null=True, blank=True)
	# used for subscans
	endpoint_subscan_ids = models.ManyToManyField('SubScan', related_name='endpoint_subscan_ids', blank=True)

	def __str__(self):
		return self.http_url

	@hybrid_property
	def is_alive(self):
		return self.http_status and (0 < self.http_status < 500) and self.http_status != 404


class VulnerabilityTags(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name


class VulnerabilityReference(models.Model):
	id = models.AutoField(primary_key=True)
	url = models.CharField(max_length=5000)

	def __str__(self):
		return self.url


class CveId(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name


class CweId(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name


class Vulnerability(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	source = models.CharField(max_length=200, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	endpoint = models.ForeignKey(
		EndPoint,
		on_delete=models.CASCADE,
		blank=True,
		null=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	template = models.CharField(max_length=100, null=True, blank=True)
	template_url = models.CharField(max_length=2500, null=True, blank=True)
	template_id = models.CharField(max_length=200, null=True, blank=True)
	matcher_name = models.CharField(max_length=500, null=True, blank=True)
	name = models.CharField(max_length=2500)
	severity = models.IntegerField()
	description = models.TextField(null=True, blank=True)
	impact = models.TextField(null=True, blank=True)
	remediation = models.TextField(null=True, blank=True)

	extracted_results = ArrayField(
		models.CharField(max_length=5000), blank=True, null=True
	)

	tags = models.ManyToManyField('VulnerabilityTags', related_name='vuln_tags', blank=True)
	references = models.ManyToManyField('VulnerabilityReference', related_name='vuln_reference', blank=True)
	cve_ids = models.ManyToManyField('CveId', related_name='cve_ids', blank=True)
	cwe_ids = models.ManyToManyField('CweId', related_name='cwe_ids', blank=True)

	cvss_metrics = models.CharField(max_length=500, null=True, blank=True)
	cvss_score = models.FloatField(null=True, blank=True, default=None)
	curl_command = models.CharField(max_length=15000, null=True, blank=True)
	type = models.CharField(max_length=100, null=True, blank=True)
	http_url = models.CharField(max_length=10000, null=True)
	discovered_date = models.DateTimeField(null=True)
	open_status = models.BooleanField(null=True, blank=True, default=True)
	hackerone_report_id = models.CharField(max_length=50, null=True, blank=True)
	request = models.TextField(blank=True, null=True)
	response = models.TextField(blank=True, null=True)
	is_gpt_used = models.BooleanField(null=True, blank=True, default=False)
	# used for subscans
	vuln_subscan_ids = models.ManyToManyField('SubScan', related_name='vuln_subscan_ids', blank=True)

	# Remediation workflow, driven by people or agents through the API / MCP. Independent of open_status above, which
	# the scan pipeline alone manages: a finding a human marks accepted_risk stays open_status=True if the scanner still
	# sees it, but drops out of the actionable view regardless. Same fields and choices as cveFeed.models.CVEMatch's.
	REMEDIATION_STATUSES = ('open', 'in_progress', 'fixed', 'accepted_risk')
	remediation_status = models.CharField(max_length=16, default='open')
	remediation_note = models.TextField(blank=True, default='')
	remediation_updated_at = models.DateTimeField(null=True, blank=True)
	remediation_by = models.ForeignKey(
		'auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
	# Who owns triaging this finding. Independent of remediation_by (who last changed the status); set through the same
	# API/MCP surface. Same field on cveFeed.models.CVEMatch and HygieneFinding.
	assignee = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')

	class Meta:
		indexes = [
			models.Index(fields=['subdomain', 'open_status', 'severity'], name='vuln_sub_open_sev_idx'),
			models.Index(fields=['scan_history', 'name'], name='vuln_scan_name_idx'),
		]
		constraints = [
			# one row per finding (see save_vulnerability); md5 keeps long names and URLs inside the btree row limit
			models.UniqueConstraint(
				*[Coalesce(name, Value(0), output_field=models.IntegerField()) for name in (
					'target_domain', 'scan_history', 'subdomain', 'endpoint')],
				Coalesce('source', Value('')), Coalesce('template_id', Value('')), Coalesce('matcher_name', Value('')),
				Md5('name'), Md5(Coalesce('http_url', Value(''))),
				name='uniq_vulnerability_finding'),
		]

	def __str__(self):
		cve_str = ', '.join(f'`{cve.name}`' for cve in self.cve_ids.all())
		severity = NUCLEI_REVERSE_SEVERITY_MAP[self.severity]
		return f'{self.http_url} | `{severity.upper()}` | `{self.name}` | `{cve_str}`'

	def get_severity(self):
		return self.severity

	def get_cve_str(self):
		return ', '.join(f'`{cve.name}`' for cve in self.cve_ids.all())

	def get_cwe_str(self):
		return ', '.join(f'`{cwe.name}`' for cwe in self.cwe_ids.all())

	def get_tags_str(self):
		return ', '.join(f'`{tag.name}`' for tag in self.tags.all())

	def get_refs_str(self):
		return '•' + '\n• '.join(f'`{ref.url}`' for ref in self.references.all())

	def get_path(self):
		return urlparse(self.http_url).path


class ScanActivity(models.Model):
	id = models.AutoField(primary_key=True)
	scan_of = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, blank=True, null=True)
	title = models.CharField(max_length=1000)
	name = models.CharField(max_length=1000)
	time = models.DateTimeField()
	status = models.IntegerField()
	error_message = models.CharField(max_length=300, blank=True, null=True)
	traceback = models.TextField(blank=True, null=True)
	celery_id = models.CharField(max_length=100, blank=True, null=True)

	def __str__(self):
		return str(self.title)


class Command(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, blank=True, null=True)
	activity = models.ForeignKey(ScanActivity, on_delete=models.CASCADE, blank=True, null=True)
	command = models.TextField(blank=True, null=True)
	return_code = models.IntegerField(blank=True, null=True)
	output = models.TextField(blank=True, null=True)
	time = models.DateTimeField()

	def __str__(self):
		return str(self.command)


class Waf(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	manufacturer = models.CharField(max_length=500, blank=True, null=True)

	def __str__(self):
		return str(self.name)


class Technology(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, blank=True, null=True, db_index=True)  # "Name" or "Name:version"
	# Both follow from the name and are kept in step by save(), so the database can filter on them.
	version = models.CharField(max_length=200, blank=True, default='')
	category = models.CharField(max_length=40, blank=True, default='', db_index=True)  # 'web server', 'language', 'cms', ...

	def save(self, *args, **kwargs):
		from cveFeed.correlation import split_name_version
		from cveFeed.fingerprint import categorize
		_base, self.version = split_name_version(self.name or '')
		self.category = categorize(self.name or '')
		fields = kwargs.get('update_fields')
		if fields is not None:
			kwargs['update_fields'] = {*fields, 'version', 'category'}
		super().save(*args, **kwargs)

	def __str__(self):
		return str(self.name)


class CountryISO(models.Model):
	id = models.AutoField(primary_key=True)
	iso = models.CharField(max_length=10, blank=True)
	name = models.CharField(max_length=100, blank=True)

	def __str__(self):
		return str(self.name)


class IpAddress(models.Model):
	id = models.AutoField(primary_key=True)
	org = models.ForeignKey('dashboard.Org', on_delete=models.CASCADE, null=True, blank=True, related_name='+', editable=False)
	address = models.CharField(max_length=100, blank=True, null=True)
	is_cdn = models.BooleanField(default=False)
	ports = models.ManyToManyField('Port', related_name='ports')
	geo_iso = models.ForeignKey(
		CountryISO, on_delete=models.CASCADE, null=True, blank=True)
	version = models.IntegerField(blank=True, null=True)
	is_private = models.BooleanField(default=False)  # not an address of the public internet (targetApp.target_types.is_public_address)
	reverse_pointer = models.CharField(max_length=100, blank=True, null=True)
	# Host-level OS fingerprint (nmap -O).
	os_guess = models.CharField(max_length=255, blank=True, default='')
	os_accuracy = models.IntegerField(null=True, blank=True)
	last_seen = models.DateTimeField(null=True, blank=True)
	# what the host-level NSE scripts (smb-os-discovery, nbstat) reported: {'scripts': {script id: output text}}
	fingerprint = models.JSONField(default=dict, blank=True)
	# the background full-port sweep (cveFeed.fullscan): when this IP was last swept (never, while null) and how many ports it had open
	full_scanned_at = models.DateTimeField(null=True, blank=True, db_index=True)
	full_scan_ports = models.IntegerField(default=0)
	full_scan_started_at = models.DateTimeField(null=True, blank=True, db_index=True)  # a sweep is in flight; cleared-by-advance once full_scanned_at passes it
	full_scan_failures = models.PositiveSmallIntegerField(default=0)  # consecutive failed sweeps (cveFeed.fullscan backs off)
	full_scan_retry_at = models.DateTimeField(null=True, blank=True, db_index=True)  # not picked again before this
	# this is used for querying which ip was discovered during subcan
	ip_subscan_ids = models.ManyToManyField('SubScan', related_name='ip_subscan_ids')

	class Meta:
		# one row per address per organization: banners and service data of one organization are never another's
		constraints = [
			models.UniqueConstraint(fields=['org', 'address'], condition=models.Q(org__isnull=False) & models.Q(address__isnull=False) & ~models.Q(address=''),
									name='uniq_ipaddress_org_address'),
			models.UniqueConstraint(fields=['address'], condition=models.Q(org__isnull=True) & models.Q(address__isnull=False) & ~models.Q(address=''),
									name='uniq_ipaddress_noorg_address'),
		]

	def __str__(self):
		return str(self.address)


OPEN_PORT_STATES = ('', 'open')
TCP_PROTOCOLS = ('', 'tcp')  # a row written before the protocol column was filled in is TCP
OPEN_FILTERED = 'open|filtered'  # a UDP port nothing answered on: open, or dropped by a firewall. Not open, so never in OPEN_PORT_STATES


def open_services(ip):
	"""The ports of an IpAddress that answered, over any protocol: nmap also reports filtered and closed ones, a UDP port that did
	not answer is ``open|filtered`` (it may be open or dropped), and a port that closed since the last scan keeps its row (state
	'closed'). What the host runs and exposes (evidence, CVE matching, the host page, counts) reads this. Reads through
	``ip.ports.all()`` so a prefetch is used."""
	return [p for p in ip.ports.all() if p.state in OPEN_PORT_STATES]


def open_ports(ip):
	"""The open TCP ports of an IpAddress. Every consumer that connects to a port (nuclei, the database and RDP checks, TLS) reads
	this, never ``ip.ports``: a UDP service answers no TCP connection, and UDP 161 is not TCP 161. A UDP port that answered is in
	``open_services``."""
	return [p for p in open_services(ip) if p.protocol in TCP_PROTOCOLS]


class Port(models.Model):
	id = models.AutoField(primary_key=True)
	number = models.IntegerField(default=0)
	service_name = models.CharField(max_length=100, blank=True, null=True)
	description = models.CharField(max_length=1000, blank=True, null=True)
	is_uncommon = models.BooleanField(default=False)
	# Shodan-style service enrichment (nmap -sV and service probes).
	protocol = models.CharField(max_length=8, blank=True, default='tcp')
	state = models.CharField(max_length=16, blank=True, default='open')
	product = models.CharField(max_length=255, blank=True, default='')
	version = models.CharField(max_length=100, blank=True, default='')
	service_extra = models.CharField(max_length=255, blank=True, default='')
	cpe = models.CharField(max_length=255, blank=True, default='')
	os_guess = models.CharField(max_length=255, blank=True, default='')
	# The distribution behind the service, read from the banner (cveFeed.distro.parse_distro): a distro patches without changing
	# the upstream version, so a match is judged against the distro's own fixed version.
	distro = models.CharField(max_length=16, blank=True, default='')  # ubuntu | debian | rhel | centos | alpine
	distro_release = models.CharField(max_length=16, blank=True, default='')  # 22.04, 12, 9
	package_release = models.CharField(max_length=64, blank=True, default='')  # dpkg/rpm version as observed: 1:8.9p1-3ubuntu0.6
	upstream_version = models.CharField(max_length=64, blank=True, default='')  # 8.9p1
	# Raw capture of whatever the probe returned, Shodan-style: the banner
	# (SSH/SMTP/... response text), HTTP metadata, TLS cert, and anything else.
	banner = models.TextField(blank=True, default='')
	http = models.JSONField(default=dict, blank=True)
	tls = models.JSONField(default=dict, blank=True)
	extra = models.JSONField(default=dict, blank=True)
	source = models.CharField(max_length=32, blank=True, default='')
	last_seen = models.DateTimeField(null=True, blank=True)

	def __str__(self):
		return str(self.service_name)


class DirectoryFile(models.Model):
	id = models.AutoField(primary_key=True)
	length = models.IntegerField(default=0)
	lines = models.IntegerField(default=0)
	http_status = models.IntegerField(default=0)
	words = models.IntegerField(default=0)
	name = models.CharField(max_length=500, blank=True, null=True)
	url = models.CharField(max_length=5000, blank=True, null=True)
	content_type = models.CharField(max_length=100, blank=True, null=True)

	def __str__(self):
		return str(self.name)


class DirectoryScan(models.Model):
	id = models.AutoField(primary_key=True)
	command_line = models.CharField(max_length=5000, blank=True, null=True)
	directory_files = models.ManyToManyField('DirectoryFile', related_name='directory_files', blank=True)
	scanned_date = models.DateTimeField(null=True)
	# this is used for querying which ip was discovered during subcan
	dir_subscan_ids = models.ManyToManyField('SubScan', related_name='dir_subscan_ids', blank=True)


class MetaFinderDocument(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	doc_name = models.CharField(max_length=1000, null=True, blank=True)
	url = models.CharField(max_length=10000, null=True, blank=True)
	title = models.CharField(max_length=1000, null=True, blank=True)
	author = models.CharField(max_length=1000, null=True, blank=True)
	producer = models.CharField(max_length=1000, null=True, blank=True)
	creator = models.CharField(max_length=1000, null=True, blank=True)
	os = models.CharField(max_length=1000, null=True, blank=True)
	http_status = models.IntegerField(default=0, null=True, blank=True)
	creation_date = models.CharField(max_length=1000, blank=True, null=True)
	modified_date = models.CharField(max_length=1000, blank=True, null=True)


class Email(models.Model):
	id = models.AutoField(primary_key=True)
	address = models.CharField(max_length=200, blank=True, null=True)
	password = models.CharField(max_length=200, blank=True, null=True)

class Employee(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=1000, null=True, blank=True)
	designation = models.CharField(max_length=1000, null=True, blank=True)


class Dork(models.Model):
	id = models.AutoField(primary_key=True)
	type = models.CharField(max_length=500, null=True, blank=True)
	url = models.CharField(max_length=10000, null=True, blank=True)
