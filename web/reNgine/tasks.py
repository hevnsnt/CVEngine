import json
import os
import subprocess
import validators

from urllib.parse import urlparse
from celery.utils.log import get_task_logger
from django.db import IntegrityError
from dotted_dict import DottedDict
from django.utils import timezone
from django.shortcuts import get_object_or_404

from reNgine.celery import app
from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.settings import *
from reNgine.utilities import *
from scanEngine.models import (EngineType, InstalledExternalTool, Notification)
from startScan.models import *
from startScan.ip_rows import get_or_create_first, get_or_create_ip, org_id_of_project, org_id_of_subdomain
from startScan.models import EndPoint, Subdomain, Vulnerability
from targetApp.models import Domain
from cveFeed import versions

"""
Celery tasks.
"""

logger = get_task_logger(__name__)


#------------------------- #
# Tracked reNgine tasks    #
#--------------------------#


def persist_bbot_result(result, ctx):
	"""Write a BbotResult to the DB as Subdomain / IpAddress / Port rows."""
	own_name = own_project = None  # the target this batch belongs to: only it can carry a tailnet device's address
	if ctx.get('scan_history_id'):  # the organization's excluded hosts, read once for the whole batch
		from cveFeed.exclusions import excluded_names
		scan = ScanHistory.objects.select_related('domain').filter(pk=ctx['scan_history_id']).first()
		own_project, own_name = (scan.domain.project_id, scan.domain.name) if scan and scan.domain else (None, None)
		project_id = own_project
		ctx = {**ctx, '_excluded_hosts': excluded_names(project_id), '_org_id': org_id_of_project(project_id), '_scan': scan}  # read once per batch, not per name
		if ctx.get('domain_id'):
			ctx['_domain'] = Domain.objects.filter(id=ctx['domain_id']).first()
	subdomains = {}
	for name in result.subdomains:
		subdomain, _ = save_subdomain(name, ctx=ctx)
		if subdomain:
			subdomains[name] = subdomain
	for name, address in result.resolutions:
		if name in subdomains:
			save_ip_address(address, subdomain=subdomains[name], org_id=ctx.get('_org_id'), project_id=own_project if name == own_name else None)
	banned = ctx.get('_excluded_hosts') or ()
	for host, port_number in result.ports:
		if banned and host.strip().lower().rstrip('.') in banned:
			continue
		subdomain = subdomains.get(host)
		if subdomain is None and ctx.get('scan_history_id'):  # found in an earlier streaming batch
			subdomain = Subdomain.objects.filter(scan_history_id=ctx['scan_history_id'], name=host).first()
		ip = None
		if validators.ipv4(host) or validators.ipv6(host):
			ip, _ = save_ip_address(host, subdomain=None, org_id=ctx.get('_org_id'), project_id=own_project if host == own_name else None)
		elif subdomain:
			ip = subdomain.ip_addresses.first()
		if not ip:
			continue
		res = get_port_service_description(port_number)
		port, _ = update_or_create_port(
			port_number=port_number,
			service_name=res.get('service_name', ''),
			description=res.get('description', ''),
			ip=ip)
		port.source = 'bbot'
		port.last_seen = timezone.now()
		port.save()
		ip.ports.add(port)
	for host, tech_name in result.technologies:
		if not tech_name:
			continue
		subdomain = subdomains.get(host)
		if subdomain is None and ctx.get('scan_history_id'):  # found in an earlier streaming batch
			subdomain = Subdomain.objects.filter(scan_history_id=ctx['scan_history_id'], name=host).first()
		if not subdomain:
			continue
		tech_name = versions.normalize_technology(tech_name)  # a CPE or a "v3.3.7" would otherwise store a name no advisory matches
		if not tech_name:
			continue
		tech, _ = get_or_create_first(Technology, name=tech_name[:500])
		subdomain.technologies.add(tech)
	_persist_bbot_findings(result, ctx, subdomains)
	_persist_bbot_urls(result, ctx, subdomains)
	_persist_bbot_http(result, ctx, subdomains)


MAX_BBOT_URLS_PER_SCAN = 2000
MAX_URL_LENGTH = 2000


def _persist_bbot_urls(result, ctx, subdomains):
	"""bbot URL events become EndPoint rows (source 'bbot') on their host, capped per scan. The root URL of a host also
	fills Subdomain.http_url / http_status when the host has none, so the Hosts page has a real HTTP status."""
	if not (result.urls and ctx.get('scan_history_id') and ctx.get('domain_id')):
		return
	scan_id = ctx['scan_history_id']
	room = MAX_BBOT_URLS_PER_SCAN - EndPoint.objects.filter(scan_history_id=scan_id).count()
	if room <= 0:
		return
	wanted = sorted({u for u, _ in result.urls if len(u) <= MAX_URL_LENGTH})
	existing = set(EndPoint.objects.filter(scan_history_id=scan_id, http_url__in=wanted).values_list('http_url', flat=True))
	hosts = {}
	rows = []
	for url, status in sorted(result.urls):
		if url in existing or len(url) > MAX_URL_LENGTH or len(rows) >= room:
			continue
		host = (urlparse(url).hostname or '').lower()
		if host not in hosts:
			hosts[host] = subdomains.get(host) or Subdomain.objects.filter(scan_history_id=scan_id, name=host).first()
		sub = hosts[host]
		if not sub:
			continue
		existing.add(url)
		rows.append(EndPoint(scan_history_id=scan_id, target_domain_id=ctx['domain_id'], subdomain=sub, http_url=url,
			http_status=status, source='bbot', discovered_date=timezone.now()))
		if urlparse(url).path in ('', '/') and not sub.http_url:
			sub.http_url = url
			if status:
				sub.http_status = status
			sub.save(update_fields=['http_url', 'http_status'])
	EndPoint.objects.bulk_create(rows)


def _persist_bbot_http(result, ctx, subdomains):
	"""bbot HTTP_RESPONSE events (httpx ran inside bbot, so this costs no extra scanning) fill what the host page shows: the root
	answer's status, title and Server header on the Subdomain, and the response summary on the Port it came from. An answer proves
	the port is open, so a port bbot did not list is added, for the first address of the host only (the answer does not say which
	address gave it). A non-root answer fills a host's fields only while they are still empty."""
	if not result.http:
		return
	scan_id = ctx.get('scan_history_id')
	cache = {}
	for rec in result.http:
		host = rec['host']
		if host not in cache:
			cache[host] = subdomains.get(host) or (Subdomain.objects.filter(scan_history_id=scan_id, name=host).first() if scan_id else None)
		sub = cache[host]
		if not sub:
			continue
		root = urlparse(rec['url']).path in ('', '/')
		fields = []
		if rec['status'] and (root or not sub.http_status):
			sub.http_status = rec['status']
			fields.append('http_status')
			if rec['title'] and (root or not sub.page_title):
				sub.page_title = rec['title']
				fields.append('page_title')
			if rec['webserver'] and (root or not sub.webserver):
				sub.webserver = rec['webserver']
				fields.append('webserver')
		if fields:
			sub.save(update_fields=fields)
		if not rec['port']:
			continue
		summary = {k: rec[k] for k in ('url', 'status', 'title', 'webserver', 'content_type', 'location') if rec[k]}
		ips = list(sub.ip_addresses.all())
		ports = [p for ip in ips for p in ip.ports.filter(number=rec['port'], protocol__in=('', 'tcp'))]
		if not ports and ips:
			port, _ = update_or_create_port(port_number=rec['port'], service_name='https' if rec['url'].startswith('https') else 'http',
				description='', ip=ips[0])
			port.source, port.last_seen = 'bbot', timezone.now()
			ips[0].ports.add(port)
			ports = [port]
		for port in ports:
			if root or not port.http:
				port.http = summary
				port.save()


def _persist_bbot_findings(result, ctx, subdomains):
	"""bbot FINDING / VULNERABILITY events become scanner findings (source 'bbot') on their host."""
	if not ctx.get('scan_history_id') or not ctx.get('domain_id'):
		return
	scan = ScanHistory.objects.filter(pk=ctx['scan_history_id']).first()
	domain = Domain.objects.filter(pk=ctx['domain_id']).first()
	if not (scan and domain):
		return
	from cveFeed.labels import record_label
	from reNgine.bbot import finding_key, label_for
	from cveFeed.exclusions import excluded_names, normalize
	banned = ctx.get('_excluded_hosts')
	if banned is None:
		banned = excluded_names(domain.project_id)
	for f in result.findings:
		if banned and normalize(f['host']) in banned:  # nothing is recorded for a host the organization excluded for good
			continue
		if f.get('informational'):
			# a pure detection ("WAF Detection", "Nginx version detect") is a chip on the host, not a finding (see reNgine.bbot)
			record_label(domain.project_id, domain.id, f['host'], label_for(f['name']), detail=f['description'])
			continue
		sub = subdomains.get(f['host']) or Subdomain.objects.filter(scan_history=scan, name=f['host']).first()
		save_vulnerability(
			target_domain=domain, scan_history=scan, subdomain=sub, http_url=f['url'] or f['host'], name=f['name'],
			severity=f['severity'], description=f['description'], source='bbot', type='bbot', template_id=f['module'],
			matcher_name=finding_key(f['description']),
			request=f"bbot {f['module']} event on {f['host']}" + (f" at {f['url']}" if f['url'] else ''),
			extracted_results=[x[:5000] for x in (f['host'], f['url']) if x])


	# with open(self.output_path, 'w') as f:
	# 	json.dump(results, f, indent=4)
	#
	# return results


#---------------------#
# Notifications tasks #
#---------------------#

@app.task(name='send_notif', bind=False, queue='send_notif_queue')
def send_notif(
		message,
		scan_history_id=None,
		subscan_id=None,
		**options):
	if not 'title' in options:
		message = enrich_notification(message, scan_history_id, subscan_id)
	send_discord_message(message, **options)
	send_slack_message(message)
	send_lark_message(message)
	send_telegram_message(message)


	


@app.task(name='send_task_notif', bind=False, queue='send_task_notif_queue')
def send_task_notif(
		task_name,
		status=None,
		result=None,
		output_path=None,
		traceback=None,
		scan_history_id=None,
		engine_id=None,
		subscan_id=None,
		severity=None,
		add_meta_info=True,
		update_fields={}):
	"""Send task status notification.

	Args:
		task_name (str): Task name.
		status (str, optional): Task status.
		result (str, optional): Task result.
		output_path (str, optional): Task output path.
		traceback (str, optional): Task traceback.
		scan_history_id (int, optional): ScanHistory id.
		subscan_id (int, optional): SuScan id.
		engine_id (int, optional): EngineType id.
		severity (str, optional): Severity (will be mapped to notif colors)
		add_meta_info (bool, optional): Wheter to add scan / subscan info to notif.
		update_fields (dict, optional): Fields key / value to update.
	"""

	# Skip send if notification settings are not configured
	notif = Notification.objects.first()
	if not (notif and notif.send_scan_status_notif):
		return

	# Build fields
	url = None
	fields = {}
	if add_meta_info:
		engine = EngineType.objects.filter(pk=engine_id).first()
		scan = ScanHistory.objects.filter(pk=scan_history_id).first()
		subscan = SubScan.objects.filter(pk=subscan_id).first()
		url = get_scan_url(scan_history_id)
		if status:
			fields['Status'] = f'**{status}**'
		if engine:
			fields['Engine'] = engine.engine_name
		if scan:
			fields['Scan ID'] = f'[#{scan.id}]({url})'
		if subscan:
			url = get_scan_url(scan_history_id, subscan_id)
			fields['Subscan ID'] = f'[#{subscan.id}]({url})'
	title = get_task_title(task_name, scan_history_id, subscan_id)
	if status:
		severity = STATUS_TO_SEVERITIES.get(status)

	msg = f'{title} {status}\n'
	msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())

	# Add fields to update
	for k, v in update_fields.items():
		fields[k] = v

	# Add traceback to notif
	if traceback and notif.send_scan_tracebacks:
		fields['Traceback'] = f'```\n{traceback}\n```'

	# Add files to notif
	files = []
	attach_file = (
		notif.send_scan_output_file and
		output_path and
		result and
		not traceback
	)
	if attach_file:
		output_title = output_path.split('/')[-1]
		files = [(output_path, output_title)]

	# Send notif
	opts = {
		'title': title,
		'url': url,
		'files': files,
		'severity': severity,
		'fields': fields,
		'fields_append': update_fields.keys()
	}
	send_notif(
		msg,
		scan_history_id=scan_history_id,
		subscan_id=subscan_id,
		**opts)


#-------------#
# Utils tasks #
#-------------#


def parse_nuclei_result(line):
	"""Parse results from nuclei JSON output.

	Args:
		line (dict): Nuclei JSON line output.

	Returns:
		dict: Vulnerability data.
	"""
	return {
		'name': line['info'].get('name', ''),
		'type': line['type'],
		'severity': NUCLEI_SEVERITY_MAP[line['info'].get('severity', 'unknown')],
		'template': line['template'],
		'template_url': line.get('template-url', []),
		'template_id': line['template-id'],
		'description': line['info'].get('description', ''),
		'matcher_name': line.get('matcher-name', ''),
		'curl_command': line.get('curl-command'),
		'request': line.get('request'),
		'response': line.get('response'),
		'extracted_results': line.get('extracted-results', []),
		'cvss_metrics': line['info'].get('classification', {}).get('cvss-metrics', ''),
		'cvss_score': line['info'].get('classification', {}).get('cvss-score'),
		'cve_ids': line['info'].get('classification', {}).get('cve_id', []) or [],
		'cwe_ids': line['info'].get('classification', {}).get('cwe_id', []) or [],
		'references': line['info'].get('reference', []) or [],
		'tags': line['info'].get('tags', []),
		'source': NUCLEI,
	}


@app.task(name='geo_localize', bind=False, queue='geo_localize_queue')
def geo_localize(host, ip_id=None):
	"""Uses geoiplookup to find location associated with host.

	Args:
		host (str): Hostname.
		ip_id (int): IpAddress object id.

	Returns:
		startScan.models.CountryISO: CountryISO object from DB or None.
	"""
	if validators.ipv6(host):
		logger.info(f'Ipv6 "{host}" is not supported by geoiplookup. Skipping.')
		return None
	cmd = f'geoiplookup {host}'
	_, out = run_command(cmd)
	if 'IP Address not found' not in out and "can't resolve hostname" not in out:
		country_iso = out.split(':')[1].strip().split(',')[0]
		country_name = out.split(':')[1].strip().split(',')[1].strip()
		geo_object, _ = CountryISO.objects.get_or_create(
			iso=country_iso,
			name=country_name
		)
		geo_json = {
			'iso': country_iso,
			'name': country_name
		}
		if ip_id:
			ip = IpAddress.objects.get(pk=ip_id)
			ip.geo_iso = geo_object
			ip.save()
		return geo_json
	logger.info(f'Geo IP lookup failed for host "{host}"')
	return None


@app.task(name='run_command', bind=False, queue='run_command_queue')
def run_command(
		cmd, 
		cwd=None, 
		shell=False, 
		history_file=None, 
		scan_id=None, 
		activity_id=None,
		remove_ansi_sequence=False,
		redact=()
	):
	"""Run a given command using subprocess module.

	Args:
		cmd (str): Command to run.
		cwd (str): Current working directory.
		echo (bool): Log command.
		shell (bool): Run within separate shell if True.
		history_file (str): Write command + output to history file.
		remove_ansi_sequence (bool): Used to remove ANSI escape sequences from output such as color coding
		redact (tuple): Secrets (API keys) on the command line; they run, but the log, the Command row and the history file show ***.
	Returns:
		tuple: Tuple with return_code, output.
	"""
	shown = cmd
	for secret in redact:
		if secret:
			shown = shown.replace(secret, '***')
	logger.info(shown)
	logger.warning(activity_id)

	# Create a command record in the database
	command_obj = Command.objects.create(
		command=shown,
		time=timezone.now(),
		scan_history_id=scan_id,
		activity_id=activity_id)
	from reNgine.resources import ScanAborted, global_pause_requested
	if global_pause_requested(fail_closed=True):
		raise ScanAborted('global scanning pause is active')

	# Run the command using subprocess
	popen = subprocess.Popen(
		cmd if shell else cmd.split(),
		shell=shell,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		cwd=cwd,
		universal_newlines=True,
		start_new_session=True)
	from reNgine.resources import LegacyProcessMonitor
	monitor = LegacyProcessMonitor(popen, scan_id)
	output = ''
	for stdout_line in iter(popen.stdout.readline, ""):
		item = stdout_line.strip()
		output += '\n' + item
		logger.debug(item)
	popen.stdout.close()
	popen.wait()
	monitor.close()
	return_code = popen.returncode
	command_obj.output = output
	command_obj.return_code = return_code
	command_obj.save()
	if history_file:
		mode = 'a'
		if not os.path.exists(history_file):
			mode = 'w'
		with open(history_file, mode) as f:
			f.write(f'\n{shown}\n{return_code}\n{output}\n------------------\n')
	if remove_ansi_sequence:
		output = remove_ansi_escape_sequences(output)
	monitor.raise_if_aborted()
	return return_code, output


#-------------#
# Other utils #
#-------------#


#-------------#
# OSInt utils #
#-------------#


#-----------------#
# Utils functions #
#-----------------#

def create_scan_activity(scan_history_id, message, status):
	scan_activity = ScanActivity()
	scan_activity.scan_of = ScanHistory.objects.get(pk=scan_history_id)
	scan_activity.title = message
	scan_activity.time = timezone.now()
	scan_activity.status = status
	scan_activity.save()
	return scan_activity.id


#--------------------#
# Database functions #
#--------------------#


VULNERABILITY_KEY = ('target_domain', 'scan_history', 'subdomain', 'endpoint', 'source', 'template_id', 'name', 'http_url',
					 'matcher_name')


def _carry_finding_state(vuln, lookup):
	"""A finding seen again on a later scan is a new row (rows are per scan); give it the remediation state a person set on the same
	finding (same host, template, name, URL and matcher) in an earlier scan, so what was marked fixed or accepted does not reopen."""
	subdomain, domain = lookup.get('subdomain'), lookup.get('target_domain')
	if subdomain is None or domain is None:
		return
	same = {k: lookup[k] for k in ('source', 'template_id', 'name', 'http_url', 'matcher_name') if k in lookup}
	earlier = (Vulnerability._base_manager.filter(target_domain=domain, subdomain__name=subdomain.name, **same)
			   .exclude(pk=vuln.pk).exclude(remediation_status='open').order_by('-id').first())
	if earlier is not None:
		vuln.remediation_status, vuln.remediation_note = earlier.remediation_status, earlier.remediation_note
		vuln.remediation_updated_at, vuln.remediation_by_id, vuln.assignee_id = (
			earlier.remediation_updated_at, earlier.remediation_by_id, earlier.assignee_id)


def _reference(url):
	"""The stored VulnerabilityReference of ``url``: the first when duplicate rows exist (``url`` is not unique), made when there is none."""
	return VulnerabilityReference.objects.filter(url=url).order_by('id').first() or VulnerabilityReference.objects.create(url=url)


def save_vulnerability(**vuln_data):
	references = vuln_data.pop('references', [])
	cve_ids = vuln_data.pop('cve_ids', [])
	cwe_ids = vuln_data.pop('cwe_ids', [])
	tags = vuln_data.pop('tags', [])
	subscan = vuln_data.pop('subscan', None)

	# remove nulls
	vuln_data = replace_nulls(vuln_data)

	# One row per finding: the key is where and what (host, template, name, URL, matcher), never the response body, which
	# differs on every request (a Date: header, a nonce) and would create a new row each time the finding is seen again.
	lookup = {k: vuln_data[k] for k in VULNERABILITY_KEY if k in vuln_data}
	defaults = {k: v for k, v in vuln_data.items() if k not in lookup}
	defaults.setdefault('discovered_date', timezone.now())
	try:
		vuln, created = Vulnerability.objects.get_or_create(**lookup, defaults=defaults)
	except (Vulnerability.MultipleObjectsReturned, IntegrityError):
		vuln, created = Vulnerability.objects.filter(**lookup).order_by('id').first(), False
	was_created = created
	if created:
		vuln.discovered_date = timezone.now()
		vuln.open_status = True
		_carry_finding_state(vuln, lookup)
		vuln.save()
	else:
		# seen again: keep the newest evidence, and it is evidently still there
		changed = [k for k, v in defaults.items() if k != 'discovered_date' and getattr(vuln, k) != v]
		for k in changed:
			setattr(vuln, k, defaults[k])
		if not vuln.open_status:
			vuln.open_status = True
			changed.append('open_status')
		if changed:
			vuln.save(update_fields=changed)

	# Save vuln tags
	for tag_name in tags or []:
		tag, _ = VulnerabilityTags.objects.get_or_create(name=tag_name)
		if tag:
			vuln.tags.add(tag)
			vuln.save()

	# Save CVEs
	for cve_id in cve_ids or []:
		cve, _ = CveId.objects.get_or_create(name=cve_id)
		if cve:
			vuln.cve_ids.add(cve)
			vuln.save()

	# Save CWEs
	for cve_id in cwe_ids or []:
		cwe, _ = CweId.objects.get_or_create(name=cve_id)
		if cwe:
			vuln.cwe_ids.add(cwe)
			vuln.save()

	# Save vuln reference
	for url in references or []:
		vuln.references.add(_reference(url))  # the table is shared and url is not unique: every finding that cites it links it
		vuln.save()

	# Save subscan id in vuln object
	if subscan:
		vuln.vuln_subscan_ids.add(subscan)
		vuln.save()

	return vuln, was_created


def save_subdomain(subdomain_name, ctx={}):
	"""Get or create Subdomain object.

	Args:
		subdomain_name (str): Subdomain name.
		scan_history (startScan.models.ScanHistory): ScanHistory object.

	Returns:
		tuple: (startScan.models.Subdomain, created) where `created` is a
			boolean indicating if the object has been created in DB.
	"""
	scan_id = ctx.get('scan_history_id')
	subscan_id = ctx.get('subscan_id')
	out_of_scope_subdomains = ctx.get('out_of_scope_subdomains', [])
	subdomain_checker = SubdomainScopeChecker(out_of_scope_subdomains)
	valid_domain = (
		validators.domain(subdomain_name) or
		validators.ipv4(subdomain_name) or
		validators.ipv6(subdomain_name)
	)
	if not valid_domain:
		logger.error(f'{subdomain_name} is not an invalid domain. Skipping.')
		return None, False

	if subdomain_checker.is_out_of_scope(subdomain_name):
		logger.error(f'{subdomain_name} is out-of-scope. Skipping.')
		return None, False

	if ctx.get('domain_id'):
		domain = ctx.get('_domain') or Domain.objects.get(id=ctx.get('domain_id'))
		if subdomain_name != domain.name and not subdomain_name.endswith('.' + domain.name):  # dot boundary: example.com.evil.net is not in scope
			logger.error(f"{subdomain_name} is not a subdomain of domain {domain.name}. Skipping.")
			return None, False

	scan = ctx.get('_scan')
	if scan is None or str(scan.pk) != str(scan_id):
		scan = ScanHistory.objects.select_related('domain').filter(pk=scan_id).first()
	domain = scan.domain if scan else None
	if domain is not None:
		from cveFeed.exclusions import excluded_names, normalize
		banned = ctx.get('_excluded_hosts')  # persist_bbot_result reads the list once for a whole batch
		if banned is None:
			banned = excluded_names(domain.project_id)
		if normalize(subdomain_name) in banned:  # the organization excluded this exact host for good
			logger.info(f'{subdomain_name} is excluded for this organization. Skipping.')
			return None, False
	subdomain, created = get_or_create_first(
		Subdomain,
		scan_history=scan,
		target_domain=domain,
		name=subdomain_name)
	if created:
		# logger.warning(f'Found new subdomain {subdomain_name}')
		subdomain.discovered_date = timezone.now()
		if subscan_id:
			subdomain.subdomain_subscan_ids.add(subscan_id)
		subdomain.save()
	return subdomain, created


def save_ip_address(ip_address, subdomain=None, subscan=None, org_id=None, project_id=None, **kwargs):
	"""Store one address (and attach it to ``subdomain``). ``project_id`` may authorise a tailnet device of that project, and only when
	the host IS that address (``subdomain`` named by it, or no subdomain because the host is the address itself)."""
	if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
		logger.info(f'IP {ip_address} is not a valid IP. Skipping.')
		return None, False
	from targetApp.target_types import in_internal_range, internal_networks, is_scannable_ip
	own = project_id if subdomain is None or str(subdomain.name) == ip_address else None
	# a tailnet device's own address is allowed on the host named by that address; an address a name resolved to never is. Likewise an
	# address of a network the project declared internal: storing it is only data, and no local scanner is ever aimed at it (they all re-check)
	if not is_scannable_ip(ip_address, project=own) and not (own and in_internal_range(ip_address, internal_networks(own))):
		# a hostname the target controls can resolve anywhere; never store (and so never scan) internal addresses
		logger.warning(f'IP {ip_address} is loopback, link-local or internal. Skipping.')
		return None, False
	if org_id is None and subdomain is not None:  # the organization of the host the address was found for
		org_id = org_id_of_subdomain(subdomain)
	ip, created = get_or_create_ip(ip_address, org_id)
	# if created:
	# 	logger.warning(f'Found new IP {ip_address}')

	# Set extra attributes
	for key, value in kwargs.items():
		setattr(ip, key, value)
	ip.save()

	# Add IP to subdomain
	if subdomain:
		subdomain.ip_addresses.add(ip)
		subdomain.save()

	# Add subscan to IP
	if subscan:
		ip.ip_subscan_ids.add(subscan)

	# Geo-localize IP asynchronously
	if created:
		geo_localize.delay(ip_address, ip.id)

	return ip, created
