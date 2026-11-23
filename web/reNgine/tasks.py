import json
import os
import re
import validators

from urllib.parse import urlparse
from celery.utils.log import get_task_logger
from django.db import IntegrityError, transaction
from dotted_dict import DottedDict
from django.utils import timezone
from django.shortcuts import get_object_or_404

from reNgine.celery import app
from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.settings import *
from reNgine.utilities import *
from scanEngine.models import (EngineType, Notification)
from startScan.models import *
from startScan.ip_rows import get_or_create_first, get_or_create_ip, org_id_of_project, org_id_of_subdomain
from startScan.models import EndPoint, Subdomain, Vulnerability
from targetApp.models import Domain
from cvengine_scanner import versions

from cveFeed import js_libraries, source_versions
from cveFeed.correlation import stored_technology_name

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
		ctx = {**ctx, '_excluded_hosts': excluded_names(project_id, names_only=True), '_org_id': org_id_of_project(project_id), '_scan': scan}  # read once per batch, not per name
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
		port.last_seen = timezone.now()
		fields = ['last_seen']
		if not port.source:  # a port another detector recorded keeps its source: bbot only names the source of a port nobody else recorded
			port.source = 'bbot'
			fields.append('source')
		port.save(update_fields=fields)
		ip.ports.add(port)
	from cveFeed import tech_links, tech_rows
	tech_seen = {}  # {(host row id, technology id): ''}: written once for the batch, source bbot (cveFeed.tech_links)
	tech_hosts = []
	tech_ids = {}  # {stored name: Technology id}: one lookup per distinct name in the batch, not one per (host, technology)
	# hosts found in an earlier streaming batch, read together once for the batch
	earlier = _hosts_of_scan(ctx.get('scan_history_id'), {host for host, tech_name in result.technologies if tech_name and host not in subdomains})
	for host, tech_name in result.technologies:
		if not tech_name:
			continue
		subdomain = subdomains.get(host) or earlier.get(host)
		if not subdomain:
			continue
		if source_versions.is_cpe(tech_name):
			# a CPE is what Shodan's InternetDB told bbot (passive, of unknown age): versioned or not, an application or an operating system, a
			# third-party reading of the host labelled "vendor product" with its CPE (cveFeed.source_versions.shodan_reading), matched only while
			# nothing first-party names the product, never a technology that outlives a fresher scan
			reported = source_versions.reported_cpe(tech_name)
			if reported:
				source_versions.store_bbot_reported(subdomain, [reported])
			continue
		tech_name = versions.normalize_technology(tech_name)  # a "v3.3.7" would otherwise store a name no advisory matches
		tech_name = stored_technology_name(tech_name)  # a Server-header token ("nginx/1.28.3") is the product and its version
		# a JavaScript library's version is read from its own file (cveFeed.js_libraries), never taken from another tool's guess
		tech_name = js_libraries.unversioned(tech_name)
		if not tech_name:
			continue
		if tech_name not in tech_ids:
			tech_ids[tech_name] = tech_rows.technology(tech_name).pk  # one row per spelling: "Caddy" and "caddy" are one (cveFeed.tech_rows)
		tech_seen[(subdomain.pk, tech_ids[tech_name])] = ''
		tech_hosts.append(subdomain)
	if tech_seen:
		tech_links.link(tech_seen, tech_links.BBOT)
		tech_links.forget(*tech_hosts)
	_persist_bbot_findings(result, ctx, subdomains)
	_persist_bbot_urls(result, ctx, subdomains)
	_persist_bbot_http(result, ctx, subdomains)


def _hosts_of_scan(scan_id, names):
	"""``{name: Subdomain}`` of the hosts of scan ``scan_id`` named in ``names`` (stored by an earlier streaming batch), in one query. A name
	stored twice gives its oldest row, as ``filter(...).first()`` did."""
	found = {}
	if scan_id and names:
		for row in Subdomain.objects.filter(scan_history_id=scan_id, name__in=sorted(names)).order_by('id'):
			found.setdefault(row.name, row)
	return found


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


def _put(row, field, value, fields):
	"""Set ``row.field`` to ``value`` and name it in ``fields`` (the columns to save) only when the value changes."""
	if getattr(row, field) != value:
		setattr(row, field, value)
		fields.append(field)


def _persist_bbot_http(result, ctx, subdomains):
	"""bbot HTTP_RESPONSE events (httpx ran inside bbot, so this costs no extra scanning) fill what the host page shows: the root
	answer's status, title and Server header on the Subdomain, and the response summary on the Port it came from. An answer proves
	the port is open, so a port bbot did not list is added, for the first address of the host only (the answer does not say which
	address gave it). A non-root answer fills a host's fields only while they are still empty."""
	if not result.http:
		return
	scan_id = ctx.get('scan_history_id')
	# every host, address and port the records name is read once for the batch (not once per record), and a row is written only when a
	# value changes, and then only that column
	cache = _hosts_of_scan(scan_id, {rec['host'] for rec in result.http if not subdomains.get(rec['host'])})
	cache.update({rec['host']: subdomains[rec['host']] for rec in result.http if subdomains.get(rec['host'])})
	ips_of, ports_of, port_rows = {}, {}, {}  # {host id: [IpAddress] by id}, {(IpAddress id, number): [Port] by id}, {Port id: Port}
	with_port = {cache[rec['host']].pk for rec in result.http if rec['port'] and cache.get(rec['host'])}
	if with_port:
		for link in Subdomain.ip_addresses.through.objects.filter(subdomain_id__in=sorted(with_port)).select_related('ipaddress').order_by('ipaddress_id'):
			ips_of.setdefault(link.subdomain_id, []).append(link.ipaddress)
		ip_ids = sorted({ip.pk for ips in ips_of.values() for ip in ips})
		numbers = sorted({rec['port'] for rec in result.http if rec['port']})
		if ip_ids:
			for link in (IpAddress.ports.through.objects.filter(ipaddress_id__in=ip_ids, port__number__in=numbers, port__protocol__in=('', 'tcp'))
						 .select_related('port').order_by('port_id')):
				port = port_rows.setdefault(link.port_id, link.port)  # one object per row, so a later record sees what an earlier one wrote
				ports_of.setdefault((link.ipaddress_id, port.number), []).append(port)
	for rec in result.http:
		sub = cache.get(rec['host'])
		if not sub:
			continue
		root = urlparse(rec['url']).path in ('', '/')
		fields = []
		if rec['status'] and (root or not sub.http_status):
			_put(sub, 'http_status', rec['status'], fields)
			if rec['title'] and (root or not sub.page_title):
				_put(sub, 'page_title', rec['title'], fields)
			if rec['webserver'] and (root or not sub.webserver):
				_put(sub, 'webserver', rec['webserver'], fields)
		if fields:
			sub.save(update_fields=fields)
		if not rec['port']:
			continue
		summary = {k: rec[k] for k in ('url', 'status', 'title', 'webserver', 'content_type', 'location') if rec[k]}
		ips = ips_of.get(sub.pk, [])
		ports = [p for ip in ips for p in ports_of.get((ip.pk, rec['port']), [])]
		added = None
		if not ports and ips:
			port, _ = update_or_create_port(port_number=rec['port'], service_name='https' if rec['url'].startswith('https') else 'http',
				description='', ip=ips[0])
			ips[0].ports.add(port)
			added = port_rows.setdefault(port.pk, port)
			added.source, added.last_seen = 'bbot', timezone.now()
			ports_of.setdefault((ips[0].pk, rec['port']), []).append(added)
			ports = [added]
		for port in ports:
			if root or not port.http:
				changed = ['http'] if port.http != summary else []
				port.http = summary
				if port is added:  # the port this answer proved open: its source and time are stored with it
					changed += ['source', 'last_seen']
				if changed:
					port.save(update_fields=changed)


def _persist_bbot_findings(result, ctx, subdomains):
	"""bbot FINDING / VULNERABILITY events become scanner findings (source 'bbot') on their host."""
	if not ctx.get('scan_history_id') or not ctx.get('domain_id'):
		return
	scan = ScanHistory.objects.filter(pk=ctx['scan_history_id']).first()
	domain = Domain.objects.filter(pk=ctx['domain_id']).first()
	if not (scan and domain):
		return
	from cveFeed.labels import record_label
	from reNgine.discovery_events import finding_key, label_for
	from cveFeed.exclusions import excluded_names, normalize
	banned = ctx.get('_excluded_hosts')
	if banned is None:
		banned = excluded_names(domain.project_id, names_only=True)
	from cveFeed import dangling_dns
	pending = [f for f in result.findings if f['module'] == 'baddns' and not f.get('informational') and not (banned and normalize(f['host']) in banned)]
	ratings = dict(zip(map(id, pending), dangling_dns.assess_all(pending, project=domain.project)))  # one batch, through a Sentinel when one can take it
	for f in result.findings:
		if banned and normalize(f['host']) in banned:  # nothing is recorded for a host the organization excluded for good
			continue
		if f.get('informational'):
			# a pure detection ("WAF Detection", "Nginx version detect") is a chip on the host, not a finding (see reNgine.discovery_events)
			record_label(domain.project_id, domain.id, f['host'], label_for(f['name']), detail=f['description'])
			continue
		severity, description = f['severity'], f['description']
		if f['module'] == 'baddns':
			# rated by what an outsider can claim, at the client's own zone cut (cveFeed.dangling_dns); a provider's DNS reached through a
			# CNAME, or a "not found" page the provider shows for every host, is not a finding
			rating = ratings.get(id(f))
			if rating is not None and rating.drop:
				logger.info(f'bbot baddns finding on {f["host"]} dropped: {rating.note}')
				continue
			if rating is not None:
				severity = rating.severity if rating.severity is not None else severity
				description = dangling_dns.with_note(description, rating)
		sub = subdomains.get(f['host']) or Subdomain.objects.filter(scan_history=scan, name=f['host']).first()
		if sub is None and f['module'] == 'baddns' and f['host']:
			# a dangling name often does not resolve, so no host row exists for it yet: the finding is still about that name ("Matched at")
			sub, _ = save_subdomain(f['host'], ctx=ctx)
		save_vulnerability(
			target_domain=domain, scan_history=scan, subdomain=sub, http_url=f['url'] or (f"{f['host']}:{f['port']}" if f['host'] and f.get('port') else f['host']), name=f['name'],
			severity=severity, description=description, source='bbot', type='bbot', template_id=f['module'],  # a finding with a port is filed against host:port
			matcher_name=finding_key(f['description']),
			request=f"bbot {f['module']} event on {f['host']}" + (f" at {f['url']}" if f['url'] else ''),
			extracted_results=[x[:5000] for x in (f['host'], f['url'], f"port {f['port']}" if f.get('port') else '') if x])


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
	if 'title' not in options:
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


NUCLEI_CVE_ID = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
NUCLEI_CWE_ID = re.compile(r'CWE-\d+', re.IGNORECASE)


def nuclei_ids(classification, kind, pattern):
	"""The CVE (or CWE) ids of a nuclei result's ``info.classification``, upper-cased and in order: nuclei writes them under ``cve-id`` and
	``cwe-id`` (its JSON tags), as a list or a string (``"cve-2021-44228"``, or several separated by commas); ``cve_id``/``cwe_id`` are read
	too. Anything that is not an id is dropped."""
	if not isinstance(classification, dict):
		return []
	found = []
	for key in (f'{kind}-id', f'{kind}_id'):
		value = classification.get(key)
		for item in (value if isinstance(value, list) else [value]):
			if isinstance(item, str):
				found += [m.upper() for m in pattern.findall(item)]
	return list(dict.fromkeys(found))


def parse_nuclei_result(line):
	"""Parse results from nuclei JSON output.

	Args:
		line (dict): Nuclei JSON line output.

	Returns:
		dict: Vulnerability data.
	"""
	from cveFeed.nuclei_fp import bounded
	return {
		'name': line['info'].get('name', ''),
		'type': line['type'],
		'severity': NUCLEI_SEVERITY_MAP[line['info'].get('severity', 'unknown')],
		'template': line['template'],
		'template_url': line.get('template-url', []),
		'template_id': line['template-id'],
		'description': line['info'].get('description', ''),
		'matcher_name': line.get('matcher-name', ''),
		'curl_command': bounded(line.get('curl-command'), 15000),
		# the matched request and response are the evidence of the finding: kept, clipped (cveFeed.nuclei_fp.MAX_EVIDENCE)
		'request': bounded(line.get('request')),
		'response': bounded(line.get('response')),
		'extracted_results': line.get('extracted-results', []),
		'cvss_metrics': line['info'].get('classification', {}).get('cvss-metrics', ''),
		'cvss_score': line['info'].get('classification', {}).get('cvss-score'),
		'cve_ids': nuclei_ids(line['info'].get('classification'), 'cve', NUCLEI_CVE_ID),
		'cwe_ids': nuclei_ids(line['info'].get('classification'), 'cwe', NUCLEI_CWE_ID),
		'references': line['info'].get('reference', []) or [],
		'tags': line['info'].get('tags', []),
		'source': NUCLEI,
	}


#-------------#
# Other utils #
#-------------#


#-------------#
# OSInt utils #
#-------------#


#-----------------#
# Utils functions #
#-----------------#


#--------------------#
# Database functions #
#--------------------#


VULNERABILITY_KEY = ('target_domain', 'scan_history', 'subdomain', 'endpoint', 'source', 'template_id', 'name', 'http_url',
					 'matcher_name')


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

	# A token template or a bbot secret module carries the secret itself: it goes to the secrets inventory and the finding keeps only its mask
	# (docs/SECRETS-PLAN.md 8.3). Taken out before anything is stored or compared.
	from cveFeed import secrets_inventory
	secret_values = secrets_inventory.take_from_finding(vuln_data, tags)

	# One row per finding: the key is where and what (host, template, name, URL, matcher), never the response body, which
	# differs on every request (a Date: header, a nonce) and would create a new row each time the finding is seen again. A finding an
	# earlier scan (or another target of the project) filed on the same host is that same row, moved onto this scan
	# (cveFeed.finding_lifecycle): rescans update it instead of opening a copy, and its history, status and assignee stay with it.
	from cveFeed import finding_lifecycle
	lookup = {k: vuln_data[k] for k in VULNERABILITY_KEY if k in vuln_data}
	defaults = {k: v for k, v in vuln_data.items() if k not in lookup}
	vuln = Vulnerability.objects.filter(**lookup).order_by('id').first()
	created = False
	if vuln is None:
		earlier = finding_lifecycle.earlier_copy(lookup)
		if earlier is not None and finding_lifecycle.move_onto(earlier, lookup, defaults):
			vuln = earlier
		else:
			try:
				with transaction.atomic():
					vuln = Vulnerability.objects.create(**lookup, **{**defaults, 'discovered_date': timezone.now(), 'open_status': True})
				created = True
			except IntegrityError:  # filed meanwhile by a parallel save of the same finding
				vuln = Vulnerability.objects.filter(**lookup).order_by('id').first()
	else:
		# seen again: keep the newest evidence, and it is evidently still there
		changed = [k for k, v in defaults.items() if k != 'discovered_date' and getattr(vuln, k) != v]
		for k in changed:
			setattr(vuln, k, defaults[k])
		changed += finding_lifecycle.seen_again(vuln)
		if changed:
			vuln.save(update_fields=changed)
	was_created = created

	# Save vuln tags
	for tag_name in tags or []:
		tag, _ = VulnerabilityTags.objects.get_or_create(name=tag_name)
		if tag:
			vuln.tags.add(tag)
			vuln.save()

	# Save CVEs (an id that cannot be one, too long for CveId.name, is dropped rather than failing the whole save)
	for cve_id in cve_ids or []:
		if not isinstance(cve_id, str) or not 0 < len(cve_id) <= 100:
			continue
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

	if secret_values:
		secrets_inventory.feed_finding_quietly(vuln, secret_values)

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
		if not domain.includes_host(subdomain_name):  # a target added as exactly one host (=example.com): nothing under it is kept
			logger.info(f'{subdomain_name} skipped: {domain.name} is scoped to that host only')
			return None, False

	scan = ctx.get('_scan')
	if scan is None or str(scan.pk) != str(scan_id):
		scan = ScanHistory.objects.select_related('domain').filter(pk=scan_id).first()
	domain = scan.domain if scan else None
	if domain is not None and domain.exact_host_only() and not domain.includes_host(subdomain_name):  # the scan's own target, when the caller named none
		logger.info(f'{subdomain_name} skipped: {domain.name} is scoped to that host only')
		return None, False
	if domain is not None:
		from cveFeed.exclusions import excluded_names, normalize
		banned = ctx.get('_excluded_hosts')  # persist_bbot_result reads the list once for a whole batch
		if banned is None:
			banned = excluded_names(domain.project_id, names_only=True)  # an address-excluded host is still recorded (it stays visible, unscanned)
		if normalize(subdomain_name) in banned:  # the organization excluded this exact host for good
			logger.info(f'{subdomain_name} is excluded for this organization. Skipping.')
			return None, False
	subdomain, created = get_or_create_first(
		Subdomain,
		defaults={'discovered_date': timezone.now()},  # stored with the row, not by a second UPDATE right after the INSERT
		scan_history=scan,
		target_domain=domain,
		name=subdomain_name)
	if created and subscan_id:
		subdomain.subdomain_subscan_ids.add(subscan_id)
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

	# Set extra attributes. Only a column whose value changes is written: a whole-row save would put back what another writer (the
	# full-port sweep, the port inventory) stored on this row since it was read
	changed = [key for key, value in kwargs.items() if getattr(ip, key, None) != value]
	for key in changed:
		setattr(ip, key, kwargs[key])
	columns = {f.name for f in IpAddress._meta.concrete_fields} | {f.attname for f in IpAddress._meta.concrete_fields}
	if any(key in columns for key in changed):
		ip.save(update_fields=[key for key in changed if key in columns])

	# Add IP to subdomain: the link is a row of its own, so the host row is not saved (that would put back the HTTP fields another
	# writer stored on it meanwhile, agentapi.dns_crosscheck.release runs this alongside a discovery's ingest)
	if subdomain:
		subdomain.ip_addresses.add(ip)

	# Add subscan to IP
	if subscan:
		ip.ip_subscan_ids.add(subscan)

	return ip, created
