"""The bbot ingest as it was before it was batched (develop before the batched rewrite), one row at a time: the reference
``tests.test_bbot_batch_equivalence`` holds the batched ``cvengine.tasks.persist_bbot_result`` to. Only the names of the functions differ."""
import validators

from urllib.parse import urlparse
from django.utils import timezone

from cvengine_scanner import versions
from cveFeed import js_libraries, source_versions
from cveFeed.correlation import stored_technology_name
from cvengine.common_func import get_port_service_description, update_or_create_port
from cvengine.tasks import (MAX_BBOT_URLS_PER_SCAN, MAX_URL_LENGTH, _hosts_of_scan, logger, save_ip_address, save_subdomain,
						   save_vulnerability)
from startScan.ip_rows import org_id_of_project
from startScan.models import EndPoint, IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain


def legacy_persist_bbot_result(result, ctx):
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
		known = get_port_service_description(port_number)  # the port's usual service name and description, when it has one
		port, _ = update_or_create_port(port_number=port_number, ip=ip, service_name=known.get('service_name', ''),
										  description=known.get('description', ''))
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
	legacy_persist_bbot_findings(result, ctx, subdomains)
	legacy_persist_bbot_urls(result, ctx, subdomains)
	legacy_persist_bbot_http(result, ctx, subdomains)



def legacy_persist_bbot_urls(result, ctx, subdomains):
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


def legacy_persist_bbot_http(result, ctx, subdomains):
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


def legacy_persist_bbot_findings(result, ctx, subdomains):
	"""bbot FINDING / VULNERABILITY events become scanner findings (source 'bbot') on their host."""
	if not ctx.get('scan_history_id') or not ctx.get('domain_id'):
		return
	scan = ScanHistory.objects.filter(pk=ctx['scan_history_id']).first()
	domain = Domain.objects.filter(pk=ctx['domain_id']).first()
	if not (scan and domain):
		return
	from cveFeed.labels import record_label
	from cvengine.discovery_events import finding_key, label_for
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
			# a pure detection ("WAF Detection", "Nginx version detect") is a chip on the host, not a finding (see cvengine.discovery_events)
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
