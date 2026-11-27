"""Tour-only seed: five more fictional companies next to the demo company, so the All projects graph has several constellations of clearly different
size and heat, plus what the 1.5 tour shows on the internal network: the names internal hosts go by and a printer that is scanned gently.
Run AFTER the rebranded copy of scripts/demo/seed_demo.py (scripts/demo/rebrand.py), in the same database (scripts/demo/make_gif.sh does both;
the CI UI gates do not, so they see no change):

    python3 manage.py shell < ../scripts/demo/seed_tour_projects.py

Everything is made up (invented names that no known company uses): the companies, their *-example.* domains, and addresses from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
Never run it against a real install.
"""
import random
from datetime import timedelta

from django.contrib.auth.models import User
from django.utils import timezone

from cveFeed.discovery import NUCLEI_SCAN_ACTIVITY_NAMES
from cveFeed.models import CVEEntry, CVEMatch, HostState
from dashboard.models import Org, OrgMembership, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain
from agentapi.models import Agent

random.seed(29)
NOW = timezone.now()
admin = User.objects.get(username='admin')
engine = EngineType.objects.first()
NUCLEI = sorted(NUCLEI_SCAN_ACTIVITY_NAMES)[0]
KEV = ['CVE-2022-0543', 'CVE-2023-22515', 'CVE-2024-21762', 'CVE-2023-42793', 'CVE-2024-23897']
ICE = ['CVE-2023-48795', 'CVE-2024-6387', 'CVE-2021-23017', 'CVE-2022-41741']
WORDS = ['www', 'app', 'api', 'shop', 'mail', 'vpn', 'dev', 'test', 'staging', 'cdn', 'docs', 'wiki', 'git', 'ci', 'db', 'portal', 'status', 'blog', 'files', 'sso', 'crm', 'erp', 'pay', 'jobs']
PRODUCTS = [(443, 'https', 'nginx', '1.25.3'), (443, 'https', 'Apache httpd', '2.4.58'), (443, 'https', 'Caddy', '2.7.6'), (22, 'ssh', 'OpenSSH', '9.2p1'),
            (8443, 'https', 'Jenkins', '2.426.2'), (5432, 'postgresql', 'PostgreSQL', '15.4'), (443, 'https', 'Atlassian Confluence', '8.3.1')]
# name, slug, domain, hosts, [(heat, count)], address prefix, first octet of addresses
PROJECTS = [
    ('Thistlegate Logistics', 'thistlegate-logistics', 'thistlegate-example.com', 24, [('fire', 3), ('smoke', 4), ('ice', 2)], '198.51.100.', 100),
    ('Grellbrook Foods', 'grellbrook-foods', 'grellbrook-example.org', 15, [('smoke', 3), ('ice', 1)], '203.0.113.', 100),
    ('Fennick Hollow Clinics', 'fennick-hollow-clinics', 'fennickhollow-example.net', 12, [('smoke', 1), ('ice', 3)], '192.0.2.', 100),
    ('Brindlewick Energy', 'brindlewick-energy', 'brindlewick-example.com', 9, [('smoke', 2), ('ice', 1)], '198.51.100.', 140),
    ('Pellowick Media', 'pellowick-media', 'pellowick-example.net', 5, [], '203.0.113.', 140),
]
for name, slug, domain_name, n_hosts, heats, prefix, first in PROJECTS:
    org = Org.objects.get_or_create(slug=slug, defaults={'name': name})[0]
    OrgMembership.objects.get_or_create(user=admin, org=org, defaults={'role': 'admin'})
    project = Project.objects.get_or_create(slug=slug, defaults={'name': name, 'insert_date': NOW - timedelta(days=40), 'org': org})[0]
    domain = Domain.objects.get_or_create(name=domain_name, project=project, defaults={'insert_date': NOW - timedelta(days=40)})[0]
    scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=NOW - timedelta(hours=random.randint(2, 20)), stop_scan_date=NOW - timedelta(minutes=random.randint(5, 50)),
                                      scan_status=2, results_dir='/tmp', tasks=['subdomain_discovery', 'port_scan'])
    ScanActivity.objects.create(scan_of=scan, title='Nuclei', name=NUCLEI, time=NOW - timedelta(minutes=20), status=2)
    wanted = [h for h, count in heats for _ in range(count)]
    for i in range(n_hosts):
        host_name = f'{WORDS[i % len(WORDS)]}{"" if i < len(WORDS) else i}.{domain_name}'
        heat = wanted[i] if i < len(wanted) else ''
        score = {'fire': random.randint(85, 97), 'smoke': random.randint(55, 84), 'ice': random.randint(30, 54)}.get(heat, random.randint(5, 29))
        sub = Subdomain.objects.create(scan_history=scan, score=score, scored_at=NOW, score_detail=[{'label': 'Open service exposed', 'points': score}], target_domain=domain, name=host_name,
                                       discovered_date=NOW - timedelta(days=random.randint(1, 30)), http_status=200, webserver=PRODUCTS[i % len(PRODUCTS)][2], page_title=host_name.split('.')[0].title())
        ip = IpAddress.objects.get_or_create(address=f'{prefix}{first + i}', org=org, defaults={'is_private': False, 'last_seen': NOW})[0]
        sub.ip_addresses.add(ip)
        number, service, product, version = PRODUCTS[i % len(PRODUCTS)]
        ip.ports.add(Port.objects.create(number=number, service_name=service, product=product, version=version, protocol='tcp', state='open', last_seen=NOW))
        HostState.objects.get_or_create(project=project, domain=domain, host=host_name, defaults={'state': {'score': 0}, 'scan': scan, 'first_seen': NOW - timedelta(days=20), 'last_seen': NOW})
        if heat:
            cve = CVEEntry.objects.get(cve_id=random.choice(ICE if heat == 'ice' else KEV))
            CVEMatch.objects.create(cve_entry=cve, subdomain=sub, scan_history=scan, matched_product=sub.webserver, matched_version='', version_in_range=True, confidence=0.9, source='version',
                                    ai_verdict='confirmed' if cve.kev else 'likely', ai_reason='The advertised version is inside the affected range.', remediation_status='open',
                                    **({'template_result': 'vulnerable', 'template_id': cve.cve_id.lower(), 'template_tested_at': NOW - timedelta(hours=3)} if heat == 'fire' else {}))

# --- 1.5: what internal hosts are called, and the printer --------------------------------------------------------------------------------------
# The Sentinel's discover sweep reports the name each address goes by inside the network (reverse DNS, mDNS, NetBIOS), kept on the host's target
# row; every page then writes the host as 'name (address)'. One host's fingerprint showed a printer: it gets only the read-only web pass.
home = Project.objects.get(slug='quillfern-group')
NAMES = {'10.20.0.5': 'files-hq', '10.20.0.7': 'print-hq-2f', '10.20.0.9': 'intranet', '10.20.0.12': 'hr-portal', '10.20.0.20': 'nas-hq',
         '10.20.0.31': 'cam-lobby', '10.20.0.40': 'pbx-hq', '10.20.0.50': 'dc01', '10.20.0.51': 'jump01', '10.30.0.4': 'erp01', '10.30.0.8': 'sql01',
         '10.30.0.9': 'ldap01', '10.30.0.15': 'build01', '10.30.0.22': 'backup01', '10.30.0.30': 'vmhost01', '10.30.0.40': 'k8s-n1', '10.30.0.41': 'k8s-n2',
         '10.30.0.50': 'runner01'}
for address, name in NAMES.items():
    Domain.objects.filter(project=home, name=address).update(display_name=name, display_name_source='rdns', display_name_at=NOW - timedelta(hours=5))
Domain.objects.filter(project=home, name='10.20.0.7').update(printer=True, printer_evidence='IPP answered on port 631')
# the Sentinels run the release the tour shows, and have just checked in
for agent in Agent.objects.filter(kind='scanner'):
    Agent.objects.filter(pk=agent.pk).update(info={**(agent.info or {}), 'version': '1.5.0'}, last_seen=NOW - timedelta(seconds=5 + agent.pk))
# --- this week's threats: two invented CVEs on an invented product, so the Overview's weekly card is not empty and names no real vendor ----------
for cve_id, summary, cvss, kev in (
        ('CVE-2026-91437', 'An authentication bypass in the Lanternfold Gateway admin console lets a remote attacker run commands as root.', 9.8, True),
        ('CVE-2026-91562', 'A crafted upload to Lanternfold Gateway file sharing writes files outside its folder; a public exploit exists.', 9.1, False)):
    CVEEntry.objects.update_or_create(cve_id=cve_id, defaults={
        'title': cve_id, 'summary': summary, 'cvss': cvss, 'kev': kev, 'status': 'published', 'exploit_db': True, 'published_at': NOW - timedelta(days=3),
        'first_seen_at': NOW - timedelta(days=3), 'affected': [{'vendor': 'Lanternfold', 'product': 'Lanternfold Gateway'}],
        'intel': {'kev': {'cisa_kev': {'added': (NOW - timedelta(days=2)).date().isoformat(), 'vendor': 'Lanternfold', 'product': 'Lanternfold Gateway',
                                       'name': 'Lanternfold Gateway authentication bypass'}}} if kev else {}})
# --- the daily history the Overview tiles draw (a sparkline and a change on each tile): today's snapshot as the product writes it, and three weeks
# before it with a little more exposure each day back and a few findings fixed along the way, so no tile shows a bare dash
from cveFeed import stats_history
from cveFeed.models import StatsSnapshot
stats_history.snapshot_all_projects()
for snap in list(StatsSnapshot.objects.filter(date=NOW.date())):
    for back in range(1, 22):
        grow = 1 + 0.015 * back
        found = {k: round(int(v or 0) * grow + (back % 3 == 0)) for k, v in (snap.open_findings or {}).items()}
        found['critical'] = max(1, round(int((snap.open_findings or {}).get('critical') or 0) * grow) + 1)
        StatsSnapshot.objects.update_or_create(project=snap.project, date=snap.date - timedelta(days=back), defaults={
            'hosts': snap.hosts - back // 4, 'exposed_hosts': round(snap.exposed_hosts * grow), 'open_findings': found, 'cve_matches': snap.cve_matches,
            'fixed': 2 + (21 - back) // 3, 'mean_days_to_fix': round(6.5 - (21 - back) * 0.08, 1),
            'needs_hosts': None if snap.needs_hosts is None else round(snap.needs_hosts * grow)})
print('seeded', len(PROJECTS), 'more projects and', len(NAMES), 'internal host names')
