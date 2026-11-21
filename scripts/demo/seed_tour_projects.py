"""Tour-only seed: five more fictional companies next to Acme Corp, so the All projects graph has several constellations of clearly different size and heat.
Run AFTER scripts/demo/seed_demo.py, in the same database (scripts/demo/make_gif.sh does it; the CI UI gates do not, so they see no change):

    python3 manage.py shell < ../scripts/demo/seed_tour_projects.py

Everything is made up: the companies, their *-example.* domains, and addresses from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
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
    ('Bluepeak Logistics', 'bluepeak-logistics', 'bluepeak-example.com', 24, [('fire', 3), ('smoke', 4), ('ice', 2)], '198.51.100.', 100),
    ('Harbor Foods', 'harbor-foods', 'harborfoods-example.org', 15, [('smoke', 3), ('ice', 1)], '203.0.113.', 100),
    ('Cedar Ridge Clinics', 'cedar-ridge-clinics', 'cedarridge-example.net', 12, [('smoke', 1), ('ice', 3)], '192.0.2.', 100),
    ('Sunvale Energy', 'sunvale-energy', 'sunvale-example.com', 9, [('smoke', 2), ('ice', 1)], '198.51.100.', 140),
    ('Pinewood Media', 'pinewood-media', 'pinewood-example.net', 5, [], '203.0.113.', 140),
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
print('seeded', len(PROJECTS), 'more projects')
