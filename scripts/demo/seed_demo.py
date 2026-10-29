"""Fill an empty cvENGINE database with a fictional company for screenshots and the tour GIFs. Run it inside the web container, or locally
with the settings environment set:  python3 manage.py shell < scripts/demo/seed_demo.py

Everything here is made up: the company (Acme Corp), its domain (acme-example.com), documentation-range addresses (198.51.100.0/24,
203.0.113.0/24) and private ranges, and the CVEs are real public ones attached to invented hosts. Never run it against a real install: it
creates an App Admin with a known password.
"""
import random
from datetime import timedelta

from django.contrib.auth.models import User
from django.utils import timezone

from agentapi.auth import SCOPE_SENTINEL, create_token
from agentapi.models import Agent, SentinelTask
from cveFeed.models import CVEEntry, CVEMatch, HostState, InternalRange
from dashboard.models import Org, OrgMembership, Project, UserProfile
from scanEngine.models import EngineType
from cveFeed.discovery import NUCLEI_SCAN_ACTIVITY_NAMES
from startScan.models import IpAddress, Port, ScanActivity, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

random.seed(13)
NOW = timezone.now()
PASSWORD = 'demo-Tour-2026'

admin, _ = User.objects.get_or_create(username='admin', defaults={'email': 'admin@acme-example.com', 'is_superuser': True, 'is_staff': True,
                                                                  'first_name': 'Ada', 'last_name': 'Admin'})
admin.set_password(PASSWORD)
admin.save()
UserProfile.objects.update_or_create(user=admin, defaults={'onboarded': True, 'must_change_password': False})

orgs = {name: Org.objects.get_or_create(slug=slug, defaults={'name': name})[0]
        for name, slug in (('Acme Corp', 'acme-corp'), ('Acme Labs', 'acme-labs'), ('Harbor Foods', 'harbor-foods'))}
org = orgs['Acme Corp']
for name, o in orgs.items():
    OrgMembership.objects.get_or_create(user=admin, org=o, defaults={'role': 'admin'})
project = Project.objects.get_or_create(slug='acme-corp', defaults={'name': 'Acme Corp', 'insert_date': NOW - timedelta(days=60), 'org': org})[0]
engine = EngineType.objects.get_or_create(engine_name='demo', defaults={'yaml_configuration': 'x', 'default_engine': True})[0]

# --- the internet-facing hosts -------------------------------------------------------------------------------------
EXTERNAL = [  # name, address, [(port, service, product, version)]
    ('www', '198.51.100.10', [(443, 'https', 'nginx', '1.25.3')]),
    ('app', '198.51.100.11', [(443, 'https', 'nginx', '1.24.0')]),
    ('api', '198.51.100.12', [(443, 'https', 'Caddy', '2.7.6')]),
    ('shop', '198.51.100.13', [(443, 'https', 'Apache httpd', '2.4.58')]),
    ('cache', '198.51.100.20', [(6379, 'redis', 'Redis', '5.0.7')]),
    ('wiki', '198.51.100.21', [(443, 'https', 'Atlassian Confluence', '8.3.1')]),
    ('sftp', '198.51.100.22', [(22, 'ssh', 'OpenSSH', '8.9p1')]),
    ('vpn', '198.51.100.23', [(443, 'https', 'Fortinet FortiGate', '7.2.4')]),
    ('mail', '198.51.100.24', [(25, 'smtp', 'Postfix', '3.7.4'), (993, 'imaps', 'Dovecot', '2.3.19')]),
    ('dev', '198.51.100.30', [(443, 'https', 'nginx', '1.22.1')]),
    ('preview', '198.51.100.31', [(443, 'https', 'nginx', '1.25.3')]),
    ('status', '203.0.113.40', [(443, 'https', 'nginx', '1.26.0')]),
    ('grafana', '203.0.113.41', [(443, 'https', 'Grafana', '10.2.3')]),
    ('git', '203.0.113.42', [(443, 'https', 'GitLab', '16.8.1'), (22, 'ssh', 'OpenSSH', '9.2p1')]),
    ('jenkins', '203.0.113.43', [(8443, 'https', 'Jenkins', '2.426.2')]),
    ('db', '203.0.113.44', [(5432, 'postgresql', 'PostgreSQL', '14.9')]),
    ('docs', '203.0.113.45', [(443, 'https', 'nginx', '1.25.3')]),
    ('cdn', '203.0.113.46', [(443, 'https', 'Varnish', '7.4.2')]),
]
domain = Domain.objects.get_or_create(name='acme-example.com', project=project, defaults={'insert_date': NOW - timedelta(days=60)})[0]
subs = {}
NUCLEI = sorted(NUCLEI_SCAN_ACTIVITY_NAMES)[0]
SCORES = {'cache': 96, 'wiki': 94, 'vpn': 88, 'jenkins': 71, 'sftp': 52, 'git': 47, 'mail': 44, 'db': 41, 'www': 22, 'app': 18, 'api': 16, 'shop': 31,
          'dev': 36, 'preview': 12, 'status': 8, 'grafana': 27, 'docs': 6, 'cdn': 9,
          'erp': 83, 'build': 78, 'files': 49, 'vmhost': 42, 'sql01': 38, 'print': 21, 'intranet': 24, 'hr': 19, 'nas': 33, 'cam-lobby': 29, 'pbx': 26,
          'ldap': 14, 'backup': 17}
UNSCANNED = {'preview', 'docs', 'status', 'cdn', 'cam-lobby', 'pbx'}  # discovered, not scanned yet
REASONS = {96: 'Known exploited CVE matched', 94: 'Known exploited CVE matched', 88: 'Known exploited CVE matched', 83: 'Known exploited CVE matched',
           78: 'Known exploited CVE matched', 71: 'Critical CVE matched', 52: 'Weak SSH algorithms', 47: 'Admin login exposed', 44: 'Mail service exposed'}


def make_scan(dom, internal=False, scanned=True):
    row = ScanHistory.objects.create(domain=dom, scan_type=engine, start_scan_date=NOW - timedelta(hours=random.randint(1, 20)),
                                     stop_scan_date=NOW - timedelta(minutes=random.randint(5, 50)), scan_status=2, results_dir='/tmp',
                                     tasks=['internal_pipeline'] if internal else ['subdomain_discovery', 'port_scan'])
    if scanned:
        ScanActivity.objects.create(scan_of=row, title='Nuclei', name=NUCLEI, time=NOW - timedelta(minutes=random.randint(5, 50)), status=2)
    return row


def host(dom, scan_row, name, address, ports, internal=False, os_guess=''):
    """One host. A domain's hosts share its latest scan (that is how cvENGINE counts live hosts), so a host is 'scanned' when its scan ran nuclei."""
    short = name.split('.')[0] if not internal else next(n for a, n, _ in INTERNAL if a == address)
    scan_row = scan_row or make_scan(dom, internal=True, scanned=short not in UNSCANNED)
    points = SCORES.get(short, 5)
    scored = short not in UNSCANNED
    sub = Subdomain.objects.create(scan_history=scan_row, score=points, scored_at=NOW if scored else None,
                                   score_detail=[{'label': REASONS.get(points, 'Open service exposed'), 'points': points}] if scored else [],
                                   target_domain=dom, name=name, discovered_date=NOW - timedelta(days=random.randint(1, 40)), http_status=200, webserver=ports[0][2] if ports else '', page_title=name.split('.')[0].title() if not internal else '')
    ip = IpAddress.objects.get_or_create(address=address, org=org, defaults={'is_private': internal, 'os_guess': os_guess, 'last_seen': NOW})[0]
    sub.ip_addresses.add(ip)
    for number, service, product, version in ports:
        port = Port.objects.create(number=number, service_name=service, product=product, version=version, protocol='tcp', state='open', last_seen=NOW)
        ip.ports.add(port)
    HostState.objects.get_or_create(project=project, domain=dom, host=name, defaults={'state': {'score': 0}, 'scan': scan_row, 'first_seen': NOW - timedelta(days=20), 'last_seen': NOW})
    return sub


domain_new = Domain.objects.get_or_create(name='acme-sites-example.com', project=project, defaults={'insert_date': NOW - timedelta(days=3)})[0]
scan_main, scan_new = make_scan(domain), make_scan(domain_new, scanned=False)
for name, address, ports in EXTERNAL:
    fresh = name in UNSCANNED  # a second, newly found domain whose hosts nothing has scanned yet
    subs[name] = host(domain_new if fresh else domain, scan_new if fresh else scan_main, f'{name}.' + ('acme-sites-example.com' if fresh else 'acme-example.com'), address, ports)

# --- the private networks a Sentinel covers ------------------------------------------------------------------------
HQ, DC = '10.20.0.0/24', '10.30.0.0/24'
InternalRange.objects.get_or_create(project=project, cidr=HQ, defaults={'description': 'Head office', 'last_discovery_at': NOW - timedelta(hours=5), 'last_discovery_hosts': 9})
InternalRange.objects.get_or_create(project=project, cidr=DC, defaults={'description': 'Data centre', 'last_discovery_at': NOW - timedelta(hours=2), 'last_discovery_hosts': 7})
INTERNAL = [
    ('10.20.0.5', 'files', [(445, 'microsoft-ds', 'Samba smbd', '4.17.12')]), ('10.20.0.7', 'print', [(631, 'ipp', 'CUPS', '2.4.2')]),
    ('10.20.0.9', 'intranet', [(443, 'https', 'Apache httpd', '2.4.57')]), ('10.20.0.12', 'hr', [(443, 'https', 'nginx', '1.18.0')]),
    ('10.20.0.20', 'nas', [(5001, 'https', 'Synology DSM', '7.2.1')]), ('10.20.0.31', 'cam-lobby', [(554, 'rtsp', 'Hikvision DS-2CD', '5.5.0')]),
    ('10.20.0.40', 'pbx', [(5060, 'sip', 'Asterisk', '18.19.0')]),
    ('10.30.0.4', 'erp', [(8443, 'https', 'Apache Tomcat', '9.0.83')]), ('10.30.0.8', 'sql01', [(1433, 'ms-sql-s', 'Microsoft SQL Server', '2019')]),
    ('10.30.0.9', 'ldap', [(389, 'ldap', 'OpenLDAP', '2.5.16')]), ('10.30.0.15', 'build', [(8080, 'http', 'Jenkins', '2.401.3')]),
    ('10.30.0.22', 'backup', [(22, 'ssh', 'OpenSSH', '8.4p1')]), ('10.30.0.30', 'vmhost', [(443, 'https', 'VMware ESXi', '7.0.3')]),
]
internal_subs = {}
for address, name, ports in INTERNAL:
    dom = Domain.objects.get_or_create(name=address, project=project, defaults={'insert_date': NOW - timedelta(days=12)})[0]
    internal_subs[name] = host(dom, None, address, address, ports, internal=True)

# --- CVEs and what they match --------------------------------------------------------------------------------------
CVES = [
    ('CVE-2022-0543', 'Packaging on Debian and Ubuntu leaves a Lua library in Redis available to scripts, allowing a sandbox escape.', 10.0, True, 'cache'),
    ('CVE-2023-22515', 'An unauthenticated attacker can create a Confluence administrator account on Data Center and Server.', 10.0, True, 'wiki'),
    ('CVE-2023-48795', 'The SSH transport protocol with certain OpenSSH extensions allows prefix truncation (Terrapin).', 5.9, False, 'sftp'),
    ('CVE-2024-21762', 'An out-of-bounds write in FortiOS SSL VPN may allow remote code execution.', 9.6, True, 'vpn'),
    ('CVE-2023-42793', 'JetBrains TeamCity and Jenkins-style CI servers allow authentication bypass leading to remote code execution.', 9.8, True, 'jenkins'),
    ('CVE-2024-23897', 'Jenkins CLI argument parsing lets unauthenticated users read arbitrary files.', 9.8, True, 'build'),
    ('CVE-2024-1086', 'A use-after-free in the Linux netfilter component allows local privilege escalation.', 7.8, False, None),
    ('CVE-2023-4966', 'Citrix NetScaler session token disclosure ("Citrix Bleed").', 9.4, True, None),
]
for cve_id, summary, cvss, kev, hostname in CVES:
    entry = CVEEntry.objects.get_or_create(cve_id=cve_id, defaults={'title': cve_id, 'summary': summary, 'cvss': cvss, 'kev': kev, 'status': 'published',
                                                                      'published_at': NOW - timedelta(days=200), 'first_seen_at': NOW - timedelta(days=30)})[0]
    sub = subs.get(hostname) or internal_subs.get(hostname)
    if sub:
        CVEMatch.objects.get_or_create(cve_entry=entry, subdomain=sub, defaults={
            'scan_history': sub.scan_history, 'matched_product': sub.webserver, 'matched_version': '', 'version_in_range': True, 'confidence': 0.9,
            'source': 'version', 'ai_verdict': 'confirmed' if kev else 'likely', 'ai_reason': 'The advertised version is inside the affected range.',
            'remediation_status': 'open'})

# --- Sentinels -----------------------------------------------------------------------------------------------------
KINDS = ['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'testssl', 'nmap_udp', 'wpscan', 'discover']
SENTINELS = [
    ('hq-sentinel', 'internal', 'Head office rack, 8 GB', 4, KINDS + ['network:internal']),
    ('dc-sentinel', 'internal', 'Data centre VM, 16 GB', 6, KINDS + ['network:internal', 'openvas']),
    ('edge-sentinel', 'external', 'Cloud VM in another region', 3, KINDS[:6]),
]
agents = {}
for name, network, note, slots, caps in SENTINELS:
    token, _ = create_token(admin, name, scope=SCOPE_SENTINEL)
    agents[name] = Agent.objects.create(token=token, name=name, kind='scanner', scope={'projects': ['acme-corp']}, capabilities=caps, network=network,
                                        max_concurrent=slots, status='active', status_note='', last_seen=NOW - timedelta(seconds=random.randint(3, 40)),
                                        info={'version': '1.3.0', 'host': note})

tasks = []
for i, (name, sub) in enumerate(list(internal_subs.items()) + list(subs.items())[:8]):
    internal = name in internal_subs
    agent = agents['hq-sentinel' if i < 7 else 'dc-sentinel'] if internal else agents['edge-sentinel']
    for kind in random.sample(KINDS[:5], 2):
        tasks.append(SentinelTask(project=project, kind=kind, host=sub.name, target={'addresses': [sub.ip_addresses.first().address]},
                                  ips=[sub.ip_addresses.first().address], status='done', agent=agent, attempts=1, result={'ok': True},
                                  claimed_at=NOW - timedelta(minutes=random.randint(10, 600)), finished_at=NOW - timedelta(minutes=random.randint(1, 9))))
for i in range(3):
    sub = list(internal_subs.values())[i]
    tasks.append(SentinelTask(project=project, kind=['nuclei_light', 'testssl', 'naabu'][i], host=sub.name, target={'addresses': [sub.ip_addresses.first().address]},
                              ips=[sub.ip_addresses.first().address], status='running', agent=agents['hq-sentinel'], attempts=1,
                              claimed_at=NOW - timedelta(seconds=90 + 40 * i), accepted_at=NOW - timedelta(seconds=80 + 40 * i),
                              lease_expires_at=NOW + timedelta(minutes=2)))
for i in range(4):
    sub = list(internal_subs.values())[7 + i]
    tasks.append(SentinelTask(project=project, kind='nmap', host=sub.name, target={'addresses': [sub.ip_addresses.first().address]},
                              ips=[sub.ip_addresses.first().address], status='queued', attempts=0))
SentinelTask.objects.bulk_create(tasks)
# --- a few scanner findings ----------------------------------------------------------------------------------------
for hostname, name, severity, template in (('jenkins', 'Jenkins script console exposed', 4, 'jenkins-script-console'), ('git', 'GitLab sign-up open', 2, 'gitlab-open-registration'),
                                            ('grafana', 'Grafana default credentials', 4, 'grafana-default-login'), ('erp', 'Tomcat manager exposed', 3, 'tomcat-manager-detect'),
                                            ('backup', 'SSH password authentication enabled', 1, 'ssh-password-auth')):
    sub = subs.get(hostname) or internal_subs.get(hostname)
    Vulnerability.objects.create(scan_history=sub.scan_history, target_domain=sub.target_domain, subdomain=sub, name=name, severity=severity, template_id=template,
                                 source='nuclei', http_url=f'https://{sub.name}/', open_status=True, discovered_date=NOW - timedelta(hours=random.randint(2, 30)))
print('seeded', project.slug, len(EXTERNAL), 'external hosts,', len(INTERNAL), 'internal,', len(agents), 'sentinels,', len(tasks), 'tasks')
