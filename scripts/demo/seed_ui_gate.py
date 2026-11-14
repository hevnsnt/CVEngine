"""Seed for the browser gates (scripts/ui_first_screen.py and the other ui_* gates): run AFTER scripts/demo/seed_demo.py, in the same database.

    python3 manage.py shell < scripts/demo/seed_demo.py && python3 manage.py shell < scripts/demo/seed_ui_gate.py

Adds to Acme Corp (all made up): 260 hosts, CVE matches in every status and heat with retest states, scanner and hygiene findings, secrets, suppliers,
one change of every kind in the shape the real code writes, an App Admin alert strip, a Sentinel whose update failed, and an empty never-scanned project
(Harbor Foods). Never run it against a real install.
"""
import random
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.models import User
from agentapi.models import Agent, SentinelTask
from cveFeed.models import *
from dashboard.models import Org, OrgMembership, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanActivity, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
random.seed(5)
NOW = timezone.now()
admin = User.objects.get(username='admin')
project = Project.objects.get(slug='acme-corp')
org = project.org
engine = EngineType.objects.first()
domain = Domain.objects.get(name='acme-example.com')
scan = ScanHistory.objects.filter(domain=domain).first()
# hosts
subs = []
WORDS = ['web','api','crm','erp','vpn','mail','dev','test','stage','cdn','ftp','db','lab','hr','pay','shop','blog','docs','wiki','git']
PROD = [('nginx','1.18.0'),('Apache httpd','2.4.49'),('OpenSSH','7.4'),('Microsoft IIS','10.0'),('Tomcat','9.0.31'),('Redis','5.0.7'),('MySQL','5.7.30'),('Jenkins','2.289')]
for i in range(260):
    name = f'{random.choice(WORDS)}{i}.acme-example.com'
    ip_addr = f'198.51.{100+i//250}.{i%250+50}'
    sub = Subdomain.objects.create(scan_history=scan, target_domain=domain, name=name, score=random.choice([0,5,10,20,35,50,70,90]), scored_at=NOW, score_detail=[{'label':'Open service exposed','points':10}], discovered_date=NOW-timedelta(days=random.randint(0,50)), http_status=random.choice([200,301,403,404]), page_title=name.split('.')[0].title()+' portal')
    ip = IpAddress.objects.get_or_create(address=ip_addr, org=org, defaults={'is_private': False, 'last_seen': NOW})[0]
    sub.ip_addresses.add(ip)
    prod = random.choice(PROD)
    p = Port.objects.create(number=random.choice([22,80,443,8080,3306]), service_name='http', product=prod[0], version=prod[1], protocol='tcp', state='open', last_seen=NOW)
    ip.ports.add(p)
    sub.webserver = prod[0]; sub.save()
    HostState.objects.get_or_create(project=project, domain=domain, host=name, defaults={'state': {'score':0}, 'scan': scan, 'first_seen': NOW-timedelta(days=20), 'last_seen': NOW})
    subs.append(sub)
# CVEs
cves = []
for n in range(40):
    cid = f'CVE-202{random.randint(0,4)}-{10000+n*137}'
    e = CVEEntry.objects.get_or_create(cve_id=cid, defaults={'title': cid, 'summary': random.choice(['A remote attacker can execute arbitrary code via a crafted request to the management interface of the affected product.','Improper input validation allows privilege escalation.','Path traversal in the file download handler discloses arbitrary files.']), 'cvss': round(random.uniform(3,10),1), 'kev': n%5==0, 'status':'published','published_at':NOW-timedelta(days=300),'first_seen_at':NOW-timedelta(days=20)})[0]
    cves.append(e)
ST = ['open']*5+['in_progress']*2+['fixed']*3+['accepted_risk','false_positive']
CL = ['confirmed','needs_validation','likely_false_positive','']
HEAT = ['','','','fire','smoke','ice']
users=[admin]
m_count=0
for sub in random.sample(subs, 150):
    for e in random.sample(cves, random.randint(1,3)):
        try:
            st = random.choice(ST)
            m = CVEMatch.objects.create(cve_entry=e, subdomain=sub, scan_history=scan, matched_product=sub.webserver, matched_version='1.0', version_in_range=True, confidence=random.random(), source=random.choice(['tech','port','cpe']), ai_verdict=random.choice(['affected','uncertain','not_affected','']), ai_reason='Version string falls in the affected range published by the vendor.', template_result=random.choice(['','vulnerable','no_match','version_only']), remediation_status=st, remediation_updated_at=NOW if st!='open' else None, remediation_by=admin if st!='open' else None)
        except Exception as ex:
            continue
        m_count+=1
        rs = ''
        if st=='fixed': rs = random.choice(['verifying','verified_fixed','still_reproduces','not_verified','no_check'])
        t = Triage.objects.create(project=project, domain=domain, host=sub.name, kind='cve_match', match=m, status='triaged', classification=random.choice(CL), reason='Checked against the vendor advisory.', heat_override=random.choice(HEAT), retest_state=rs, retest_at=NOW if rs else None, retest_reason='Host not reachable from any Sentinel' if rs=='not_verified' else '', retest_sentinel='hq-sentinel' if rs in('verified_fixed','still_reproduces') else '')
        if st=='fixed' and rs in ('verifying','verified_fixed','still_reproduces','not_verified'):
            FixRetest.objects.create(triage=t, project=project, status='running' if rs=='verifying' else 'done', outcome={'verifying':'','verified_fixed':'verified_fixed','still_reproduces':'still_reproduces','not_verified':'not_verified'}[rs], reason=t.retest_reason, sentinel=t.retest_sentinel, started_at=NOW, finished_at=None if rs=='verifying' else NOW)
print('matches', m_count)
# vulns
for i in range(70):
    sub = random.choice(subs); st=random.choice(ST)
    Vulnerability.objects.create(scan_history=scan, target_domain=domain, subdomain=sub, name=random.choice(['Exposed .git directory','Default admin credentials','Open redirect on login','Missing X-Frame-Options','Directory listing enabled','Jenkins script console exposed']), severity=random.randint(0,4), template_id=f'tpl-{i}', source='nuclei', http_url=f'https://{sub.name}/p{i}', open_status=st in('open','in_progress'), remediation_status=st, discovered_date=NOW-timedelta(hours=random.randint(1,400)))
# hygiene
CHK=[('tls_expired','TLS certificate has expired',4),('spf_missing','No SPF record',2),('dmarc_none','DMARC policy is none',2),('tls_weak','Weak TLS protocol TLS 1.0 offered',3),('cleartext_http','Cleartext HTTP login form',3),('caa_missing','No CAA record',1)]
for sub in random.sample(subs, 60):
    c = random.choice(CHK)
    HygieneFinding.objects.get_or_create(domain=domain, host=sub.name, check_name=c[0], defaults={'severity':c[2],'title':c[1],'detail':'Found while checking the host.','status':'open','remediation_status':random.choice(ST)})
# secrets
for i in range(40):
    SecretFinding.objects.create(project=project, domain=domain, fingerprint=f'fp{i:032d}', provider=random.choice(['AWS','GitHub','Stripe','Slack','Google']), kind=random.choice(['access_key','api_token','webhook_url']), klass=random.choice('PSI'), masked=f'AKIA****{i:04d}', length=40, confidence='high', severity=random.randint(1,4), status=random.choice(['unverified','active','inactive','revoked']), occurrence_count=random.randint(1,5), host_count=random.randint(1,3), remediation_status=random.choice(ST))
# suppliers
for nm,tier in [('Payroll SaaS Ltd','critical'),('Cloud CRM Inc','high'),('Print Services Co','normal'),('Courier Tracking','normal')]:
    s = Supplier.objects.create(project=project, name=nm, tier=tier, domains=[nm.split()[0].lower()+'-example.net'], contact='security@'+nm.split()[0].lower()+'-example.net', last_checked_at=NOW-timedelta(days=2))
    for k in range(random.randint(1,4)):
        SupplierFinding.objects.create(supplier=s, domain=s.domains[0], check_name=f'chk{k}', category=random.choice(['tls','email','web','cve']), severity=random.randint(0,4), title=random.choice(['Certificate expires in 12 days','No DMARC record','Server banner discloses version']), ask='Ask the supplier to renew the certificate.', status=random.choice(['open','open','accepted','resolved']))
# changes: one of every kind, in the shapes cveFeed/changes.py and route_auth.py write (before and after are what the real diff stores)
def _state(ip, port, product, version):
    return {'ips': {ip: {'ports': {f'{port}/tcp': {'service': 'https', 'product': product, 'version': version}}}}, 'techs': [f'{product}:{version}']}
CH = [
    ('host_new', '', None, None, _state('203.0.113.7', 443, 'nginx', '1.24')),
    ('host_returned', '', None, None, {'evidence': 'scannable address in a new scan'}),
    ('host_retired', '', None, {'ips': ['203.0.113.7']}, None),
    ('port_opened', '203.0.113.7', 8443, None, {'port': '8443/tcp', 'service': 'https', 'product': 'nginx', 'version': '1.24'}),
    ('port_closed', '203.0.113.7', 22, {'port': '22/tcp', 'service': 'ssh', 'product': 'OpenSSH', 'version': '8.9'}, None),
    ('service_changed', '203.0.113.7', 22, {'port': '22/tcp', 'product': 'OpenSSH', 'version': '8.9'}, {'port': '22/tcp', 'product': 'OpenSSH', 'version': '9.6'}),
    ('tech_added', '', None, None, 'nginx:1.24'),
    ('tech_removed', '', None, 'php:7.4', None),
    ('tech_version_changed', '', None, 'php:7.4', 'php:8.2'),
    ('cert_changed', '', 443, {'subject': 'a.acme-example.com', 'issuer': 'R3', 'sans': [], 'not_after': '2026-12-01T00:00:00+00:00', 'key_description': ''}, {'subject': 'a.acme-example.com', 'issuer': 'E5', 'sans': [], 'not_after': '2027-02-01T00:00:00+00:00', 'key_description': ''}),
    ('auth_changed', '', None, {'auth_state': 'login', 'url': 'https://a.acme-example.com/admin'}, {'auth_state': 'open', 'url': 'https://a.acme-example.com/admin', 'http_status': 200}),
    ('sensitive_found', '', None, {'types': []}, {'url': 'https://a.acme-example.com/export', 'types': ['email'], 'counts': {'email': 3}}),
    ('zombie_host', '', None, {'ips': ['203.0.113.7']}, {'alive': ['203.0.113.7:443']}),
    ('zombie_cleared', '', None, {'zombie_since': '2026-11-01T00:00:00+00:00'}, None),
    ('route_retired', '', None, {'auth_state': 'login', 'url': 'https://a.acme-example.com/old'}, {'url': 'https://a.acme-example.com/old', 'auth_state': 'not_found', 'http_status': 404}),
    ('zombie_route', '', None, {'retired_at': '2026-11-01T00:00:00+00:00', 'url': 'https://a.acme-example.com/old'}, {'url': 'https://a.acme-example.com/old', 'auth_state': 'open', 'http_status': 200}),
    ('screenshot_changed', '', None, {'hash': 'ab', 'subdomain_id': 1}, {'hash': 'cd', 'subdomain_id': 2, 'distance': 18, 'root_auth': 'login'}),
]
for i, sub in enumerate(random.sample(subs, 40)):
    kind, ip, port, before, after = CH[i % len(CH)]
    AssetChange.objects.create(project=project, domain=domain, scan=scan, host=sub.name, kind=kind, ip=ip, port=port, before=before, after=after, detected_at=NOW-timedelta(hours=random.randint(1, 150)))
# alert strip + empty project + a stale sentinel
AdminAlert.objects.create(code='disk_low', severity='warning', title='Disk space is running low', detail='The data volume has 7% free. Scans may stop when it is full.')
# the auto-tune card's History (static/cve/autotune-history.js): a change that is being checked, a recommendation, one an agent asked for, one that helped, one that
# made things worse and was undone (with the revert row), one that changed nothing, a back-off, a person's change, and an alert that one of them answered
admin_user = User.objects.filter(username='admin').first()


def tuning(minutes, **f):
    fields = dict(mode='auto', source='controller', action='raise', layer='auto', applied=True, signals={'summary': {}})
    fields.update(f)
    d = TuningDecision.objects.create(**fields)
    TuningDecision.objects.filter(pk=d.pk).update(created_at=NOW - timedelta(minutes=minutes))
    return d


def after(metric, value, **x):
    return {'metric': metric, 'value': value, 'trouble': 0, 'kills': 0, 'oom': 0, 'n': 3, **x}


TuningDecision.objects.all().delete()
tuning(9, setting='discovery_concurrency', old_value=12, new_value=14, phase='probe', reason='two healthy hours, work waiting in 3 measurements in a row, 40% memory free: probed 12 to 14',
       verify_at=NOW + timedelta(minutes=21), expected='discovery_queue', baseline={'metric': 'discovery_queue', 'value': 11.0})
tuning(22, setting='assess_batch', old_value=16, new_value=20, applied=False, mode='suggest', layer='', phase='probe', reason='the oldest waiting assessment is 52 minutes old')
tuning(48, setting='stage_parallel', old_value=6, new_value=8, source='agent', actor=admin_user, reason='asked by an agent: Sentinel slots are idle while chunks wait',
       verify_at=NOW - timedelta(minutes=18), verified_at=NOW - timedelta(minutes=16), outcome='helped', outcome_detail='share of Sentinel slots idle: 0.5 before, 0.1 after',
       baseline={'metric': 'sentinel_idle_share', 'value': 0.5, 'after': after('sentinel_idle_share', 0.1)})
bad = tuning(130, setting='heavy.nmap', old_value=4, new_value=6, phase='probe', reason='two healthy hours, work waiting in 3 measurements in a row: probed 4 to 6', resolution='reverted',
             resolved_by='auto-tune', resolved_at=NOW - timedelta(minutes=95), verify_at=NOW - timedelta(minutes=100), verified_at=NOW - timedelta(minutes=96), outcome='regressed',
             outcome_detail='2 memory kill(s) after the change, 0 before', baseline={'metric': 'wait_share', 'value': 0.4, 'after': after('wait_share', 0.4, kills=2)})
tuning(96, setting='heavy.nmap', old_value=6, new_value=4, action='revert', phase='verify', pressure=True, outcome='reverted', verified_at=NOW - timedelta(minutes=96),
       outcome_detail=f'undid decision {bad.pk}: 2 memory kill(s) after the change', reason='verification of the change: put 6 back to 4', signals={'verified_decision': bad.pk})
tuning(260, setting='work_depth', old_value=6, new_value=7, phase='probe', reason='two healthy hours: probed 6 to 7', verify_at=NOW - timedelta(hours=3), verified_at=NOW - timedelta(hours=3),
       outcome='no_effect', outcome_detail='x', baseline={'metric': 'conductor_saturated_share', 'value': 0.1, 'after': after('conductor_saturated_share', 0.1)})
tuning(600, setting='discovery_concurrency', old_value=20, new_value=12, action='lower', pressure=True, phase='back_off', reason='the scanning container has 6% memory free: backed off 20 to 12',
       verify_at=NOW - timedelta(hours=9), verified_at=NOW - timedelta(hours=9), outcome='helped', outcome_detail='x', baseline={'metric': 'trouble', 'value': 1.0, 'after': after('trouble', 0.0)},
       signals={'alerts': ['memory']})
# proposals of the health-check AI (WP6): applied (being checked), suggested, held for flagged text, refused as out of range
tuning(14, setting='assess_batch', old_value=16, new_value=12, action='lower', source='ai', reason='The worker lane is at 93 percent of its memory limit', verify_at=NOW + timedelta(minutes=16),
       expected='trouble', baseline={'metric': 'trouble', 'value': 1.0}, signals={'alerts': ['memory']})
tuning(30, setting='stage_parallel', old_value=6, new_value=4, action='lower', source='ai', mode='suggest', applied=False, layer='', reason='Sentinel tasks of one kind wait 40 minutes')
tuning(70, setting='heavy.testssl', old_value=3, new_value=2, action='lower', source='ai', applied=False, layer='', resolution='held', resolved_by='auto-tune', resolved_at=NOW - timedelta(minutes=70),
       reason='Memory is at 94 percent', outcome_detail='text aimed at an AI may be in what it read (instructions to an AI), so nothing was applied')
tuning(85, setting='discovery_concurrency', old_value=12, new_value=40, source='ai', applied=False, layer='', resolution='refused', resolved_by='auto-tuning', resolved_at=NOW - timedelta(minutes=85),
       reason='The discovery queue holds 30 scans', outcome_detail='outside what the controller allows now (4 to 12)')
tuning(1500, setting='heavy.nuclei', old_value=2, new_value=3, source='person', action='apply', actor=admin_user, reason='admin applied the recommendation')
AdminAlert.objects.create(code='memory', severity='warning', title='A worker lane is close to its memory limit', detail='The cve_feed lane uses 91% of its limit.',
                          first_seen=NOW - timedelta(hours=11), last_seen=NOW - timedelta(minutes=3))
Agent.objects.filter(name='edge-sentinel').update(last_seen=NOW-timedelta(hours=3), status_note='Update failed: could not pull image')
op = Org.objects.get(slug='harbor-foods')
Project.objects.get_or_create(slug='harbor-foods', defaults={'name':'Harbor Foods','org':op,'insert_date':NOW})
print('done')
