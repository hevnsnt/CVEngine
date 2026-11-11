"""Build a synthetic project of a chosen size, so the slow paths of a large install can be measured on a throwaway database.

    python manage.py seed_scale_fixture --hosts 3000 [--seed 1] [--reset]

One project (``scale-fixture``) with a dozen targets, ``--hosts`` hosts in the current inventory (the latest scan of each target) and two
older scans of every target that keep a copy of each host (the retention default keeps the three newest), about 0.9 addresses and 2.7 ports per
host, 3 scanner findings and 2 CVE matches per host with a realistic severity, status and tag mix, hygiene findings, certificates, one triage
row per finding, service-ledger rows, host states, an activity feed, two Sentinels with a task backlog and a daily history of counts.

Everything is synthetic and deterministic for a seed: names are ``hN.tK.example.com``; addresses come from the documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 first, then 2001:db8::/32 once those 762 are used up). It writes only under its own project, a
user ``scale-admin`` and two Sentinel agents, so ``--reset`` removes a previous run of the same name. Never run it on a database you care about:
the command refuses unless ``CVENGINE_SCALE_FIXTURE=1`` is set or the database name contains ``scale``.
"""
import hashlib
import ipaddress
import random
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils import timezone

SLUG = 'scale-fixture'
TARGETS = 12
SERVICES = ('nmap-fast', 'nuclei', 'bbot', 'hygiene', 'probe', 'wafw00f')
TAGS = ('cve', 'tech', 'exposure', 'misconfig', 'default-login', 'xss', 'sqli', 'rce', 'lfi', 'ssrf', 'wordpress', 'apache', 'nginx', 'iis', 'tomcat',
        'jenkins', 'panel', 'token', 'takeover', 'ssl', 'tls', 'cors', 'redirect', 'disclosure', 'edb', 'kev', 'vkev', 'oast', 'fuzz', 'dns')
FINDING_NAMES = ('Apache HTTP Server version disclosure', 'nginx version detected', 'Missing X-Frame-Options header', 'Exposed .git directory',
                 'WordPress login panel', 'Jenkins dashboard exposed', 'TLS 1.0 enabled', 'Directory listing enabled', 'phpinfo exposed',
                 'Open redirect', 'CORS misconfiguration', 'Default credentials on admin panel', 'Exposed server-status', 'SQL error disclosed',
                 'Outdated jQuery', 'Subdomain takeover candidate', 'Weak cipher suite', 'HTTP TRACE enabled', 'Exposed environment file',
                 'Spring actuator exposed')
PRODUCTS = ('nginx', 'Apache httpd', 'OpenSSH', 'Microsoft IIS', 'Tomcat', 'MySQL', 'PostgreSQL', 'Postfix', 'Exim', 'lighttpd', 'Node.js', 'WordPress')
PORT_POOL = ((22, 'ssh'), (25, 'smtp'), (53, 'domain'), (80, 'http'), (110, 'pop3'), (143, 'imap'), (443, 'https'), (465, 'smtps'), (587, 'submission'),
             (993, 'imaps'), (995, 'pop3s'), (3306, 'mysql'), (5432, 'postgresql'), (8080, 'http-proxy'), (8443, 'https-alt'))


def synthetic_address(n):
    """The n-th documentation address: the three IPv4 test networks first (762 usable), then 2001:db8::/32."""
    nets = ('192.0.2.', '198.51.100.', '203.0.113.')
    if n < 254 * 3:
        return f'{nets[n // 254]}{n % 254 + 1}'
    return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address('2001:db8::')) + n - 254 * 3 + 1))


def pick(rng, weighted):
    r, acc = rng.random(), 0.0
    for value, w in weighted:
        acc += w
        if r < acc:
            return value
    return weighted[-1][0]


class Command(BaseCommand):
    help = 'Create a synthetic project of --hosts hosts (default 3000) for scale measurements.'

    def add_arguments(self, parser):
        parser.add_argument('--hosts', type=int, default=3000)
        parser.add_argument('--seed', type=int, default=1)
        parser.add_argument('--targets', type=int, default=TARGETS, help='how many targets (domains) the hosts are spread over')
        parser.add_argument('--sentinels', type=int, default=2, help='how many Sentinel agents to create')
        parser.add_argument('--tasks', type=int, default=400, help='how many SentinelTask rows (spread over --task-days, all finished but a small live backlog)')
        parser.add_argument('--task-days', type=int, default=7)
        parser.add_argument('--secrets', type=int, default=0, help='how many exposed secrets (and 2 occurrences each)')
        parser.add_argument('--history-scans', type=int, default=2, help='older scans of each target that keep a copy of every host')
        parser.add_argument('--reset', action='store_true', help='delete a previous run first')

    def handle(self, *args, hosts, seed, history_scans, reset, targets=TARGETS, sentinels=2, tasks=400, task_days=7, secrets=0, **opts):
        import os
        if not (os.environ.get('CVENGINE_SCALE_FIXTURE') == '1' or 'scale' in settings.DATABASES['default']['NAME']):
            raise CommandError('refusing: this writes thousands of rows; use a throwaway database named *scale* or set CVENGINE_SCALE_FIXTURE=1')
        from dashboard.models import Project
        if Project.objects.filter(slug=SLUG).exists():
            if not reset:
                raise CommandError(f'project {SLUG} exists; pass --reset to rebuild it')
            self.reset()
        rng = random.Random(seed)
        with transaction.atomic():
            counts = self.build(hosts, rng, history_scans, targets, sentinels, tasks, task_days, secrets)
        with connection.cursor() as c:
            c.execute('ANALYZE')
        self.stdout.write(self.style.SUCCESS('seeded ' + ', '.join(f'{k}={v}' for k, v in counts.items())))

    def reset(self):
        from agentapi.models import Agent
        from cveFeed.models import CVEEntry, ServiceRun
        from dashboard.models import ApiToken, Org, Project
        from startScan.models import IpAddress, Technology, VulnerabilityTags
        Project.objects.filter(slug=SLUG).delete()
        ServiceRun.objects.filter(project__isnull=True, asset__startswith='scalefx:').delete()
        Agent.objects.filter(name__startswith='scale-sentinel').delete()
        ApiToken.objects.filter(name__startswith='scale-sentinel').delete()
        CVEEntry.objects.filter(cve_id__startswith='CVE-2099-9').delete()
        IpAddress.objects.filter(org__slug=SLUG).delete()
        Technology.objects.filter(name__startswith='scalefx-').delete()
        VulnerabilityTags.objects.filter(name__startswith='scalefx-').delete()
        Org.objects.filter(slug=SLUG).delete()
        User.objects.filter(username__in=('scale-admin', 'scale-viewer')).delete()

    def build(self, n_hosts, rng, history_scans, TARGETS=TARGETS, n_sentinels=2, n_tasks=400, task_days=7, n_secrets=0):
        from agentapi.models import Agent
        from cveFeed.models import (AgentActivity, CVEEntry, CVEMatch, HostState, HygieneFinding, ServiceRun, StatsSnapshot, TlsCertificate,
                                    Triage)
        from dashboard.models import ApiToken, Org, OrgMembership, Project, ProjectMembership
        from scanEngine.models import EngineType
        from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology, Vulnerability, VulnerabilityTags
        from targetApp.models import Domain
        from cvengine_scanner.fingerprint import categorize
        now = timezone.now()
        out = {}

        admin = User.objects.create_superuser('scale-admin', 'scale-admin@example.com', 'scale-fixture-pw')
        viewer = User.objects.create_user('scale-viewer', 'scale-viewer@example.com', 'scale-fixture-pw')
        org = Org.objects.create(name='Scale Fixture', slug=SLUG)
        project = Project.objects.create(name='Scale Fixture', slug=SLUG, insert_date=now, org=org)
        for model, kw in ((OrgMembership, {'org': org}), (ProjectMembership, {'project': project})):
            try:
                model.objects.create(user=admin, **kw)
            except Exception:  # noqa: BLE001 - a role field the model needs is not worth failing the fixture for
                pass
        ProjectMembership.objects.create(user=viewer, project=project, role='audit')
        engine = EngineType.objects.get_or_create(engine_name='scale-fixture', defaults={'yaml_configuration': 'x', 'default_engine': False})[0]

        Domain.objects.bulk_create([Domain(name=f't{k}.example.com', project=project, insert_date=now - timedelta(days=120)) for k in range(TARGETS)])
        domains = list(Domain.objects.filter(project=project).order_by('id'))

        # scans: history_scans older full scans, then the latest; a running and queued scan of a few targets
        gens = history_scans + 1
        rows = []
        for k, d in enumerate(domains):
            for g in range(gens):
                age = timedelta(days=7 * (gens - 1 - g), hours=k)
                rows.append(ScanHistory(domain=d, scan_type=engine, scan_status=2, start_scan_date=now - age - timedelta(hours=2),
                                        stop_scan_date=now - age, tasks=['subdomain_discovery', 'port_scan', 'nuclei']))
        ScanHistory.objects.bulk_create(rows)
        by_dom = {}
        for s in ScanHistory.objects.filter(domain__in=domains).order_by('id'):
            by_dom.setdefault(s.domain_id, []).append(s)
        extra = [ScanHistory(domain=domains[k], scan_type=engine, scan_status=1, start_scan_date=now - timedelta(minutes=10 + k), tasks=[])
                 for k in range(3)]
        extra += [ScanHistory(domain=domains[k % TARGETS], scan_type=engine, scan_status=-1, start_scan_date=now - timedelta(minutes=k), tasks=[])
                  for k in range(20)]
        extra += [ScanHistory(domain=domains[k % TARGETS], scan_type=engine, scan_status=0, start_scan_date=now - timedelta(days=2, hours=k),
                              stop_scan_date=now - timedelta(days=2), tasks=[], error_message='synthetic failure') for k in range(10)]
        ScanHistory.objects.bulk_create(extra)
        out['scans'] = ScanHistory.objects.filter(domain__in=domains).count()

        # technologies and tags (shared rows)
        tech_rows = []
        for p in PRODUCTS:
            for v in ('1.0', '1.1', '2.0', '2.4', '3.1'):
                name = f'scalefx-{p}:{v}'
                tech_rows.append(Technology(name=name, version=v, category=categorize(name)))
        techs = Technology.objects.bulk_create(tech_rows)
        tags = VulnerabilityTags.objects.bulk_create([VulnerabilityTags(name=f'scalefx-{t}') for t in TAGS])
        cves = CVEEntry.objects.bulk_create([
            CVEEntry(cve_id=f'CVE-2099-9{i:04d}', title=f'Synthetic issue {i}', cvss=round(rng.choice((2.1, 4.3, 5.0, 6.8, 7.5, 8.1, 9.0, 9.8, 10.0)), 1),
                     kev=(i % 25 == 0), affected=[], published_at=now - timedelta(days=rng.randint(1, 900))) for i in range(600)])

        # addresses: ~0.9 per host, then ports, ~2.7 per host
        n_ips = int(n_hosts * 0.9)
        ips = IpAddress.objects.bulk_create([
            IpAddress(org=org, address=synthetic_address(i), is_cdn=(i % 20 == 0), version=4 if i < 762 else 6, last_seen=now - timedelta(hours=rng.randint(0, 100)))
            for i in range(n_ips)])
        port_rows, port_ip = [], []
        for ip in ips:
            for number, svc in rng.sample(PORT_POOL, min(len(PORT_POOL), max(1, round(rng.gauss(3.0, 1.2))))):
                port_rows.append(Port(number=number, service_name=svc, product=rng.choice(PRODUCTS), version=rng.choice(('1.0', '2.4', '3.1')),
                                      state=pick(rng, (('open', .9), ('filtered', .06), ('closed', .04))), protocol='tcp', last_seen=now))
                port_ip.append(ip.id)
        ports = Port.objects.bulk_create(port_rows)
        Through = IpAddress.ports.through
        Through.objects.bulk_create([Through(ipaddress_id=i, port_id=p.id) for i, p in zip(port_ip, ports)])
        out['addresses'] = len(ips)
        out['ports'] = len(ports)

        # hosts: stored once per scan. The latest scan of each target holds the current inventory; older scans keep a copy
        host_defs = []  # (name, domain index, ip id or None, score)
        for h in range(n_hosts):
            k = h % TARGETS
            live = rng.random() > 0.08
            host_defs.append((f'h{h}.t{k}.example.com', k, ips[h % n_ips].id if live else None, rng.randint(0, 100), rng.random() < .85))
        sub_rows, sub_meta = [], []
        for g in range(gens):
            for name, k, ip_id, score, web in host_defs:
                scan = by_dom[domains[k].id][g]
                sub_rows.append(Subdomain(scan_history=scan, target_domain=domains[k], name=name, http_status=(rng.choice((200, 200, 301, 403, 404)) if web and ip_id else 0),
                                          http_url=f'https://{name}/' if web else None, page_title=f'Synthetic {name}', webserver=rng.choice(PRODUCTS),
                                          is_cdn=False, discovered_date=now - timedelta(days=30), score=score, scored_at=now))
                sub_meta.append((g, ip_id))
        subs = Subdomain.objects.bulk_create(sub_rows, batch_size=2000)
        SubIp, SubTech = Subdomain.ip_addresses.through, Subdomain.technologies.through
        SubIp.objects.bulk_create([SubIp(subdomain_id=s.id, ipaddress_id=ip) for s, (g, ip) in zip(subs, sub_meta) if ip], batch_size=5000)
        SubTech.objects.bulk_create([SubTech(subdomain_id=s.id, technology_id=t.id) for s in subs for t in rng.sample(techs, 2)], batch_size=5000)
        current = subs[(gens - 1) * n_hosts:]
        out['subdomain_rows'] = len(subs)
        out['hosts'] = len(current)

        # scanner findings (3 per host in the current scan, half as many in each older scan) and CVE matches (2 per host, current scan only)
        sev_mix = ((0, .45), (1, .20), (2, .20), (3, .10), (4, .05))
        rem_mix = (('open', .85), ('in_progress', .05), ('fixed', .04), ('accepted_risk', .03), ('false_positive', .03))
        vuln_rows, taken = [], set()
        for g in range(gens):
            share = 3.0 if g == gens - 1 else 1.5
            for s in subs[g * n_hosts:(g + 1) * n_hosts]:
                for _ in range(int(share) + (1 if rng.random() < share - int(share) else 0)):
                    sev = pick(rng, sev_mix)
                    name, tid = rng.choice(FINDING_NAMES), f'synthetic-{rng.randint(1, 80)}'
                    if (s.id, name, tid) in taken:  # one row per finding (uniq_vulnerability_finding)
                        continue
                    taken.add((s.id, name, tid))
                    vuln_rows.append(Vulnerability(
                        scan_history=s.scan_history, subdomain=s, target_domain=s.target_domain, source='nuclei', name=name, severity=sev,
                        template_id=tid, http_url=f'https://{s.name}/', type='vulnerability',
                        discovered_date=now - timedelta(days=rng.randint(0, 60)), open_status=rng.random() < .88,
                        remediation_status=pick(rng, rem_mix), description='Synthetic finding for scale measurements.'))
        vulns = Vulnerability.objects.bulk_create(vuln_rows, batch_size=2000)
        VTag = Vulnerability.tags.through
        VTag.objects.bulk_create([VTag(vulnerability_id=v.id, vulnerabilitytags_id=t.id) for v in vulns for t in rng.sample(tags, rng.randint(1, 3))], batch_size=5000)
        out['vulnerabilities'] = len(vulns)

        match_rows = []
        seen = set()
        for s in current:
            for _ in range(2):
                cve = rng.choice(cves)
                product = rng.choice(PRODUCTS)
                if (cve.id, s.id, product) in seen:
                    continue
                seen.add((cve.id, s.id, product))
                match_rows.append(CVEMatch(cve_entry=cve, subdomain=s, scan_history=s.scan_history, matched_product=product, matched_version='2.4',
                                           confidence=round(rng.random(), 2), source=rng.choice(('tech', 'port', 'cpe')),
                                           ai_verdict=pick(rng, (('', .35), ('affected', .30), ('uncertain', .15), ('not_affected', .20))),
                                           remediation_status=pick(rng, rem_mix), version_in_range=rng.random() < .7))
        matches = CVEMatch.objects.bulk_create(match_rows, batch_size=2000)
        out['cve_matches'] = len(matches)

        triage = [Triage(project=project, domain=m.subdomain.target_domain, host=m.subdomain.name, kind='cve_match', match=m, status='triaged',
                         classification=rng.choice(('needs_validation', 'likely_true_positive', 'likely_false_positive', 'confirmed'))) for m in matches]
        triage += [Triage(project=project, domain=v.target_domain, host=v.subdomain.name, kind='nuclei', vulnerability=v, status='triaged',
                          classification=rng.choice(('needs_validation', 'likely_true_positive', 'likely_false_positive', 'confirmed')))
                   for v in vulns if v.scan_history_id in {by_dom[d.id][-1].id for d in domains}]
        Triage.objects.bulk_create(triage, batch_size=2000)
        out['triage'] = len(triage)

        hyg, certs = [], []
        for h, s in enumerate(current):
            if rng.random() < .5:
                hyg.append(HygieneFinding(domain=s.target_domain, host=s.name, check_name=rng.choice(('spf_missing', 'dmarc_none', 'tls_expired', 'caa_missing')),
                                          severity=rng.randint(0, 3), title='Synthetic hygiene finding'))
            if rng.random() < .4:
                certs.append(TlsCertificate(domain=s.target_domain, host=s.name, port=443, subject=s.name, issuer='Synthetic CA',
                                            not_after=now + timedelta(days=rng.randint(-5, 400))))
        HygieneFinding.objects.bulk_create(hyg, batch_size=2000)
        TlsCertificate.objects.bulk_create(certs, batch_size=2000)
        out['hygiene'], out['certs'] = len(hyg), len(certs)

        # ledger: which scanner last ran on which host (project rows), and nmap per address (global rows)
        ledger = []
        for name, k, ip_id, score, web in host_defs:
            for svc in SERVICES:
                ledger.append(ServiceRun(service=svc, asset=name, project=project, scan=by_dom[domains[k].id][-1], status='done',
                                         finished_at=now - timedelta(hours=rng.randint(0, 24 * 14))))
        for ip in ips:
            ledger.append(ServiceRun(service='nmap-fast', asset=f'scalefx:{ip.address}', project=None, status='done',
                                     finished_at=now - timedelta(hours=rng.randint(0, 24 * 10))))
        ServiceRun.objects.bulk_create(ledger, batch_size=5000)
        out['ledger'] = len(ledger)

        HostState.objects.bulk_create([
            HostState(project=project, domain=domains[k], host=name, state={'ports': []}, fingerprint=hashlib.sha1(name.encode()).hexdigest(),
                      scan=by_dom[domains[k].id][-1], score=score) for name, k, ip_id, score, web in host_defs], batch_size=2000)

        AgentActivity.objects.bulk_create([
            AgentActivity(kind=rng.choice(('inventory', 'confirm', 'scan', 'hygiene', 'validate', 'changes')), message=f'Synthetic activity {i} on h{i % n_hosts}.t{i % TARGETS}.example.com',
                          status=rng.choice(('done', 'done', 'done', 'running', 'failed')), project=project, detail={}) for i in range(3000)], batch_size=2000)

        StatsSnapshot.objects.bulk_create([
            StatsSnapshot(project=project, date=(now - timedelta(days=d)).date(), hosts=n_hosts, exposed_hosts=n_hosts // 3,
                          open_findings={'critical': 40, 'high': 150, 'medium': 600, 'low': 900, 'info': 3000}, cve_matches={'fire': 20, 'smoke': 200, 'ice': 900})
            for d in range(90)])

        # Sentinels (their raw bearer keys are ``cve_scalefx<i>`` padded, so a load script can call the real API) with task history
        from agentapi import auth as agent_auth
        sentinels = []
        for i in range(n_sentinels):
            raw = f'cve_scalefx{i:03d}' + 'x' * 32
            token = ApiToken.objects.create(user=admin, name=f'scale-sentinel-{i}', key_hash=agent_auth.hash_token(raw), prefix=raw[:8],
                                            scope='sentinel')
            sentinels.append(Agent.objects.create(token=token, name=f'scale-sentinel-{i}', kind='scanner', status='active', last_seen=now,
                                                  capabilities=['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'http_probe', 'waf', 'discover', 'secrets_scan'],
                                                  max_concurrent=4, scope={'projects': [SLUG]}, info={'version': '1.4.0'}))
        out['sentinels'] = len(sentinels)
        self.seed_tasks(project, sentinels, by_dom, domains, host_defs, n_tasks, task_days, rng)
        out['sentinel_tasks'] = n_tasks
        if n_secrets:
            out['secrets'] = self.seed_secrets(project, domains, host_defs, n_secrets, rng, now)
        return out

    def seed_tasks(self, project, sentinels, by_dom, domains, host_defs, n_tasks, days, rng):
        """``n_tasks`` SentinelTask rows over the last ``days`` days: mostly finished, with the realistic status mix and a small live backlog.
        One INSERT ... SELECT generate_series (a few hundred thousand rows in seconds); ``result`` is a small typed record like a Sentinel's."""
        from agentapi.models import SentinelTask
        table = SentinelTask._meta.db_table
        kinds = ('nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'http_probe', 'waf', 'discover', 'secrets_scan')
        scan_ids = [by_dom[d.id][-1].id for d in domains]
        agent_ids = [a.id for a in sentinels] or [None]
        n_hosts = len(host_defs)
        with connection.cursor() as c:
            c.execute('create temp table _fx_scans (n int, scan_id int)')
            c.executemany('insert into _fx_scans values (%s, %s)', [(k, sid) for k, sid in enumerate(scan_ids)])
            c.execute('create temp table _fx_agents (n int, agent_id int)')
            c.executemany('insert into _fx_agents values (%s, %s)', [(k, a) for k, a in enumerate(agent_ids)])
            c.execute(f"""
                insert into {table} (project_id, scan_id, kind, target, host, ips, priority, status, agent_id, attempts, max_attempts, lease_expires_at,
                                     claimed_at, accepted_at, finished_at, result, error, secret_ref, secret_read_at, trace_id, partial_seq, created_by_id,
                                     created_at, updated_at, not_before)
                select %s, sc.scan_id, (%s::text[])[1 + t.g %% 8], jsonb_build_object('host', 'h' || (t.g %% %s) || '.example.com', 'ports', jsonb_build_array(80, 443)),
                       'h' || (t.g %% %s) || '.t' || (t.g %% %s) || '.example.com', jsonb_build_array('192.0.2.' || (1 + t.g %% 254)), 1,
                       st.status, case when st.status = 'queued' then null else ag.agent_id end, 1, 1,
                       case when st.status in ('claimed', 'running') then now() + interval '5 minutes' end,
                       case when st.status <> 'queued' then t.ts end, case when st.status in ('running', 'done', 'failed') then t.ts end,
                       case when st.status in ('done', 'failed', 'expired') then t.ts + interval '40 seconds' end,
                       case when st.status = 'done' then jsonb_build_object('outcome', 'done', 'ports', jsonb_build_array(jsonb_build_object('port', 80, 'service', 'http'),
                            jsonb_build_object('port', 443, 'service', 'https')), 'notes', repeat('x', 600)) else '{{}}'::jsonb end,
                       case when st.status = 'failed' then 'synthetic failure' else '' end, null, null, md5(t.g::text), 0, null, t.ts, t.ts, null
                from (select g, now() - (random() * interval '{days} days') as ts, random() as r from generate_series(1, %s) g) t
                cross join lateral (select case when t.g > %s - 60 then (array['queued', 'queued', 'claimed', 'running'])[1 + t.g %% 4]
                                                when t.r < .78 then 'done' when t.r < .90 then 'failed' else 'expired' end as status) st
                join _fx_scans sc on sc.n = t.g %% %s
                join _fx_agents ag on ag.n = t.g %% %s
                """, [project.id, list(kinds), n_hosts, n_hosts, len(domains), n_tasks, n_tasks, len(scan_ids), len(agent_ids)])

    def seed_secrets(self, project, domains, host_defs, n, rng, now):
        from cveFeed.models import SecretFinding, SecretOccurrence
        kinds = (('aws_access_key', 'aws', 'S', 4), ('stripe_publishable', 'stripe', 'P', 1), ('github_token', 'github', 'S', 4), ('jwt', '', 'S', 2), ('google_api_key', 'google', 'P', 1))
        rows = []
        for i in range(n):
            kind, provider, klass, sev = kinds[i % len(kinds)]
            rows.append(SecretFinding(project=project, domain=domains[i % len(domains)], fingerprint=hashlib.sha256(f'fx-secret-{i}'.encode()).hexdigest(), provider=provider,
                                      kind=kind, klass=klass, masked=f'{kind[:4]}...{i:04d}', severity=sev, status=rng.choice(('unverified', 'unverified', 'active', 'revoked')),
                                      occurrence_count=2, host_count=2, rule_ids=[f'rule.{kind}']))
        found = SecretFinding.objects.bulk_create(rows, batch_size=2000)
        occ = []
        for i, f in enumerate(found):
            for k in range(2):
                host = host_defs[(i * 2 + k) % len(host_defs)][0]
                occ.append(SecretOccurrence(finding=f, project=project, domain=f.domain, host=host, url=f'https://{host}/static/app{k}.js', source='kingfisher',
                                            rule_id=f'rule.{f.kind}', line=k + 10, context='const key = "****"'))
        SecretOccurrence.objects.bulk_create(occ, batch_size=2000)
        return len(found)
