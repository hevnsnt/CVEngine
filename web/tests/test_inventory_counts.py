"""The status's inventory counts are read once for all projects and worked out in Python (``cveFeed.inventory_counts``, and the grouped counts of
``agentapi.system_status._shared_inputs``). They must be the numbers the per-project SQL gives: random inventories (scans of every kind, hosts in several
copies, aliases on shared addresses, CDN addresses, open ports, matches, findings, probe rows, screenshots) are compared, world by world, with the SQL
definitions (``correlation.latest_scan_q``, ``stats_history.compute_snapshot`` for one project, ``web_shot._web_evidence_q``, ``status_counts`` for one project).
"""
import os
import random
from datetime import timedelta

from django.core.cache import cache
from django.db import transaction
from django.test import TestCase
from django.utils import timezone

from agentapi import system_status
from cveFeed import correlation, counts, inventory_counts, stats_history, subdir_apps, vhost_scan, web_shot, wpscan_scan
from cveFeed.models import CVEEntry, CVEMatch, HostScreenshot, HygieneFinding, ProbeObservation
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

TASKS = [None, [], ['host_pipeline'], ['host_pipeline'], ['host_pipeline', 'x'], ['subdomain_discovery'], ['x', 'host_pipeline']]
STATUS = [2, 2, 2, 2, 2, 0, 1, -1, 3]
WORLDS = int(os.environ.get('INVENTORY_FUZZ_WORLDS', '15'))
SEED = int(os.environ.get('INVENTORY_FUZZ_SEED', '7001'))


def previous_oldest_open(now):
    """``counts.oldest_open`` as it was (a correlated first-seen subquery per scanner finding), with ties broken by id: the oracle."""
    from django.db.models import OuterRef, Subquery

    from cveFeed.threat import HIGH_CVSS
    best = {'at': None, 'kind': None, 'id': None}

    def consider(kind, at, row_id):
        if at is not None and (best['at'] is None or at < best['at']):
            best.update(at=at, kind=kind, id=row_id)
    first_match = Subquery(CVEMatch.objects.filter(cve_entry=OuterRef('cve_entry'), subdomain__target_domain=OuterRef('subdomain__target_domain'),
                                                   subdomain__name=OuterRef('subdomain__name')).order_by('created_at').values('created_at')[:1])
    row = counts.exposed_matches().filter(cve_entry__cvss__gte=HIGH_CVSS).annotate(first=first_match).order_by('first', 'id').values('id', 'first').first()
    if row:
        consider('cve', row['first'], row['id'])
    first_finding = Subquery(Vulnerability.objects.filter(name=OuterRef('name'), subdomain__target_domain=OuterRef('subdomain__target_domain'),
                                                          subdomain__name=OuterRef('subdomain__name'), discovered_date__isnull=False).order_by('discovered_date').values('discovered_date')[:1])
    row = (counts.actionable_findings(Vulnerability.objects.filter(severity__gte=3, subdomain__isnull=False)).annotate(first=first_finding)
           .filter(first__isnull=False).order_by('first', 'id').values('id', 'first').first())
    if row:
        consider('scanner', row['first'], row['id'])
    row = counts.actionable_hygiene(HygieneFinding.objects.all(), 3).order_by('first_seen', 'id').values('id', 'first_seen').first()
    if row:
        consider('hygiene', row['first_seen'], row['id'])
    if best['at'] is None:
        return {'days': None, 'kind': None, 'id': None}
    return {'days': max(0, (now - best['at']).days), 'kind': best['kind'], 'id': best['id']}


class RandomInventories(TestCase):
    def build(self, rnd, now):
        engine = EngineType.objects.create(engine_name='ic')
        cves = [CVEEntry.objects.create(cve_id=f'CVE-2099-{8000 + i}', cvss=c, kev=(i == 0), published_at=now, affected=[]) for i, c in enumerate((9.8, 5.0, 7.5))]
        orgs = [Org.objects.create(name=f'o{i}', slug=f'o{i}') for i in range(2)]
        projects = [Project.objects.create(name=f'p{i}', slug=f'p{i}', insert_date=now, org=orgs[i % 2]) for i in range(3)]
        domains = [Domain.objects.create(name=f'd{i}.t', project=rnd.choice(projects), insert_date=now) for i in range(rnd.randint(1, 6))]
        plan = []
        for d in domains:
            plan += [d] * rnd.choice([0, 0, 1, 2, 3, 5, 10, 20, rnd.randint(0, 30)])
        rnd.shuffle(plan)
        ScanHistory.objects.bulk_create([ScanHistory(start_scan_date=now - timedelta(hours=rnd.choice([1, 2, 30])), scan_status=rnd.choice(STATUS), domain=d,
                                                     scan_type=engine, tasks=rnd.choice(TASKS)) for d in plan])
        scans = list(ScanHistory.objects.order_by('id'))
        by_dom = {}
        for s in scans:
            by_dom.setdefault(s.domain_id, []).append(s)
        subs = []
        for d in domains:
            pool = [f'h{k}.{d.name}' for k in range(5)] + [d.name]
            for _ in range(rnd.randint(0, 25)):
                r = rnd.random()
                scan = None
                if r > 0.08 and scans:
                    scan = rnd.choice(by_dom.get(d.id) or scans) if r < 0.97 else rnd.choice(scans)
                subs.append(Subdomain(name=rnd.choice(pool), target_domain=d, scan_history=scan, http_url=rnd.choice(['', '', 'https://x.invalid/'])))
        if rnd.random() < 0.3:
            subs.append(Subdomain(name='orphan', target_domain=None, scan_history=rnd.choice(scans) if scans else None))
        Subdomain.objects.bulk_create(subs)
        subs = list(Subdomain.objects.order_by('id'))
        ips = [IpAddress.objects.create(address=f'10.0.0.{i}', is_cdn=(i == 3)) for i in range(5)]
        ports = [Port.objects.create(number=n, service_name=sv, protocol=pr, state=st) for n, sv, pr, st in (
            (443, 'https', 'tcp', 'open'), (22, 'ssh', 'tcp', 'open'), (8080, '', 'tcp', ''), (53, 'domain', 'udp', 'open'), (80, 'http', 'tcp', 'closed'),
            (3306, 'mysql', 'tcp', 'open'), (9999, 'http-alt', 'tcp', 'open'), (25, 'smtp', 'tcp', 'filtered'))]
        for ip in ips:
            ip.ports.add(*rnd.sample(ports, rnd.randint(0, 4)))
        through = Subdomain.ip_addresses.through
        through.objects.bulk_create([through(subdomain_id=s.id, ipaddress_id=ip.id) for s in subs if rnd.random() < 0.6 for ip in rnd.sample(ips, rnd.randint(1, 2))])
        CVEMatch.objects.bulk_create([CVEMatch(cve_entry=rnd.choice(cves), subdomain=s, matched_product=f'p{rnd.random()}', remediation_status=rnd.choice(['', '', 'fixed', 'accepted_risk']),
                                               ai_verdict=rnd.choice(['', '', 'not_affected'])) for s in subs for _ in range(rnd.choice([0, 0, 1, 2]))])
        HygieneFinding.objects.bulk_create([HygieneFinding(domain=d, host=f'h0.{d.name}', check_name=f'c{k}', severity=rnd.randint(0, 3), status=rnd.choice(['open', 'closed']), title='t')
                                            for d in domains for k in range(rnd.randint(0, 3))])
        Vulnerability.objects.bulk_create([Vulnerability(name='v', severity=rnd.randint(1, 4), subdomain=s, target_domain=s.target_domain, open_status=rnd.choice([True, True, False]),
                                                         remediation_status=rnd.choice(['', '', 'fixed']), discovered_date=now, http_url='http://x/')
                                           for s in subs if s.target_domain_id and rnd.random() < 0.2])
        observations = []
        for d in domains:
            for k in range(rnd.randint(0, 6)):
                probe, kind = rnd.choice([('wpscan', 'wordpress'), ('wordpress-detect', 'wordpress'), ('wordpress-signals', 'wordpress'), (vhost_scan.PROBE, 'vhost'), (subdir_apps.PROBE, 'subapp')])
                observations.append(ProbeObservation(project=d.project, domain=d, host=f'h{rnd.randint(0, 3)}.{d.name}', probe=probe, kind=kind, product=f'p{k}', port=0,
                                                     outcome=rnd.choice(['found', 'found', 'absent', 'challenged', 'hidden']), variant=rnd.choice(['', 'lead']),
                                                     version=rnd.choice(['', '1.0']), evidence={'state': rnd.choice(['scanned', 'blocked', 'failed', 'not_wordpress'])}))
        ProbeObservation.objects.bulk_create(observations)
        for d in domains:
            for k in range(rnd.randint(0, 4)):
                HostScreenshot.objects.create(project=d.project, domain=d, host=f'h{k}.{d.name}', scheme=rnd.choice(['http', 'https', 'rdp']), port=443 + k,
                                              image_path=rnd.choice(['', 'a.png']), outcome=rnd.choice(['ok', 'queued', 'timeout', 'blocked', 'nla_required']),
                                              attempted_at=now - timedelta(minutes=rnd.randint(0, 99)))
        return projects, subs

    def test_the_shared_counts_are_the_per_project_sql_counts(self):
        now = timezone.now()
        stats = {'worlds': 0, 'subs': 0, 'current': 0}
        bad = []
        for w in range(WORLDS):
            rnd = random.Random(SEED * 100000 + w)
            with transaction.atomic():
                cache.clear()
                projects, subs = self.build(rnd, now)
                ids = [p.id for p in projects]
                expected = set(Subdomain.objects.filter(correlation.latest_scan_q()).values_list('id', flat=True))
                rows = inventory_counts.current_rows()
                stats['worlds'] += 1
                stats['subs'] += len(subs)
                stats['current'] += len(expected)
                if {r[0] for r in rows} != expected:
                    bad.append(('current', w, sorted({r[0] for r in rows} ^ expected)[:10]))
                shared = system_status._shared_inputs(ids)
                if counts.oldest_open(now) != previous_oldest_open(now):
                    bad.append(('oldest_open', w, counts.oldest_open(now), previous_oldest_open(now)))
                if set(inventory_counts.rep_ids()) != set(counts.host_reps().values_list('pk', flat=True)):
                    bad.append(('rep_ids', w))
                web = inventory_counts.web_hosts_by_project()
                for project in projects:
                    own = stats_history.compute_snapshot(project, with_fixed=False)
                    if (own['hosts'], own['exposed_hosts']) != (shared['hosts'].get(project.id, 0), shared['exposed'].get(project.id, 0)):
                        bad.append(('hosts', w, project.id, own['hosts'], own['exposed_hosts'], shared['hosts'].get(project.id), shared['exposed'].get(project.id)))
                    sql_web = Subdomain.objects.filter(target_domain__project_id=project.id).filter(web_shot._web_evidence_q()).values('target_domain__project_id', 'name').distinct().count()
                    if sql_web != web.get(project.id, 0):
                        bad.append(('web', w, project.id, sql_web, web.get(project.id, 0)))
                    row_alone, row_shared = system_status._project_row(project), system_status._project_row(project, shared)
                    if row_alone != row_shared:
                        bad.append(('row', w, project.id, {k: (row_alone[k], row_shared[k]) for k in row_alone if row_alone[k] != row_shared[k]}))
                    for name, single, grouped in (('wordpress', wpscan_scan.status_counts([project.id]), shared['wordpress'][project.id]),
                                                  ('web_discovery', subdir_apps.status_counts([project.id]), shared['web_discovery'][project.id])):
                        if single != grouped:
                            bad.append((name, w, project.id, single, grouped))
                transaction.set_rollback(True)
        self.assertGreater(stats['current'], 50)  # the worlds are not empty
        self.assertEqual(bad, [], stats)
