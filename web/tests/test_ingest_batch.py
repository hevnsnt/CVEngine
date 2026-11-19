"""Ingest, correlation and triage read and write per chunk, not per host: a port inventory chunk costs a handful of statements per host whatever its
ports, the host contexts ``triage.track`` describes are read together (and come out exactly as one host's read), correlation reads each per-host
table once per chunk, and ``close_stale`` writes one activity line per project instead of one per closed match."""
import json
from datetime import timedelta
from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import correlation, host_context, port_inventory, triage
from cveFeed.models import (AgentActivity, CVEEntry, CVEMatch, HostInventory, HostLabel, ProbeObservation, RouteAuth, TlsCertificate, Triage)
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology
from targetApp.models import Domain
from tests.test_investigation import ContextFixture

NGINX = [{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.25.0'}]}]


def _inventory(prefix, count, ports=(22, 80, 443, 8080, 3306), product='nginx'):
    return [{'ip': f'{prefix}.{i}', 'os_guess': 'Linux 5.x', 'os_accuracy': 95, 'status': 'up', 'scanned': list(range(1, 10001)), 'hostscripts': {}, 'cuts': [],
             'ports': [{'number': n, 'protocol': 'tcp', 'state': 'open', 'service_name': 'http', 'product': product, 'version': '1.24.0', 'method': 'probed',
                        'cpes': ['cpe:/a:nginx:nginx:1.24.0'], 'banner': 'x'} for n in ports]} for i in range(count)]


class PortInventoryBatchTests(TestCase):
    def setUp(self):
        self.org = Org.objects.create(name='O', slug='o')

    def persist(self, inventory):
        with CaptureQueriesContext(connection) as captured:
            out = port_inventory.persist_inventory(inventory, org_id=self.org.pk, os_reliable=True)
        return out, len(captured.captured_queries)

    def test_a_chunk_costs_a_few_statements_per_host_first_time_and_again(self):
        out, first = self.persist(_inventory('198.51.100', 12))
        self.assertEqual(out, {'ports': 60, 'hosts_with_os': 12})
        self.assertLessEqual(first, 8 * 12)
        out, again = self.persist(_inventory('198.51.100', 12))
        self.assertEqual(out['ports'], 60)
        self.assertLessEqual(again, 8 * 12)
        self.assertEqual(Port.objects.count(), 60)  # nothing created twice
        ip = IpAddress.objects.get(address='198.51.100.3', org=self.org)
        self.assertEqual(sorted(ip.ports.values_list('number', flat=True)), [22, 80, 443, 3306, 8080])
        self.assertEqual({p.product for p in ip.ports.all()}, {'nginx'})

    def test_only_what_changed_is_written_and_unreported_ports_close_together(self):
        port_inventory.persist_inventory(_inventory('198.51.100', 2), org_id=self.org.pk, os_reliable=True)
        ip = IpAddress.objects.get(address='198.51.100.1', org=self.org)
        changed = _inventory('198.51.100', 2, ports=(22, 80), product='Apache httpd')
        with CaptureQueriesContext(connection) as captured:
            port_inventory.persist_inventory(changed, org_id=self.org.pk, os_reliable=True)
        closes = [q['sql'] for q in captured.captured_queries if q['sql'].startswith('UPDATE "startScan_port" SET "state"')]
        self.assertEqual(len(closes), 2)  # one per host, for its three ports
        states = dict(ip.ports.values_list('number', 'state'))
        self.assertEqual(states, {22: 'open', 80: 'open', 443: 'closed', 8080: 'closed', 3306: 'closed'})
        port = ip.ports.get(number=80)
        self.assertEqual((port.product, port.version, port.banner), ('Apache httpd', '1.24.0', 'x'))

    def test_a_port_shared_with_another_address_is_split_off(self):
        shared = Port.objects.create(number=443, protocol='tcp', product='old')
        one = IpAddress.objects.create(address='198.51.100.1', org=self.org)
        two = IpAddress.objects.create(address='198.51.100.2', org=self.org)
        one.ports.add(shared)
        two.ports.add(shared)
        port_inventory.persist_inventory(_inventory('198.51.100', 2, ports=(443,)), org_id=self.org.pk, os_reliable=True)
        self.assertNotEqual(one.ports.get(number=443).pk, two.ports.get(number=443).pk)
        self.assertEqual(one.ports.get(number=443).product, 'nginx')

    def test_a_port_that_cannot_be_stored_costs_only_itself(self):
        def fail(objs, *args, **kwargs):
            from django.db import DatabaseError
            raise DatabaseError('boom')
        with mock.patch.object(Port.objects, 'bulk_create', side_effect=fail):
            out = port_inventory.persist_inventory(_inventory('198.51.100', 1, ports=(22, 80)), org_id=self.org.pk, os_reliable=True)
        self.assertEqual(out['ports'], 2)  # stored one at a time instead
        self.assertEqual(sorted(IpAddress.objects.get(address='198.51.100.0').ports.values_list('number', flat=True)), [22, 80])


class HostContextsBatchTests(ContextFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'api.rt.test', 'mail.rt.test'), ports=((443, 'https'), (22, 'ssh')))
        self.subs = list(Subdomain.objects.filter(scan_history=self.scan_obj).order_by('name'))
        now = timezone.now()
        for n, sub in enumerate(self.subs):
            sub.technologies.add(Technology.objects.create(name=f'nginx:1.{n}'), Technology.objects.create(name='WordPress'))
            RouteAuth.objects.create(project=self.project, domain=self.domain, host=sub.name, url=f'https://{sub.name}/', path='/', auth_state='open',
                                     http_status=200, title='Hi', evidence={'server': 'nginx', 'headers': {'server': 'nginx'}})
            for i in range(3):
                ProbeObservation.objects.create(project=self.project, domain=self.domain, host=sub.name, probe=f'p{i}', kind='version', product='nginx',
                                                version=f'1.{i}', outcome='found', source='body:test', confidence=0.8)
            HostLabel.objects.create(project=self.project, domain=self.domain, host=sub.name, label=f'WAF{n}')
            TlsCertificate.objects.create(domain=self.domain, host=sub.name, port=443, issuer='R3', not_after=now + timedelta(days=40 + n))
            HostInventory.objects.create(project=self.project, key=f'h:{sub.name}', host=sub.name, os_name='Ubuntu', os_version='22.04', package_count=3)
            match = CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', matched_version=f'1.{n}', version_in_range=True,
                                            source='tech')
            Triage.objects.create(project=self.project, domain=self.domain, host=sub.name, kind='cve_match', match=match, validated_at=now,
                                  validation_steps=[{'kind': 'probe', 'result': 'hit', 'summary': 'saw it'}])

    def test_the_batch_reads_exactly_what_one_host_at_a_time_reads(self):
        batch = host_context.host_contexts(list(Subdomain.objects.filter(pk__in=[s.pk for s in self.subs]).select_related('target_domain')))
        for sub in self.subs:
            one = host_context.host_context(Subdomain.objects.select_related('target_domain').get(pk=sub.pk))
            self.assertEqual(json.dumps(one, sort_keys=True, default=str), json.dumps(batch[sub.pk], sort_keys=True, default=str), sub.name)
            self.assertTrue(one['probe_results'] and one['certificates'] and one['labels'] and one['host_inventory'] and one['earlier_checks']
                            and one['other_cve_matches'])

    def test_the_reads_do_not_grow_with_the_hosts(self):
        def reads(subs):
            subs = list(Subdomain.objects.filter(pk__in=[s.pk for s in subs]).select_related('target_domain'))
            with CaptureQueriesContext(connection) as captured:
                host_context.host_contexts(subs)
            return len(captured.captured_queries)
        self.assertEqual(reads(self.subs[:1]), reads(self.subs))

    def test_track_reads_the_hosts_of_a_chunk_together(self):
        matches = triage.with_cves(CVEMatch.objects.filter(subdomain__in=self.subs).select_related('subdomain__target_domain'))
        with mock.patch('cveFeed.host_context.host_context', wraps=host_context.host_context) as one:
            with CaptureQueriesContext(connection) as captured:
                pairs = triage.track(matches)
        self.assertEqual(len(pairs), 3)
        self.assertTrue(all(call.kwargs.get('pre') is not None for call in one.call_args_list))  # never the one-host path
        self.assertLess(len(captured.captured_queries), 45)
        for row, d in pairs:
            self.assertIn('host_context', d)
        again = triage.with_cves(CVEMatch.objects.filter(subdomain__in=self.subs).select_related('subdomain__target_domain'))
        self.assertEqual([d['signature'] for _, d in triage.track(again)], [d['signature'] for _, d in pairs])  # same descriptions, same signatures

    def test_a_match_read_without_the_batch_is_described_the_same(self):
        match = triage.with_cves(CVEMatch.objects.filter(subdomain=self.subs[0]).select_related('subdomain__target_domain'))[0]
        alone = triage.describe(match)
        tracked = triage.track([triage.with_cves(CVEMatch.objects.filter(pk=match.pk).select_related('subdomain__target_domain'))[0]])[0][1]
        self.assertEqual(alone['signature'], tracked['signature'])
        self.assertEqual(alone['host_context'], tracked['host_context'])


class CorrelationChunkTests(TestCase):
    def setUp(self):
        correlation._INDEX_CACHE.update(key=None, value=None)
        org = Org.objects.create(name='A', slug='a')
        self.project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='perf.test', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-1', cvss=9.8, published_at=timezone.now(), affected=NGINX)

    def hosts(self, count):
        out = []
        for i in range(count):
            sub = Subdomain.objects.create(name=f'h{len(out)}-{Subdomain.objects.count()}.perf.test', target_domain=self.domain, scan_history=self.scan)
            sub.technologies.add(Technology.objects.get_or_create(name='nginx:1.18.0')[0])
            out.append(sub)
        return out

    def correlate(self, subs):
        cve_by_id, index = correlation.cve_pool()
        subs = Subdomain.objects.filter(pk__in=[s.pk for s in subs]).prefetch_related('technologies', 'ip_addresses__ports')
        with CaptureQueriesContext(connection) as captured:
            correlation.correlate_subdomains(subs, index, cve_by_id)
        return len(captured.captured_queries)

    def test_the_per_host_readings_are_read_once_per_chunk(self):
        few = self.correlate(self.hosts(2))
        CVEMatch.objects.all().delete()
        many = self.correlate(self.hosts(12))
        self.assertLessEqual(many, few + 3)  # was three more statements for every host (runtimes, version ranges, Java runtimes) and its target
        self.assertEqual(CVEMatch.objects.count(), 12)

    def test_closing_many_stale_matches_writes_one_activity_line_per_project(self):
        subs = self.hosts(5)
        for sub in subs:
            CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0', version_in_range=True, source='tech')
        before = AgentActivity.objects.count()
        hosts = correlation.close_stale(set(), ({s.pk for s in subs}, {self.cve.pk}))
        self.assertEqual(hosts, {s.pk for s in subs})
        self.assertEqual(CVEMatch.objects.filter(ai_verdict='not_affected', ai_reason__startswith='Closed automatically:').count(), 5)
        self.assertEqual(AgentActivity.objects.count(), before + 1)
        line = AgentActivity.objects.latest('id')
        self.assertEqual(line.project_id, self.project.pk)
        self.assertEqual(line.message, '5 CVE candidates closed after their product or version disappeared from inventory')
        self.assertEqual((line.detail['count'], line.detail['decision'], sorted(line.detail['match_ids'])),
                         (5, 'closed_not_applicable', sorted(CVEMatch.objects.values_list('pk', flat=True))))
