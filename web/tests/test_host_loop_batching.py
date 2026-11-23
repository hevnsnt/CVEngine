"""The per-host loops of scan post-processing read what is the same for every host once per call, not once per host: the screenshot stage's
exclusion list, archived hosts and internal networks (cveFeed.web_shot.queue_for_subs), the TLS and SLP target gate (cveFeed.hygiene), the version
source pages and stored readings (cveFeed.version_sources) and the Java runtime rows (cveFeed.java_runtime). Each host still gets exactly the
decision it gets on its own, an excluded or address-excluded host is still refused, and an unreadable do-not-scan list still refuses everything."""
from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import hygiene, java_runtime, version_sources, web_shot
from cveFeed import version_catalogue as catalogue
from cveFeed.models import ExcludedAddress, HostExclusion, HostScreenshot, HostState, JavaRuntime, ProbeObservation
from dashboard.models import Org, Project
from startScan.models import EndPoint, IpAddress, Port, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_java_runtime import JavaFixture, reading
from tests.test_version_sources import VersionFixture
from tests.test_web_shot import ShotFixture


def count(ctx, *tables):
    """How many captured statements name one of ``tables`` (lowercase fragments of the table names)."""
    return sum(1 for q in ctx.captured_queries if any(t in q['sql'].lower() for t in tables))


# ------------------------------------------------------------------------------------------------ screenshots

class ScreenshotGateTests(ShotFixture, TestCase):
    GATE_TABLES = ('cvefeed_hostexclusion', 'cvefeed_hostmove', 'cvefeed_excludedaddress', 'cvefeed_hoststate', 'cvefeed_internalrange')

    def subs(self, project):
        return list(Subdomain.objects.filter(target_domain__project=project).select_related('target_domain')
                    .prefetch_related('ip_addresses__ports').order_by('id'))

    def gate_reads(self, project):
        ExcludedAddress.objects.create(org=project.org, cidr='192.0.2.0/24')  # a do-not-scan list, so the address-aware read runs too
        subs = self.subs(project)
        with CaptureQueriesContext(connection) as ctx:
            out = web_shot.queue_for_subs(subs, project.pk)
        self.assertEqual(out['queued'], len(subs))
        return count(ctx, *self.GATE_TABLES)

    def test_the_gate_reads_do_not_grow_with_the_hosts(self):
        small = self.gate_reads(self.project_with_hosts('small', 2, start=20))
        big = self.gate_reads(self.project_with_hosts('big', 8, start=30))
        self.assertGreater(small, 0)
        self.assertEqual(small, big)

    def test_the_lists_are_read_once_per_call_and_afresh_by_the_next_call(self):
        from cveFeed import archive_rediscovery, exclusions
        from targetApp import target_types
        project = self.project_with_hosts('once', 6, start=60)
        with mock.patch('cveFeed.exclusions.excluded_names', wraps=exclusions.excluded_names) as banned, \
                mock.patch('cveFeed.archive_rediscovery.archived_names', wraps=archive_rediscovery.archived_names) as archived, \
                mock.patch('targetApp.target_types.internal_networks', wraps=target_types.internal_networks) as networks:
            web_shot.queue_for_subs(self.subs(project), project.pk)
            web_shot.queue_for_subs(self.subs(project), project.pk)
        self.assertEqual((banned.call_count, archived.call_count, networks.call_count), (2, 2, 2))

    def test_every_host_gets_the_decision_it_gets_on_its_own(self):
        from cveFeed.bounty_gate import Gate
        project = self.project_with_hosts('mix', 5, start=40)
        subs = self.subs(project)
        HostExclusion.objects.create(org=project.org, host=subs[1].name)  # excluded by name
        ExcludedAddress.objects.create(org=project.org, cidr='198.51.40.3/32')  # subs[2]'s stored address: excluded by address
        HostState.objects.create(project=project, domain=subs[0].target_domain, host=subs[3].name, archived_at=timezone.now())
        alone = {sub.name: web_shot.queue_refusal(project.pk, sub.name, Gate(), unattended=True) for sub in subs}  # the per-host read
        self.assertEqual(alone, {subs[0].name: '', subs[1].name: 'excluded', subs[2].name: 'excluded', subs[3].name: 'archived', subs[4].name: ''})
        out = web_shot.queue_for_subs(subs, project.pk)
        self.assertEqual(set(HostScreenshot.objects.filter(project=project).values_list('host', flat=True)), {n for n, why in alone.items() if not why})
        self.assertEqual((out['queued'], out['hosts']), (2, 2))

    def test_an_unreadable_address_list_still_refuses_every_host(self):
        project = self.project_with_hosts('dark', 3, start=50)
        with mock.patch('cveFeed.exclusions.address_networks', side_effect=RuntimeError('db down')):
            out = web_shot.queue_for_subs(self.subs(project), project.pk)
        self.assertEqual((out['queued'], out['hosts'], out['blocked']), (0, 0, 0))
        self.assertFalse(HostScreenshot.objects.filter(project=project).exists())

    def test_an_unreadable_name_list_still_stops_the_stage(self):
        project = self.project_with_hosts('stop', 2, start=70)
        with mock.patch('cveFeed.exclusions.excluded_names', side_effect=RuntimeError('db down')), self.assertRaises(RuntimeError):
            web_shot.queue_for_subs(self.subs(project), project.pk)
        self.assertFalse(HostScreenshot.objects.filter(project=project).exists())

    def test_an_internal_address_is_still_blocked_among_other_hosts(self):
        from cveFeed.models import InternalRange
        InternalRange.objects.create(project=self.project, cidr='10.1.2.0/24')
        subs = [self.host(name='10.1.2.3', ports=((80, 'http'),), address='10.1.2.3'), self.host(name='www.rt.test')]
        out = web_shot.queue_for_subs(subs, self.project.pk)
        rows = {(r.host, r.port): r.outcome for r in HostScreenshot.objects.filter(project=self.project)}
        self.assertEqual(rows, {('10.1.2.3', 80): 'blocked', ('www.rt.test', 443): 'queued', ('www.rt.test', 80): 'queued'})
        self.assertEqual((out['queued'], out['blocked']), (2, 1))


# ------------------------------------------------------------------------------------------------ hygiene TLS and SLP targets

class HygieneTargetGateTests(TestCase):
    GATE_TABLES = ('cvefeed_hostexclusion', 'cvefeed_hostmove', 'cvefeed_hoststate', 'cvefeed_bountyengagement')

    def setUp(self):
        now = timezone.now()
        self.project = Project.objects.create(name='T', slug='tt', insert_date=now, org=Org.objects.create(name='T', slug='t'))
        self.domain = Domain.objects.create(name='tls.test', project=self.project, insert_date=now)

    def hosts(self, start, count):
        for i in range(start, start + count):
            sub = Subdomain.objects.create(name=f'h{i}.tls.test', target_domain=self.domain)
            ip = IpAddress.objects.create(address=f'198.51.100.{i + 1}')
            sub.ip_addresses.add(ip)
            ip.ports.add(Port.objects.create(number=8443), Port.objects.create(number=427, state='open'))

    def gate_reads(self, run):
        with CaptureQueriesContext(connection) as ctx:
            run()
        return count(ctx, *self.GATE_TABLES)

    def test_the_gate_reads_do_not_grow_with_the_hosts(self):
        self.hosts(0, 2)
        small = (self.gate_reads(lambda: hygiene.tls_targets(self.domain)), self.gate_reads(lambda: hygiene.slp_targets(self.domain)))
        self.hosts(2, 6)
        big = (self.gate_reads(lambda: hygiene.tls_targets(self.domain)), self.gate_reads(lambda: hygiene.slp_targets(self.domain)))
        self.assertEqual(small, big)
        from targetApp import target_types
        with mock.patch('targetApp.target_types.scannable_hosts', wraps=target_types.scannable_hosts) as gate:
            hygiene.tls_targets(self.domain)
        self.assertEqual(gate.call_count, 1)

    def test_the_same_hosts_are_kept_and_refused_as_one_at_a_time(self):
        from targetApp.target_types import scannable_hosts
        self.hosts(0, 5)
        HostExclusion.objects.create(org=self.project.org, host='h1.tls.test')
        HostState.objects.create(project=self.project, domain=self.domain, host='h2.tls.test', archived_at=timezone.now())
        names = ['tls.test'] + [f'h{i}.tls.test' for i in range(5)]
        alone = {name for name in names if scannable_hosts([name], project=self.project.pk)}
        self.assertFalse({'h1.tls.test', 'h2.tls.test'} & alone)
        tls = hygiene.tls_targets(self.domain)
        self.assertEqual({host for host, _port in tls}, alone)
        self.assertEqual({port for host, port in tls if host == 'h0.tls.test'}, {443, 8443})
        self.assertEqual([host for host, _port in hygiene.slp_targets(self.domain)], sorted(alone - {'tls.test'}))

    def test_nothing_to_judge_reads_nothing(self):
        with mock.patch('targetApp.target_types.scannable_hosts') as gate:
            self.assertEqual(hygiene.slp_targets(self.domain), [])
            self.assertEqual(hygiene.tls_targets(self.domain, hosts=['other.test']), [])
        gate.assert_not_called()


# ------------------------------------------------------------------------------------------------ version sources

class VersionLoopTests(VersionFixture, TestCase):
    def passive_run(self, scan):
        with mock.patch('cveFeed.version_sources.enabled', return_value=False), CaptureQueriesContext(connection) as ctx:
            version_sources.run_for_scan(scan.id)
        return count(ctx, 'cvefeed_probeobservation')

    def test_hosts_with_nothing_stored_cost_no_reading_reads_each(self):
        small = self.passive_run(self.host_scan(names=('a.rt.test', 'b.rt.test'), web=False))
        big = self.passive_run(self.host_scan(names=tuple(f'h{i}.rt.test' for i in range(6)), web=False, address='203.0.113.9'))
        self.assertEqual(small, big)

    def test_a_reading_is_stored_and_one_the_host_no_longer_gives_is_dropped(self):
        scan = self.host_scan(names=('a.rt.test', 'b.rt.test'), web=False)
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='b.rt.test', probe='vsrc:nmap', kind='version',
                                        product='OpenSSH', version='9.6', port=22)  # a port the host no longer shows
        Subdomain.objects.filter(scan_history=scan, name='a.rt.test').update(webserver='Werkzeug/2.3.7 Python/3.11.4')
        self.passive_run(scan)
        self.assertTrue(ProbeObservation.objects.filter(host='a.rt.test', probe='vsrc:passive').exists())
        self.assertFalse(ProbeObservation.objects.filter(host='b.rt.test').exists())
        Subdomain.objects.filter(scan_history=scan, name='a.rt.test').update(webserver='')
        self.passive_run(scan)
        self.assertFalse(ProbeObservation.objects.filter(host='a.rt.test', probe='vsrc:passive').exists())

    def test_a_later_row_of_the_same_name_still_drops_what_an_earlier_one_stored(self):
        first = self.host_scan(names=('a.rt.test',), web=False)
        second = self.host_scan(names=('a.rt.test',), web=False)
        Subdomain.objects.filter(scan_history=first).update(webserver='Werkzeug/2.3.7 Python/3.11.4')
        subs = [Subdomain.objects.select_related('target_domain').prefetch_related('technologies', 'ip_addresses__ports').get(scan_history=s)
                for s in (first, second)]
        version_sources.prefetch_derived(subs)
        self.assertIs(subs[0]._derived_probes, subs[1]._derived_probes)
        version_sources.refresh_host(subs[0])
        self.assertTrue(ProbeObservation.objects.filter(host='a.rt.test', probe='vsrc:passive').exists())
        version_sources.refresh_host(subs[1])  # gives nothing: what the first row stored goes, as it does one host at a time
        self.assertFalse(ProbeObservation.objects.filter(host='a.rt.test', probe='vsrc:passive').exists())

    def test_discovered_pages_for_many_hosts_is_what_each_host_gets_alone(self):
        scan = self.host_scan(names=('a.rt.test', 'b.rt.test', 'c.rt.test', 'd.rt.test'))
        subs = list(scan.subdomain_set.select_related('target_domain').order_by('name'))
        a, b, c, _d = subs
        template = catalogue.BY_ID['phpinfo'].exposure.template
        Vulnerability.objects.create(target_domain=self.domain, scan_history=scan, subdomain=a, source='nuclei', template_id=template, name='phpinfo',
                                     severity=1, open_status=True, http_url='https://a.rt.test/info.php?x=1')
        EndPoint.objects.create(scan_history=scan, target_domain=self.domain, subdomain=b, http_url='https://b.rt.test/x.php', http_status=200,
                                page_title='PHP 8.2.12 - phpinfo()')
        for i in range(12):  # more than the ten each query keeps
            EndPoint.objects.create(scan_history=scan, target_domain=self.domain, subdomain=c, http_url=f'https://c.rt.test/p{i}/phpinfo.php', http_status=200)
        batch = version_sources.discovered_pages_for(subs)
        for sub in subs:
            self.assertEqual(batch[sub.pk], version_sources.discovered_pages(sub), sub.name)
        self.assertTrue(batch[a.pk] and batch[b.pk] and batch[c.pk])
        self.assertEqual(len(batch[c.pk]['phpinfo']), 10)
        self.assertEqual(batch[_d.pk], {})

    def test_planning_reads_the_pages_in_queries_that_do_not_grow_with_the_hosts(self):
        def reads(scan):
            with CaptureQueriesContext(connection) as ctx:
                version_sources.candidates(scan)
            return count(ctx, 'startscan_endpoint', 'startscan_vulnerability')
        small = reads(self.host_scan(names=('a.rt.test', 'b.rt.test')))
        big = reads(self.host_scan(names=tuple(f'h{i}.rt.test' for i in range(6)), address='203.0.113.9'))
        self.assertEqual(small, big)

    def test_an_excluded_host_is_still_left_out_of_the_plan(self):
        scan = self.host_scan(techs=('Grafana',), names=('a.rt.test', 'b.rt.test'))
        HostExclusion.objects.create(org=self.project.org, host='b.rt.test')
        self.assertEqual(set(version_sources.candidates(scan)), {'a.rt.test'})
        with mock.patch('cveFeed.exclusions.address_networks', side_effect=RuntimeError('db down')):
            self.assertEqual(version_sources.candidates(scan), {})  # an unreadable do-not-scan list: nothing


# ------------------------------------------------------------------------------------------------ Java runtime

class JavaLoopTests(JavaFixture, TestCase):
    def passive_run(self, scan):
        with mock.patch('cveFeed.java_runtime.enabled', return_value=True), mock.patch('cveFeed.java_runtime.candidates', return_value={}), \
                CaptureQueriesContext(connection) as ctx:
            java_runtime.run_for_scan(scan.id)
        return count(ctx, 'cvefeed_javaruntime', 'cvefeed_probeobservation')

    def test_hosts_with_no_java_cost_no_reads_each(self):
        small = self.passive_run(self.java_scan(names=('a.rt.test', 'b.rt.test'), web=False))
        big = self.passive_run(self.java_scan(names=tuple(f'h{i}.rt.test' for i in range(6)), web=False, address='203.0.113.9'))
        self.assertEqual(small, big)

    def test_a_derived_reading_is_stored_and_dropped_when_the_host_no_longer_gives_it(self):
        scan = self.java_scan(techs=('Confluence:8.5.3',), names=('a.rt.test', 'b.rt.test'))
        java_runtime.store(self.project.pk, self.domain.pk, 'b.rt.test', 'metrics:9100', reading('17.0.9', source='metrics'))
        self.passive_run(scan)
        self.assertEqual(set(JavaRuntime.objects.filter(key='bundled:confluence').values_list('host', flat=True)), {'a.rt.test', 'b.rt.test'})
        Subdomain.objects.get(scan_history=scan, name='b.rt.test').technologies.clear()
        self.passive_run(scan)
        self.assertEqual(set(JavaRuntime.objects.filter(key='bundled:confluence').values_list('host', flat=True)), {'a.rt.test'})
        self.assertTrue(JavaRuntime.objects.filter(host='b.rt.test', key='metrics:9100').exists())  # not derived: kept

    def test_a_later_row_of_the_same_name_still_drops_what_an_earlier_one_stored(self):
        first = self.java_scan(techs=('Confluence:8.5.3',))
        second = self.java_scan()
        subs = [Subdomain.objects.select_related('target_domain', 'scan_history').prefetch_related('technologies', 'ip_addresses__ports').get(scan_history=s)
                for s in (first, second)]
        prefetched = java_runtime.prefetch_passive(subs)
        java_runtime.refresh_host(subs[0], prefetched=prefetched)
        self.assertTrue(JavaRuntime.objects.filter(key='bundled:confluence').exists())
        java_runtime.refresh_host(subs[1], prefetched=prefetched)  # gives nothing: dropped, as it is one host at a time
        self.assertFalse(JavaRuntime.objects.filter(key='bundled:confluence').exists())
