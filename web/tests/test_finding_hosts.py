"""Findings that outlive their host, or name it differently from the Hosts page (cveFeed.host_resolver, cveFeed.finding_hosts, archive_closure.close_gone).

The scene, project ``fh`` with the target ``zebra.test`` and three finished full scans, 30, 10 and 1 day ago (the newest is the current inventory):

* ``confluence.zebra.test`` is a current host; its certificate finding names the endpoint ``confluence.zebra.test:443`` (cause A).
* ``confluence-alt.zebra.test`` answers on confluence's address (an alias, folded into confluence on the Hosts page).
* ``outbound.zebra.test`` is current twice: its scanned row and a scanless row with no address beside it (cause B: a lookup of one row of the name
  found a host key the collapse never chose).
* ``ftpr.zebra.test`` was only in the oldest full scan, last seen 30 days ago and missed by the two since; its old address still has FTP open
  (cause C: gone).
* ``mail-only.zebra.test`` never was a host row: a DMARC finding names it (not a host; never closed).
"""
import os
from datetime import timedelta
from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from cveFeed import (
    archive_closure,
    cleartext,
    finding_hosts,
    host_resolver,
    report_data,
    scoring,
    situations,
)
from cveFeed.models import CVEEntry, CVEMatch, HostState, HygieneFinding
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class ResolverUnitTests(TestCase):
    def test_a_port_is_cut_from_a_name_and_never_from_a_bare_ipv6_address(self):
        self.assertEqual(host_resolver.candidates(' Mail.Example.com.:443'), ['mail.example.com.:443', 'mail.example.com'])
        self.assertEqual(host_resolver.base_name('Mail.Example.COM:443'), 'mail.example.com')
        self.assertEqual(host_resolver.base_name('mail.example.com.'), 'mail.example.com')
        self.assertEqual(host_resolver.base_name('2001:db8::1'), '2001:db8::1')
        self.assertEqual(host_resolver.base_name('[2001:db8::1]:443'), '2001:db8::1')
        self.assertEqual(host_resolver.base_name('203.0.113.5:8443'), '203.0.113.5')


class Base(TestCase):
    def setUp(self):
        now = timezone.now()
        self.org = Org.objects.create(name='FH', slug='fh-org')
        self.project = Project.objects.create(name='FH', slug='fh', insert_date=now, org=self.org)
        self.other = Project.objects.create(name='FH2', slug='fh2', insert_date=now, org=self.org)
        self.engine = EngineType.objects.create(engine_name='fh', yaml_configuration='x', default_engine=True)
        self.domain = Domain.objects.create(name='zebra.test', project=self.project, insert_date=now)
        self.old_scan = self.scan(now - timedelta(days=30))
        self.mid_scan = self.scan(now - timedelta(days=10))
        self.new_scan = self.scan(now - timedelta(days=1))
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-8101', cvss=9.8)
        self.root = self.sub('zebra.test', '203.0.113.1')
        self.confluence = self.sub('confluence.zebra.test', '203.0.113.5')
        self.www = self.sub('confluence-alt.zebra.test', '203.0.113.5')
        self.outbound = self.sub('outbound.zebra.test', '203.0.113.9')
        self.outbound_ct = Subdomain.objects.create(target_domain=self.domain, scan_history=None, name='outbound.zebra.test')  # certificate transparency
        self.ftpr_old = self.sub('ftpr.zebra.test', '192.0.2.33', scan=self.old_scan, ports=[(21, 'ftp', '220 FTP server ready')])
        self.sub('confluence.zebra.test', '203.0.113.5', scan=self.old_scan)
        self.cert = HygieneFinding.objects.create(domain=self.domain, host='confluence.zebra.test:443', check_name='tls_expiring', severity=3,
                                                  title='Certificate for confluence.zebra.test:443 expires in 5 days')
        self.dmarc = HygieneFinding.objects.create(domain=self.domain, host='mail-only.zebra.test', check_name='dmarc_missing', severity=3, title='No DMARC')
        self.ftp = HygieneFinding.objects.create(domain=self.domain, host='ftpr.zebra.test', check_name='cleartext_ftp', severity=3,
                                                 title='ftpr.zebra.test: FTP is open (21/tcp)')
        self.match = CVEMatch.objects.create(cve_entry=self.cve, subdomain=self.outbound, scan_history=self.new_scan, matched_product='nginx',
                                             matched_version='1.18.0', version_in_range=True, confidence=0.9, source='port')
        self.alias_vuln = Vulnerability.objects.create(name='Open admin', severity=3, subdomain=self.www, target_domain=self.domain,
                                                       scan_history=self.new_scan, http_url='https://confluence-alt.zebra.test/admin', open_status=True)
        self.ftpr_vuln = Vulnerability.objects.create(name='Anonymous FTP', severity=3, subdomain=self.ftpr_old, target_domain=self.domain,
                                                      scan_history=self.old_scan, http_url='ftp://ftpr.zebra.test/', open_status=True)
        self.ftpr_state = HostState.objects.create(project=self.project, domain=self.domain, host='ftpr.zebra.test', last_seen=now - timedelta(days=30))
        patcher = mock.patch('cveFeed.scoring.rescore_quietly')
        patcher.start()
        self.addCleanup(patcher.stop)

    def scan(self, when, status=2, domain=None):
        return ScanHistory.objects.create(domain=domain or self.domain, scan_type=self.engine, start_scan_date=when, scan_status=status, results_dir='/tmp')

    def sub(self, name, address, scan=None, ports=(), domain=None):
        sub = Subdomain.objects.create(target_domain=domain or self.domain, scan_history=scan or self.new_scan, name=name,
                                       discovered_date=(scan or self.new_scan).start_scan_date)
        ip = IpAddress.objects.get_or_create(address=address)[0]
        sub.ip_addresses.add(ip)
        for number, service, banner in ports:
            ip.ports.add(Port.objects.create(number=number, service_name=service, banner=banner, state='open', protocol='tcp', extra={'method': 'probed'}))
        return sub


class ResolverTests(Base):
    def test_each_name_resolves_to_the_host_the_hosts_page_lists(self):
        inventory = host_resolver.Inventory([self.project.pk])
        self.assertEqual(inventory.resolve(self.project.pk, 'confluence.zebra.test:443')['name'], 'confluence.zebra.test')  # cause A
        self.assertEqual(inventory.resolve(self.project.pk, 'CONFLUENCE-ALT.zebra.test.')['name'], 'confluence.zebra.test')  # an alias: folded into confluence
        self.assertEqual(inventory.resolve(self.project.pk, 'outbound.zebra.test')['id'], self.outbound.pk)  # cause B: two current rows, one host
        self.assertIsNone(inventory.resolve(self.project.pk, 'ftpr.zebra.test'))  # cause C: gone
        self.assertIsNone(inventory.resolve(self.project.pk, 'mail-only.zebra.test'))
        self.assertIsNone(inventory.resolve(self.other.pk, 'confluence.zebra.test'))  # another project: never
        from agentapi import services as svc
        listed = {r.pk for r in svc._one_per_host(host_resolver.current_rows([self.project.pk]), per_project=True)}
        self.assertEqual({rep['id'] for rep in inventory.hosts.values()}, listed)  # the same hosts as the Hosts page

    def test_a_host_gone_from_the_latest_full_scan_is_gone_and_a_target_without_a_full_scan_keeps_its_hosts(self):
        gone = host_resolver.gone_names([self.project.pk], {self.project.pk: {'ftpr.zebra.test', 'confluence.zebra.test', 'mail-only.zebra.test'}})
        self.assertEqual(set(gone), {(self.project.pk, 'ftpr.zebra.test')})
        # a target whose only full scan failed or is still running decides nothing
        fresh = Domain.objects.create(name='fresh.test', project=self.project, insert_date=timezone.now())
        early = self.scan(timezone.now() - timedelta(days=3), status=0, domain=fresh)
        self.sub('a.fresh.test', '198.51.100.7', scan=early, domain=fresh)
        self.scan(timezone.now(), status=1, domain=fresh)
        self.assertEqual(host_resolver.gone_names([self.project.pk], {self.project.pk: {'a.fresh.test'}}), {})

    def test_a_scan_running_on_the_target_holds_its_hosts(self):
        self.scan(timezone.now(), status=1)
        self.assertEqual(host_resolver.gone_names([self.project.pk], {self.project.pk: {'ftpr.zebra.test'}}), {})


class ProducerTests(Base):
    def test_cleartext_reads_only_hosts_of_the_current_inventory(self):
        self.sub('ftp.zebra.test', '203.0.113.21', ports=[(21, 'ftp', '220 FTP server ready')])
        hosts = {f.host for f in cleartext.service_findings(self.domain)}
        self.assertIn('ftp.zebra.test', hosts)
        self.assertNotIn('ftpr.zebra.test', hosts)  # its old row still has FTP open: not a host any more

    def test_the_tls_and_mail_targets_are_current_hosts(self):
        from cveFeed import hygiene
        with mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda names, project=None: list(names)):
            hosts = {host for host, _port in hygiene.tls_targets(self.domain)}
        self.assertIn('confluence.zebra.test', hosts)
        self.assertNotIn('ftpr.zebra.test', hosts)
        self.assertNotIn('ftpr.zebra.test', hygiene.mail_candidates(self.domain)[1])


class GoneClosureTests(Base):
    def test_the_open_findings_of_a_gone_host_close_with_the_marker_and_reopen_when_it_is_back(self):
        out = archive_closure.close_gone([self.project.pk])
        self.assertEqual((out['hosts'], out['hygiene'], out['vulnerability']), (1, 1, 1))
        self.ftp.refresh_from_db()
        self.assertEqual((self.ftp.remediation_status, self.ftp.remediation_by_id), ('fixed', None))
        first = self.ftp.remediation_note.split('\n')[0]
        self.assertTrue(first.startswith(archive_closure.GONE), first)
        self.assertIn('last seen', first)
        self.assertTrue(first.endswith('(ftpr.zebra.test).'))
        self.assertTrue(archive_closure.is_archive_closed(self.ftp, 'ftpr.zebra.test'))
        for row in (self.cert, self.dmarc, self.match, self.alias_vuln):  # current hosts, and a name that never was a host
            row.refresh_from_db()
            self.assertEqual(row.remediation_status, 'open')
        self.assertEqual(archive_closure.close_gone([self.project.pk])['hosts'], 0)  # idempotent
        # the name is back in a scan: what closed as gone reopens
        self.assertEqual(archive_closure.reopen_returned(self.project.pk, ['ftpr.zebra.test']), 2)
        self.ftp.refresh_from_db()
        self.assertEqual(self.ftp.remediation_status, 'open')
        self.assertTrue(self.ftp.remediation_note.startswith(archive_closure.RETURNED))

    def test_one_missed_full_scan_keeps_them_open(self):
        self.sub('ftpr.zebra.test', '192.0.2.33', scan=self.mid_scan)  # the scan 10 days ago still saw it: only the newest one missed it
        HostState.objects.filter(pk=self.ftpr_state.pk).update(last_seen=self.mid_scan.start_scan_date)
        self.assertEqual(archive_closure.close_gone([self.project.pk])['hosts'], 0)
        self.ftp.refresh_from_db()
        self.assertEqual(self.ftp.remediation_status, 'open')
        info = host_resolver.absent_names([self.project.pk], {self.project.pk: {'ftpr.zebra.test'}})[(self.project.pk, 'ftpr.zebra.test')]
        self.assertEqual((info['missed_scans'], info['eligible']), (1, False))
        per = finding_hosts.audit([self.project.pk])['projects'][self.project.pk]
        self.assertEqual((per['gone'], per['gone_grace']), (0, 2))

    def test_missing_for_less_than_the_grace_period_keeps_them_open(self):
        HostState.objects.filter(pk=self.ftpr_state.pk).update(last_seen=timezone.now() - timedelta(days=3))  # two scans missed it, but only 3 days
        self.assertEqual(archive_closure.close_gone([self.project.pk])['hosts'], 0)
        self.ftp.refresh_from_db()
        self.assertEqual(self.ftp.remediation_status, 'open')
        with mock.patch.dict('os.environ', {'CVENGINE_GONE_AFTER_DAYS': '2', 'CVENGINE_TTL_BBOT_DEEP': '0'}):
            self.assertEqual(archive_closure.close_gone([self.project.pk])['hosts'], 1)  # the grace period is set by CVENGINE_GONE_AFTER_DAYS

    def test_a_name_only_the_weekly_deep_discovery_finds_does_not_close_before_the_next_deep_run(self):
        # missed by the standard full scans since a deep run saw it 8 days ago: with the default 7 day grace it closed just before the next deep
        # run (due after 7 days) and reopened when that run found it again, every week. The grace is never shorter than the deep cadence plus 2 days.
        env = {k: v for k, v in os.environ.items() if k not in ('CVENGINE_GONE_AFTER_DAYS', 'CVENGINE_TTL_BBOT_DEEP')}
        with mock.patch.dict('os.environ', env, clear=True):
            self.assertEqual(host_resolver.gone_after_days(), 9)
            HostState.objects.filter(pk=self.ftpr_state.pk).update(last_seen=timezone.now() - timedelta(days=8))
            self.assertEqual(archive_closure.close_gone([self.project.pk])['hosts'], 0)
            self.ftp.refresh_from_db()
            self.assertEqual(self.ftp.remediation_status, 'open')
            # a host that is really gone (the deep run missed it too) still closes
            HostState.objects.filter(pk=self.ftpr_state.pk).update(last_seen=timezone.now() - timedelta(days=10))
            self.assertEqual(archive_closure.close_gone([self.project.pk])['hosts'], 1)
        with mock.patch.dict('os.environ', {'CVENGINE_GONE_AFTER_DAYS': '3', 'CVENGINE_TTL_BBOT_DEEP': '336'}):
            self.assertEqual(host_resolver.gone_after_days(), 16)  # a two week deep cadence raises it with it
        with mock.patch.dict('os.environ', {'CVENGINE_GONE_AFTER_DAYS': '30'}):
            self.assertEqual(host_resolver.gone_after_days(), 30)  # a longer grace is kept as set

    def test_a_person_s_closure_is_never_touched(self):
        HygieneFinding.objects.filter(pk=self.ftp.pk).update(remediation_status='accepted_risk', remediation_by=User.objects.create_user('p'))
        archive_closure.close_gone([self.project.pk])
        self.ftp.refresh_from_db()
        self.assertEqual(self.ftp.remediation_status, 'accepted_risk')

    def test_the_hygiene_run_closes_them(self):
        from cveFeed import hygiene
        review = {'infos': {}, 'mail_hosts': [], 'mail': {}, 'unknown_tls': set(), 'unknown_mail': set()}
        with mock.patch.object(hygiene, '_remote_review', return_value=(review, False)), mock.patch('cveFeed.triage.triage_hygiene'):
            hygiene.run_hygiene(self.domain.pk)
        self.ftp.refresh_from_db()
        self.assertNotEqual((self.ftp.status, self.ftp.remediation_status), ('open', 'open'))  # resolved by the run or closed as gone: not open


class SituationTests(Base):
    def rows(self):
        return {r['host']: r for r in situations.listing([self.project.pk], size=100)['results']}

    def test_findings_are_grouped_under_the_host_the_hosts_page_lists_and_link_to_it(self):
        rows = self.rows()
        self.assertNotIn('confluence.zebra.test:443', rows)
        confluence = rows['confluence.zebra.test']
        self.assertEqual(confluence['host_link'], '/cve/fh/hosts/?host=confluence.zebra.test')
        self.assertEqual({f['kind'] for f in confluence['findings']}, {'hygiene', 'vulnerability'})  # its certificate and its alias's finding
        self.assertIn('confluence-alt.zebra.test', confluence['also_known_as'])
        self.assertIsNotNone(rows['outbound.zebra.test']['host_id'])  # cause B: the host is found
        self.assertNotIn('ftpr.zebra.test', rows)  # gone from the inventory: no situation
        mail = rows['mail-only.zebra.test']  # never a host: kept, linked to its finding, not to an empty Hosts search
        self.assertIsNone(mail['host_id'])
        self.assertEqual(mail['host_link'], f'/cve/fh/hygiene/#hygiene-{self.dmarc.pk}')
        self.assertEqual(situations.one([self.project.pk], 'confluence.zebra.test:443')['host'], 'confluence.zebra.test')


class ReportAndScoreTests(Base):
    def test_a_certificate_finding_counts_for_its_host_in_the_reports(self):
        sources, _ = report_data._sources(self.project, False)
        self.assertEqual(report_data._per_host(sources)['confluence.zebra.test'], 1)
        sources, _ = report_data._sources(self.project, False, names=['confluence.zebra.test'])
        self.assertEqual(sources['hygiene'].count(), 1)

    def test_a_certificate_finding_counts_in_its_hosts_score(self):
        before = Subdomain.objects.get(pk=self.confluence.pk).score
        scoring.rescore_hosts(self.project.pk, ['confluence.zebra.test'])
        self.assertGreater(Subdomain.objects.get(pk=self.confluence.pk).score, before)


class AuditTests(Base):
    def test_the_audit_names_each_cause_and_apply_closes_the_gone_ones(self):
        result = finding_hosts.audit([self.project.pk])
        per = result['projects'][self.project.pk]
        self.assertEqual((per['port'], per['alias'], per['gone'], per['not_a_host']), (1, 2, 2, 1))  # alias: the alias's finding and outbound's match
        out = StringIO()
        call_command('audit_finding_hosts', stdout=out)
        self.assertIn('Dry run', out.getvalue())
        self.assertIn('gone: 2 eligible now, 0 missing but inside the grace period (2 full scans and 7 days)', out.getvalue())
        call_command('audit_finding_hosts', '--apply', stdout=out)
        after = finding_hosts.audit([self.project.pk])
        self.assertEqual((after['totals']['gone'], after['totals']['archived']), (0, 0))
        out = StringIO()
        call_command('audit_finding_hosts', '--apply', stdout=out)
        self.assertIn('closed 0 on 0 hosts gone', out.getvalue())  # idempotent

    def test_every_open_finding_maps_to_a_current_host_or_is_closed(self):
        """The consistency rule: after the fix, no open finding points at a host that is gone or archived; what does not map is a name that never was a host."""
        HostState.objects.create(project=self.project, domain=self.domain, host='confluence-alt.zebra.test', archived_at=timezone.now(), archived_by_user=True)
        finding_hosts.fix()
        result = finding_hosts.audit()
        self.assertEqual({c: n for c, n in result['totals'].items() if c in finding_hosts.UNRESOLVED and n}, {'not_a_host': 1})
        inventory = host_resolver.Inventory([self.project.pk])
        for f in archive_closure._live('hygiene', HygieneFinding.objects.filter(domain__project=self.project)):
            self.assertTrue(inventory.resolve(self.project.pk, f.host) or f.host == 'mail-only.zebra.test', f.host)

    def test_system_status_says_so_until_they_are_closed(self):
        from django.core.cache import cache
        cache.delete(finding_hosts.CACHE_KEY)
        problems = []
        finding_hosts.status_check(problems)
        self.assertTrue(any('point at hosts not in the inventory' in p for p in problems), problems)
        finding_hosts.fix([self.project.pk])
        cache.delete(finding_hosts.CACHE_KEY)
        problems = []
        finding_hosts.status_check(problems)
        self.assertEqual(problems, [])


class DeleteHostTests(Base):
    def test_deleting_a_host_takes_its_certificate_findings_and_leaves_a_look_alike(self):
        from agentapi import host_manage as hm
        other = HygieneFinding.objects.create(domain=self.domain, host='xconfluence.zebra.test:443', check_name='tls_expiring', severity=3, title='x')
        hm._purge(self.project, 'confluence.zebra.test')
        self.assertFalse(HygieneFinding.objects.filter(pk=self.cert.pk).exists())
        self.assertTrue(HygieneFinding.objects.filter(pk=other.pk).exists())
