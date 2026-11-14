"""The optional OpenVAS (Greenbone) add-on, run by Sentinels: the host gating, the hand-off of a due batch to a Sentinel, the one-task-at-a-time
sweep, the import of a Sentinel's report (QoD, severity, dedupe, resolution), the settings API and its permissions, and the off-by-default behaviour
(nothing is scheduled, nothing starts). This server opens no GMP session and runs no scan (``sentinel_dispatch.NEVER_LOCAL``); the GMP client and the
parsing of gvmd's answers are the Sentinel repo's (client/openvas.py, client/tests/test_openvas.py and test_openvas_gmp.py)."""
import json
import os
import re
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_dispatch as dispatch
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed import openvas_scan as ov
from cveFeed.models import CVEEntry, CVEMatch, OpenvasOrg, OpenvasProject, OpenvasRun, OpenvasSettings, ProbeObservation, ScanControl, ServiceRun
from dashboard.models import AuditLog, Org, OrgMembership, Project
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.fake_scanner import LocalFallback, assert_ran_nowhere_locally
from tests.test_route_auth import RouteFixture
from tests.test_settings import send
from tests.test_tenancy import client_for

ROOT = Path(__file__).resolve().parents[2]
OID_APACHE = '1.3.6.1.4.1.25623.1.0.117721'
OID_BANNER = '1.3.6.1.4.1.25623.1.0.100315'
OID_SSH = '1.3.6.1.4.1.25623.1.0.105001'
OID_PLAIN = '1.3.6.1.4.1.25623.1.0.900001'
IPS = {'www.rt.test': '93.184.216.5', 'api.rt.test': '93.184.216.6', 'db.rt.test': '93.184.214.7'}


class ParseTests(SimpleTestCase):


    def test_an_overlong_cve_id_from_a_sentinel_is_dropped_not_stored(self):
        # security review 1.3.4 (sentinel-2): CveId.name holds 100 characters; a longer id failed the save and with it the whole stage
        from agentapi.sentinel_broker import _clean_findings, _clean_openvas_result
        long_id = 'CVE-2024-' + '1' * 200
        self.assertIsNone(ov.CVE_RE.match(long_id))
        self.assertTrue(ov.CVE_RE.match('CVE-2024-1234567'))
        found, _ = _clean_findings([{'template_id': 't', 'host': 'h', 'cve_ids': [long_id, 'CVE-2021-41773']}])
        self.assertEqual(found[0]['cve_ids'], ['CVE-2021-41773'])
        body = _clean_openvas_result({'results': [{'oid': '1.3.6.1.4.1.25623.1.0.1', 'address': '93.184.216.5', 'cves': [long_id]}]})
        self.assertEqual(body['results'][0]['cves'], [])


    def test_clean_strips_control_characters_and_clips(self):
        self.assertEqual(ov.clean('a\x00b\x1b[0mc\x7fd\te\nf'), 'ab[0mcd\te\nf')
        self.assertEqual(len(ov.clean('x' * 9000)), ov.MAX_TEXT)
        self.assertEqual(ov.clean(None), '')

    def test_severity_levels_follow_cvss(self):
        self.assertEqual([ov.severity_level(s) for s in (0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)], [0, 1, 1, 2, 2, 3, 3, 4, 4])

    def test_the_type_decides_and_qod_80_is_a_banner_read_not_a_confirmation(self):
        self.assertEqual(ov.CONFIRMED_QOD, 95)
        for qod_type in ('remote_active', 'remote_vul', 'remote_app', 'package', 'registry', 'exploit'):
            self.assertTrue(ov.confirmed({'qod': 80, 'qod_type': qod_type}), qod_type)
        for qod_type in ('remote_banner', 'executable_version', 'remote_analysis', 'remote_probe', 'remote_banner_unreliable'):
            self.assertFalse(ov.confirmed({'qod': 99, 'qod_type': qod_type}), qod_type)  # the number never overrides a banner type
        self.assertTrue(ov.confirmed({'qod': 95, 'qod_type': ''}))  # no type from gvmd: the number alone
        self.assertFalse(ov.confirmed({'qod': 94, 'qod_type': ''}))

    def test_nothing_marks_third_party_text_safe_for_html(self):
        for name in ('openvas_scan.py', 'openvas_admin.py'):
            text = (ROOT / 'web' / 'cveFeed' / name).read_text()
            self.assertNotIn('mark_safe', text)
            self.assertNotIn('|safe', text)
        js = (ROOT / 'web' / 'static' / 'cve' / 'settings.js').read_text()
        section = js[js.index('async openvas(m)'):js.index('async keys(m)')]
        self.assertNotIn('innerHTML', section)


def as_item(kw):
    """A Sentinel-reported OpenVAS result (``sentinel_broker.clean_result``'s own output shape) from the short dicts the tests below use (``APACHE``...)."""
    port = kw.get('port', '443/tcp')
    item = {'oid': kw['oid'], 'name': kw['name'], 'family': 'Web application abuses', 'address': kw['host'], 'hostname': kw.get('hostname', ''), 'port': port,
            'port_number': int(port.split('/')[0]) if port.split('/')[0].isdigit() else 0, 'severity': kw['severity'], 'threat': 'High', 'qod': kw['qod'],
            'qod_type': kw.get('qod_type', 'remote_banner'), 'result': kw.get('description', 'Detection result.'),
            'summary': f"The product {kw['name']} is affected.", 'insight': 'A flaw in request handling.', 'impact': '', 'affected': 'Versions before 2.4.51',
            'solution': 'Update to the fixed release.', 'solution_type': 'VendorFix', 'cvss_vector': 'AV:N/AC:L/Au:N/C:P/I:P/A:P', 'cves': list(kw.get('cves', ())),
            'urls': list(kw.get('urls', ()))}
    for pair in str(kw.get('tags') or '').split('|'):  # gvmd's own ``key=value|key=value`` tag text, as the Sentinel splits it
        key, _, value = pair.partition('=')
        if key in ('summary', 'insight', 'impact', 'affected', 'solution'):
            item[key] = value
    item.update(kw.get('over', {}))
    return item


class Fixture(RouteFixture):
    """An organisation, a project with three hosts, the add-on switched on and the project opted in. No Sentinel exists until a test makes one
    (``make_sentinel``): with none, a due batch stays due."""

    def setUp(self):
        super().setUp()
        mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MAX_HOSTS': '2'}).start()  # the shipped default is one host per task (HeatGateTests); these tests batch two
        self.scan_obj = self.scan(names=('www.rt.test',), ip='93.184.216.5')
        self.scan(names=('api.rt.test',), ip='93.184.216.6')
        self.scan(names=('db.rt.test',), ip='93.184.214.7')
        self.settings = OpenvasSettings.current()
        self.settings.enabled = True
        self.settings.save()
        self.link = OpenvasProject.objects.create(project=self.project, enabled=True, hosts=['www.rt.test', 'api.rt.test'],
                                                 forced_hosts=['www.rt.test', 'api.rt.test'])  # listed and forced: the heat gate has its own tests (HeatGateTests)
        self.cve = CVEEntry.objects.create(cve_id='CVE-2021-41773', title='Apache path traversal', published_at=timezone.now(), cvss=7.5)
        self.cve2 = CVEEntry.objects.create(cve_id='CVE-2019-0001', title='Old thing', published_at=timezone.now(), cvss=5.0)

    def resolve(self, host, project_id):
        return IPS[host]

    def make_sentinel(self, capabilities=('openvas',), scope_project=True):
        """One live Sentinel that may take OpenVAS work of the project (made once per test)."""
        if getattr(self, '_sentinel', None) is None or capabilities != ('openvas',) or not scope_project:
            user = User.objects.create_user(f'sentinel-owner-ov-{Agent.objects.count()}', password='x')
            token, _raw = create_token(user, f'sentinel-token-ov-{Agent.objects.count()}')
            agent = Agent.objects.create(token=token, name=f'gvm-sentinel-{Agent.objects.count()}', kind='scanner', status='active',
                                         scope={'orgs': [], 'projects': [self.project.slug] if scope_project else [], 'hosts': []},
                                         capabilities=list(capabilities), last_seen=timezone.now())
            if capabilities == ('openvas',) and scope_project:
                self._sentinel = agent
            return agent
        return self._sentinel

    def tick(self):
        return ov.tick(resolve=self.resolve, blocked=lambda h: False)

    def run_scan(self, results, scanned=None, partial=False, stale=0):
        """A whole sweep through a Sentinel: hand the due batch over (forgetting earlier runs), let the Sentinel report ``results`` (a list of the\n        ``APACHE`` style dicts) for ``scanned`` addresses (default: those with a result), import the report. Returns the import's answer."""
        self.make_sentinel()
        ServiceRun.objects.all().delete()
        self.assertEqual(self.tick()['status'], 'running')
        run = OpenvasRun.objects.get(status='running')
        task = run.sentinel_task
        from agentapi.sentinel_broker import _clean_openvas_result
        items = [as_item(r) for r in results]
        task.result = _clean_openvas_result({'results': items, 'scanned_addresses': sorted(scanned if scanned is not None else {i['address'] for i in items}),
                                             'without_cve': sum(1 for i in items if not i['cves']), 'unusable': 0, 'partial': partial, 'nvt_cache_stale': stale})  # as the broker stores it
        task.status = 'done'
        task.save(update_fields=['result', 'status'])
        return self.tick()


APACHE = dict(host='93.184.216.5', port='443/tcp', oid=OID_APACHE, name='Apache HTTP Server < 2.4.51 Path Traversal', severity=9.8, qod=99,
              cves=['CVE-2021-41773'], hostname='www.rt.test', qod_type='remote_active')
BANNER = dict(host='93.184.216.5', port='80/tcp', oid=OID_BANNER, name='Old thing version check', severity=5.0, qod=30, cves=['CVE-2019-0001'],
              hostname='www.rt.test', qod_type='remote_banner_unreliable')
PLAIN = dict(host='93.184.216.5', port='22/tcp', oid=OID_PLAIN, name='SSH weak algorithms', severity=5.3, qod=80, cves=[], hostname='www.rt.test')
LOG = dict(host='93.184.216.6', port='general/tcp', oid='1.3.6.1.4.1.25623.1.0.10267', name='OS detection', severity=0.0, qod=80, cves=[], hostname='api.rt.test')


class OffByDefaultTests(Fixture, TestCase):
    def test_a_fresh_install_has_the_addon_off_and_nothing_scheduled(self):
        from django_celery_beat.models import PeriodicTask
        OpenvasSettings.objects.all().delete()
        row = OpenvasSettings.current()
        self.assertEqual((row.enabled, row.gmp_username, bool(row.gmp_password)), (False, '', False))
        task = PeriodicTask.objects.get(name='cvengine-openvas-sweep')
        self.assertEqual((task.task, task.queue, task.enabled), ('openvas_sweep', 'openvas_queue', False))
        self.assertFalse(OpenvasProject.objects.exclude(pk=self.link.pk).exists())

    def test_while_it_is_off_the_sweep_does_nothing_and_asks_no_sentinel(self):
        self.make_sentinel()
        self.settings.enabled = False
        self.settings.save()
        self.assertEqual(self.tick(), {'skipped': 'the OpenVAS add-on is switched off'})
        self.assertEqual(OpenvasRun.objects.count(), 0)
        self.assertFalse(SentinelTask.objects.exists())

    def test_the_check_task_is_not_part_of_a_default_scan(self):
        self.settings.enabled = False
        self.settings.save()
        self.assertEqual(ov.carry_forward(self.scan_obj), 0)

    def test_the_celery_worker_consumes_the_queue_and_status_knows_it(self):
        entry = (ROOT / 'web' / 'celery-entrypoint.sh').read_text()
        self.assertIn('openvas_queue', entry.split('classic_queues+=')[1].splitlines()[0])
        from agentapi import system_status
        self.assertIn('openvas_queue', system_status.QUEUES)
        from reNgine.celery import app
        import cveFeed.tasks  # noqa: F401
        self.assertEqual(app.tasks['openvas_sweep'].queue, 'openvas_queue')
        self.assertNotIn('openvas_check', app.tasks)  # no worker opens a GMP session any more


class GatingTests(Fixture, TestCase):
    def due(self, hosts=None, **kw):
        return ov.due(self.project.id, hosts if hosts is not None else self.link.hosts, resolve=kw.get('resolve', self.resolve), blocked=kw.get('blocked', lambda h: False))

    def test_opted_in_hosts_are_due_with_their_vetted_address(self):
        self.assertEqual({(h, ip) for h, ip, _d in self.due()}, {('www.rt.test', '93.184.216.5'), ('api.rt.test', '93.184.216.6')})

    def test_a_host_that_is_not_opted_in_is_never_scanned(self):
        self.assertNotIn('db.rt.test', {h for h, _ip, _d in self.due()})

    def test_the_default_is_no_hosts(self):
        self.assertEqual(self.due([]), [])
        self.assertEqual(OpenvasProject.objects.create(project=Project.objects.create(name='Q', slug='q', insert_date=timezone.now())).hosts, [])

    def test_an_excluded_host_is_dropped(self):
        from cveFeed.models import HostExclusion
        HostExclusion.objects.create(org=self.project.org, host='api.rt.test', include_subdomains=False)
        self.assertEqual({h for h, _ip, _d in self.due()}, {'www.rt.test'})

    def test_a_name_that_resolves_somewhere_prohibited_is_dropped_by_the_scannable_gate(self):
        self.assertEqual({h for h, _ip, _d in self.due(blocked=lambda h: h == 'api.rt.test')}, {'www.rt.test'})

    def test_the_real_vetting_refuses_a_name_pointed_at_a_prohibited_address(self):
        """No injected resolver: pinned_transport.resolve runs against what DNS says now."""
        with mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('169.254.169.254', 443))]):
            self.assertEqual(ov.due(self.project.id, ['www.rt.test'], blocked=lambda h: False), [])
        with mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 443))]):
            self.assertEqual(ov.due(self.project.id, ['www.rt.test'], blocked=lambda h: False), [])
        with mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('93.184.216.5', 443))]):
            self.assertEqual([(h, ip) for h, ip, _d in ov.due(self.project.id, ['www.rt.test'], blocked=lambda h: False)], [('www.rt.test', '93.184.216.5')])

    def test_a_name_that_does_not_resolve_at_all_is_dropped_by_the_real_vetting(self):
        """No injected resolver: a name with no DNS answer (NXDOMAIN) must be skipped exactly like one that resolves somewhere
        prohibited, never handed to gvmd as a bare name or an empty address."""
        import socket
        with mock.patch('socket.getaddrinfo', side_effect=socket.gaierror(-2, 'Name or service not known')):
            self.assertEqual(ov.due(self.project.id, ['www.rt.test'], blocked=lambda h: False), [])

    def test_a_name_with_no_address_family_cvengine_understands_is_dropped(self):
        """A getaddrinfo answer with no usable family, or an empty answer set, never produces a target: pinned_transport.resolve
        raises for both, and due() skips the host rather than letting an empty or missing address reach gvmd."""
        with mock.patch('socket.getaddrinfo', return_value=[]):
            self.assertEqual(ov.due(self.project.id, ['www.rt.test'], blocked=lambda h: False), [])

    def test_documentation_ranges_and_this_instances_own_address_are_refused(self):
        for ip in ('192.0.2.1', '198.51.100.9', '203.0.113.200', '2001:db8::5'):
            self.assertTrue(bool(ov.refuse_reason(ip)), ip)
        with mock.patch.dict(os.environ, {'CVENGINE_OWN_ADDRESSES': '93.184.216.99, 2606:4700::99'}), mock.patch.dict(ov._own, {'at': 0.0}):
            self.assertTrue(bool(ov.refuse_reason('93.184.216.99')))
            self.assertTrue(bool(ov.refuse_reason('2606:4700::99')))
            self.assertFalse(bool(ov.refuse_reason('93.184.216.98')))
        with mock.patch.dict(ov._own, {'at': 0.0}):
            self.assertFalse(bool(ov.refuse_reason('93.184.216.99')))  # the cache is rebuilt from the environment

    def test_a_name_on_a_shared_saas_front_or_cdn_is_never_given_to_the_sidecar(self):
        sub = Subdomain.objects.filter(name='www.rt.test').first()
        mail = Subdomain.objects.create(name='autodiscover.rt.test', target_domain=sub.target_domain, scan_history=sub.scan_history,
                                        cname='autodiscover.outlook.com')
        edge = Subdomain.objects.create(name='shop.rt.test', target_domain=sub.target_domain, scan_history=sub.scan_history, is_cdn=True)
        self.assertTrue(ov._platform_reason(mail))
        self.assertTrue(ov._platform_reason(edge))
        self.assertFalse(ov._platform_reason(sub))
        due = ov.due(self.project.id, ['autodiscover.rt.test', 'shop.rt.test', 'www.rt.test'], resolve=lambda h, p: {
            'autodiscover.rt.test': '52.96.1.1', 'shop.rt.test': '104.16.1.1', 'www.rt.test': '93.184.216.7'}[h], blocked=lambda h: False)
        self.assertEqual([h for h, _ip, _d in due], ['www.rt.test'])

    def test_the_sidecar_is_never_given_a_tailnet_address(self):
        for ip in ('100.64.0.7', '100.127.255.254', 'fd7a:115c:a1e0::7'):
            self.assertTrue(bool(ov.refuse_reason(ip)), ip)
        for ip in ('93.184.216.5', '93.184.214.7', '2606:4700::5'):
            self.assertFalse(bool(ov.refuse_reason(ip)), ip)
        self.assertEqual(self.due(resolve=lambda h, p: '100.64.0.9'), [])
        with mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('100.64.0.9', 443))]):
            self.assertEqual(ov.due(self.project.id, ['www.rt.test'], blocked=lambda h: False), [])

    def test_a_name_the_project_does_not_have_is_never_scanned(self):
        self.assertEqual(self.due(['stranger.example.test']), [])

    def test_a_host_that_failed_to_resolve_is_skipped_without_stopping_the_rest(self):
        def resolve(host, project_id):
            if host == 'www.rt.test':
                raise ValueError('probe destination is prohibited')
            return IPS[host]
        self.assertEqual([h for h, _ip, _d in self.due(resolve=resolve)], ['api.rt.test'])

    def test_two_names_on_one_address_are_one_scan_target(self):
        self.assertEqual(len(self.due(resolve=lambda h, p: '93.184.216.5')), 1)

    def test_a_host_scanned_within_a_week_is_not_due_and_one_scanned_longer_ago_is(self):
        from cveFeed import ledger
        ledger.record(ov.SERVICE, ['www.rt.test'], self.project.id)
        self.assertEqual({h for h, _ip, _d in self.due()}, {'api.rt.test'})
        ServiceRun.objects.filter(service=ov.SERVICE).update(finished_at=timezone.now() - timedelta(days=8))
        self.assertEqual({h for h, _ip, _d in self.due()}, {'www.rt.test', 'api.rt.test'})

    def test_a_host_that_failed_is_left_alone_for_three_days(self):
        from cveFeed import ledger
        ledger.record(ov.FAILED_SERVICE, ['www.rt.test'], self.project.id)
        self.assertEqual({h for h, _ip, _d in self.due()}, {'api.rt.test'})
        ServiceRun.objects.filter(service=ov.FAILED_SERVICE).update(finished_at=timezone.now() - timedelta(days=4))
        self.assertEqual(len(self.due()), 2)

    def test_the_never_scanned_go_first_then_the_longest_waiting(self):
        from cveFeed import ledger
        ledger.record(ov.SERVICE, ['www.rt.test'], self.project.id)
        ServiceRun.objects.filter(service=ov.SERVICE).update(finished_at=timezone.now() - timedelta(days=9))
        self.assertEqual([h for h, _ip, _d in self.due()], ['api.rt.test', 'www.rt.test'])


class SweepTests(Fixture, TestCase):
    """A due batch goes to a Sentinel, never to a gvmd of this server (the GMP client itself is the Sentinel repo's)."""

    def test_a_due_batch_is_handed_to_a_sentinel_with_a_vetted_target_and_the_servers_policy(self):
        self.make_sentinel()
        out = self.tick()
        self.assertEqual((out['status'], out['hosts'], out['via']), ('running', 2, 'sentinel'))
        run = OpenvasRun.objects.get()
        task = run.sentinel_task
        self.assertEqual((task.kind, task.project_id, task.status), ('openvas', self.project.id, 'queued'))
        self.assertEqual(set(task.target['hosts']), {'93.184.216.5', '93.184.216.6'})  # numeric addresses only, never a name
        self.assertEqual(task.target['excluded_families'], ['Denial of Service', 'Brute force attacks'])
        self.assertEqual(task.target['preferences'], {'max_checks': '4', 'max_hosts': '1'})
        self.assertEqual((run.status, run.project_id), ('running', self.project.id))
        self.assertEqual(run.hosts, {'93.184.216.5': 'www.rt.test', '93.184.216.6': 'api.rt.test'})

    def test_the_batch_is_capped(self):
        self.make_sentinel()
        with mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MAX_HOSTS': '1'}):
            self.assertEqual(self.tick()['hosts'], 1)

    def test_only_one_task_runs_at_a_time(self):
        self.make_sentinel()
        self.tick()
        again = self.tick()
        self.assertEqual(again['status'], 'running')
        self.assertEqual(SentinelTask.objects.filter(kind='openvas').count(), 1)
        # and the database refuses a second running row whoever asks
        from django.db import IntegrityError, transaction
        with self.assertRaises(IntegrityError), transaction.atomic():
            OpenvasRun.objects.create(project=self.project, status='running')

    def test_a_global_pause_refuses_to_start(self):
        self.make_sentinel()
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        self.assertEqual(self.tick(), {'skipped': 'scanning is paused'})
        self.assertFalse(SentinelTask.objects.filter(kind='openvas').exists())

    def test_a_pause_expires_the_running_sentinel_task_and_the_hosts_stay_due(self):
        self.make_sentinel()
        self.tick()
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        out = self.tick()
        self.assertEqual(out['status'], 'failed')
        self.assertEqual(OpenvasRun.objects.get().sentinel_task.status, 'expired')
        self.assertFalse(ServiceRun.objects.filter(service__in=(ov.SERVICE, ov.FAILED_SERVICE)).exists())
        ScanControl.objects.filter(pk=1).update(paused=False)
        self.assertEqual(self.tick()['status'], 'running')


class ImportTests(Fixture, TestCase):
    def test_cve_results_become_findings_and_evidence_non_cve_ones_do_not(self):
        out = self.run_scan([APACHE, BANNER, PLAIN, LOG])
        self.assertEqual((out['status'], out['results'], out['without_cve'], out['findings'], out['evidence']), ('done', 4, 2, 2, 2))
        www = Subdomain.objects.get(name='www.rt.test')
        hard = Vulnerability.objects.get(subdomain=www, template_id=f'openvas:{OID_APACHE}')
        self.assertEqual((hard.source, hard.severity, hard.cvss_score, hard.type, hard.http_url), ('openvas', 4, 9.8, 'openvas', 'www.rt.test:443/tcp'))
        self.assertEqual(hard.name, 'OpenVAS: Apache HTTP Server < 2.4.51 Path Traversal')
        self.assertEqual(list(hard.cve_ids.values_list('name', flat=True)), ['CVE-2021-41773'])
        self.assertIn('qod-confirmed', set(hard.tags.values_list('name', flat=True)))
        self.assertEqual(hard.extracted_results, ['Detection result.'])
        self.assertTrue(hard.open_status)
        self.assertEqual(Vulnerability.objects.filter(source='openvas').count(), 2)
        self.assertFalse(Vulnerability.objects.filter(template_id=f'openvas:{OID_PLAIN}').exists())  # no CVE reference, no evidence

    def test_only_a_high_quality_of_detection_is_hard_evidence(self):
        self.run_scan([APACHE, BANNER])
        hard = CVEMatch.objects.get(cve_entry=self.cve, source='openvas')
        soft = CVEMatch.objects.get(cve_entry=self.cve2, source='openvas')
        self.assertEqual((hard.template_result, hard.template_id, hard.version_in_range, hard.confidence), ('vulnerable', f'openvas:{OID_APACHE}', True, 0.95))
        self.assertIsNotNone(hard.template_tested_at)
        self.assertEqual((soft.template_result, soft.template_id, soft.version_in_range), ('', '', None))
        self.assertLess(soft.confidence, 0.5)
        self.assertEqual((hard.evidence['qod'], soft.evidence['qod'], soft.evidence['qod_type']), (99, 30, 'remote_banner_unreliable'))
        self.assertEqual(hard.evidence['oid'], OID_APACHE)
        vuln = Vulnerability.objects.get(template_id=f'openvas:{OID_BANNER}')
        self.assertIn('qod-unconfirmed', set(vuln.tags.values_list('name', flat=True)))
        self.assertIn('Not confirmed', vuln.description)
        self.assertEqual(vuln.severity, 2)  # the severity still follows the CVSS

    def test_a_banner_version_check_at_qod_80_is_not_hard_evidence(self):
        for qod, qod_type, expected in ((80, 'remote_banner', ''), (80, 'executable_version', ''), (80, 'remote_active', 'vulnerable'),
                                        (97, 'package', 'vulnerable')):
            CVEMatch.objects.all().delete()
            ProbeObservation.objects.all().delete()
            Vulnerability.objects.all().delete()
            self.run_scan([{**APACHE, 'qod': qod, 'qod_type': qod_type}])
            self.assertEqual(CVEMatch.objects.get(cve_entry=self.cve).template_result, expected, (qod, qod_type))

    def test_a_cve_the_catalogue_does_not_know_is_a_finding_without_a_match(self):
        self.run_scan([{**APACHE, 'cves': ['CVE-2099-0001']}])
        self.assertEqual(Vulnerability.objects.filter(source='openvas').count(), 1)
        self.assertEqual(CVEMatch.objects.filter(source='openvas').count(), 0)

    def test_a_rejected_cve_never_becomes_a_match(self):
        self.cve.status = 'REJECTED'
        self.cve.save()
        self.run_scan([APACHE])
        self.assertEqual(CVEMatch.objects.filter(source='openvas').count(), 0)

    def test_severity_comes_from_the_cvss_score(self):
        results = [{**APACHE, 'severity': s, 'oid': f'1.3.6.1.4.1.25623.1.0.9{i}', 'cves': [f'CVE-2021-{1000 + i}']} for i, s in enumerate((9.0, 7.5, 5.0, 2.0))]
        self.run_scan(results)
        self.assertEqual(sorted(Vulnerability.objects.filter(source='openvas').values_list('severity', flat=True)), [1, 2, 3, 4])

    def test_the_same_result_again_is_one_finding_one_observation_one_match(self):
        self.run_scan([APACHE, BANNER])
        self.run_scan([APACHE, BANNER])
        self.assertEqual(Vulnerability.objects.filter(source='openvas').count(), 2)
        self.assertEqual(ProbeObservation.objects.filter(probe='openvas').count(), 2)
        self.assertEqual(CVEMatch.objects.filter(source='openvas').count(), 2)

    def test_dedupe_is_by_host_port_and_oid(self):
        self.run_scan([APACHE, {**APACHE, 'port': '8443/tcp'}, {**APACHE, 'host': '93.184.216.6', 'hostname': 'api.rt.test'}])
        self.assertEqual(Vulnerability.objects.filter(source='openvas').count(), 3)
        self.assertEqual(ProbeObservation.objects.filter(probe='openvas').count(), 3)
        keys = set(ProbeObservation.objects.filter(probe='openvas').values_list('host', 'port', 'product'))
        self.assertEqual(keys, {('www.rt.test', 443, OID_APACHE), ('www.rt.test', 8443, OID_APACHE), ('api.rt.test', 443, OID_APACHE)})

    def test_a_result_that_disappears_in_a_later_complete_scan_is_resolved(self):
        self.run_scan([APACHE, BANNER])
        self.run_scan([APACHE])
        self.assertTrue(Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}').open_status)
        gone = Vulnerability.objects.get(template_id=f'openvas:{OID_BANNER}')
        self.assertFalse(gone.open_status)
        match = CVEMatch.objects.get(cve_entry=self.cve2, source='openvas')
        self.assertEqual((match.template_result, match.ai_verdict), ('no_match', 'not_affected'))
        self.assertEqual(CVEMatch.objects.get(cve_entry=self.cve, source='openvas').template_result, 'vulnerable')
        self.assertEqual(ProbeObservation.objects.get(host='www.rt.test', product=OID_BANNER).outcome, 'absent')
        out = self.run_scan([APACHE, BANNER])  # and it reopens when it comes back
        self.assertTrue(Vulnerability.objects.get(template_id=f'openvas:{OID_BANNER}').open_status)

    def test_a_match_a_person_already_works_is_closed_as_a_record_not_discarded(self):
        self.run_scan([APACHE])
        match = CVEMatch.objects.get(cve_entry=self.cve, source='openvas')
        match.remediation_status = 'in_progress'
        match.save()
        self.run_scan([{**LOG, 'host': '93.184.216.5', 'hostname': 'www.rt.test'}])  # www answered, and no longer shows the problem
        match.refresh_from_db()
        self.assertEqual((match.template_result, match.remediation_status, match.ai_verdict), ('no_match', 'in_progress', ''))

    def test_results_whose_cves_gvmd_left_out_close_nothing_and_ask_for_a_gvmd_restart(self):
        # camstork, #394: a stale NVT cache sends every result without its CVE references. Read as "no CVE", the host looked scanned clean
        # and every earlier OpenVAS finding on it was closed.
        self.run_scan([APACHE, BANNER])
        stale = [{**APACHE, 'cves': []}, {**BANNER, 'cves': []}]
        out = self.run_scan(stale, stale=2)
        self.assertEqual((out['status'], out['nvt_cache_stale'], out['partial'], out['resolved']), ('done', 2, True, 0))
        self.assertTrue(Vulnerability.objects.get(template_id=f'openvas:{OID_BANNER}').open_status)
        self.assertEqual(ProbeObservation.objects.get(host='www.rt.test', product=OID_BANNER).outcome, 'found')
        run = OpenvasRun.objects.order_by('-pk').first()
        self.assertIn("the Sentinel's gvmd sent 2 result(s) without their CVE references", run.error)
        self.assertIn('restart its openvas-gvmd container', run.error)
        self.assertTrue(ServiceRun.objects.filter(service=ov.FAILED_SERVICE, asset='www.rt.test').exists())  # asked again in three days
        self.assertFalse(ServiceRun.objects.filter(service=ov.SERVICE, asset='www.rt.test').exists())


    def test_a_host_gvmd_did_not_scan_is_not_resolved(self):
        self.run_scan([APACHE])
        out = self.run_scan([LOG])  # only api answered; www was down: no result, not in the report's host list
        self.assertEqual((out['hosts_scanned'], out['hosts_not_scanned']), (1, 1))
        self.assertTrue(Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}').open_status)
        self.assertEqual(ProbeObservation.objects.get(host='www.rt.test').outcome, 'found')
        self.assertTrue(ServiceRun.objects.filter(service=ov.FAILED_SERVICE, asset='www.rt.test').exists())  # asked again in three days
        self.assertTrue(ServiceRun.objects.filter(service=ov.SERVICE, asset='api.rt.test').exists())

    def test_a_live_host_with_no_result_is_known_from_the_report(self):
        self.run_scan([APACHE])
        self.run_scan([LOG], scanned={'93.184.216.5', '93.184.216.6'})  # www was scanned and nothing was found
        self.assertFalse(Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}').open_status)

    def test_results_for_an_address_that_was_not_requested_are_ignored(self):
        out = self.run_scan([{**APACHE, 'host': '93.184.216.99', 'hostname': 'surprise.example.test'}, LOG])
        self.assertEqual(out['not_in_batch'], 1)  # the Sentinel reported an address the task did not name
        self.assertFalse(Vulnerability.objects.filter(source='openvas').exists())
        self.assertFalse(ProbeObservation.objects.filter(probe='openvas').exists())


    def test_the_run_keeps_a_summary_and_the_activity_says_what_happened(self):
        from cveFeed.models import AgentActivity
        self.run_scan([APACHE, PLAIN])
        run = OpenvasRun.objects.get()
        self.assertEqual((run.status, run.summary['findings'], run.summary['without_cve']), ('done', 1, 1))
        message = AgentActivity.objects.filter(kind='run_check', message__contains='host(s) scanned').latest('id').message
        self.assertIn('1 result(s) without a CVE not imported', message)
        self.assertTrue(message.startswith(f'OpenVAS run {run.pk} on api.rt.test, www.rt.test (Sentinel task {run.sentinel_task_id}): '), message)


    def test_hostile_text_is_stored_clipped_and_plain(self):
        evil = '<img src=x onerror=alert(1)>' + 'B' * 20000
        self.run_scan([{**APACHE, 'description': evil, 'tags': 'summary=<script>x</script>|insight=' + evil}])
        vuln = Vulnerability.objects.get(source='openvas')
        self.assertLessEqual(len(vuln.description), 6000)
        self.assertLessEqual(len(vuln.extracted_results[0]), 2000)
        self.assertIn('<script>x</script>', vuln.description)  # inert text; every template autoescapes it


def _sentinel_item(**over):
    """A Sentinel-reported, already-cleaned OpenVAS result (``sentinel_broker.clean_result``'s own output shape), which is
    exactly ``parse_result``'s shape minus the GVM-internal ``id``. The cleaner itself is unit-tested in
    ``tests.test_sentinels.OpenvasResultCleanerTests``; this is only used to drive ``poll_sentinel``/``tick``'s import
    path end to end."""
    item = {'oid': OID_APACHE, 'name': 'Apache HTTP Server < 2.4.51 Path Traversal', 'family': 'Web application abuses',
            'address': '93.184.216.5', 'hostname': 'www.rt.test', 'port': '443/tcp', 'port_number': 443, 'severity': 9.8,
            'threat': 'Critical', 'qod': 99, 'qod_type': 'remote_active', 'result': 'Installed version: 2.4.49',
            'summary': 'The product is affected.', 'insight': 'A flaw in request handling.', 'impact': '',
            'affected': 'Versions before 2.4.51', 'solution': 'Update to the fixed release.', 'solution_type': 'VendorFix',
            'cvss_vector': 'AV:N/AC:L/Au:N/C:P/I:P/A:P', 'cves': ['CVE-2021-41773'], 'urls': []}
    item.update(over)
    return item


class SentinelDispatchTests(Fixture, TestCase):
    """OpenVAS honours exactly the same two gates (this instance's global switch, the per-project opt-in) when deciding
    whether a Sentinel may take the work: there is no organization level to check and nothing here invents one. A project with no eligible
    Sentinel for ``openvas`` has its hosts stay due, and nothing ever runs on this server."""

    def test_with_no_eligible_sentinel_the_hosts_stay_due_and_nothing_runs_here(self):
        guard = assert_ran_nowhere_locally(self, 'openvas')
        self.assertFalse(dispatch.any_scanner_for(self.project, 'openvas'))
        out = self.tick()
        self.assertEqual(out, {'skipped': 'no opted-in host with an eligible Sentinel is due'})
        self.assertFalse(OpenvasRun.objects.exists())
        self.assertFalse(SentinelTask.objects.exists())
        self.assertFalse(ServiceRun.objects.filter(service__in=(ov.SERVICE, ov.FAILED_SERVICE)).exists())  # a host nobody could scan is not a failed host
        self.assertEqual(guard.calls, [])

    def test_a_sentinel_without_the_openvas_capability_is_not_eligible(self):
        self.make_sentinel(capabilities=('nmap',))
        self.assertFalse(dispatch.any_scanner_for(self.project, 'openvas'))
        out = self.tick()
        self.assertIn('skipped', out)
        self.assertFalse(OpenvasRun.objects.exists())

    def test_a_sentinel_out_of_this_projects_scope_is_not_eligible(self):
        self.make_sentinel(scope_project=False)
        self.assertFalse(dispatch.any_scanner_for(self.project, 'openvas'))

    def test_an_eligible_sentinel_is_dispatched_to(self):
        self.make_sentinel()
        out = self.tick()
        self.assertEqual((out['status'], out.get('via')), ('running', 'sentinel'))
        run = OpenvasRun.objects.get()
        self.assertIsNotNone(run.sentinel_task_id)
        task = run.sentinel_task
        self.assertEqual(task.kind, 'openvas')
        self.assertEqual(task.project_id, self.project.id)
        self.assertEqual(set(run.hosts.values()), {'www.rt.test', 'api.rt.test'})
        self.assertEqual(task.target['excluded_families'], list(ov.EXCLUDED_FAMILIES))
        self.assertEqual(task.target['max_hours'], ov.budget_hours(2))
        self.assertEqual(sorted(task.target['hosts'].values()), ['api.rt.test', 'www.rt.test'])

    def test_while_a_sentinel_task_is_in_flight_tick_only_polls_it(self):
        self.make_sentinel()
        self.tick()
        out = self.tick()
        self.assertEqual(out, {'run': OpenvasRun.objects.get().pk, 'status': 'running', 'sentinel_status': 'queued'})
        self.assertEqual(SentinelTask.objects.filter(kind='openvas').count(), 1)

    def test_a_done_sentinel_task_imports_its_results(self):
        self.make_sentinel()
        self.tick()
        run = OpenvasRun.objects.get()
        task = run.sentinel_task
        task.result = {'results': [_sentinel_item(), _sentinel_item(port='80/tcp', port_number=80, oid=OID_BANNER,
                       name='Old thing version check', severity=5.0, qod=30, cves=['CVE-2019-0001'], qod_type='remote_banner_unreliable')],
                      'scanned_addresses': ['93.184.216.5', '93.184.216.6'], 'without_cve': 0, 'unusable': 0}
        task.status = 'done'
        task.save(update_fields=['result', 'status'])
        out = self.tick()
        self.assertEqual((out['status'], out['findings'], out['evidence']), ('done', 2, 2))
        hard = Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}')
        self.assertEqual((hard.source, hard.cvss_score, hard.severity), ('openvas', 9.8, 4))
        self.assertTrue(CVEMatch.objects.filter(cve_entry=self.cve, source='openvas', template_result='vulnerable').exists())
        self.assertTrue(ServiceRun.objects.filter(service=ov.SERVICE, asset='www.rt.test').exists())
        self.assertEqual(OpenvasRun.objects.get().status, 'done')

    def test_a_sentinel_whose_gvmd_left_out_the_cves_closes_nothing(self):
        from agentapi.sentinel_broker import _clean_openvas_result
        self.run_scan([APACHE, BANNER])  # found by an earlier, complete scan
        ServiceRun.objects.all().delete()
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        body = _clean_openvas_result({'results': [{'address': '93.184.216.5', 'port': '443/tcp'}], 'scanned_addresses': ['93.184.216.5'],
                                      'without_cve': 1, 'unusable': 0, 'nvt_cache_stale': 1})
        self.assertEqual((body['partial'], body['nvt_cache_stale']), (True, 1))
        run.sentinel_task.result, run.sentinel_task.status = body, 'done'
        run.sentinel_task.save(update_fields=['result', 'status'])
        out = self.tick()
        self.assertEqual((out['status'], out['nvt_cache_stale'], out['resolved']), ('done', 1, 0))
        self.assertTrue(Vulnerability.objects.get(template_id=f'openvas:{OID_BANNER}').open_status)
        self.assertEqual(ProbeObservation.objects.get(host='www.rt.test', product=OID_BANNER).outcome, 'found')
        self.assertIn("the Sentinel's gvmd sent 1 result(s) without their CVE references", OpenvasRun.objects.get(pk=run.pk).error)

    def test_a_failed_sentinel_task_marks_the_run_failed_and_the_hosts_stay_due_again(self):
        self.make_sentinel()
        self.tick()
        run = OpenvasRun.objects.get()
        run.sentinel_task.status, run.sentinel_task.error = 'failed', 'the Sentinel lost its GVM connection'
        run.sentinel_task.save(update_fields=['status', 'error'])
        out = self.tick()
        self.assertEqual(out['status'], 'failed')
        self.assertEqual(OpenvasRun.objects.get().status, 'failed')
        self.assertTrue(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())

    def test_an_expired_sentinel_task_marks_the_run_failed_but_no_host(self):
        self.make_sentinel()
        self.tick()
        run = OpenvasRun.objects.get()
        run.sentinel_task.status = 'expired'
        run.sentinel_task.save(update_fields=['status'])
        out = self.tick()
        self.assertEqual(out['status'], 'failed')
        self.assertFalse(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())  # the Sentinel went away; nothing was learned about the hosts

    def test_a_sentinel_whose_own_stack_was_not_ready_marks_no_host_failed(self):
        for error in ('the default GVM login did not work (GvmResponseError)', 'GVM is still syncing its SCAP feed(s); it cannot scan yet',
                      'gvmd answered with an error: GvmResponseError: Response Error 400. Family "AIX Local Security Checks" must be growing',
                      'the "Full and fast" scan configuration is not in gvmd yet (the feed is not loaded)',
                      'gvmd could not be reached (ConnectionRefusedError): is the GVM stack up yet?'):
            self.assertTrue(ov.infrastructure_failure('failed', error), error)
        for error in ('the task ran past its time budget', 'gvmd reports the task as "Stopped"', 'the Sentinel lost its GVM connection', ''):
            self.assertFalse(ov.infrastructure_failure('failed', error), error)
        self.make_sentinel()
        self.tick()
        run = OpenvasRun.objects.get()
        run.sentinel_task.status, run.sentinel_task.error = 'failed', 'GVM is still syncing its SCAP feed(s); it cannot scan yet'
        run.sentinel_task.save(update_fields=['status', 'error'])
        self.assertEqual(self.tick()['status'], 'failed')
        self.assertFalse(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())
        self.assertEqual(self.tick()['status'], 'running')  # the same hosts are handed out again at the next tick

    def test_only_one_task_runs_at_a_time(self):
        self.make_sentinel()
        self.tick()  # handed to the Sentinel
        self.assertIsNone(ov.dispatch_to_sentinel(self.link, [('db.rt.test', '93.184.214.7', 1)]))
        self.assertEqual(OpenvasRun.objects.count(), 1)

    def test_hosts_per_task_are_held_to_what_a_sentinel_takes(self):
        # The Sentinel client refuses an OpenVAS task of more than 16 hosts, so the setting is held to 16 (warned once per value) and a task
        # target never names more.
        self.assertEqual(ov.MAX_HOSTS_PER_TASK, 16)
        ov._warned_max_hosts.clear()
        for raw, expected in (('16', 16), ('3', 3), ('0', 1), ('x', ov.DEFAULT_MAX_HOSTS)):
            with mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MAX_HOSTS': raw}), self.assertNoLogs('cveFeed.openvas_scan', 'WARNING'):
                self.assertEqual(ov.max_hosts(), expected, raw)
        with mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MAX_HOSTS': '40'}):
            with self.assertLogs('cveFeed.openvas_scan', 'WARNING') as logs:
                self.assertEqual(ov.max_hosts(), 16)
            self.assertIn('CVENGINE_OPENVAS_MAX_HOSTS=40 is above 16', logs.output[0])
            with self.assertNoLogs('cveFeed.openvas_scan', 'WARNING'):
                self.assertEqual(ov.max_hosts(), 16)  # said once, not at every tick
        batch = [(f'h{i}.rt.test', f'93.184.215.{i}', 1) for i in range(20)]
        run = ov.dispatch_to_sentinel(self.link, batch)
        self.assertEqual(len(run.sentinel_task.target['hosts']), 16)
        self.assertEqual(len(run.sentinel_task.ips), 16)
        self.assertEqual(run.sentinel_task.target['hosts'], {ip: host for host, ip, _ in batch[:16]})

    def test_while_the_addon_is_off_a_sentinel_is_never_asked_either(self):
        self.make_sentinel()
        self.settings.enabled = False
        self.settings.save()
        self.assertEqual(self.tick(), {'skipped': 'the OpenVAS add-on is switched off'})
        self.assertFalse(OpenvasRun.objects.exists())


class NoLocalPathTests(Fixture, TestCase):
    """``openvas`` is in ``sentinel_dispatch.NEVER_LOCAL``: whatever ``CVENGINE_LOCAL_FALLBACK`` or the old ``sentinel_only`` switch say, a due host with no
    eligible Sentinel stays due, and a run an earlier version started against this server's own gvmd is closed without blaming a host."""

    def test_the_kind_has_no_local_path_and_the_fallback_variable_cannot_give_it_one(self):
        self.assertIn('openvas', dispatch.NEVER_LOCAL)
        for value in ('all', 'openvas', 'none', 'openvas,hygiene_check'):
            with LocalFallback(value):
                self.assertIn('openvas', dispatch.NEVER_LOCAL, value)
                guard = assert_ran_nowhere_locally(self, 'openvas')
                self.assertIn('skipped', self.tick(), value)
                self.assertFalse(OpenvasRun.objects.exists(), value)
                self.assertEqual(guard.calls, [])

    def test_the_old_sentinel_only_switch_changes_nothing_either_way(self):
        for flag in (True, False):
            self.settings.sentinel_only = flag
            self.settings.save()
            self.assertEqual(self.tick(), {'skipped': 'no opted-in host with an eligible Sentinel is due'}, flag)
        self.assertFalse(OpenvasRun.objects.exists())
        self.make_sentinel()
        out = self.tick()
        self.assertEqual((out['status'], out.get('via')), ('running', 'sentinel'))
        self.assertIsNotNone(OpenvasRun.objects.get().sentinel_task_id)

    def test_a_run_of_an_earlier_version_with_no_sentinel_task_is_closed_and_blames_no_host(self):
        self.make_sentinel()
        for task_id in ('', 'abc-task-7'):  # one the worker never finished creating, one that was running in this server's gvmd
            old = OpenvasRun.objects.create(project=self.project, status='running', task_id=task_id, hosts={'93.184.216.5': 'www.rt.test'})
            out = self.tick()
            old.refresh_from_db()
            self.assertEqual((old.status, old.error), ('failed', ov.LOCAL_RUN_CLOSED), task_id)
            self.assertIsNotNone(old.finished_at)
            self.assertEqual((out['status'], out['via']), ('running', 'sentinel'))  # the slot is free again: the same hosts go to a Sentinel at once
            self.assertFalse(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())  # they stay due, not failed for three days
            OpenvasRun.objects.filter(sentinel_task__isnull=False).update(status='done')

    def test_a_sentinel_run_is_not_touched_by_that_closing(self):
        self.make_sentinel()
        self.tick()
        run = OpenvasRun.objects.get()
        self.assertEqual(self.tick()['status'], 'running')
        run.refresh_from_db()
        self.assertEqual(run.status, 'running')


class HeldHostsOfEarlierVersionsTests(Fixture, TestCase):
    """A host a gvmd of an earlier version gave up on (``summary['interrupt_limit']``) still waits its three days: the server reads that record."""

    def test_a_host_given_up_on_after_repeated_interruptions_is_not_due_again_at_once(self):
        run = OpenvasRun.objects.create(project=self.project, status='failed', hosts={'93.184.216.5': 'www.rt.test'}, error=ov.interrupted_reason(3),
                                        summary={'interrupt_limit': {'www.rt.test': 3}}, finished_at=timezone.now())
        from cveFeed import ledger
        ledger.record(ov.FAILED_SERVICE, ['www.rt.test'], self.project.id)  # what the run did when it gave the host up
        verdict = {r['host']: r for r in ov.explain(self.link)}['www.rt.test']
        self.assertFalse(verdict['ready'])
        self.assertEqual(verdict['reason'], run.error)
        ServiceRun.objects.filter(service=ov.FAILED_SERVICE).update(finished_at=timezone.now() - timedelta(days=4))  # three days later it is due again
        self.assertTrue({r['host']: r for r in ov.explain(self.link)}['www.rt.test']['ready'])


class CarryForwardTests(Fixture, TestCase):
    def test_a_later_scans_host_row_gets_the_findings_and_the_evidence(self):
        self.run_scan([APACHE, BANNER])
        later = self.scan(names=('www.rt.test',), ip='93.184.216.5')
        sub = Subdomain.objects.get(scan_history=later, name='www.rt.test')
        self.assertFalse(Vulnerability.objects.filter(subdomain=sub).exists())
        self.assertEqual(ov.carry_forward(later), 2)
        self.assertEqual(Vulnerability.objects.filter(subdomain=sub, source='openvas').count(), 2)
        self.assertEqual(CVEMatch.objects.get(subdomain=sub, cve_entry=self.cve).template_result, 'vulnerable')
        self.assertEqual(ov.carry_forward(later), 2)  # idempotent
        self.assertEqual(Vulnerability.objects.filter(subdomain=sub, source='openvas').count(), 2)

    def test_it_does_not_resolve_what_merely_went_stale(self):
        self.run_scan([APACHE])
        ProbeObservation.objects.update(observed_at=timezone.now() - timedelta(days=40))
        later = self.scan(names=('www.rt.test',), ip='93.184.216.5')
        self.assertEqual(ov.carry_forward(later), 0)
        self.assertEqual(ov.apply_observations(Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')), (0, 0, 0))  # stale is not "gone"

        self.assertTrue(Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}', scan_history=self.scan_obj).open_status)

    def test_a_person_s_decision_on_an_earlier_finding_is_kept_on_the_new_row(self):
        self.run_scan([APACHE])
        Vulnerability.objects.update(remediation_status='accepted_risk', remediation_note='known')
        later = self.scan(names=('www.rt.test',), ip='93.184.216.5')
        ov.carry_forward(later)
        new = Vulnerability.objects.get(subdomain__scan_history=later, source='openvas')
        self.assertEqual((new.remediation_status, new.remediation_note), ('accepted_risk', 'known'))


class HostContextTests(Fixture, TestCase):
    def test_openvas_rows_do_not_crowd_the_version_probes_out_of_the_ai_context(self):
        from cveFeed import host_context
        self.run_scan([APACHE, BANNER])
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='server-header', kind='version', product='nginx',
                                        version='1.24.0', outcome='found', confidence=0.9, source='header:server')
        probes = host_context._probe_rows(self.project.id, 'www.rt.test')
        self.assertEqual([(p.probe, p.product) for p in probes], [('server-header', 'nginx')])


class SettingsApiTests(Fixture, TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('oroot', 'o@x.io', 'x')
        cls.admin = User.objects.create_user('oadmin', password='x')
        org = Org.objects.create(name='O', slug='o')
        OrgMembership.objects.create(user=cls.admin, org=org, role='admin')

    def setUp(self):
        super().setUp()
        self.c = client_for(self.root)
        OpenvasSettings.objects.all().delete()
        OpenvasProject.objects.all().delete()
        self.pid = self.project.id

    def test_only_a_superuser_may_touch_it(self):
        other = client_for(self.admin)  # an organization admin is still not an App Admin
        for method, path, body in (('GET', 'openvas', None), ('PUT', 'openvas', {}), ('PUT', f'openvas/projects/{self.pid}', {}),
                                   ('DELETE', f'openvas/projects/{self.pid}', None)):
            self.assertEqual(send(other, method, path, body)[0], 403, path)
        self.assertEqual(self.client.get('/cve/api/settings/openvas').status_code, 302)
        member = User.objects.create_user('omember', password='x')
        self.assertEqual(send(client_for(member), 'GET', 'openvas')[0], 403)

    def test_it_starts_off_and_says_what_the_floor_is(self):
        status, data = send(self.c, 'GET', 'openvas')
        self.assertEqual(status, 200)
        self.assertEqual((data['enabled'], data['links'], data['running']), (False, [], False))
        for gone in ('sentinel_only', 'password_set', 'username', 'transport', 'state'):  # a local engine this server no longer has: nothing to show
            self.assertNotIn(gone, data)
        self.assertEqual(data['floor']['confirmed_qod'], 95)
        self.assertEqual(data['floor']['excluded_families'], ['Denial of Service', 'Brute force attacks'])
        self.assertIn(self.pid, [p['id'] for p in data['projects']])


    def test_it_can_be_switched_on_with_no_login_because_this_server_keeps_none(self):
        status, data = send(self.c, 'PUT', 'openvas', {'enabled': True})
        self.assertEqual(status, 200, data)
        self.assertTrue(OpenvasSettings.current().enabled)

    def test_a_login_in_the_request_is_ignored_not_stored(self):
        send(self.c, 'PUT', 'openvas', {'gmp_username': 'cvengine', 'gmp_password': 'secret-pw-12345', 'enabled': True})
        row = OpenvasSettings.current()
        self.assertEqual((row.gmp_username, row.gmp_password), ('', ''))
        self.assertNotIn('secret-pw-12345', json.dumps(send(self.c, 'GET', 'openvas')[1]))

    def test_the_connection_test_that_opened_a_gmp_session_is_gone(self):
        self.assertEqual(send(self.c, 'POST', 'openvas/test', {})[0], 404)
        self.assertEqual(self.call_check()[0], 404)

    def call_check(self):
        r = client_for(User.objects.get(username='oroot')).post('/cve/api/admin/openvas/check', '{}', content_type='application/json')
        return r.status_code, None

    def test_the_switch_turns_the_beat_entry_on_and_off_with_it(self):
        from django_celery_beat.models import PeriodicTask
        self.assertFalse(PeriodicTask.objects.get(name='cvengine-openvas-sweep').enabled)
        status, data = send(self.c, 'PUT', 'openvas', {'enabled': True})
        self.assertEqual(status, 200, data)
        self.assertTrue(data['enabled'])
        self.assertTrue(PeriodicTask.objects.get(name='cvengine-openvas-sweep').enabled)
        status, data = send(self.c, 'PUT', 'openvas', {'enabled': False})
        self.assertFalse(data['enabled'])
        self.assertFalse(PeriodicTask.objects.get(name='cvengine-openvas-sweep').enabled)
        self.assertEqual(list(AuditLog.objects.filter(action__startswith='openvas.').order_by('id').values_list('action', flat=True)), ['openvas.enable', 'openvas.disable'])


    def test_a_project_opts_in_with_a_list_of_its_own_hosts(self):
        status, data = send(self.c, 'PUT', f'openvas/projects/{self.pid}', {'enabled': True, 'hosts': 'www.rt.test, API.rt.test www.rt.test'})
        self.assertEqual(status, 200, data)
        self.assertEqual((data['enabled'], data['hosts']), (True, ['www.rt.test', 'api.rt.test']))
        listed = send(self.c, 'GET', 'openvas')[1]
        self.assertEqual([l['project']['id'] for l in listed['links']], [self.pid])
        self.assertNotIn(self.pid, [p['id'] for p in listed['projects']])
        self.assertTrue(AuditLog.objects.filter(action='openvas.project.update', detail__hosts=2).exists())

    def test_a_host_the_project_does_not_have_is_refused(self):
        status, data = send(self.c, 'PUT', f'openvas/projects/{self.pid}', {'hosts': ['www.rt.test', 'stranger.example.test']})
        self.assertEqual(status, 400)
        self.assertIn('stranger.example.test', data['error'])
        self.assertFalse(OpenvasProject.objects.exists())

    def test_the_other_projects_hosts_are_refused_too(self):
        other = Project.objects.create(name='Other', slug='other', insert_date=timezone.now(), org=self.project.org)
        status, data = send(self.c, 'PUT', f'openvas/projects/{other.id}', {'hosts': ['www.rt.test']})
        self.assertEqual(status, 400)

    def test_an_excluded_host_cannot_be_opted_in(self):
        from cveFeed.models import HostExclusion
        HostExclusion.objects.create(org=self.project.org, host='api.rt.test', include_subdomains=False)
        status, data = send(self.c, 'PUT', f'openvas/projects/{self.pid}', {'hosts': ['www.rt.test', 'api.rt.test']})
        self.assertEqual(status, 400)
        self.assertIn('api.rt.test', data['error'])

    def test_a_host_that_resolves_to_a_prohibited_range_cannot_be_opted_in(self):
        with mock.patch('targetApp.target_types.blocked_names', return_value={'www.rt.test'}):
            status, data = send(self.c, 'PUT', f'openvas/projects/{self.pid}', {'hosts': ['www.rt.test']})
        self.assertEqual(status, 400)
        self.assertIn('may not be pointed at', data['error'])

    def test_malformed_hosts_and_too_many_are_refused(self):
        for hosts in (['bad host'], ['a;b'], 'x' * 300, [f'h{i}.rt.test' for i in range(201)], 5):
            self.assertEqual(send(self.c, 'PUT', f'openvas/projects/{self.pid}', {'hosts': hosts})[0], 400, hosts)

    def test_an_unknown_project_is_a_404_and_removing_an_opt_in_works(self):
        self.assertEqual(send(self.c, 'PUT', 'openvas/projects/999999', {})[0], 404)
        send(self.c, 'PUT', f'openvas/projects/{self.pid}', {'enabled': True, 'hosts': ['www.rt.test']})
        self.assertEqual(send(self.c, 'DELETE', f'openvas/projects/{self.pid}')[0], 200)
        self.assertEqual(send(self.c, 'DELETE', f'openvas/projects/{self.pid}')[0], 404)
        self.assertFalse(OpenvasProject.objects.exists())


class ComposeTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            import yaml
            cls.compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())
        except (ImportError, OSError):
            cls.compose = None

    def setUp(self):
        if not self.compose:
            self.skipTest('needs PyYAML and the compose file')
        self.services = self.compose['services']
        self.openvas = {n: s for n, s in self.services.items() if n.startswith('openvas-')}

    def test_every_addon_service_is_in_the_profile_and_the_default_stack_is_unchanged(self):
        self.assertEqual({n for n, s in self.services.items() if 'profiles' not in s}, {'db', 'redis', 'celery', 'celery-beat', 'web', 'proxy', 'reviewer', 'scanner'})  # the AI reviewer and the built-in scanner are part of the default stack
        self.assertGreaterEqual(len(self.openvas), 10)
        for name, service in self.openvas.items():
            self.assertEqual(service['profiles'], ['openvas'], name)

    def test_the_program_images_are_pinned_by_tag_and_digest_and_the_feed_data_follows_its_tag_on_purpose(self):
        programs = {'gvmd', 'pg-gvm', 'pg-gvm-migrator', 'redis-server', 'ospd-openvas', 'openvas-scanner', 'gpg-data'}
        seen = set()
        for name, service in self.openvas.items():
            image = service['image']
            self.assertTrue(image.split('/')[:2] == ['registry.community.greenbone.net', 'community'], name)
            repo, _, rest = image.rpartition('/')[2].partition(':')
            if repo in programs:
                seen.add(repo)
                self.assertRegex(rest, r'^stable@sha256:[0-9a-f]{64}$', name)
            else:
                self.assertEqual(rest, 'community', name)  # a data image: a pinned feed would be a stale one
        self.assertEqual(seen, programs)

    def test_the_scanner_is_pinned_to_a_digest_the_registry_still_serves(self):
        # Greenbone removes the digest behind an old "stable" (the registry answers 404, so a fresh pull of the add-on fails): sha256:5067aa68...
        # before 11/2, sha256:7a7c440c... (and the Sentinel's sha256:d6d8288c...) on 11/10. Both services that run the scanner image
        # (openvas-configure and openvas-openvasd) pin the stable digest read on 2026-11-10, the one the Sentinel client pins too.
        withdrawn = ('5067aa68bdb63038180cbdbb5cdc199c1908ec6b7d55997a41b6a51b14c12eee', '7a7c440cf675a83ca1b6d8284eb28450893a8b05f5fed1f98e997df605792632')
        current = '5b2043df8abed6acff7cd4c08636ea87c57f73b95cd406c88dc2adcec24426dd'
        scanner = [s['image'] for s in self.openvas.values() if s['image'].rpartition('/')[2].startswith('openvas-scanner:')]
        self.assertEqual(len(scanner), 2)
        for image in scanner:
            self.assertEqual(image, f'registry.community.greenbone.net/community/openvas-scanner:stable@sha256:{current}')
        for path in ('docker-compose.yml', 'docs/OPENVAS.md'):
            for gone in withdrawn:
                self.assertNotIn(f'sha256:{gone}', (ROOT / path).read_text(), path)

    def test_only_celery_mounts_gvmds_socket_and_read_only(self):
        for name, service in self.services.items():
            mounts = [v for v in service.get('volumes', []) if 'gvmd_socket_vol' in v]
            if name == 'celery':
                self.assertEqual(mounts, ['openvas_gvmd_socket_vol:/run/gvmd:ro'])
            elif name == 'openvas-gvmd':
                self.assertEqual(mounts, ['openvas_gvmd_socket_vol:/run/gvmd'])
            else:
                self.assertEqual(mounts, [], name)

    def test_the_addon_is_isolated_and_publishes_nothing(self):
        for name, service in self.openvas.items():
            self.assertNotIn('ports', service, name)
            self.assertNotIn('network_mode', service, name)
            self.assertNotIn('rengine_network', service.get('networks', []) if isinstance(service.get('networks'), list) else service.get('networks', {}), name)
            self.assertNotIn('env_file', service, name)  # .env reaches no add-on container
        self.assertEqual(self.services['celery']['networks'], ['rengine_network'])
        raised = {n for n, s in self.openvas.items() if s.get('cap_add')}
        self.assertEqual(raised, {'openvas-ospd'})  # the one container that needs raw sockets

    def test_no_secret_is_in_the_compose_file_and_celery_gained_nothing_else(self):
        text = (ROOT / 'docker-compose.yml').read_text()
        self.assertNotRegex(text, r'(?i)gmp[_ ]?password\s*[:=]')
        self.assertNotIn('admin:admin', text)
        celery = self.services['celery']
        self.assertNotIn('cap_add', celery)
        self.assertNotIn('network_mode', celery)

    def test_the_addon_does_not_start_with_a_plain_up_but_does_with_the_profile(self):
        text = (ROOT / 'Makefile').read_text()
        services = re.search(r'^SERVICES\s*:=\s*(.*)$', text, re.M).group(1).split()
        self.assertFalse([s for s in services if s.startswith('openvas')])
        self.assertIn('openvas-up:', text)
        self.assertIn('--profile openvas up -d', text)
        listed = re.search(r'^OPENVAS_SERVICES\s*:=\s*(.*)$', text, re.M).group(1).split()
        self.assertEqual(set(listed), set(self.openvas))

    def test_env_example_documents_the_profile_and_no_login_script_remains(self):
        self.assertIn('COMPOSE_PROFILES=openvas', (ROOT / '.env.example').read_text())
        self.assertFalse((ROOT / 'scripts' / 'openvas-user.sh').exists())  # the GMP login is the Sentinel's: nothing here makes one


class SupplyChainTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import importlib.util
        for name in ('generate_sbom', 'check_tool_versions'):
            spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / f'{name}.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            setattr(cls, name, module)

    def test_the_client_library_is_pinned_and_checked_for_newer_releases(self):
        pin = re.search(r'(?m)^python-gvm==(\d+\.\d+\.\d+)$', (ROOT / 'web' / 'requirements.txt').read_text())
        self.assertIsNotNone(pin)
        def get(url, as_json=True):
            if url == 'https://pypi.org/pypi/python-gvm/json':
                return {'info': {'version': '99.0.0'}}
            raise OSError('offline')
        rows = {r['tool']: r for r in self.check_tool_versions.collect(get)}
        self.assertEqual(rows['python-gvm (OpenVAS add-on client)']['pinned'], pin.group(1))
        self.assertTrue(rows['python-gvm (OpenVAS add-on client)']['behind'])

    def test_the_sbom_lists_the_greenbone_images_with_their_digests(self):
        by_name = {c['name']: c for c in self.generate_sbom.build()['components']}
        gvmd = by_name['registry.community.greenbone.net/community/gvmd']
        self.assertEqual((gvmd['version'], gvmd['properties'][0]['value']), ('stable', 'true'))
        self.assertRegex(gvmd['hashes'][0]['content'], r'^[0-9a-f]{64}$')
        feed = by_name['registry.community.greenbone.net/community/vulnerability-tests']
        self.assertEqual((feed['properties'][0]['value'], 'hashes' in feed), ('false', False))  # the feed follows its tag on purpose
        self.assertIn('python-gvm', by_name)

    def test_the_digests_in_the_docs_are_the_ones_the_compose_file_runs(self):
        doc = (ROOT / 'docs' / 'OPENVAS.md').read_text()
        # the Greenbone images only: the built-in scanner's image is pinned by scanner.lock.json and checked in test_compose
        for digest in re.findall(r'registry\.community\.greenbone\.net/\S+?@sha256:([0-9a-f]{64})', (ROOT / 'docker-compose.yml').read_text()):
            self.assertIn(digest, doc)


class DocsTests(SimpleTestCase):
    def test_the_docs_exist_and_are_linked(self):
        doc = (ROOT / 'docs' / 'OPENVAS.md').read_text()
        for needle in ('COMPOSE_PROFILES=openvas', 'Denial of Service', 'Brute force attacks', 'QoD', '80', 'Not verified', 'sha256:'):
            self.assertIn(needle, doc)
        self.assertIn('OPENVAS.md', (ROOT / 'docs' / 'README.md').read_text())
        self.assertIn('OPENVAS.md', (ROOT / 'README.md').read_text())
        self.assertIn('OpenVAS', (ROOT / 'docs' / 'COMPARISON.md').read_text())
        self.assertIn('OpenVAS', (ROOT / 'CHANGELOG.md').read_text())
        self.assertIn('CVENGINE_OPENVAS_MAX_HOSTS', (ROOT / 'docs' / 'CONFIGURATION.md').read_text())

    def test_no_em_dashes(self):
        for path in ('docs/OPENVAS.md', 'web/cveFeed/openvas_scan.py', 'web/cveFeed/openvas_admin.py', 'web/tests/test_openvas.py', 'docker-compose.yml'):
            self.assertNotIn(chr(0x2014), (ROOT / path).read_text(), path)


class ChooseWhatToScanTests(Fixture, TestCase):
    """Administration > OpenVAS: App Admins and Org Admins pick organizations or projects, nothing is typed."""

    def setUp(self):
        super().setUp()
        self.settings.enabled = False
        self.settings.save()
        self.link.delete()
        self.root = User.objects.create_superuser('oroot', 'o@x.io', 'x')
        self.org = self.project.org
        self.other_org = Org.objects.create(name='Other', slug='other')
        self.other = Project.objects.create(name='Theirs', slug='theirs', insert_date=timezone.now(), org=self.other_org)
        self.org_admin = User.objects.create_user('oadmin', password='x')
        OrgMembership.objects.create(user=self.org_admin, org=self.org, role='admin')
        self.member = User.objects.create_user('omember', password='x')
        OrgMembership.objects.create(user=self.member, org=self.org, role='user')

    def call(self, user, method, path='', body=None):
        client = client_for(user)
        url = f'/cve/api/admin/openvas{path}'
        kw = {'content_type': 'application/json'}
        r = (client.get(url) if method == 'GET' else getattr(client, method.lower())(url, json.dumps(body or {}), **kw))
        return r.status_code, (r.json() if r.content else None)

    def switch_on(self):
        self.assertEqual(self.call(self.root, 'PUT', body={'enabled': True})[0], 200)

    def test_an_org_admin_sees_only_their_organization(self):
        code, data = self.call(self.org_admin, 'GET')
        self.assertEqual(code, 200)
        self.assertEqual([o['name'] for o in data['orgs']], ['R'])
        self.assertEqual(data['who'], 'org_admin')
        self.assertFalse(data['engine']['can_switch'])

    def test_an_app_admin_sees_every_organization(self):
        _code, data = self.call(self.root, 'GET')
        self.assertTrue({'R', 'Other'} <= {o['name'] for o in data['orgs']})
        self.assertTrue(data['engine']['can_switch'])

    def test_a_plain_member_gets_nothing(self):
        self.assertEqual(self.call(self.member, 'GET')[0], 403)
        self.assertEqual(self.call(self.member, 'PUT', body={'orgs': {str(self.org.pk): True}})[0], 403)

    def test_an_app_admin_has_to_switch_it_on_before_an_org_admin_can_choose(self):
        code, data = self.call(self.org_admin, 'PUT', body={'projects': {str(self.project.pk): True}})
        self.assertEqual(code, 409)
        self.assertIn('App Admin has to switch OpenVAS on first', data['error'])
        self.assertEqual(self.call(self.org_admin, 'PUT', body={'enabled': True})[0], 403)
        self.assertFalse(OpenvasSettings.current().enabled)
        self.assertFalse(OpenvasProject.objects.exists())
        code, data = self.call(self.root, 'PUT', body={'enabled': True})
        self.assertEqual(code, 200)
        self.assertEqual((data['engine']['state'], data['engine']['headline']), ('ready', 'On, scanned by Sentinels'))
        from django_celery_beat.models import PeriodicTask
        self.assertTrue(PeriodicTask.objects.get(name=ov.BEAT_NAME).enabled)
        self.assertEqual(self.call(self.org_admin, 'PUT', body={'projects': {str(self.project.pk): True}})[0], 200)
        self.assertTrue(OpenvasProject.objects.get(project=self.project).enabled)

    def test_while_it_is_off_choices_can_still_be_cleared(self):
        self.assertEqual(self.call(self.org_admin, 'PUT', body={'projects': {str(self.project.pk): False}})[0], 200)

    def test_choosing_several_organizations_and_projects_at_once(self):
        self.switch_on()
        body = {'orgs': {str(self.org.pk): True}, 'projects': {}}
        self.assertEqual(self.call(self.root, 'PUT', body={**body, 'orgs': {str(self.org.pk): True, str(self.other_org.pk): True}})[0], 200)
        self.assertEqual(set(OpenvasOrg.objects.filter(enabled=True).values_list('org_id', flat=True)), {self.org.pk, self.other_org.pk})

    def test_an_org_admin_cannot_choose_someone_elses_organization_or_project(self):
        self.switch_on()
        self.assertEqual(self.call(self.org_admin, 'PUT', body={'orgs': {str(self.other_org.pk): True}})[0], 403)
        self.assertEqual(self.call(self.org_admin, 'PUT', body={'projects': {str(self.other.pk): True}})[0], 404)  # not even visible to them
        self.assertEqual(self.call(self.org_admin, 'PUT', body={'projects': {'99999': True}})[0], 404)
        self.assertFalse(OpenvasOrg.objects.exists() or OpenvasProject.objects.exists())

    def test_only_an_app_admin_switches_it_off_for_everyone(self):
        self.switch_on()
        self.call(self.org_admin, 'PUT', body={'projects': {str(self.project.pk): True}})
        self.assertEqual(self.call(self.org_admin, 'PUT', body={'enabled': False})[0], 403)
        self.assertTrue(OpenvasSettings.current().enabled)
        self.assertEqual(self.call(self.root, 'PUT', body={'enabled': False})[0], 200)
        self.assertFalse(OpenvasSettings.current().enabled)
        self.assertTrue(OpenvasProject.objects.get(project=self.project).enabled)  # the choices are kept

    def test_a_malformed_choice_is_refused(self):
        self.assertEqual(self.call(self.root, 'PUT', body={'orgs': {'x': True}})[0], 400)
        self.assertEqual(self.call(self.root, 'PUT', body={'orgs': {str(self.org.pk): 'yes'}})[0], 400)
        self.assertEqual(self.call(self.root, 'PUT', body={'orgs': [1]})[0], 400)

    def test_every_choice_is_in_the_audit_log(self):
        self.switch_on()
        self.call(self.org_admin, 'PUT', body={'orgs': {str(self.org.pk): True}})
        actions = set(AuditLog.objects.values_list('action', flat=True))
        self.assertIn('openvas.org.update', actions)
        self.assertIn('openvas.enable', actions)

    def test_an_opted_in_organization_covers_its_projects_including_new_ones(self):
        OpenvasOrg.objects.create(org=self.org, enabled=True)
        later = Project.objects.create(name='Later', slug='later', insert_date=timezone.now(), org=self.org)
        covered = {link.project_id for link in ov.sweep_links()}
        self.assertEqual(covered, {self.project.pk, later.pk})
        self.assertNotIn(self.other.pk, covered)

    def test_unticking_a_project_of_an_opted_in_organization_excludes_it_and_the_page_shows_the_truth(self):
        self.switch_on()
        later = Project.objects.create(name='Later', slug='later', insert_date=timezone.now(), org=self.org)
        self.call(self.org_admin, 'PUT', body={'orgs': {str(self.org.pk): True}})
        projects = {p['name']: p for p in self.call(self.org_admin, 'GET')[1]['orgs'][0]['projects']}
        self.assertEqual((projects['Later']['enabled'], projects['Later']['via_org'], projects['Later']['excluded']), (True, True, False))
        self.call(self.org_admin, 'PUT', body={'projects': {str(self.project.pk): False}})
        projects = {p['name']: p for p in self.call(self.org_admin, 'GET')[1]['orgs'][0]['projects']}
        self.assertEqual((projects[self.project.name]['enabled'], projects[self.project.name]['excluded']), (False, True))
        self.assertEqual({l.project_id for l in ov.sweep_links()}, {later.pk})  # what the page shows is what the sweep does
        self.call(self.org_admin, 'PUT', body={'projects': {str(self.project.pk): True}})  # ticked again: back under the organization
        link = OpenvasProject.objects.get(project=self.project)
        self.assertEqual((link.enabled, link.excluded), (False, False))
        self.assertEqual({l.project_id for l in ov.sweep_links()}, {later.pk, self.project.pk})

    def test_unticking_a_project_while_its_organization_is_off_is_just_off(self):
        self.switch_on()
        self.call(self.org_admin, 'PUT', body={'projects': {str(self.project.pk): True}})
        self.call(self.org_admin, 'PUT', body={'projects': {str(self.project.pk): False}})
        link = OpenvasProject.objects.get(project=self.project)
        self.assertEqual((link.enabled, link.excluded), (False, False))  # a later organization tick still covers it


class HostWatcherTests(SimpleTestCase):


    def test_the_sync_script_accepts_only_on_and_off_and_lists_the_makefile_services(self):
        script = (ROOT / 'scripts' / 'openvas-sync.sh').read_text()
        self.assertIn('case $want in on | off) ;; *) exit 0 ;; esac', script)
        self.assertIn('update-state.py openvas-wanted', script)  # the request is read without following a link planted in ./web (this runs as root)
        listed = re.search(r'^SERVICES=\((.*)\)$', script, re.M).group(1).split()
        makefile = (ROOT / 'Makefile').read_text()
        self.assertEqual(listed, re.search(r'^OPENVAS_SERVICES\s*:=\s*(.*)$', makefile, re.M).group(1).split())
        watch = (ROOT / 'scripts' / 'update-watch.sh').read_text()
        self.assertIn('scripts/openvas-sync.sh', watch)
        self.assertIn('web/.openvas-wanted', (ROOT / '.gitignore').read_text())
        # a gvmd restart request (stale NVT cache) restarts openvas-gvmd only, while the add-on is on, and is answered so it runs once
        self.assertIn('scripts/openvas-sync.sh restart-gvmd', watch)
        self.assertIn('web/.openvas-restart -nt web/.openvas-restarted', watch)
        self.assertIn('--profile openvas restart openvas-gvmd', script)
        self.assertIn('ps --status running -q openvas-gvmd', script)  # only a running gvmd, also one started by hand (no web/.openvas-wanted)
        self.assertIn('[ "$want" != off ]', script)
        # the restart is handled before the on/off gate, which exits without an answer when web/.openvas-wanted is missing (make openvas-up)
        self.assertLess(script.index('restart-gvmd ]'), script.index('case $want in on | off) ;; *) exit 0 ;; esac'))
        self.assertIn('update-state.py openvas-restarted', script)
        self.assertIn('web/.openvas-restart', (ROOT / '.gitignore').read_text())

    def test_the_page_has_nothing_to_type_and_builds_no_markup(self):
        js = (ROOT / 'web' / 'static' / 'cve' / 'openvas-panel.js').read_text()
        self.assertNotIn('innerHTML', js)
        self.assertNotIn('type: "password"', js)
        self.assertNotIn('textarea', js)


class InternalNetworkTests(Fixture, TestCase):
    """A project's declared internal networks: OpenVAS reaches them only through a Sentinel inside the network, in a batch of their own."""

    def setUp(self):
        super().setUp()
        from cveFeed.models import InternalRange
        from targetApp.models import Domain
        self.env = mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': ''})
        self.env.start()
        self.addCleanup(self.env.stop)
        InternalRange.objects.create(project=self.project, cidr='10.20.0.0/24')
        self.inside = Domain.objects.create(name='10.20.0.7', project=self.project, insert_date=timezone.now())
        Subdomain.objects.create(name='10.20.0.7', target_domain=self.inside, scan_history=self.scan_obj)
        self.link.hosts, self.link.forced_hosts = [], ['10.20.0.7']  # the whole project, not a list; the internal host is forced past the heat gate
        self.link.save()

    def sentinel(self, capabilities):
        user = User.objects.create_user(f'ov-{"-".join(capabilities)}', password='x', is_superuser=True)  # reaches every project
        token, _raw = create_token(user, f'ov-token-{"-".join(capabilities)}')
        return Agent.objects.create(token=token, name='-'.join(capabilities), kind='scanner', status='active',
                                    scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                    capabilities=list(capabilities), last_seen=timezone.now(),
                                    network='internal' if 'network:internal' in capabilities else 'external')  # the server grants it, a Sentinel only claims it

    def test_the_internal_batch_holds_only_the_declared_internal_targets(self):
        self.assertEqual(ov.internal_batch(self.link), [('10.20.0.7', '10.20.0.7', self.inside.id)])

    def test_nothing_is_due_without_a_declared_range_and_a_listed_host_limits_it(self):
        self.project.internal_ranges.all().delete()
        self.assertEqual(ov.internal_batch(self.link), [])
        from cveFeed.models import InternalRange
        InternalRange.objects.create(project=self.project, cidr='10.20.0.0/24')
        self.link.hosts, self.link.forced_hosts = ['www.rt.test'], []  # not forced, not hot: nothing
        self.link.save()
        self.assertEqual(ov.internal_batch(self.link), [])

    def test_an_outside_sentinel_is_never_given_the_internal_batch(self):
        self.link.hosts, self.link.forced_hosts = ['www.rt.test'], ['10.20.0.7', 'www.rt.test']
        self.link.save()
        self.sentinel(['openvas'])
        self.tick()
        run = OpenvasRun.objects.get()
        self.assertNotIn('10.20.0.7', run.hosts)  # the external batch (or local run) never carries it

    def test_an_internal_sentinel_gets_the_internal_batch_alone(self):
        from cveFeed import ledger
        ledger.record(ov.SERVICE, ['www.rt.test', 'api.rt.test', 'db.rt.test'], self.project.id)  # the external hosts are not due: their batch goes first
        self.sentinel(['openvas', 'network:internal'])
        out = self.tick()
        self.assertEqual((out.get('status'), out.get('via')), ('running', 'internal sentinel'), out)
        run = OpenvasRun.objects.get()
        self.assertEqual(run.hosts, {'10.20.0.7': '10.20.0.7'})
        self.assertEqual(run.sentinel_task.ips, ['10.20.0.7'])

    def test_the_task_for_an_internal_address_can_only_be_claimed_by_an_internal_sentinel(self):
        from agentapi import sentinel_broker as sb
        from cveFeed import ledger
        ledger.record(ov.SERVICE, ['www.rt.test', 'api.rt.test', 'db.rt.test'], self.project.id)
        outside, inside = self.sentinel(['openvas']), self.sentinel(['openvas', 'network:internal'])
        self.tick()
        task = OpenvasRun.objects.get().sentinel_task
        self.assertEqual(sb.effective(outside).refusal(task), ('capability', sb.INTERNAL_CAPABILITY))
        self.assertIsNone(sb.effective(inside).refusal(task))


class HeatGateTests(Fixture, TestCase):
    """OpenVAS is slow (hours per host): it is spent only on hosts on fire or smoke, Fire first, never on what the project does not own."""

    def setUp(self):
        super().setUp()
        mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MAX_HOSTS': '1'}).start()  # the shipped default
        # the ordering below rests on a CVSS 7.5 CVE reading smoke: the legacy heat policy. Under the KEV rule (the default) a CVE that is
        # neither on the KEV nor exploited is ice and its host does not qualify (tests.test_heat_policy covers that gate)
        legacy = mock.patch.dict(os.environ, {'CVENGINE_HEAT_POLICY': 'legacy'})
        legacy.start()
        self.addCleanup(legacy.stop)
        self.link.hosts, self.link.forced_hosts = [], []
        self.link.save()
        self.kev = CVEEntry.objects.create(cve_id='CVE-2024-0001', title='Exploited', published_at=timezone.now(), cvss=9.8, kev=True)
        self.high = CVEEntry.objects.create(cve_id='CVE-2024-0002', title='High', published_at=timezone.now(), cvss=7.5)  # smoke
        self.low = CVEEntry.objects.create(cve_id='CVE-2024-0003', title='Low', published_at=timezone.now(), cvss=3.1)  # ice

    def heat(self, host, cve, **kw):
        sub = Subdomain.objects.filter(name=host).order_by('-scan_history_id').first()
        return CVEMatch.objects.update_or_create(cve_entry=cve, subdomain=sub, matched_product='x', defaults={'confidence': 0.9, 'matched_version': '1', **kw})[0]

    def batch(self, **kw):
        link = OpenvasProject.objects.get(pk=self.link.pk)
        return [h for h, _ip, _d in ov.next_batch(link, resolve=self.resolve, blocked=lambda h: False)]

    def test_a_project_with_no_hot_host_scans_nothing_and_a_listed_clean_host_is_still_gated(self):
        self.assertEqual(self.batch(), [])
        self.link.hosts = ['www.rt.test']
        self.link.save()
        self.assertEqual(self.batch(), [])

    def test_a_host_that_turns_fire_or_smoke_becomes_due_by_itself_and_leaves_when_it_cools(self):
        match = self.heat('api.rt.test', self.high)
        self.assertEqual(self.batch(), ['api.rt.test'])  # smoke, nobody listed it
        self.heat('www.rt.test', self.low)  # ice does not count
        self.assertEqual(self.batch(), ['api.rt.test'])
        match.remediation_status = 'fixed'
        match.save()
        self.assertEqual(self.batch(), [])  # cooled to clean

    def test_ice_clean_and_unscanned_are_never_scanned(self):
        self.heat('www.rt.test', self.low)
        for host in ('www.rt.test', 'api.rt.test', 'db.rt.test'):
            self.link.hosts = [host]
            self.link.save()
            self.assertEqual(self.batch(), [], host)
        self.assertEqual({h: v[0] for h, v in ov.host_heat(self.project.id, ['www.rt.test', 'db.rt.test']).items()}['www.rt.test'], 'ice')

    def test_fire_before_smoke_then_the_most_reasons_then_the_longest_waiting(self):
        from cveFeed import ledger
        self.heat('www.rt.test', self.high)
        self.heat('api.rt.test', self.kev)
        self.heat('db.rt.test', self.high)
        self.heat('db.rt.test', CVEEntry.objects.create(cve_id='CVE-2024-0004', title='Another', published_at=timezone.now(), cvss=8.0))
        link = OpenvasProject.objects.get(pk=self.link.pk)
        ready, _v = ov.assess(self.project.id, ov.hot_names(self.project.id), resolve=self.resolve, blocked=lambda h: False)
        self.assertEqual([h for h, _ip, _d in ready], ['api.rt.test', 'db.rt.test', 'www.rt.test'])  # fire; then smoke with two reasons; then smoke
        self.assertEqual(self.batch(), ['api.rt.test'])  # one host per task by default
        ledger.record(ov.SERVICE, ['api.rt.test'], self.project.id)
        self.assertEqual(self.batch(), ['db.rt.test'])
        self.assertEqual(link.pk, self.link.pk)

    def test_the_stalest_goes_first_among_equals(self):
        from cveFeed import ledger
        self.heat('www.rt.test', self.high)
        self.heat('api.rt.test', self.high)
        ledger.record(ov.SERVICE, ['www.rt.test'], self.project.id)
        ServiceRun.objects.filter(service=ov.SERVICE, asset='www.rt.test').update(finished_at=timezone.now() - timedelta(days=30))
        ledger.record(ov.SERVICE, ['api.rt.test'], self.project.id)
        ServiceRun.objects.filter(service=ov.SERVICE, asset='api.rt.test').update(finished_at=timezone.now() - timedelta(days=20))
        ready, _v = ov.assess(self.project.id, ['www.rt.test', 'api.rt.test'], resolve=self.resolve, blocked=lambda h: False)
        self.assertEqual([h for h, _ip, _d in ready], ['www.rt.test', 'api.rt.test'])

    def test_a_forced_host_is_scanned_whatever_its_heat_but_after_the_hot_ones(self):
        self.heat('www.rt.test', self.high)
        self.link.hosts, self.link.forced_hosts = ['db.rt.test'], ['db.rt.test']
        self.link.save()
        link = OpenvasProject.objects.get(pk=self.link.pk)
        ready, _v = ov.assess(link.project_id, ov.hot_names(link.project_id) | {'db.rt.test'}, {'db.rt.test'}, resolve=self.resolve, blocked=lambda h: False)
        self.assertEqual([h for h, _ip, _d in ready], ['www.rt.test', 'db.rt.test'])

    def refused(self, host, **over):
        """The reason ``assess`` gives for a hot host with the stored address (no DNS)."""
        self.heat(host, self.kev)
        ready, verdicts = ov.assess(self.project.id, [host], forced={host}, resolve=over.get('resolve') or (lambda h, p: IPS.get(h, '93.184.216.9')), blocked=lambda h: False)
        return ready, verdicts[host]

    def test_a_cdn_a_saas_front_and_a_shared_address_are_refused_even_when_hot_and_forced(self):
        Subdomain.objects.filter(name='www.rt.test').update(is_cdn=True, cdn_name='CloudFront')
        ready, verdict = self.refused('www.rt.test')
        self.assertEqual(ready, [])
        self.assertIn('CDN', verdict['reason'])
        Subdomain.objects.filter(name='api.rt.test').update(name='client-a.atlassian.net')
        ready, verdict = self.refused('client-a.atlassian.net')
        self.assertEqual(ready, [])
        self.assertIn('third-party platform', verdict['reason'])

    def test_documentation_this_server_and_the_tailnet_are_refused_with_the_reason(self):
        for ip, text in (('192.0.2.1', 'documentation'), ('100.64.1.1', 'tailnet')):
            ready, verdict = self.refused('www.rt.test', resolve=lambda h, p, ip=ip: ip)
            self.assertEqual(ready, [], ip)
            self.assertIn(text, verdict['reason'], ip)
        with mock.patch.dict(os.environ, {'CVENGINE_OWN_ADDRESSES': '93.184.216.5'}), mock.patch.dict(ov._own, {'at': 0.0}):
            ready, verdict = self.refused('www.rt.test')
        self.assertEqual(ready, [])
        self.assertIn('this cvENGINE server', verdict['reason'])

    def test_not_a_host_of_the_project_excluded_and_recent_runs_say_why(self):
        from cveFeed import ledger
        from cveFeed.models import HostExclusion
        _r, verdict = ov.assess(self.project.id, ['nobody.rt.test'], resolve=self.resolve)
        self.assertEqual(verdict['nobody.rt.test']['reason'], 'not a host of this project')
        self.heat('api.rt.test', self.kev)
        HostExclusion.objects.create(org=self.project.org, host='api.rt.test', include_subdomains=False)
        self.assertEqual(ov.assess(self.project.id, ['api.rt.test'], resolve=self.resolve)[1]['api.rt.test']['reason'], 'excluded from scanning')
        HostExclusion.objects.all().delete()
        self.heat('www.rt.test', self.kev)
        ledger.record(ov.SERVICE, ['www.rt.test'], self.project.id)
        ServiceRun.objects.filter(asset='www.rt.test').update(finished_at=timezone.now() - timedelta(days=3))
        self.assertEqual(ov.assess(self.project.id, ['www.rt.test'], resolve=self.resolve)[1]['www.rt.test']['reason'], 'scanned 3 days ago; due again after a week')
        ledger.record(ov.FAILED_SERVICE, ['db.rt.test'], self.project.id)
        self.heat('db.rt.test', self.kev)
        self.assertIn('could not be scanned', ov.assess(self.project.id, ['db.rt.test'], resolve=self.resolve)[1]['db.rt.test']['reason'])

    def test_the_explanation_names_the_heat_gate_and_needs_no_dns(self):
        self.heat('api.rt.test', self.kev)
        link = OpenvasProject.objects.get(pk=self.link.pk)
        self.link.hosts = ['www.rt.test']
        self.link.save()
        with mock.patch('socket.getaddrinfo', side_effect=AssertionError('no DNS')):
            rows = {r['host']: r for r in ov.explain(OpenvasProject.objects.get(pk=link.pk))}
        self.assertEqual(rows['api.rt.test']['ready'], True)
        self.assertEqual(rows['api.rt.test']['order'], 0)
        self.assertFalse(rows['www.rt.test']['ready'])
        self.assertIn('not Fire or Smoke', rows['www.rt.test']['reason'])

    def test_a_name_that_does_not_resolve_is_asked_again_in_three_days_not_every_tick(self):
        self.heat('api.rt.test', self.kev)

        def broken(host, project_id):
            raise OSError('no answer')
        link = OpenvasProject.objects.get(pk=self.link.pk)
        self.assertEqual(ov.next_batch(link, resolve=broken, blocked=lambda h: False), [])
        self.assertTrue(ServiceRun.objects.filter(service=ov.FAILED_SERVICE, asset='api.rt.test').exists())

    def test_the_cve_of_another_project_never_makes_a_host_hot(self):
        other = Project.objects.create(name='Theirs', slug='theirs2', insert_date=timezone.now(), org=self.project.org)
        domain = Domain.objects.create(name='x.test', project=other, insert_date=timezone.now())
        scan = ScanHistory.objects.create(domain=domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=1, tasks=[], results_dir='x')
        sub = Subdomain.objects.create(name='x.other.test', target_domain=domain, scan_history=scan)
        CVEMatch.objects.create(cve_entry=self.kev, subdomain=sub, confidence=0.9, matched_product='x', matched_version='1')
        self.assertNotIn('x.other.test', ov.hot_names(self.project.id))
        self.assertIn('x.other.test', ov.hot_names(other.id))

    def test_one_host_per_task_and_the_budget_is_per_host(self):
        self.assertEqual((ov.max_hosts(), ov.max_hours()), (1, 24))
        self.assertEqual(ov.budget_hours(1), 24)
        self.assertEqual(ov.budget_hours(3), 72)
        self.assertEqual(ov.task_preferences(), {'max_checks': '4', 'max_hosts': '1'})
        with mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MAX_CHECKS': '2'}):
            self.assertEqual(ov.task_preferences()['max_checks'], '2')
        with mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MAX_CHECKS': '99'}):
            self.assertEqual(ov.task_preferences()['max_checks'], '10')

    def test_the_tick_scans_the_hottest_host_alone_with_a_task_of_one(self):
        self.heat('www.rt.test', self.high)
        self.heat('api.rt.test', self.kev)
        self.make_sentinel()
        out = self.tick()
        self.assertEqual((out['status'], out['hosts']), ('running', 1))
        self.assertEqual(OpenvasRun.objects.get().hosts, {'93.184.216.6': 'api.rt.test'})


class KevHeatGateTests(Fixture, TestCase):
    """The heat gate under the KEV heat policy (the default; HeatGateTests pins legacy): a host qualifies through a CVE on the KEV or with a
    known exploit (rated by its validation heat, the heat once proven: OpenVAS is how it is proven), or an open finding of medium severity or
    more that names no CVE; a CVE that is neither on the KEV nor exploited is ice, whatever its CVSS, and a host with only such CVEs (as matches
    or as scanner findings) is not scanned. Fire before smoke, then the most reasons, then the longest waiting."""

    def setUp(self):
        super().setUp()
        mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MAX_HOSTS': '1'}).start()
        kev = mock.patch.dict(os.environ, {'CVENGINE_HEAT_POLICY': 'kev'})
        kev.start()
        self.addCleanup(kev.stop)
        self.link.hosts, self.link.forced_hosts = [], []
        self.link.save()
        self.kev = CVEEntry.objects.create(cve_id='CVE-2024-0001', title='Exploited', published_at=timezone.now(), cvss=6.5, kev=True)
        self.exploit = CVEEntry.objects.create(cve_id='CVE-2024-0005', title='Exploit', published_at=timezone.now(), cvss=4.0, exploit_db=True)
        self.critical = CVEEntry.objects.create(cve_id='CVE-2024-0002', title='Critical', published_at=timezone.now(), cvss=9.8, epss_reached=True)

    def latest(self, host):
        return Subdomain.objects.filter(name=host).order_by('-scan_history_id').first()

    def heat(self, host, cve, **kw):
        return CVEMatch.objects.update_or_create(cve_entry=cve, subdomain=self.latest(host), matched_product='x',
                                                 defaults={'confidence': 0.9, 'matched_version': '1', **kw})[0]

    def finding(self, host, severity, cves=(), source='nuclei-cve'):
        from startScan.models import CveId
        sub = self.latest(host)
        v = Vulnerability.objects.create(name=f'finding {severity}', severity=severity, source=source, subdomain=sub,
                                         target_domain=sub.target_domain, scan_history=sub.scan_history, open_status=True)
        for cve in cves:
            v.cve_ids.add(CveId.objects.create(name=cve))
        return v

    def batch(self):
        link = OpenvasProject.objects.get(pk=self.link.pk)
        return [h for h, _ip, _d in ov.next_batch(link, resolve=self.resolve, blocked=lambda h: False)]

    def test_a_critical_score_alone_does_not_qualify_a_host_and_a_kev_cve_does(self):
        self.heat('www.rt.test', self.critical)
        self.finding('db.rt.test', 4, ['CVE-2024-0002'])  # the same CVE confirmed by a template: still neither on the KEV nor exploited
        self.assertEqual(self.batch(), [])
        self.assertEqual({h: v[0] for h, v in ov.host_heat(self.project.id, ['www.rt.test', 'db.rt.test']).items()},
                         {'www.rt.test': 'ice', 'db.rt.test': 'ice'})
        match = self.heat('api.rt.test', self.kev)  # version not proven: smoke on the host, fire here (validation heat)
        self.assertEqual(self.batch(), ['api.rt.test'])
        match.remediation_status = 'fixed'
        match.save()
        self.assertEqual(self.batch(), [])  # cooled

    def test_fire_before_smoke_then_the_most_reasons_then_the_longest_waiting(self):
        from cveFeed import ledger
        self.finding('www.rt.test', 2, source='bbot')  # a medium finding that names no CVE: smoke by its severity
        self.heat('api.rt.test', self.exploit)
        self.finding('db.rt.test', 2, source='bbot')
        self.finding('db.rt.test', 2, source='wapiti')
        ready, _v = ov.assess(self.project.id, ov.hot_names(self.project.id), resolve=self.resolve, blocked=lambda h: False)
        self.assertEqual([h for h, _ip, _d in ready], ['api.rt.test', 'db.rt.test', 'www.rt.test'])
        self.assertEqual(self.batch(), ['api.rt.test'])
        ledger.record(ov.SERVICE, ['api.rt.test'], self.project.id)
        self.assertEqual(self.batch(), ['db.rt.test'])

    def test_a_hot_cve_finding_qualifies_its_host(self):
        self.finding('www.rt.test', 3, ['CVE-2024-0001'], source='openvas')
        self.assertEqual(self.batch(), ['www.rt.test'])


class BudgetTests(Fixture, TestCase):
    """A task that runs out of its time budget keeps what it found."""

    def setUp(self):
        super().setUp()
        mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MAX_HOSTS': '1'}).start()
        self.link.hosts, self.link.forced_hosts = ['www.rt.test'], ['www.rt.test']
        self.link.save()

    def test_a_partial_scan_resolves_nothing_it_did_not_get_to(self):
        self.run_scan([APACHE, BANNER])  # a complete scan found both
        out = self.run_scan([APACHE], partial=True)  # the next one stopped at its budget after the Apache check
        self.assertEqual(out['partial'], True)
        self.assertTrue(Vulnerability.objects.filter(template_id=f'openvas:{OID_BANNER}', open_status=True).exists())  # not resolved by a partial scan

    def test_a_sentinels_partial_result_is_kept_the_same_way(self):
        from agentapi.models import SentinelTask
        ServiceRun.objects.all().delete()
        task = SentinelTask.objects.create(project=self.project, kind='openvas', ips=['93.184.216.5'], status='done',
                                           target={'hosts': {'93.184.216.5': 'www.rt.test'}},
                                           result={'results': [_sentinel_item()], 'scanned_addresses': ['93.184.216.5'], 'without_cve': 0, 'unusable': 0, 'partial': True})
        OpenvasRun.objects.create(project=self.project, status='running', sentinel_task=task, hosts={'93.184.216.5': 'www.rt.test'})
        out = ov.poll_sentinel(OpenvasRun.objects.get())
        self.assertEqual((out['status'], out['partial']), ('done', True))
        self.assertIn('time budget', OpenvasRun.objects.get().error)

    def sentinel_run(self, **result):
        from agentapi.models import SentinelTask
        ServiceRun.objects.all().delete()
        task = SentinelTask.objects.create(project=self.project, kind='openvas', ips=['93.184.216.5'], status='done',
                                           target={'hosts': {'93.184.216.5': 'www.rt.test'}}, result=result)
        return OpenvasRun.objects.create(project=self.project, status='running', sentinel_task=task, hosts={'93.184.216.5': 'www.rt.test'})

    def test_a_sentinel_task_done_with_no_scanned_host_is_inconclusive_not_a_scan(self):
        run = self.sentinel_run(outcome='done', results=[], unusable=0, without_cve=0, scanned_addresses=[])
        out = ov.poll_sentinel(run)
        run.refresh_from_db()
        self.assertEqual(out['status'], 'done')
        self.assertTrue(run.summary['inconclusive'])
        self.assertEqual(run.error, ov.INCONCLUSIVE)
        self.assertFalse(ServiceRun.objects.filter(service=ov.SERVICE).exists())  # never stamped as scanned
        self.assertTrue(ServiceRun.objects.filter(service=ov.FAILED_SERVICE, asset='www.rt.test').exists())  # asked again in three days
        self.assertEqual(ov.inconclusive_hosts(self.project.id, ['www.rt.test']), {'www.rt.test'})

    def test_a_scan_that_reported_its_host_is_not_inconclusive_even_with_no_result(self):
        run = self.sentinel_run(outcome='done', results=[], unusable=0, without_cve=0, scanned_addresses=['93.184.216.5'])
        ov.poll_sentinel(run)
        run.refresh_from_db()
        self.assertFalse(run.summary['inconclusive'])
        self.assertEqual(run.error, '')
        self.assertTrue(ServiceRun.objects.filter(service=ov.SERVICE, asset='www.rt.test', status='done').exists())
        self.assertEqual(ov.inconclusive_hosts(self.project.id, ['www.rt.test']), set())

    def test_the_host_reason_says_the_scan_was_inconclusive(self):
        run = self.sentinel_run(outcome='done', results=[], scanned_addresses=[])
        ov.poll_sentinel(run)
        verdict = {r['host']: r for r in ov.explain(self.link)}['www.rt.test']
        self.assertFalse(verdict['ready'])
        self.assertIn(ov.INCONCLUSIVE, verdict['reason'])

    def test_the_sentinel_task_carries_the_budget_and_preferences_the_server_decided(self):
        from agentapi import sentinel_broker as sb
        cleaned = sb._clean_openvas_result({'results': [], 'scanned_addresses': [], 'partial': True})
        self.assertIs(cleaned['partial'], True)
        self.assertIs(sb._clean_openvas_result({'results': [], 'partial': 'yes'})['partial'], False)


class SentinelViewTests(Fixture, TestCase):
    """Settings > OpenVAS shows the Sentinels (ready, or why not), the run and the last result, never a stale local-engine error;
    and with no ready Sentinel nothing is marked failed and nothing runs here."""

    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('ovroot', 'r@x.io', 'x')
        self.owner = User.objects.create_user('ov-owner', password='x')
        self.settings.state = {'connected': False, 'error': 'gvmd could not be reached (Socket /run/gvmd/gvmd.sock does not exist): is the openvas profile running?'}  # left by an earlier version
        self.settings.save()

    def agent(self, name, capabilities, info=None, status='active', seen=True):
        token, _raw = create_token(self.owner, f'tok-{name}')
        return Agent.objects.create(token=token, name=name, kind='scanner', status=status, scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                    capabilities=capabilities, info=info or {}, last_seen=timezone.now() if seen else None)

    def page(self):
        r = client_for(self.root).get('/cve/api/settings/openvas')
        self.assertEqual(r.status_code, 200)
        return r.json()

    def test_the_stale_local_engine_error_is_not_shown_and_the_engine_is_scanned_by_sentinels(self):
        data = self.page()
        self.assertNotIn('state', data)
        self.assertNotIn('is the openvas profile running', json.dumps(data))
        from cveFeed import openvas_admin
        self.assertEqual(openvas_admin.engine_status(self.settings)['state'], 'ready')
        self.assertEqual(openvas_admin.engine_status(OpenvasSettings(enabled=False))['state'], 'off')

    def test_each_sentinel_is_ready_or_says_why_not(self):
        self.agent('ready-one', ['nmap', 'openvas'], info={'openvas': {'ready': True, 'reason': ''}})
        self.agent('syncing', ['nmap'], info={'openvas': {'ready': False, 'reason': 'GVM is still syncing its nvt feed(s)'}})
        self.agent('light', ['nmap'])
        self.agent('away', ['openvas'], seen=False)
        rows = {r['name']: r for r in self.page()['sentinels']}
        self.assertTrue(rows['ready-one']['ready'])
        self.assertFalse(rows['syncing']['ready'])
        self.assertIn('still syncing', rows['syncing']['reason'])
        self.assertIn('light', rows['light']['reason'])
        self.assertFalse(rows['away']['ready'])  # declares it, but is not checking in

    def test_the_run_and_the_last_result_are_on_the_page(self):
        self.assertIsNone(self.page()['last_run'])
        OpenvasRun.objects.create(project=self.project, status='done', hosts={'93.184.216.5': 'www.rt.test'}, summary={'findings': 3, 'partial': True})
        last = self.page()['last_run']
        self.assertEqual((last['status'], last['hosts'], last['summary']['findings']), ('done', ['www.rt.test'], 3))

    def test_no_ready_sentinel_means_nothing_runs_locally_and_nothing_is_marked_failed(self):
        guard = assert_ran_nowhere_locally(self, 'openvas')
        self.agent('syncing', ['nmap'], info={'openvas': {'ready': False, 'reason': 'GVM is still syncing'}})  # does not declare openvas
        for _ in range(3):
            self.assertIn('skipped', self.tick())
        self.assertFalse(OpenvasRun.objects.exists())
        self.assertFalse(ServiceRun.objects.filter(service__in=(ov.SERVICE, ov.FAILED_SERVICE)).exists())  # the hosts simply stay due
        self.assertEqual(guard.calls, [])

    def test_a_sentinel_reports_its_gvm_readiness_in_the_heartbeat_info(self):
        from agentapi import sentinel_settings as ss
        self.assertEqual(ss.clean_info({'openvas': {'ready': False, 'reason': 'GVM is still syncing\x00 feeds'}})['openvas'],
                         {'ready': False, 'reason': 'GVM is still syncing feeds'})
        from agentapi.services import ApiError
        for bad in ('yes', {'ready': 'yes'}, {'ready': True, 'reason': 5}):
            with self.assertRaises(ApiError):
                ss.clean_info({'openvas': bad})
