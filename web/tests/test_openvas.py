"""The optional OpenVAS (Greenbone) add-on: the GMP client against a fake gvmd that speaks the real protocol, the resource guard, the host gating,
the one-task-at-a-time sweep, the import (QoD, severity, dedupe, resolution), the settings API and its permissions, and the off-by-default
behaviour (nothing contacts the sidecar, nothing is scheduled, nothing starts). python-gvm itself runs unmodified over a unix socket; only gvmd is
simulated (tests/fake_gvmd.py), so nothing here proves a real gvmd answers the same way (docs/OPENVAS.md says what that leaves open)."""
import json
import os
import re
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from gvm.connections import UnixSocketConnection
from lxml import etree

from cveFeed import openvas_scan as ov
from cveFeed.models import CVEEntry, CVEMatch, OpenvasProject, OpenvasRun, OpenvasSettings, ProbeObservation, ScanControl, ServiceRun
from dashboard.models import AuditLog, Org, OrgMembership, Project
from reNgine import resources
from startScan.models import ScanHistory, Subdomain, Vulnerability
from tests.fake_gvmd import FULL_AND_FAST, FakeGvmd
from tests.test_route_auth import RouteFixture
from tests.test_settings import send
from tests.test_tenancy import client_for

ROOT = Path(__file__).resolve().parents[2]
OID_APACHE = '1.3.6.1.4.1.25623.1.0.117721'
OID_BANNER = '1.3.6.1.4.1.25623.1.0.100315'
OID_SSH = '1.3.6.1.4.1.25623.1.0.105001'
OID_PLAIN = '1.3.6.1.4.1.25623.1.0.900001'
HEALTHY = {'total_mb': 16000, 'limit_mb': None, 'used_mb': 3000, 'available_mb': 13000}
IPS = {'www.rt.test': '203.0.113.5', 'api.rt.test': '203.0.113.6', 'db.rt.test': '198.51.100.7'}


def memory(**over):
    return {**HEALTHY, **over}


def result_xml(host='203.0.113.5', port='443/tcp', oid=OID_APACHE, name='Apache HTTP Server < 2.4.51 Path Traversal', severity=9.8, qod=99, cves=('CVE-2021-41773',),
               description='Installed version: 2.4.49', tags=None, hostname='www.rt.test'):
    """One <result> as gvmd 22.x prints it in get_results."""
    from tests.fake_gvmd import FakeGvmd as F
    gvmd = F.__new__(F)
    F.__init__(gvmd)
    gvmd.add_result('t', host, port, oid, name, severity, qod, cves=cves, description=description, hostname=hostname, tags=tags)
    return etree.fromstring(gvmd.results['t'][0])


class ParseTests(SimpleTestCase):
    def test_a_result_is_read_with_its_cves_qod_and_severity(self):
        item = ov.parse_result(result_xml())
        self.assertEqual((item['oid'], item['address'], item['port'], item['port_number']), (OID_APACHE, '203.0.113.5', '443/tcp', 443))
        self.assertEqual((item['severity'], item['qod'], item['qod_type'], item['cves']), (9.8, 99, 'remote_banner', ['CVE-2021-41773']))
        self.assertEqual(item['summary'], 'The product Apache HTTP Server < 2.4.51 Path Traversal is affected.')
        self.assertEqual(item['solution_type'], 'VendorFix')
        self.assertEqual(item['cvss_vector'], 'AV:N/AC:L/Au:N/C:P/I:P/A:P')

    def test_only_valid_cve_ids_survive_and_they_are_normalised(self):
        item = ov.parse_result(result_xml(cves=('cve-2021-41773', 'CVE-2021-41773', 'CVE-21-1', 'CVE-2021-1', 'NOT-A-CVE', 'CVE-2020-1234567')))
        self.assertEqual(item['cves'], ['CVE-2020-1234567', 'CVE-2021-41773'])

    def test_a_result_without_a_host_or_an_oid_is_unusable(self):
        self.assertIsNone(ov.parse_result(etree.fromstring('<result><nvt oid="1.2.3"/></result>')))
        self.assertIsNone(ov.parse_result(etree.fromstring('<result><host>203.0.113.5</host><nvt oid="not an oid"/></result>')))
        self.assertIsNone(ov.parse_result(etree.fromstring('<result><host>203.0.113.5</host></result>')))

    def test_ports(self):
        self.assertEqual(ov._port('443/tcp'), ('443/tcp', 443))
        self.assertEqual(ov._port('53/UDP'), ('53/udp', 53))
        self.assertEqual(ov._port('general/tcp'), ('general/tcp', 0))
        self.assertEqual(ov._port('99999/tcp'), ('general/tcp', 0))
        self.assertEqual(ov._port('; rm -rf /'), ('general/tcp', 0))

    def test_numbers_are_bounded_and_malformed_ones_read_as_zero(self):
        item = ov.parse_result(result_xml(severity=9.8))
        self.assertTrue(0 <= item['qod'] <= 100 and 0 <= item['severity'] <= 10)
        broken = etree.fromstring(etree.tostring(result_xml()).replace(b'<severity>9.8</severity>', b'<severity>lots</severity>').replace(b'<value>99</value>', b'<value>9999</value>'))
        parsed = ov.parse_result(broken)
        self.assertEqual((parsed['severity'], parsed['qod']), (0.0, 100))

    def test_hostile_nvt_text_is_stored_as_plain_bounded_text(self):
        evil = '<script>alert(1)</script>\x7f[31m' + 'A' * 50000
        item = ov.parse_result(result_xml(name=evil[:60], description=evil,
                                          tags='summary=' + evil + '|insight=' + evil + '|solution_type=VendorFix'))
        for key in ('result', 'summary', 'insight'):
            self.assertLessEqual(len(item[key]), 2000, key)
            self.assertNotIn('\x7f', item[key])
        self.assertIn('<script>', item['result'])  # kept as inert text: it is the template's job to escape it, and nothing here marks it safe

    def test_clean_strips_control_characters_and_clips(self):
        self.assertEqual(ov.clean('a\x00b\x1b[0mc\x7fd\te\nf'), 'ab[0mcd\te\nf')
        self.assertEqual(len(ov.clean('x' * 9000)), ov.MAX_TEXT)
        self.assertEqual(ov.clean(None), '')

    def test_severity_levels_follow_cvss(self):
        self.assertEqual([ov.severity_level(s) for s in (0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)], [0, 1, 1, 2, 2, 3, 3, 4, 4])

    def test_the_confirmation_line_is_80(self):
        self.assertEqual(ov.CONFIRMED_QOD, 80)
        self.assertTrue(ov.confirmed({'qod': 80}))
        self.assertFalse(ov.confirmed({'qod': 79}))

    def test_nothing_marks_third_party_text_safe_for_html(self):
        for name in ('openvas_scan.py', 'openvas_admin.py'):
            text = (ROOT / 'web' / 'cveFeed' / name).read_text()
            self.assertNotIn('mark_safe', text)
            self.assertNotIn('|safe', text)
        js = (ROOT / 'web' / 'static' / 'cve' / 'settings.js').read_text()
        section = js[js.index('async openvas(m)'):js.index('async keys(m)')]
        self.assertNotIn('innerHTML', section)


class GvmdFixture:
    """A running fake gvmd and a session factory pointed at it."""

    def start_gvmd(self, **kw):
        self.gvmd = FakeGvmd(**kw).__enter__()
        self.addCleanup(self.gvmd.__exit__, None, None, None)
        gvmd = self.gvmd

        def factory(creds=None):
            return ov.session(creds=creds or (gvmd.user, gvmd.password), connection=UnixSocketConnection(path=gvmd.path, timeout=5))
        self.factory = factory
        return self.gvmd


class ClientTests(GvmdFixture, TestCase):
    def test_the_real_client_negotiates_the_version_and_signs_in(self):
        gvmd = self.start_gvmd()
        with self.factory() as gmp:
            self.assertEqual(ov._text(gmp.get_version(), 'version'), '22.7')
        self.assertGreaterEqual(gvmd.connections, 2)  # python-gvm asks the version on a connection of its own first

    def test_a_wrong_password_is_an_error_that_never_repeats_it(self):
        self.start_gvmd()
        with self.assertRaises(ov.OpenvasError) as raised:
            with self.factory(('cvengine', 'guess-hunter2')):
                pass
        self.assertNotIn('guess-hunter2', str(raised.exception))
        self.assertIn('refused', str(raised.exception))

    def test_no_login_saved_is_said_plainly(self):
        self.start_gvmd()
        with self.assertRaises(ov.OpenvasError) as raised:
            with ov.session(creds=('', '')):
                pass
        self.assertIn('no GMP login', str(raised.exception))

    def test_a_missing_socket_is_a_message_not_a_traceback(self):
        with self.assertRaises(ov.OpenvasError) as raised:
            with ov.session(creds=('u', 'p'), connection=UnixSocketConnection(path='/nonexistent/gvmd.sock', timeout=2)):
                pass
        self.assertIn('gvmd could not be reached', str(raised.exception))

    def test_a_gvmd_error_status_is_an_error(self):
        gvmd = self.start_gvmd()
        gvmd.fail['get_feeds'] = ('500', 'Internal error')
        with self.factory() as gmp:
            with self.assertRaises(Exception):
                gmp.get_feeds()

    def test_the_transport_defaults_to_the_socket_and_tls_is_opt_in(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('CVENGINE_OPENVAS_HOST', None)
            self.assertEqual(ov.transport(), 'socket:/run/gvmd/gvmd.sock')
        with mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_HOST': 'gvm.example.test', 'CVENGINE_OPENVAS_PORT': '9391'}):
            self.assertEqual(ov.transport(), 'tls:gvm.example.test:9391')


class FeedStateTests(GvmdFixture, TestCase):
    def state(self, **kw):
        self.start_gvmd(**kw)
        with self.factory() as gmp:
            return ov.feed_state(gmp)

    def test_a_loaded_feed_is_ready(self):
        state = self.state()
        self.assertTrue(state['ready'], state)
        self.assertEqual((state['nvts'], state['scanner'], state['reason']), (95000, 'OpenVAS Default', ''))
        self.assertEqual(state['feeds']['NVT']['version'], '202610270500')

    def test_vulnerability_tests_not_loaded_means_no_scan_and_says_why(self):
        state = self.state(nvts=0)
        self.assertFalse(state['ready'])
        self.assertIn('not loaded yet', state['reason'])
        self.assertIn('takes a long time', state['reason'])

    def test_a_feed_that_is_still_synchronising_says_so_with_the_disk_warning(self):
        state = self.state(syncing=True)
        self.assertFalse(state['ready'])
        self.assertIn('NVT feed is synchronising', state['reason'])
        self.assertIn('GB of disk', state['reason'])

    def test_missing_feed_data_is_named(self):
        state = self.state(feeds=('NVT', 'SCAP'))
        self.assertFalse(state['ready'])
        self.assertIn('CERT', state['reason'])
        self.assertIn('GVMD_DATA', state['reason'])


class ConfigTests(GvmdFixture, TestCase):
    def test_the_safe_configuration_is_a_copy_of_full_and_fast_without_the_dangerous_families(self):
        gvmd = self.start_gvmd()
        with self.factory() as gmp:
            config_id = ov.ensure_config(gmp)
        config = gvmd.configs[config_id]
        self.assertEqual(config['name'], 'cvENGINE safe scan')
        self.assertNotIn('Denial of Service', config['families'])
        self.assertNotIn('Brute force attacks', config['families'])
        self.assertIn('Web application abuses', config['families'])
        self.assertEqual(config['safe_checks'], 'yes')
        self.assertEqual(set(ov.EXCLUDED_FAMILIES), {'Denial of Service', 'Brute force attacks'})
        self.assertIn(FULL_AND_FAST, gvmd.configs)  # the built-in is never modified
        self.assertIn('Denial of Service', gvmd.configs[FULL_AND_FAST]['families'])

    def test_new_families_are_not_added_automatically(self):
        gvmd = self.start_gvmd()
        with self.factory() as gmp:
            ov.ensure_config(gmp)
        selection = gvmd.sent('modify_config')[0].find('family_selection')
        self.assertEqual(selection.findtext('growing'), '0')

    def test_it_is_built_once_and_reused(self):
        gvmd = self.start_gvmd()
        with self.factory() as gmp:
            first = ov.ensure_config(gmp)
            second = ov.ensure_config(gmp)
        self.assertEqual(first, second)
        self.assertEqual(len(gvmd.sent('create_config')), 1)

    def test_an_existing_configuration_that_is_not_safe_is_refused_not_used(self):
        gvmd = self.start_gvmd()
        with self.factory() as gmp:
            config_id = ov.ensure_config(gmp)
        gvmd.configs[config_id]['safe_checks'] = 'no'
        with self.factory() as gmp:
            with self.assertRaises(ov.OpenvasError) as raised:
                ov.ensure_config(gmp)
        self.assertIn('safe_checks', str(raised.exception))
        gvmd.configs[config_id]['safe_checks'] = 'yes'
        gvmd.configs[config_id]['families']['Denial of Service'] = {'count': 12, 'growing': False}
        with self.factory() as gmp:
            with self.assertRaises(ov.OpenvasError) as raised:
                ov.ensure_config(gmp)
        self.assertIn('Denial of Service', str(raised.exception))

    def test_without_the_feed_there_is_no_base_to_copy(self):
        gvmd = self.start_gvmd()
        del gvmd.configs[FULL_AND_FAST]
        with self.factory() as gmp:
            with self.assertRaises(ov.OpenvasError) as raised:
                ov.ensure_config(gmp)
        self.assertIn('not in gvmd yet', str(raised.exception))


class GuardTests(SimpleTestCase):
    """The platform's job budget (reNgine.resources) applied to the sidecar's scan, with a real MemoryStore."""

    def guard(self, state=None, store=None, now=1000.0):
        return ov.resource_guard(state_fn=lambda: state or memory(), store=store or resources.MemoryStore(), now=now)

    def test_a_healthy_machine_may_start(self):
        self.assertEqual(self.guard(), (True, ''))

    def test_short_memory_refuses_and_says_by_how_much(self):
        ok, reason = self.guard(memory(available_mb=2000))
        self.assertFalse(ok)
        self.assertIn('memory is short: 2000 MB free', reason)
        self.assertIn(str(ov.min_available_mb()), reason)

    def test_the_floor_includes_the_platforms_headroom(self):
        headroom = resources.headroom_mb(memory())
        self.assertEqual(self.guard(memory(available_mb=ov.min_available_mb() + headroom))[0], True)
        self.assertEqual(self.guard(memory(available_mb=ov.min_available_mb() + headroom - 1))[0], False)

    def test_the_floor_is_tunable(self):
        with mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MIN_AVAILABLE_MB': '9000'}):
            self.assertFalse(self.guard(memory(available_mb=9100))[0])
            self.assertTrue(self.guard(memory(available_mb=12000))[0])

    def test_running_scanners_that_use_up_the_job_budget_refuse(self):
        store = resources.MemoryStore()
        budget = resources.budget_mb(memory())
        store.reserve('a', budget - 100, 'nuclei: x', budget, 1000.0, 'nuclei')
        ok, reason = self.guard(store=store)
        self.assertFalse(ok)
        self.assertIn('job budget', reason)

    def test_jobs_waiting_for_memory_refuse(self):
        store = resources.MemoryStore()
        store.wait('w', 1000, 'bbot-deep: x', 1000.0)
        self.assertEqual(self.guard(store=store, now=1000.0), (False, 'other scanner jobs are waiting for memory'))

    def test_a_recent_memory_kill_refuses_an_old_one_does_not(self):
        store = resources.MemoryStore()
        store.event({'t': 900.0, 'kind': 'nuclei'})
        self.assertFalse(self.guard(store=store, now=1000.0)[0])
        self.assertTrue(self.guard(store=store, now=900.0 + 3601)[0])

    def test_a_task_in_flight_is_stopped_below_the_critical_floor(self):
        critical = resources.critical_mb(memory())
        self.assertTrue(ov.memory_critical(lambda: memory(available_mb=critical - 1)))
        self.assertFalse(ov.memory_critical(lambda: memory(available_mb=critical + 1)))


class Fixture(GvmdFixture, RouteFixture):
    """An organisation, a project with three hosts, a fake gvmd, the add-on switched on, the project opted in, and a healthy machine."""

    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test',), ip='203.0.113.5')
        self.scan(names=('api.rt.test',), ip='203.0.113.6')
        self.scan(names=('db.rt.test',), ip='198.51.100.7')
        self.start_gvmd()
        self.settings = OpenvasSettings.current()
        self.settings.enabled, self.settings.gmp_username, self.settings.gmp_password = True, self.gvmd.user, self.gvmd.password
        self.settings.save()
        self.link = OpenvasProject.objects.create(project=self.project, enabled=True, hosts=['www.rt.test', 'api.rt.test'])
        self.store = resources.MemoryStore()
        mock.patch('reNgine.resources.memory_state', lambda *a, **k: dict(self.memory_state)).start()
        mock.patch('reNgine.resources.get_store', lambda: self.store).start()
        self.memory_state = dict(HEALTHY)
        self.cve = CVEEntry.objects.create(cve_id='CVE-2021-41773', title='Apache path traversal', published_at=timezone.now(), cvss=7.5)
        self.cve2 = CVEEntry.objects.create(cve_id='CVE-2019-0001', title='Old thing', published_at=timezone.now(), cvss=5.0)

    def resolve(self, host, project_id):
        return IPS[host]

    def tick(self):
        return ov.tick(session_factory=self.factory, resolve=self.resolve, blocked=lambda h: False)

    def finish_task(self, results, status='Done'):
        """Make the running task finish with ``results`` (a list of kwargs for add_result)."""
        run = OpenvasRun.objects.get(status='running')
        for kw in results:
            self.gvmd.add_result(run.task_id, **kw)
        self.gvmd.set_status(run.task_id, status, 100 if status == 'Done' else 50)
        return run

    def run_scan(self, results, status='Done'):
        """A whole sweep: start the due batch (forgetting earlier runs), let the task finish with ``results``, import them. Returns the import's answer."""
        ServiceRun.objects.all().delete()
        self.assertEqual(self.tick()['status'], 'running')
        self.finish_task(results, status)
        return self.tick()


APACHE = dict(host='203.0.113.5', port='443/tcp', oid=OID_APACHE, name='Apache HTTP Server < 2.4.51 Path Traversal', severity=9.8, qod=99,
              cves=['CVE-2021-41773'], hostname='www.rt.test')
BANNER = dict(host='203.0.113.5', port='80/tcp', oid=OID_BANNER, name='Old thing version check', severity=5.0, qod=30, cves=['CVE-2019-0001'],
              hostname='www.rt.test', qod_type='remote_banner_unreliable')
PLAIN = dict(host='203.0.113.5', port='22/tcp', oid=OID_PLAIN, name='SSH weak algorithms', severity=5.3, qod=80, cves=[], hostname='www.rt.test')
LOG = dict(host='203.0.113.6', port='general/tcp', oid='1.3.6.1.4.1.25623.1.0.10267', name='OS detection', severity=0.0, qod=80, cves=[], hostname='api.rt.test')


class OffByDefaultTests(Fixture, TestCase):
    def test_a_fresh_install_has_the_addon_off_and_nothing_scheduled(self):
        from django_celery_beat.models import PeriodicTask
        OpenvasSettings.objects.all().delete()
        row = OpenvasSettings.current()
        self.assertEqual((row.enabled, row.gmp_username, bool(row.gmp_password)), (False, '', False))
        task = PeriodicTask.objects.get(name='cvengine-openvas-sweep')
        self.assertEqual((task.task, task.queue, task.enabled), ('openvas_sweep', 'openvas_queue', False))
        self.assertFalse(OpenvasProject.objects.exclude(pk=self.link.pk).exists())

    def test_while_it_is_off_the_sweep_does_nothing_and_never_touches_the_sidecar(self):
        self.settings.enabled = False
        self.settings.save()
        before = self.gvmd.connections
        self.assertEqual(self.tick(), {'skipped': 'the OpenVAS add-on is switched off'})
        self.assertEqual(self.gvmd.connections, before)
        self.assertEqual(OpenvasRun.objects.count(), 0)

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
        self.assertEqual((app.tasks['openvas_sweep'].queue, app.tasks['openvas_check'].queue), ('openvas_queue', 'cve_feed_queue'))


class GatingTests(Fixture, TestCase):
    def due(self, hosts=None, **kw):
        return ov.due(self.project.id, hosts if hosts is not None else self.link.hosts, resolve=kw.get('resolve', self.resolve), blocked=kw.get('blocked', lambda h: False))

    def test_opted_in_hosts_are_due_with_their_vetted_address(self):
        self.assertEqual({(h, ip) for h, ip, _d in self.due()}, {('www.rt.test', '203.0.113.5'), ('api.rt.test', '203.0.113.6')})

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
        with mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('203.0.113.5', 443))]):
            self.assertEqual([(h, ip) for h, ip, _d in ov.due(self.project.id, ['www.rt.test'], blocked=lambda h: False)], [('www.rt.test', '203.0.113.5')])

    def test_the_sidecar_is_never_given_a_tailnet_address(self):
        for ip in ('100.64.0.7', '100.127.255.254', 'fd7a:115c:a1e0::7'):
            self.assertTrue(ov.refuse_address(ip), ip)
        for ip in ('203.0.113.5', '198.51.100.7', '2001:db8::5'):
            self.assertFalse(ov.refuse_address(ip), ip)
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
        self.assertEqual(len(self.due(resolve=lambda h, p: '203.0.113.5')), 1)

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
    def test_a_due_batch_starts_one_task_with_a_vetted_target_and_the_safe_config(self):
        out = self.tick()
        self.assertEqual((out['status'], out['hosts']), ('running', 2))
        target = next(iter(self.gvmd.targets.values()))
        self.assertEqual(set(target['hosts'].split(',')), {'203.0.113.5', '203.0.113.6'})  # numeric addresses only, never a name
        self.assertEqual(target['port_list'], '33d0cd82-57c6-11e1-8ed1-406186ea4fc5')
        task = next(iter(self.gvmd.tasks.values()))
        self.assertEqual(task['config'], next(i for i, c in self.gvmd.configs.items() if c['name'] == 'cvENGINE safe scan'))
        self.assertEqual((task['prefs'], task['status']), ({'max_checks': '2', 'max_hosts': '1'}, 'Requested'))
        run = OpenvasRun.objects.get()
        self.assertEqual((run.status, run.project_id, run.task_id), ('running', self.project.id, next(iter(self.gvmd.tasks))))
        self.assertEqual(run.hosts, {'203.0.113.5': 'www.rt.test', '203.0.113.6': 'api.rt.test'})

    def test_the_batch_is_capped(self):
        with mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_MAX_HOSTS': '1'}):
            self.assertEqual(self.tick()['hosts'], 1)

    def test_only_one_task_runs_at_a_time(self):
        self.tick()
        again = self.tick()
        self.assertEqual(again['status'], 'running')
        self.assertEqual(len(self.gvmd.tasks), 1)
        self.assertEqual(len(self.gvmd.sent('create_task')), 1)
        # and the database refuses a second running row whoever asks
        from django.db import IntegrityError, transaction
        with self.assertRaises(IntegrityError), transaction.atomic():
            OpenvasRun.objects.create(project=self.project, status='running')

    def test_the_target_is_reused_for_an_unchanged_host_set(self):
        self.tick()
        run = OpenvasRun.objects.get()
        self.finish_task([LOG], 'Stopped')
        self.tick()
        ServiceRun.objects.all().delete()
        self.tick()
        self.assertEqual(len(self.gvmd.sent('create_target')), 1)
        self.assertEqual(OpenvasRun.objects.count(), 2)
        self.assertEqual(OpenvasRun.objects.exclude(pk=run.pk).get().target_id, run.target_id)

    def test_a_changed_host_set_makes_a_new_target_and_removes_the_old_one(self):
        self.tick()
        old = OpenvasRun.objects.get().target_id
        self.finish_task([LOG], 'Stopped')
        self.tick()
        OpenvasProject.objects.filter(pk=self.link.pk).update(hosts=['www.rt.test', 'api.rt.test', 'db.rt.test'])
        self.tick()
        self.assertEqual(len(self.gvmd.sent('create_target')), 2)
        self.assertNotIn(old, self.gvmd.targets)

    def test_no_feed_no_scan_and_the_reason_is_recorded(self):
        self.start_gvmd(nvts=0)
        self.settings.gmp_username, self.settings.gmp_password = self.gvmd.user, self.gvmd.password
        self.settings.save()
        out = self.tick()
        self.assertIn('not loaded yet', out['skipped'])
        self.assertEqual(self.gvmd.sent('create_task'), [])
        state = OpenvasSettings.current().state
        self.assertTrue(state['connected'])
        self.assertFalse(state['feed']['ready'])
        self.assertIn('not loaded yet', state['feed']['reason'])

    def test_short_memory_refuses_to_start_a_scan(self):
        self.memory_state['available_mb'] = 1500
        out = self.tick()
        self.assertIn('memory is short', out['skipped'])
        self.assertEqual((self.gvmd.sent('create_task'), self.gvmd.sent('start_task'), OpenvasRun.objects.count()), ([], [], 0))
        self.assertFalse(OpenvasSettings.current().state['guard']['ok'])
        self.memory_state['available_mb'] = 13000
        self.assertEqual(self.tick()['status'], 'running')  # and starts as soon as there is room

    def test_a_global_pause_refuses_to_start(self):
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        self.assertEqual(self.tick(), {'skipped': 'scanning is paused'})
        self.assertEqual(self.gvmd.sent('create_task'), [])

    def test_a_pause_stops_the_running_task_and_the_hosts_stay_due(self):
        self.tick()
        run = OpenvasRun.objects.get()
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        out = self.tick()
        self.assertEqual(out['status'], 'stopped')
        self.assertEqual(self.gvmd.tasks[run.task_id]['status'], 'Stop Requested')
        self.assertFalse(ServiceRun.objects.filter(service=ov.SERVICE).exists())
        self.assertFalse(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())
        ScanControl.objects.filter(pk=1).update(paused=False)
        self.assertEqual(self.tick()['status'], 'running')

    def test_critically_low_memory_stops_the_running_task(self):
        self.tick()
        self.memory_state['available_mb'] = 100
        out = self.tick()
        self.assertEqual(out['status'], 'stopped')
        self.assertIn('memory ran critically low', OpenvasRun.objects.get().error)

    def test_a_task_that_runs_too_long_is_stopped_and_not_retried_at_once(self):
        self.tick()
        OpenvasRun.objects.update(started_at=timezone.now() - timedelta(hours=13))
        out = self.tick()
        self.assertEqual(out['status'], 'failed')
        self.assertIn('more than 12 hours', OpenvasRun.objects.get().error)
        self.assertEqual(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).count(), 2)

    def test_the_polled_status_is_kept(self):
        self.tick()
        run = OpenvasRun.objects.get()
        for word, progress in (('Queued', 0), ('Running', 37)):
            self.gvmd.set_status(run.task_id, word, progress)
            self.assertEqual(self.tick()['gvm_status'], word)
        run.refresh_from_db()
        self.assertEqual((run.gvm_status, run.progress), ('Running', 37))

    def test_a_task_gvmd_lost_is_a_failure_not_a_hang(self):
        self.tick()
        self.gvmd.tasks.clear()
        self.assertEqual(self.tick()['status'], 'failed')
        self.assertIn('no longer has the task', OpenvasRun.objects.get().error)
        self.assertEqual(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).count(), 2)

    def test_an_interrupted_task_is_a_failure_and_a_stopped_one_is_not(self):
        self.tick()
        self.finish_task([], 'Interrupted')
        self.assertEqual(self.tick()['status'], 'failed')
        self.assertEqual(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).count(), 2)

    def test_a_sidecar_that_is_down_is_reported_not_raised(self):
        out = ov.tick(session_factory=lambda: ov.session(creds=('a', 'b'), connection=UnixSocketConnection(path='/nonexistent/gvmd.sock', timeout=2)),
                      resolve=self.resolve, blocked=lambda h: False)
        self.assertIn('error', out)
        state = OpenvasSettings.current().state
        self.assertFalse(state['connected'])
        self.assertTrue(state['error'])

    def test_a_task_that_cannot_be_created_fails_the_run_and_backs_off(self):
        self.gvmd.fail['create_task'] = ('400', 'Failed to find config')
        out = self.tick()
        self.assertIn('could not create or start', out['error'])
        run = OpenvasRun.objects.get()
        self.assertEqual(run.status, 'failed')
        self.assertEqual(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).count(), 2)
        self.assertEqual(self.tick()['skipped'], 'no opted-in host is due')

    def test_a_dead_celery_between_making_the_run_and_the_task_does_not_wedge_the_sweep(self):
        OpenvasRun.objects.create(project=self.project, status='running', task_id='')
        self.assertEqual(self.tick()['status'], 'failed')
        self.assertEqual(self.tick()['status'], 'running')

    def test_the_login_never_reaches_the_activity_log_the_state_or_the_run(self):
        from cveFeed.models import AgentActivity
        self.tick()
        self.finish_task([APACHE])
        self.tick()
        blob = json.dumps(list(AgentActivity.objects.values()), default=str) + json.dumps(OpenvasSettings.current().state) + json.dumps(list(OpenvasRun.objects.values_list('error', 'summary')), default=str)
        self.assertNotIn(self.gvmd.password, blob)
        for request in self.gvmd.requests:
            self.assertNotIn(self.gvmd.password.encode(), etree.tostring(request))


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

    def test_the_boundary_is_exactly_80(self):
        for qod, expected in ((79, ''), (80, 'vulnerable')):
            CVEMatch.objects.all().delete()
            ProbeObservation.objects.all().delete()
            Vulnerability.objects.all().delete()
            self.run_scan([{**APACHE, 'qod': qod}])
            self.assertEqual(CVEMatch.objects.get(cve_entry=self.cve).template_result, expected, qod)

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
        self.run_scan([APACHE, {**APACHE, 'port': '8443/tcp'}, {**APACHE, 'host': '203.0.113.6', 'hostname': 'api.rt.test'}])
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
        self.run_scan([{**LOG, 'host': '203.0.113.5', 'hostname': 'www.rt.test'}])  # www answered, and no longer shows the problem
        match.refresh_from_db()
        self.assertEqual((match.template_result, match.remediation_status, match.ai_verdict), ('no_match', 'in_progress', ''))

    def test_a_host_gvmd_did_not_scan_is_not_resolved(self):
        self.run_scan([APACHE])
        ServiceRun.objects.all().delete()
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        self.gvmd.add_result(run.task_id, **LOG)  # only api answered; www was down: no result, not in the report's host list
        self.gvmd.set_status(run.task_id, 'Done', 100)
        out = self.tick()
        self.assertEqual((out['hosts_scanned'], out['hosts_not_scanned']), (1, 1))
        self.assertTrue(Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}').open_status)
        self.assertEqual(ProbeObservation.objects.get(host='www.rt.test').outcome, 'found')
        self.assertTrue(ServiceRun.objects.filter(service=ov.FAILED_SERVICE, asset='www.rt.test').exists())  # asked again in three days
        self.assertTrue(ServiceRun.objects.filter(service=ov.SERVICE, asset='api.rt.test').exists())

    def test_a_live_host_with_no_result_is_known_from_the_report(self):
        self.run_scan([APACHE])
        ServiceRun.objects.all().delete()
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        self.gvmd.add_result(run.task_id, **LOG)
        self.gvmd.extra_report_hosts = {'203.0.113.5'}  # www was scanned and nothing was found
        self.gvmd.set_status(run.task_id, 'Done', 100)
        self.tick()
        self.assertFalse(Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}').open_status)

    def test_results_for_an_address_that_was_not_requested_are_ignored(self):
        out = self.run_scan([{**APACHE, 'host': '203.0.113.99', 'hostname': 'surprise.example.test'}, LOG])
        self.assertEqual(out['not_in_batch'], 1)
        self.assertFalse(Vulnerability.objects.filter(source='openvas').exists())
        self.assertFalse(ProbeObservation.objects.filter(probe='openvas').exists())

    def test_a_finished_task_is_removed_from_gvmd_after_the_import(self):
        self.run_scan([APACHE])
        self.assertEqual(self.gvmd.tasks, {})
        self.assertEqual(self.gvmd.sent('delete_task')[0].get('ultimate'), '1')

    def test_the_run_keeps_a_summary_and_the_activity_says_what_happened(self):
        from cveFeed.models import AgentActivity
        self.run_scan([APACHE, PLAIN])
        run = OpenvasRun.objects.get()
        self.assertEqual((run.status, run.summary['findings'], run.summary['without_cve']), ('done', 1, 1))
        message = AgentActivity.objects.filter(kind='run_check', message__startswith='OpenVAS:').latest('id').message
        self.assertIn('1 result(s) without a CVE not imported', message)

    def test_many_results_are_read_a_page_at_a_time_and_capped(self):
        run_results = [{**APACHE, 'oid': f'1.3.6.1.4.1.25623.1.0.{200000 + i}', 'cves': []} for i in range(250)]
        self.assertEqual(self.tick()['status'], 'running')
        run = self.finish_task(run_results)
        self.tick()
        self.assertEqual(OpenvasRun.objects.get().summary['results'], 250)
        pages = [r for r in self.gvmd.sent('get_results')]
        self.assertEqual(len(pages), 3)
        with mock.patch.object(ov, 'MAX_RESULTS', 100):
            gmp_results = self.factory()
            with gmp_results as gmp:
                items, _no_cve, _bad = ov.fetch_results(gmp, run.task_id)
        self.assertEqual(len(items), 100)

    def test_hostile_text_is_stored_clipped_and_plain(self):
        evil = '<img src=x onerror=alert(1)>' + 'B' * 20000
        self.run_scan([{**APACHE, 'description': evil, 'tags': 'summary=<script>x</script>|insight=' + evil}])
        vuln = Vulnerability.objects.get(source='openvas')
        self.assertLessEqual(len(vuln.description), 6000)
        self.assertLessEqual(len(vuln.extracted_results[0]), 2000)
        self.assertIn('<script>x</script>', vuln.description)  # inert text; every template autoescapes it


class CarryForwardTests(Fixture, TestCase):
    def test_a_later_scans_host_row_gets_the_findings_and_the_evidence(self):
        self.run_scan([APACHE, BANNER])
        later = self.scan(names=('www.rt.test',), ip='203.0.113.5')
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
        later = self.scan(names=('www.rt.test',), ip='203.0.113.5')
        self.assertEqual(ov.carry_forward(later), 0)
        self.assertEqual(ov.apply_observations(Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')), (0, 0, 0))  # stale is not "gone"

        self.assertTrue(Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}', scan_history=self.scan_obj).open_status)

    def test_a_person_s_decision_on_an_earlier_finding_is_kept_on_the_new_row(self):
        self.run_scan([APACHE])
        Vulnerability.objects.update(remediation_status='accepted_risk', remediation_note='known')
        later = self.scan(names=('www.rt.test',), ip='203.0.113.5')
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


class BootstrapTests(GvmdFixture, TestCase):
    def test_the_default_login_is_replaced_over_gmp_and_the_new_one_is_saved_encrypted(self):
        gvmd = self.start_gvmd(user='admin', password='admin')
        with mock.patch.object(ov, '_connection', lambda: UnixSocketConnection(path=gvmd.path, timeout=5)):
            name = ov.bootstrap(token=lambda n: 'generated-password-0123456789')
        self.assertEqual(name, 'admin')
        self.assertEqual(gvmd.users['admin'], 'generated-password-0123456789')
        row = OpenvasSettings.current()
        self.assertEqual((row.gmp_username, row.gmp_password), ('admin', 'generated-password-0123456789'))
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute('select gmp_password from "cveFeed_openvassettings"')
            self.assertNotIn('generated-password', cursor.fetchone()[0])  # encrypted at rest

    def test_a_password_that_was_changed_already_is_not_overwritten(self):
        gvmd = self.start_gvmd(user='admin', password='already-changed')
        with mock.patch.object(ov, '_connection', lambda: UnixSocketConnection(path=gvmd.path, timeout=5)):
            with self.assertRaises(ov.OpenvasError) as raised:
                ov.bootstrap()
        self.assertIn('no longer works', str(raised.exception))
        self.assertEqual(gvmd.users['admin'], 'already-changed')
        self.assertFalse(OpenvasSettings.current().gmp_password)

    def test_the_command_prints_only_the_user_name(self):
        from io import StringIO
        gvmd = self.start_gvmd(user='admin', password='admin')
        out = StringIO()
        with mock.patch.object(ov, '_connection', lambda: UnixSocketConnection(path=gvmd.path, timeout=5)):
            call_command('openvas_bootstrap', stdout=out)
        self.assertIn('GMP login for admin generated and saved', out.getvalue())
        self.assertNotIn(gvmd.users['admin'], out.getvalue())

    def test_a_manual_login_is_read_from_standard_input_never_an_argument(self):
        from io import StringIO
        out = StringIO()
        with mock.patch('sys.stdin', StringIO("User created with password 'abc-DEF-123'.\n")):
            call_command('openvas_credentials', username='cvengine', stdout=out)
        row = OpenvasSettings.current()
        self.assertEqual((row.gmp_username, row.gmp_password), ('cvengine', 'abc-DEF-123'))
        self.assertNotIn('abc-DEF-123', out.getvalue())
        with mock.patch('sys.stdin', StringIO('   \n')):
            from django.core.management.base import CommandError
            with self.assertRaises(CommandError):
                call_command('openvas_credentials', username='cvengine')
        parser_args = [a for a in __import__('cveFeed.management.commands.openvas_credentials', fromlist=['Command']).Command().create_parser('m', 'openvas_credentials')._actions]
        self.assertFalse(any('password' in ' '.join(a.option_strings) for a in parser_args))


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
        for method, path, body in (('GET', 'openvas', None), ('PUT', 'openvas', {}), ('POST', 'openvas/test', {}), ('PUT', f'openvas/projects/{self.pid}', {}),
                                   ('DELETE', f'openvas/projects/{self.pid}', None)):
            self.assertEqual(send(other, method, path, body)[0], 403, path)
        self.assertEqual(self.client.get('/cve/api/settings/openvas').status_code, 302)
        member = User.objects.create_user('omember', password='x')
        self.assertEqual(send(client_for(member), 'GET', 'openvas')[0], 403)

    def test_it_starts_off_and_says_what_the_floor_is(self):
        status, data = send(self.c, 'GET', 'openvas')
        self.assertEqual(status, 200)
        self.assertEqual((data['enabled'], data['password_set'], data['links'], data['running']), (False, False, [], False))
        self.assertEqual(data['floor']['confirmed_qod'], 80)
        self.assertEqual(data['floor']['excluded_families'], ['Denial of Service', 'Brute force attacks'])
        self.assertEqual(data['transport'], 'socket:/run/gvmd/gvmd.sock')
        self.assertIn(self.pid, [p['id'] for p in data['projects']])

    def test_it_cannot_be_switched_on_without_a_login(self):
        status, data = send(self.c, 'PUT', 'openvas', {'enabled': True})
        self.assertEqual(status, 400)
        self.assertIn('GMP login', data['error'])
        self.assertFalse(OpenvasSettings.current().enabled)

    def test_the_switch_turns_the_beat_entry_on_and_off_with_it(self):
        from django_celery_beat.models import PeriodicTask
        self.assertFalse(PeriodicTask.objects.get(name='cvengine-openvas-sweep').enabled)
        status, data = send(self.c, 'PUT', 'openvas', {'gmp_username': 'cvengine', 'gmp_password': 'secret-pw-12345', 'enabled': True})
        self.assertEqual(status, 200, data)
        self.assertTrue(data['enabled'])
        self.assertTrue(PeriodicTask.objects.get(name='cvengine-openvas-sweep').enabled)
        status, data = send(self.c, 'PUT', 'openvas', {'enabled': False})
        self.assertFalse(data['enabled'])
        self.assertFalse(PeriodicTask.objects.get(name='cvengine-openvas-sweep').enabled)
        self.assertEqual(list(AuditLog.objects.filter(action__startswith='openvas.').order_by('id').values_list('action', flat=True)), ['openvas.enable', 'openvas.disable'])

    def test_the_password_is_write_only_and_a_blank_keeps_it(self):
        send(self.c, 'PUT', 'openvas', {'gmp_username': 'cvengine', 'gmp_password': 'secret-pw-12345'})
        status, data = send(self.c, 'GET', 'openvas')
        self.assertNotIn('secret-pw-12345', json.dumps(data))
        self.assertEqual((data['username'], data['password_set']), ('cvengine', True))
        send(self.c, 'PUT', 'openvas', {'gmp_password': ''})
        self.assertEqual(OpenvasSettings.current().gmp_password, 'secret-pw-12345')
        self.assertNotIn('secret-pw-12345', json.dumps(list(AuditLog.objects.values('detail', 'target'))))
        send(self.c, 'PUT', 'openvas', {'clear_credentials': True})
        self.assertEqual(send(self.c, 'GET', 'openvas')[1]['password_set'], False)

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

    def test_test_connection_asks_a_worker_and_reports_a_down_sidecar_as_an_answer(self):
        self.assertFalse(send(self.c, 'POST', 'openvas/test', {})[1]['connected'])  # no login yet
        send(self.c, 'PUT', 'openvas', {'gmp_username': 'cvengine', 'gmp_password': 'secret-pw-12345'})
        answer = {'connected': False, 'error': 'gvmd could not be reached (OSError): is the openvas profile running?', 'feed': None, 'guard': None, 'gmp_version': ''}
        with mock.patch('cveFeed.tasks.openvas_check.delay') as delay:
            delay.return_value.get.return_value = answer
            status, data = send(self.c, 'POST', 'openvas/test', {})
        self.assertEqual((status, data['connected']), (200, False))
        self.assertIn('is the openvas profile running', data['error'])
        self.assertEqual(delay.call_args, mock.call())  # no credential travels in the task message
        with mock.patch('cveFeed.tasks.openvas_check.delay', side_effect=OSError('broker down')):
            status, data = send(self.c, 'POST', 'openvas/test', {})
        self.assertEqual(status, 200)
        self.assertIn('no worker answered', data['error'])

    def test_the_worker_side_of_test_connection_records_the_state(self):
        self.settings = OpenvasSettings.current()
        self.settings.gmp_username, self.settings.gmp_password = self.gvmd.user, self.gvmd.password
        self.settings.save()
        answer = ov.check_now(session_factory=self.factory)
        self.assertEqual((answer['connected'], answer['gmp_version'], answer['feed']['ready'], answer['guard']['ok']), (True, '22.7', True, True))
        self.assertEqual(OpenvasSettings.current().state['gmp_version'], '22.7')
        self.gvmd.fail['get_feeds'] = ('500', 'boom')
        down = ov.check_now(session_factory=self.factory)
        self.assertFalse(down['connected'])
        self.assertTrue(down['error'])


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
        self.assertEqual({n for n, s in self.services.items() if 'profiles' not in s}, {'db', 'redis', 'celery', 'celery-beat', 'web', 'proxy'})
        self.assertGreaterEqual(len(self.openvas), 10)
        for name, service in self.openvas.items():
            self.assertEqual(service['profiles'], ['openvas'], name)

    def test_the_program_images_are_pinned_by_tag_and_digest_and_the_feed_data_follows_its_tag_on_purpose(self):
        programs = {'gvmd', 'pg-gvm', 'pg-gvm-migrator', 'redis-server', 'ospd-openvas', 'openvas-scanner', 'gpg-data'}
        seen = set()
        for name, service in self.openvas.items():
            image = service['image']
            self.assertTrue(image.startswith('registry.community.greenbone.net/community/'), name)
            repo, _, rest = image.rpartition('/')[2].partition(':')
            if repo in programs:
                seen.add(repo)
                self.assertRegex(rest, r'^stable@sha256:[0-9a-f]{64}$', name)
            else:
                self.assertEqual(rest, 'community', name)  # a data image: a pinned feed would be a stale one
        self.assertEqual(seen, programs)

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

    def test_env_example_documents_the_profile_and_user_script_prints_no_password(self):
        self.assertIn('COMPOSE_PROFILES=openvas', (ROOT / '.env.example').read_text())
        script = (ROOT / 'scripts' / 'openvas-user.sh').read_text()
        self.assertNotIn('--new-password', script)
        self.assertNotIn('echo', script.replace('#', '\n#').split('set -euo')[1])


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
        for digest in re.findall(r'@sha256:([0-9a-f]{64})', (ROOT / 'docker-compose.yml').read_text()):
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
        self.assertIn('CVENGINE_OPENVAS_MIN_AVAILABLE_MB', (ROOT / 'docs' / 'CONFIGURATION.md').read_text())

    def test_no_em_dashes(self):
        for path in ('docs/OPENVAS.md', 'web/cveFeed/openvas_scan.py', 'web/cveFeed/openvas_admin.py', 'web/tests/test_openvas.py', 'web/tests/fake_gvmd.py',
                     'scripts/openvas-user.sh', 'docker-compose.yml'):
            self.assertNotIn(chr(0x2014), (ROOT / path).read_text(), path)
