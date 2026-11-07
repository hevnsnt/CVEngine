"""Virtual host discovery from the project's own names: how an answer is classified, which names are asked at all (scope, exclusions, what a
scan already found), what is recorded and added, and the politeness the sweep keeps (pause, caps, pace, challenges, no body, vetted addresses)."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import ledger, route_auth, slow_web, vhost_scan
from cveFeed.models import BountyEngagement, BountyProgram, HostExclusion, ProbeObservation, RouteAuth, ScanControl, ServiceRun, TlsCertificate
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally
from tests.test_tenancy import client_for

DEFAULT_PAGE = {'status': 200, 'title': 'Welcome to nginx!', 'length': 615}
PORTAL_PAGE = {'status': 200, 'title': 'Portal login', 'length': 4200, 'powered_by': 'PHP/8.1.2'}
WIKI_PAGE = {'status': 200, 'title': 'Wiki', 'length': 3000}


def answer(status=200, title='', length=100, location='', server='nginx/1.25.3', powered_by='', challenge='', url='https://203.0.113.10/'):
    headers = {k: v for k, v in (('server', server), ('x-powered-by', powered_by)) if v}
    return {'url': url, 'status': status, 'title': title, 'body': '<html>' + 'x' * max(0, length - 13), 'bytes': length, 'location': location,
            'server': server, 'powered_by': powered_by, 'content_type': 'text/html', 'headers': headers, 'raw_headers': headers, 'challenge': challenge}


class Server:
    """A fake network: answers by (host, connect_ip). A key that is not there raises OSError, as an unreachable site does."""

    def __init__(self, table):
        self.table, self.calls = table, []

    def __call__(self, url, connect_ip=None):
        host = url.split('://', 1)[1].split('/', 1)[0].rsplit(':', 1)[0] if '[' not in url else url
        self.calls.append((host, connect_ip))
        if (host, connect_ip) not in self.table:
            raise OSError('unreachable')
        return self.table[(host, connect_ip)]

    def asked(self, connect_ip='203.0.113.10'):
        return [host for host, ip in self.calls if ip == connect_ip]


def pace():
    return slow_web.Pace(sleep=lambda s: None, overall=0, per_host=0)


class VhostFixture:
    ADDRESS = '203.0.113.10'

    def setUp(self):
        now = timezone.now()
        cache.clear()
        self.org = Org.objects.create(name='V', slug='v')
        self.project = Project.objects.create(name='VH', slug='vh', insert_date=now, org=self.org)
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=now - timedelta(hours=1), tasks=[])
        self.ip = IpAddress.objects.create(address=self.ADDRESS, org=self.org)
        self.ip.ports.add(Port.objects.create(number=443, service_name='https', state='open'), Port.objects.create(number=80, service_name='http', state='open'))
        self.www = self.host('www.example.test', self.ip)
        self.app = self.host('app.example.test')  # stored, resolves elsewhere (nothing recorded on this address)
        self.wiki = self.host('wiki.example.test')
        self.files = self.host('files.example.test')
        TlsCertificate.objects.create(domain=self.domain, host='www.example.test', port=443,
                                      sans=['www.example.test', 'portal.example.test', '*.example.test', 'cdn.thirdparty.test'])
        RouteAuth.objects.create(project=self.project, domain=self.domain, url='https://wiki.example.test/', host='wiki.example.test', path='/',
                                 auth_state='open', http_status=200, title='Wiki', evidence={'bytes': 3010}, checked_at=now)
        for patcher in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
                        mock.patch('cveFeed.hosting.canonical_name', return_value='')):
            patcher.start()
        self.addCleanup(mock.patch.stopall)
        self.table = {
            (self.ADDRESS, None): answer(**DEFAULT_PAGE),
            ('portal.example.test', self.ADDRESS): answer(**PORTAL_PAGE),
            ('app.example.test', self.ADDRESS): answer(**DEFAULT_PAGE),  # the address ignores the name: the default site
            ('files.example.test', self.ADDRESS): answer(404, 'Not Found', 150),
            ('wiki.example.test', self.ADDRESS): answer(**WIKI_PAGE),  # the same application the name serves on its own address
        }
        self.server = Server(self.table)
        LocalFallback('none').apply(self)
        mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real')).start()
        self.guard = assert_ran_nowhere_locally(self, 'vhost_probe')

    def host(self, name, *ips, scan=True):
        sub = Subdomain.objects.create(target_domain=self.domain, name=name, scan_history=self.scan if scan else None)
        sub.ip_addresses.add(*ips)
        return sub

    def _page_of(self, response):
        return {'status': response['status'], 'title': response['title'], 'server': response['server'], 'content_type': response['content_type'],
                'powered_by': response['powered_by'], 'url': response['url'], 'body': response['body'], 'headers': response['headers']}

    def scanner_report(self, task):
        """What a Sentinel's ``vhost_probe`` reads from ``self.table`` for ``task``: the default of each address, then each name (the table's
        key is (name, address); a key that is not there is a name that did not answer). Every read is noted in ``self.server.calls``."""
        out = []
        for item in task['target']['addresses']:
            self.server.calls.append((item['address'], None))
            default = self.table.get((item['address'], None))
            if default is None:  # the address did not answer: no name is asked
                out.append({'id': item['id'], 'default': {'state': 'no_answer'}, 'names': []})
                continue
            names = []
            for entry in item['names']:
                self.server.calls.append((entry['name'], item['address']))
                response = self.table.get((entry['name'], item['address']))
                if response is None:
                    names.append({'name': entry['name'], 'state': 'no_answer'})
                    continue
                row = {'name': entry['name'], 'state': 'answered', 'fingerprint': vhost_scan.fingerprint_of(response)}
                if response.get('challenge'):
                    row['state'], row['challenge'] = 'challenged', response['challenge']
                if not vhost_scan.similar(row['fingerprint'], vhost_scan.fingerprint_of(default)):
                    row['page'] = self._page_of(response)
                names.append(row)
            out.append({'id': item['id'], 'default': {'state': 'answered', 'fingerprint': vhost_scan.fingerprint_of(default)}, 'names': names})
        return {'outcome': 'done', 'addresses': out, 'touched': [item['address'] for item in task['target']['addresses']], 'refused': []}

    def subdir_report(self, task):
        raise AssertionError('this test did not expect a subdir_probe task')

    def scanner(self):
        """The fake Sentinel of the test (started once): it answers vhost_probe from ``self.table`` and subdir_probe from ``subdir_report``."""
        if getattr(self, 'fake', None) is None:
            self.fake = FakeScanner(kinds=['vhost_probe', 'subdir_probe'],
                                    responders={'vhost_probe': self.scanner_report, 'subdir_probe': lambda task: self.subdir_report(task)}).start_for(self)
        return self.fake

    def run_sweep(self, responder=None, **kw):
        """The sweep with a Sentinel (the fake scanner) answering from ``self.table``: this server asks nothing itself."""
        fake = self.scanner()
        if responder is not None:
            fake.responders['vhost_probe'] = responder
        return vhost_scan.sweep(self.project.id, **kw)

    def observations(self, **kw):
        return {(o.host, o.outcome, o.variant) for o in ProbeObservation.objects.filter(probe=vhost_scan.PROBE, **kw)}


class ClassificationTests(SimpleTestCase):
    def fp(self, **kw):
        return vhost_scan.fingerprint_of(answer(**kw))

    def test_an_address_that_ignores_the_name_serves_its_default_site(self):
        self.assertEqual(vhost_scan.classify(self.fp(**DEFAULT_PAGE), self.fp(**DEFAULT_PAGE), None), 'default_site')

    def test_a_small_difference_in_length_is_still_the_same_page(self):
        default = self.fp(**DEFAULT_PAGE)
        self.assertEqual(vhost_scan.classify(self.fp(**{**DEFAULT_PAGE, 'length': 640}), default, None), 'default_site')

    def test_another_title_or_a_much_longer_page_is_another_application(self):
        default = self.fp(**DEFAULT_PAGE)
        self.assertEqual(vhost_scan.classify(self.fp(**PORTAL_PAGE), default, None), 'distinct')
        self.assertEqual(vhost_scan.classify(self.fp(**{**DEFAULT_PAGE, 'length': 9000}), default, None), 'distinct')

    def test_the_name_s_own_site_served_here_is_the_same_app_not_a_new_one(self):
        self.assertEqual(vhost_scan.classify(self.fp(**WIKI_PAGE), self.fp(**DEFAULT_PAGE), self.fp(**{**WIKI_PAGE, 'length': 3010})), 'same_app')

    def test_the_default_site_wins_over_the_name_s_own_site_when_both_match(self):
        self.assertEqual(vhost_scan.classify(self.fp(**DEFAULT_PAGE), self.fp(**DEFAULT_PAGE), self.fp(**DEFAULT_PAGE)), 'default_site')

    def test_an_address_with_no_site_for_the_name_is_no_answer(self):
        for status in (400, 404, 421, 500, 503):
            self.assertEqual(vhost_scan.classify(self.fp(status=status, title='x'), self.fp(**DEFAULT_PAGE), None), 'no_answer')

    def test_a_protected_site_counts_as_a_site(self):
        self.assertEqual(vhost_scan.classify(self.fp(status=401, title='', length=0), self.fp(**DEFAULT_PAGE), None), 'distinct')
        self.assertEqual(vhost_scan.classify(self.fp(status=403, title='Forbidden', length=300), self.fp(**DEFAULT_PAGE), None), 'distinct')

    def test_redirects_are_compared_by_where_they_lead_not_by_host(self):
        default = self.fp(status=301, location='https://203.0.113.10/')
        same = self.fp(status=301, location='https://portal.example.test/')
        elsewhere = self.fp(status=302, location='https://portal.example.test/login')
        self.assertEqual(vhost_scan.classify(same, default, None), 'default_site')
        self.assertEqual(vhost_scan.classify(elsewhere, default, None), 'distinct')

    def test_without_a_default_answer_a_name_that_answers_is_distinct(self):
        self.assertEqual(vhost_scan.classify(self.fp(**PORTAL_PAGE), None, None), 'distinct')


class ScopeTests(SimpleTestCase):
    TARGETS = [('example.test', False, 1), ('www.shared.test', True, 2), ('deep.example.test', False, 3)]

    def test_a_name_under_a_target_or_equal_to_it_is_in_scope(self):
        self.assertEqual(vhost_scan.covering_domain('example.test', self.TARGETS), 1)
        self.assertEqual(vhost_scan.covering_domain('Portal.Example.Test.', self.TARGETS), 1)

    def test_the_most_specific_target_covers_the_name(self):
        self.assertEqual(vhost_scan.covering_domain('a.deep.example.test', self.TARGETS), 3)

    def test_a_name_outside_every_target_is_out_of_scope(self):
        for name in ('example.org', 'notexample.test', 'example.test.evil.test', 'cdn.thirdparty.test', ''):
            self.assertIsNone(vhost_scan.covering_domain(name, self.TARGETS), name)

    def test_a_host_scoped_target_covers_its_own_name_only(self):
        self.assertEqual(vhost_scan.covering_domain('www.shared.test', self.TARGETS), 2)
        self.assertIsNone(vhost_scan.covering_domain('api.www.shared.test', self.TARGETS))


class SweepTests(VhostFixture, TestCase):
    def test_a_distinct_application_is_recorded_and_added_the_others_are_recorded_only(self):
        summary = self.run_sweep()
        self.assertEqual((summary['asked'], summary['distinct'], summary['default_site'], summary['same_app'], summary['no_answer']), (4, 1, 1, 1, 1))
        self.assertEqual(self.observations(), {('portal.example.test', 'found', 'distinct'), ('app.example.test', 'absent', 'default_site'),
                                               ('wiki.example.test', 'absent', 'same_app')})
        row = ProbeObservation.objects.get(host='portal.example.test', probe=vhost_scan.PROBE)
        self.assertEqual((row.kind, row.product, row.port, row.url), ('vhost', self.ADDRESS, 443, '/'))
        self.assertEqual(row.evidence['answer']['title'], 'Portal login')
        self.assertEqual(row.evidence['default']['title'], 'Welcome to nginx!')
        self.assertNotIn('xxxx', str(row.evidence))  # fingerprints, never a body

    def test_what_the_distinct_application_s_page_states_becomes_the_host_s_technologies(self):
        self.run_sweep()
        sub = Subdomain.objects.get(name='portal.example.test', scan_history__isnull=True)
        self.assertEqual(sorted(t.name for t in sub.technologies.all()), ['PHP:8.1.2', 'nginx:1.25.3'])

    def test_the_distinct_name_becomes_a_host_of_the_project_linked_to_the_address(self):
        self.run_sweep()
        sub = Subdomain.objects.get(name='portal.example.test')
        self.assertEqual((sub.target_domain_id, sub.scan_history_id, sub.is_imported_subdomain), (self.domain.id, None, True))
        self.assertEqual([ip.address for ip in sub.ip_addresses.all()], [self.ADDRESS])
        self.assertEqual((sub.http_status, sub.page_title), (200, 'Portal login'))

    def test_the_default_site_and_the_same_app_add_nothing(self):
        self.run_sweep()
        for name in ('app.example.test', 'wiki.example.test', 'files.example.test'):
            self.assertFalse(Subdomain.objects.get(name=name).ip_addresses.exists(), name)
            self.assertFalse(Subdomain.objects.filter(name=name, scan_history__isnull=True).exists(), name)

    def test_the_name_s_own_site_is_read_from_its_route_check_before_asking_for_it(self):
        self.run_sweep()
        self.assertNotIn(('wiki.example.test', None), self.server.calls)  # its stored front page answered the comparison


    def test_a_name_a_scan_found_on_the_address_is_never_asked(self):
        self.host('blog.example.test', self.ip)
        self.run_sweep()
        self.assertNotIn('blog.example.test', self.server.asked())
        self.assertNotIn('www.example.test', self.server.asked())

    def test_names_come_from_the_project_s_own_data_in_a_fixed_order_and_nothing_is_guessed(self):
        self.run_sweep()
        self.assertEqual(self.server.asked(), ['portal.example.test', 'app.example.test', 'files.example.test', 'wiki.example.test'])

    def test_a_name_outside_the_project_s_scope_is_never_asked_and_never_added(self):
        outsider = self.host('cdn.thirdparty.test')  # stored for the project, and named by the certificate, but no target covers it
        summary = self.run_sweep()
        self.assertEqual(summary['out_of_scope'], 1)
        self.assertNotIn('cdn.thirdparty.test', self.server.asked())
        self.assertFalse(ProbeObservation.objects.filter(host='cdn.thirdparty.test').exists())
        self.assertFalse(Subdomain.objects.filter(name='cdn.thirdparty.test', scan_history__isnull=True).exists())
        self.assertFalse(outsider.ip_addresses.exists())

    def test_an_out_of_scope_name_that_answers_distinctly_would_still_not_be_added(self):
        """The scope rule is checked where the name is chosen: with it removed this name would be asked and added."""
        self.table[('cdn.thirdparty.test', self.ADDRESS)] = answer(200, 'Someone else', 5000)
        self.run_sweep()
        self.assertFalse(Subdomain.objects.filter(name='cdn.thirdparty.test').exclude(scan_history=self.scan).exists())
        self.assertNotIn(('cdn.thirdparty.test', self.ADDRESS), self.server.calls)

    def test_a_target_that_is_an_address_gives_no_name_scope(self):
        Domain.objects.filter(pk=self.domain.pk).update(name='203.0.113.0/24')
        summary = self.run_sweep()
        self.assertIn('no domain target', summary['skipped'])
        self.assertEqual(self.server.calls, [])

    def test_a_wildcard_certificate_name_is_not_a_site_to_ask_for(self):
        self.run_sweep()
        self.assertFalse(any(host.startswith('*') for host in self.server.asked()))

    def test_an_excluded_name_is_never_asked(self):
        HostExclusion.objects.create(org=self.org, host='portal.example.test')
        self.run_sweep()
        self.assertNotIn('portal.example.test', self.server.asked())
        self.assertFalse(Subdomain.objects.filter(name='portal.example.test').exists())

    def test_a_name_under_an_excluded_domain_is_never_asked(self):
        HostExclusion.objects.create(org=self.org, host='example.test', include_subdomains=True)
        self.run_sweep()
        self.assertEqual(self.server.calls, [])

    def test_scanning_paused_asks_nothing(self):
        ScanControl.objects.create(pk=1, paused=True)
        summary = self.run_sweep()
        self.assertIn('paused', summary['skipped'])
        self.assertEqual(self.server.calls, [])

    def test_a_project_whose_bounty_engagement_has_not_confirmed_automated_testing_asks_nothing(self):
        program = BountyProgram.objects.create(platform='hackerone', handle='ex', name='Example')
        BountyEngagement.objects.create(project=self.project, program=program, status='active', automated_ok=False)
        summary = self.run_sweep()
        self.assertIn('automated testing', summary['skipped'])
        self.assertEqual(self.server.calls, [])



    def test_it_can_be_switched_off(self):
        with mock.patch.dict('os.environ', {'CVENGINE_VHOST': '0'}):
            summary = self.run_sweep()
        self.assertIn('CVENGINE_VHOST=0', summary['skipped'])
        self.assertEqual(self.server.calls, [])

    def test_at_most_max_names_are_asked_per_address(self):
        with mock.patch.dict('os.environ', {'CVENGINE_VHOST_MAX_NAMES': '2'}):
            self.run_sweep()
        self.assertEqual(self.server.asked(), ['portal.example.test', 'app.example.test'])

    def test_the_rest_is_asked_at_the_next_run_not_all_at_once(self):
        with mock.patch.dict('os.environ', {'CVENGINE_VHOST_MAX_NAMES': '2'}):
            self.run_sweep()
            self.run_sweep()
        self.assertEqual(self.server.asked(), ['portal.example.test', 'app.example.test', 'files.example.test', 'wiki.example.test'])

    def test_at_most_max_ips_are_asked_per_run(self):
        second = IpAddress.objects.create(address='198.51.100.7', org=self.org)
        second.ports.add(Port.objects.create(number=443, service_name='https', state='open'))
        self.host('other.example.test', second)
        self.table[('198.51.100.7', None)] = answer(**DEFAULT_PAGE)
        with mock.patch.dict('os.environ', {'CVENGINE_VHOST_MAX_IPS': '1'}):
            summary = self.run_sweep()
        self.assertEqual(summary['ips'], 1)
        self.assertEqual(len({ip for _host, ip in self.server.calls if ip}), 1)  # one address was asked its names, the other waits for the next run

    def test_a_second_run_inside_the_window_asks_nothing(self):
        self.run_sweep()
        before = len(self.server.calls)
        again = self.run_sweep()
        self.assertEqual(len(self.server.calls), before)
        self.assertEqual(again['asked'], 0)

    def test_the_ledger_window_is_a_week_and_expires(self):
        self.assertEqual(ledger.ttl(vhost_scan.SERVICE), 7 * 24 * 3600)
        self.run_sweep()
        ServiceRun.objects.filter(service=vhost_scan.SERVICE).update(finished_at=timezone.now() - timedelta(days=8))
        before = len(self.server.calls)
        self.run_sweep()
        self.assertGreater(len(self.server.calls), before)

    def test_running_it_again_creates_no_duplicates(self):
        self.run_sweep()
        counts = (Subdomain.objects.count(), ProbeObservation.objects.count(), Technology.objects.count(),
                  Subdomain.objects.get(name='portal.example.test').ip_addresses.count(), Subdomain.objects.get(name='portal.example.test').technologies.count())
        ServiceRun.objects.filter(service=vhost_scan.SERVICE).delete()
        self.run_sweep()
        self.assertEqual(counts, (Subdomain.objects.count(), ProbeObservation.objects.count(), Technology.objects.count(),
                                  Subdomain.objects.get(name='portal.example.test').ip_addresses.count(),
                                  Subdomain.objects.get(name='portal.example.test').technologies.count()))

    def test_a_name_that_stops_being_distinct_is_unlinked_and_its_record_says_so(self):
        self.run_sweep()
        self.table[('portal.example.test', self.ADDRESS)] = answer(**DEFAULT_PAGE)
        ServiceRun.objects.filter(service=vhost_scan.SERVICE).delete()
        self.run_sweep()
        self.assertEqual(ProbeObservation.objects.get(host='portal.example.test', probe=vhost_scan.PROBE).outcome, 'absent')
        self.assertFalse(Subdomain.objects.get(name='portal.example.test', scan_history__isnull=True).ip_addresses.exists())

    def test_an_address_that_does_not_answer_is_left_alone_for_a_few_days(self):
        del self.table[(self.ADDRESS, None)]
        self.run_sweep()
        self.assertEqual(self.server.calls, [(self.ADDRESS, None)])
        self.run_sweep()
        self.assertEqual(self.server.calls, [(self.ADDRESS, None)])




class VettingTests(VhostFixture, TestCase):
    def test_an_internal_address_is_never_asked(self):
        IpAddress.objects.filter(pk=self.ip.pk).update(address='10.0.0.5')
        self.run_sweep()
        self.assertEqual(self.server.calls, [])

    def test_the_address_of_a_cdn_is_not_a_place_to_look_for_other_sites(self):
        IpAddress.objects.filter(pk=self.ip.pk).update(is_cdn=True)
        self.run_sweep()
        self.assertEqual(self.server.calls, [])

    def test_a_shared_platform_address_is_never_asked(self):
        Subdomain.objects.filter(pk=self.www.pk).update(cname='example.netlify.app')
        self.run_sweep()
        self.assertEqual(self.server.calls, [])

    def test_a_host_the_organization_archived_is_not_a_reason_to_ask_its_address(self):
        from cveFeed.models import HostState
        HostState.objects.create(project=self.project, domain=self.domain, host='www.example.test', archived_at=timezone.now())
        self.run_sweep()
        self.assertEqual(self.server.calls, [])

    def test_an_address_that_resolves_nowhere_a_scanner_may_go_is_refused_by_the_transport_too(self):
        with self.assertRaises(ValueError):
            route_auth.probe_url('https://portal.example.test/', connect_ip='127.0.0.1')
        with self.assertRaises(ValueError):
            route_auth.probe_url('https://portal.example.test/', connect_ip='169.254.169.254')


class HostMergeTests(VhostFixture, TestCase):
    def hosts(self):
        user, _ = User.objects.get_or_create(username='merger')
        ProjectMembership.objects.get_or_create(user=user, project=self.project, defaults={'role': 'user'})
        response = client_for(user).get('/api/v1/projects/vh/hosts', {'page_size': 50})
        self.assertEqual(response.status_code, 200, response.content[:200])
        return {h['host']: h for h in response.json()['results']}

    def test_a_distinct_name_on_the_same_addresses_is_an_alias_of_the_host_there_not_a_second_host(self):
        self.run_sweep()
        rows = self.hosts()
        self.assertNotIn('portal.example.test', rows)
        self.assertEqual(rows['www.example.test']['aliases'], ['portal.example.test'])

    def test_the_host_page_says_which_other_sites_are_served_there(self):
        self.run_sweep()
        row = self.hosts()['www.example.test']
        self.assertEqual([(a['name'], a['address'], a['status'], a['title']) for a in row['also_served']],
                         [('portal.example.test', self.ADDRESS, 200, 'Portal login')])

    def test_the_host_count_does_not_grow_when_a_name_is_merged_and_not_when_it_is_asked_again(self):
        before = len(self.hosts())
        self.run_sweep()
        after = len(self.hosts())
        ServiceRun.objects.filter(service=vhost_scan.SERVICE).delete()
        self.run_sweep()
        self.assertEqual((before, after), (after, len(self.hosts())))

    def test_the_name_has_one_row_even_when_a_scan_already_knows_it_elsewhere(self):
        self.host('portal.example.test', IpAddress.objects.create(address='203.0.113.77', org=self.org))  # a known name that resolves to another address
        self.run_sweep()
        rows = Subdomain.objects.filter(name='portal.example.test')
        self.assertEqual(rows.count(), 2)  # the scan's row and the scan-less row that carries this address
        self.assertEqual(rows.filter(scan_history__isnull=True).count(), 1)
        names = [h['host'] for h in self.hosts().values()] + [a for h in self.hosts().values() for a in h['aliases']]
        self.assertEqual(names.count('portal.example.test'), 1)  # one host, once, whichever way the page folds it


class ModelContextTests(VhostFixture, TestCase):
    def test_the_address_a_name_was_found_on_never_reaches_the_ai_context(self):
        import json

        from cveFeed import host_context
        self.run_sweep()
        sub = Subdomain.objects.filter(name='portal.example.test').prefetch_related('technologies', 'ip_addresses__ports', 'waf').first()
        context = host_context.host_context(sub, self.project.id)
        self.assertNotIn(self.ADDRESS, json.dumps(context, default=str))
        self.assertTrue(ProbeObservation.objects.filter(host='portal.example.test', kind='vhost').exists())  # recorded, just not given to the model




