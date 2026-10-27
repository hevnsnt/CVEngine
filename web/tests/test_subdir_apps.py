"""Applications under subdirectories: the curated list and what it indicates, how a response is read into a product and a version, which
answers count, what is a lead and what is a confirmed application, and the politeness the sweep keeps (cap, pace, pause, exclusions, challenges,
no body, one GET per path)."""
import os
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import correlation, ledger, slow_web, subdir_apps, vhost_scan
from cveFeed.models import CVEEntry, CVEMatch, HostArchive, HostExclusion, ProbeObservation, RouteAuth, ScanControl, ServiceRun
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import EndPoint, IpAddress, Port, ScanHistory, Subdomain, Technology
from targetApp.models import Domain
from tests.test_vhost_scan import VhostFixture, answer, pace

EXPECTED_PATHS = [
    '/jira/', '/confluence/', '/bitbucket/', '/grafana/', '/wordpress/', '/phpmyadmin/', '/gitlab/', '/jenkins/', '/owa/', '/sonarqube/',
    '/nexus/', '/artifactory/', '/kibana/', '/zabbix/', '/nagios/', '/cacti/', '/roundcube/', '/squirrelmail/', '/horde/', '/joomla/',
    '/drupal/', '/moodle/', '/mediawiki/', '/redmine/', '/mantis/', '/bugzilla/', '/gitea/', '/portainer/', '/manager/html', '/solr/',
    '/zimbra/', '/pgadmin4/', '/adminer/', '/prometheus/', '/airflow/', '/superset/', '/metabase/', '/nextcloud/', '/owncloud/', '/typo3/',
    '/umbraco/', '/sitecore/', '/graylog/',
]
DOCS = os.path.join(os.path.dirname(__file__), '..', '..', 'docs')


def page(status=200, title='', body='', headers=None, location='', length=None, url='https://www.example.test/'):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    return {'url': url, 'status': status, 'title': title, 'body': body, 'bytes': len(body) if length is None else length, 'location': location,
            'server': headers.get('server', ''), 'powered_by': '', 'content_type': 'text/html', 'headers': headers, 'raw_headers': headers, 'challenge': ''}


class Site:
    """A fake web host: answers by path (404 for anything else), records every request."""

    def __init__(self, table=None, host='www.example.test'):
        self.table, self.calls, self.host = dict(table or {}), [], host

    def __call__(self, url, connect_ip=None):
        rest = url.split('://', 1)[1]
        host, path = rest.split('/', 1)[0], '/' + rest.split('/', 1)[1]
        self.calls.append((host, path, connect_ip))
        if path in self.table:
            value = self.table[path]
            if isinstance(value, Exception):
                raise value
            return value
        return page(404, 'Not Found', '<html><title>Not Found</title>' + 'n' * 120)

    def paths(self):
        return [path for _host, path, _ip in self.calls]


class CatalogueTests(SimpleTestCase):
    def test_the_path_list_is_the_curated_list_and_nothing_else(self):
        self.assertEqual(subdir_apps.curated_paths(), EXPECTED_PATHS)

    def test_it_is_about_forty_plain_mount_paths(self):
        paths = subdir_apps.curated_paths()
        self.assertTrue(35 <= len(paths) <= 50, len(paths))
        for path in paths:
            self.assertRegex(path, r'^/[a-z0-9][a-z0-9_./-]*$')
            self.assertNotIn('..', path)
            self.assertNotIn('?', path)
            self.assertNotIn('%', path)

    def test_every_entry_names_the_product_it_indicates(self):
        for entry in subdir_apps.catalogue():
            self.assertTrue(entry['product'] and entry['indicates'] and entry['signatures'], entry['path'])
        products = [e['product'] for e in subdir_apps.catalogue()]
        self.assertEqual(len(products), len(set(products)))  # one path per product: a row is one application

    def test_the_documentation_lists_every_curated_path(self):
        text = open(os.path.join(DOCS, 'PIPELINE.md'), encoding='utf-8').read()
        for entry in subdir_apps.catalogue():
            self.assertTrue(f"`{entry['path']}`" in text, entry["path"])

    def test_a_corrupt_data_file_is_refused(self):
        for bad in ('../etc/passwd', 'jira', '/jira?x=1', '/a b'):
            with self.subTest(bad=bad):
                import json
                import tempfile
                with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
                    json.dump([{'path': bad, 'product': 'X', 'indicates': 'x', 'signatures': [{'where': 'body', 'regex': 'x', 'confidence': 0.9}]}], handle)
                subdir_apps.catalogue.cache_clear()
                try:
                    with mock.patch.object(subdir_apps, 'DATA_FILE', handle.name), self.assertRaises(subdir_apps.CatalogueError):
                        subdir_apps.catalogue()
                finally:
                    os.unlink(handle.name)
                    subdir_apps.catalogue.cache_clear()


class IdentifyTests(SimpleTestCase):
    def test_jenkins_names_itself_and_its_version_in_a_header(self):
        found = subdir_apps.identify(page(403, 'Authentication required', '', {'X-Jenkins': '2.401.3'}), '/jenkins/')
        self.assertEqual((found['product'], found['version']), ('Jenkins', '2.401.3'))
        self.assertGreaterEqual(found['confidence'], subdir_apps.CONFIRM)

    def test_grafana_states_its_version_in_the_login_page(self):
        body = '<script>window.grafanaBootData = {"settings":{"buildInfo":{"hasUpdate":false,"version":"9.3.2","commit":"abc"}}}</script>'
        found = subdir_apps.identify(page(200, 'Grafana', body), '/grafana/')
        self.assertEqual((found['product'], found['version']), ('Grafana', '9.3.2'))

    def test_a_product_that_states_no_version_has_none(self):
        found = subdir_apps.identify(page(200, 'phpMyAdmin', '<html>login</html>'), '/phpmyadmin/')
        self.assertEqual((found['product'], found['version']), ('phpMyAdmin', ''))

    def test_outlook_on_the_web_reads_its_build_from_the_header_or_a_script_path(self):
        by_header = subdir_apps.identify(page(302, '', '', {'X-OWA-Version': '15.2.1118.7'}, location='/owa/auth/logon.aspx?replaceCurrent=1'), '/owa/')
        by_body = subdir_apps.identify(page(200, 'Outlook', '<link href="/owa/auth/15.1.2507.6/themes/resources/favicon.ico">'), '/owa/')
        self.assertEqual((by_header['product'], by_header['version']), ('Microsoft Exchange Server', '15.2.1118.7'))
        self.assertEqual(by_body['version'], '15.1.2507.6')

    def test_a_redirect_to_a_known_login_names_the_product(self):
        found = subdir_apps.identify(page(302, '', '', location='http://www.example.test/grafana/login'), '/grafana/')
        self.assertEqual(found['product'], 'Grafana')

    def test_a_response_that_names_nothing_names_no_product(self):
        self.assertIsNone(subdir_apps.identify(page(200, 'Welcome', '<html>Hello world</html>'), '/jira/'))

    def test_a_product_named_only_in_passing_is_a_hint_below_the_confirmation_level(self):
        found = subdir_apps.identify(page(200, 'Cloud storage', '<p>We also run Nextcloud somewhere.</p>'), '/nextcloud/')
        self.assertEqual(found['product'], 'Nextcloud')
        self.assertLess(found['confidence'], subdir_apps.CONFIRM)

    def test_the_content_decides_not_the_path(self):
        found = subdir_apps.identify(page(200, 'Zabbix', '<footer>Zabbix 6.0.14. &copy; 2001-2023, Zabbix SIA</footer>'), '/helpdesk/')
        self.assertEqual((found['product'], found['version']), ('Zabbix', '6.0.14'))

    def test_a_hostile_page_cannot_make_a_pattern_slow(self):
        import time
        body = '<meta name="generator" content="' * 3000 + 'x' * 60000
        started = time.monotonic()
        subdir_apps.identify(page(200, 'x' * 5000, body), '/jira/')
        self.assertLess(time.monotonic() - started, 2.0)


class LeadTests(SimpleTestCase):
    def test_a_mount_is_the_first_directory_of_a_crawled_url(self):
        self.assertEqual(subdir_apps.mount_of('https://www.example.test/portal/index.jsp?x=1'), '/portal/')
        self.assertEqual(subdir_apps.mount_of('/helpdesk/'), '/helpdesk/')

    def test_root_pages_assets_languages_and_content_directories_are_not_mounts(self):
        for url in ('/login', '/', '/about', '/static/app.js', '/assets/x/y.css', '/en/page', '/wp-content/uploads/a.png', '/api/v1/users', '/a/b'):
            self.assertIsNone(subdir_apps.mount_of(url), url)

    def test_leads_are_capped_and_never_repeat_a_curated_path(self):
        urls = {'crawled': [f'/app{n}/index.html' for n in range(30)] + ['/jira/browse/X-1', '/portal/a', '/portal/b'], 'archive': ['/legacy/x']}
        leads = subdir_apps.lead_paths(urls, set(subdir_apps.curated_paths()))
        self.assertEqual(len(leads), subdir_apps.MAX_LEADS)
        self.assertNotIn('/jira/', leads)
        self.assertEqual(next(iter(leads)), '/portal/')  # the most often seen first
        self.assertEqual(leads['/portal/'], 'crawled')

    def test_robots_and_sitemap_hints_are_read_from_their_own_lines_and_the_same_host_only(self):
        robots = 'User-agent: *\nDisallow: /intranet/\nAllow: /tools/\nSitemap: https://elsewhere.test/sitemap.xml\n'
        self.assertEqual(subdir_apps.robots_paths(robots), ['/intranet/', '/tools/'])
        sitemap = '<urlset><url><loc>https://www.example.test/crm/login</loc></url><url><loc>https://evil.test/x/y</loc></url></urlset>'
        self.assertEqual(subdir_apps.sitemap_paths(sitemap, 'www.example.test'), ['/crm/login'])

    def test_an_answer_the_server_gives_to_every_path_is_not_a_mount(self):
        baseline = vhost_scan.fingerprint_of(page(200, 'Home', 'h' * 500))
        same = vhost_scan.fingerprint_of(page(200, 'Home', 'h' * 520))
        other = vhost_scan.fingerprint_of(page(200, 'Jenkins', 'j' * 5000))
        self.assertTrue(subdir_apps.is_catch_all(same, [baseline]))
        self.assertFalse(subdir_apps.is_catch_all(other, [baseline]))
        login = vhost_scan.fingerprint_of(page(302, location='https://www.example.test/login?next=/jira/'))
        every = vhost_scan.fingerprint_of(page(302, location='https://www.example.test/login?next=/x/'))
        mount = vhost_scan.fingerprint_of(page(302, location='https://www.example.test/jira/login.jsp'))
        self.assertTrue(subdir_apps.is_catch_all(login, [every]))
        self.assertFalse(subdir_apps.is_catch_all(mount, [every]))


class SubdirFixture(VhostFixture):
    """The vhost fixture's project, with the web host ``www.example.test`` on https."""

    def setUp(self):
        super().setUp()
        self.site = Site({'/jenkins/': page(403, 'Authentication required', '<html>x</html>', {'X-Jenkins': '2.401.3'}),
                          '/grafana/': page(302, '', '', location='https://www.example.test/grafana/login'),
                          '/phpmyadmin/': page(200, 'phpMyAdmin', '<html>' + 'p' * 300 + '</html>'),
                          '/nexus/': page(500, 'Nexus Repository Manager', 'e' * 100),
                          '/portal/': page(200, 'Staff portal', '<html>' + 's' * 900 + '</html>')})
        EndPoint.objects.create(subdomain=self.www, target_domain=self.domain, scan_history=self.scan, http_url='https://www.example.test/portal/index.jsp')
        cache.clear()

    def run_subdirs(self, **kw):
        kw.setdefault('fetch', self.site)
        kw.setdefault('pace', pace())
        kw.setdefault('vet_ip', lambda address: True)
        return subdir_apps.sweep(self.project.id, **kw)

    def rows(self, **kw):
        return {(o.url, o.product, o.version, o.outcome, o.variant) for o in ProbeObservation.objects.filter(probe=subdir_apps.PROBE, **kw)}


class SweepTests(SubdirFixture, TestCase):
    def test_a_confirmed_application_a_hidden_version_a_lead_and_nothing_for_an_error(self):
        summary = self.run_subdirs()
        self.assertEqual((summary['hosts'], summary['confirmed'], summary['versions'], summary['leads']), (1, 3, 1, 1))
        self.assertEqual(self.rows(), {('/jenkins/', 'Jenkins', '2.401.3', 'found', ''), ('/grafana/', 'Grafana', '', 'hidden', ''),
                                       ('/phpmyadmin/', 'phpMyAdmin', '', 'hidden', ''), ('/portal/', '/portal/', '', 'found', 'lead')})

    def test_only_200_301_302_401_and_403_count_as_something_there(self):
        self.site.table.update({'/solr/': page(204, 'Solr Admin', ''), '/kibana/': page(500, 'Kibana', ''), '/zabbix/': page(404, 'Zabbix', ''),
                                '/nagios/': page(401, '', '', {'WWW-Authenticate': 'Basic realm="Nagios Access"'}), '/cacti/': page(301, 'Login to Cacti', ''),
                                '/gitea/': page(307, 'Gitea', 'Powered by Gitea Version: 1.20.5'), '/mantis/': page(418, 'MantisBT', '')})
        self.run_subdirs()
        products = {o.product for o in ProbeObservation.objects.filter(probe=subdir_apps.PROBE)}
        self.assertTrue({'Nagios Core', 'Cacti'} <= products)
        self.assertFalse({'Apache Solr', 'Kibana', 'Zabbix', 'Gitea', 'Mantis Bug Tracker', 'Nexus Repository Manager'} & products)

    def test_a_path_that_only_answered_is_a_lead_with_its_status_never_a_technology(self):
        self.run_subdirs()
        lead = ProbeObservation.objects.get(probe=subdir_apps.PROBE, url='/portal/')
        self.assertEqual((lead.variant, lead.confidence, lead.evidence['confirmed'], lead.evidence['status'], lead.evidence['lead']), ('lead', 0.3, False, 200, 'crawled'))
        self.assertNotIn('/portal/', ' '.join(t.name for t in self.www.technologies.all()))

    def test_only_a_confirmed_product_with_a_stated_version_becomes_a_technology(self):
        self.run_subdirs()
        self.assertEqual(sorted(t.name for t in self.www.technologies.all()), ['Jenkins:2.401.3'])  # Grafana and phpMyAdmin state no version

    def test_a_bare_path_hit_is_not_a_cve_match_and_a_confirmed_version_is(self):
        CVEEntry.objects.create(cve_id='CVE-2099-1111', title='Jenkins issue', cvss=8.8, affected=[
            {'vendor': 'jenkins', 'product': 'Jenkins', 'ranges': [{'type': 'SEMVER', 'introduced': '0', 'fixed': '2.442'}]}])
        CVEEntry.objects.create(cve_id='CVE-2099-2222', title='phpMyAdmin issue', cvss=8.8, affected=[
            {'vendor': 'phpmyadmin', 'product': 'phpMyAdmin', 'ranges': [{'type': 'SEMVER', 'introduced': '0', 'fixed': '5.2.2'}]}])
        correlation._INDEX_CACHE.update(key=None, value=None)
        self.run_subdirs()
        matches = CVEMatch.objects.filter(subdomain=self.www)
        self.assertEqual([(m.cve_entry.cve_id, m.matched_version) for m in matches], [('CVE-2099-1111', '2.401.3')])  # no version, no match

    def test_the_sweep_is_get_only_one_request_per_path_and_every_path_is_a_curated_or_a_seen_one(self):
        self.run_subdirs()
        paths = self.site.paths()
        self.assertEqual(len(paths), len(set(paths)))  # one GET per path per host
        allowed = {subdir_apps.BASELINE_PATH, '/robots.txt', '/sitemap.xml', '/portal/'} | set(EXPECTED_PATHS)
        self.assertEqual(set(paths) - allowed, set())

    def test_the_questions_asked_of_a_host_are_the_curated_paths_one_lead_and_three_fixed_ones_in_that_order(self):
        self.run_subdirs()
        self.assertEqual(self.site.paths(), [subdir_apps.BASELINE_PATH, '/robots.txt', '/sitemap.xml'] + EXPECTED_PATHS + ['/portal/'])

    def test_a_per_host_cap_limits_the_requests_of_one_sweep(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SUBDIR_MAX_REQUESTS': '12'}):
            summary = self.run_subdirs()
        self.assertEqual(len(self.site.calls), 12)
        self.assertEqual(summary['requests'], 12)

    def test_the_default_cap_is_sixty_requests_and_covers_the_curated_list(self):
        self.assertEqual(subdir_apps.max_requests(), 60)
        self.assertGreaterEqual(subdir_apps.max_requests(), len(EXPECTED_PATHS) + 3 + subdir_apps.MAX_LEADS)

    def test_a_server_that_answers_every_path_alike_has_no_mounts(self):
        everything = page(200, 'Single page app', '<html>' + 'a' * 800 + '</html>')

        class Everywhere(Site):
            def __call__(self, url, connect_ip=None):
                self.calls.append((None, '/' + url.split('://', 1)[1].split('/', 1)[1], connect_ip))
                return everything
        self.site = Everywhere()
        summary = self.run_subdirs()
        self.assertEqual((summary['confirmed'], summary['leads']), (0, 0))
        self.assertGreater(summary['catch_all'], 40)
        self.assertFalse(ProbeObservation.objects.filter(probe=subdir_apps.PROBE).exists())

    def test_a_server_that_redirects_every_path_to_its_login_has_no_mounts(self):
        class Login(Site):
            def __call__(self, url, connect_ip=None):
                self.calls.append((None, '/' + url.split('://', 1)[1].split('/', 1)[1], connect_ip))
                return page(302, location='https://www.example.test/login?next=' + url.split('://', 1)[1].split('/', 1)[1])
        self.site = Login()
        self.assertEqual(self.run_subdirs()['confirmed'], 0)
        self.assertFalse(ProbeObservation.objects.filter(probe=subdir_apps.PROBE).exists())

    def test_the_front_page_served_for_every_path_is_not_a_mount_either(self):
        RouteAuth.objects.create(project=self.project, domain=self.domain, url='https://www.example.test/', host='www.example.test', path='/',
                                 auth_state='open', http_status=200, title='Staff portal', evidence={'bytes': 900}, checked_at=timezone.now())
        self.run_subdirs()
        self.assertNotIn('/portal/', {o.url for o in ProbeObservation.objects.filter(probe=subdir_apps.PROBE)})

    def test_robots_and_sitemap_name_directories_to_ask(self):
        self.site.table['/robots.txt'] = page(200, '', 'User-agent: *\nDisallow: /intranet/\n')
        self.site.table['/sitemap.xml'] = page(200, '', '<urlset><url><loc>https://www.example.test/crm/login</loc></url></urlset>')
        self.site.table['/intranet/'] = page(200, 'Intranet', '<html>' + 'i' * 700 + '</html>')
        self.run_subdirs()
        self.assertIn('/intranet/', self.site.paths())
        self.assertIn('/crm/', self.site.paths())
        self.assertEqual(ProbeObservation.objects.get(probe=subdir_apps.PROBE, url='/intranet/').evidence['lead'], 'robots')

    def test_archived_paths_are_asked_too(self):
        HostArchive.objects.create(project=self.project, domain=self.domain, host='www.example.test', technologies={'Java': {'count': 2, 'sample': ['/legacy/app.jsp']}})
        self.run_subdirs()
        self.assertIn('/legacy/', self.site.paths())

    def test_running_it_again_inside_the_window_asks_nothing(self):
        self.run_subdirs()
        before = len(self.site.calls)
        self.assertEqual(self.run_subdirs()['hosts'], 0)
        self.assertEqual(len(self.site.calls), before)

    def test_the_ledger_window_is_a_week(self):
        self.assertEqual(ledger.ttl(subdir_apps.SERVICE), 7 * 24 * 3600)

    def test_running_it_again_after_the_window_creates_no_duplicates(self):
        self.run_subdirs()
        counts = (ProbeObservation.objects.count(), Technology.objects.count(), self.www.technologies.count(), Subdomain.objects.count())
        ServiceRun.objects.filter(service=subdir_apps.SERVICE).delete()
        self.run_subdirs()
        self.assertEqual(counts, (ProbeObservation.objects.count(), Technology.objects.count(), self.www.technologies.count(), Subdomain.objects.count()))

    def test_a_mount_that_is_gone_is_marked_absent_and_the_row_stays(self):
        self.run_subdirs()
        del self.site.table['/phpmyadmin/']
        ServiceRun.objects.filter(service=subdir_apps.SERVICE).delete()
        self.run_subdirs()
        self.assertEqual(ProbeObservation.objects.get(probe=subdir_apps.PROBE, url='/phpmyadmin/').outcome, 'absent')
        self.assertEqual(subdir_apps.applications_from_rows(ProbeObservation.objects.filter(probe=subdir_apps.PROBE)).__len__(), 3)

    def test_the_technologies_follow_a_fresh_scan_row(self):
        self.run_subdirs()
        engine = EngineType.objects.first()
        scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now(), tasks=[])
        fresh = Subdomain.objects.create(target_domain=self.domain, name='www.example.test', scan_history=scan)
        self.assertEqual(subdir_apps.carry_forward(scan), 1)
        self.assertEqual([t.name for t in fresh.technologies.all()], ['Jenkins:2.401.3'])

    def test_the_host_page_lists_the_applications_under_subdirectories(self):
        from django.contrib.auth.models import User

        from dashboard.models import ProjectMembership
        from tests.test_tenancy import client_for
        self.run_subdirs()
        user = User.objects.create_user('subber', password='x')
        ProjectMembership.objects.create(user=user, project=self.project, role='user')
        response = client_for(user).get('/api/v1/projects/vh/hosts', {'page_size': 50})
        row = next(h for h in response.json()['results'] if h['host'] == 'www.example.test')
        apps = {(a['path'], a['product'], a['version'], a['confirmed']) for a in row['subdirectory_apps']}
        self.assertEqual(apps, {('/jenkins/', 'Jenkins', '2.401.3', True), ('/grafana/', 'Grafana', '', True), ('/phpmyadmin/', 'phpMyAdmin', '', True),
                                ('/portal/', '/portal/', '', False)})
        self.assertEqual(row['subdirectory_apps'][-1]['confirmed'], False)  # leads after the confirmed ones


class GateTests(SubdirFixture, TestCase):
    def test_it_can_be_switched_off(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SUBDIR_APPS': '0'}):
            summary = self.run_subdirs()
        self.assertIn('CVENGINE_SUBDIR_APPS=0', summary['skipped'])
        self.assertEqual(self.site.calls, [])

    def test_scanning_paused_asks_nothing(self):
        ScanControl.objects.create(pk=1, paused=True)
        summary = self.run_subdirs()
        self.assertIn('paused', summary['skipped'])
        self.assertEqual(self.site.calls, [])

    def test_a_pause_that_arrives_mid_sweep_stops_it_and_the_host_stays_due(self):
        summary = self.run_subdirs(stop=lambda: len(self.site.calls) >= 5)
        self.assertEqual(len(self.site.calls), 5)
        self.assertIn('paused', summary['skipped'])
        self.assertFalse(ServiceRun.objects.filter(service=subdir_apps.SERVICE).exists())

    def test_an_excluded_host_is_never_asked(self):
        HostExclusion.objects.create(org=self.org, host='www.example.test')
        self.run_subdirs()
        self.assertEqual(self.site.calls, [])

    def test_a_host_under_an_excluded_domain_is_never_asked(self):
        HostExclusion.objects.create(org=self.org, host='example.test', include_subdomains=True)
        self.run_subdirs()
        self.assertEqual(self.site.calls, [])

    def test_a_host_the_organization_archived_is_never_asked(self):
        from cveFeed.models import HostState
        HostState.objects.create(project=self.project, domain=self.domain, host='www.example.test', archived_at=timezone.now())
        self.run_subdirs()
        self.assertEqual(self.site.calls, [])

    def test_a_host_that_resolves_to_a_prohibited_address_is_never_asked(self):
        with mock.patch('targetApp.target_types.resolves_to_blocked', return_value=True):
            self.run_subdirs()
        self.assertEqual(self.site.calls, [])

    def test_at_most_max_hosts_are_asked_per_run(self):
        for n in range(4):
            other = IpAddress.objects.create(address=f'198.51.100.{20 + n}', org=self.org)
            other.ports.add(Port.objects.create(number=443, service_name='https', state='open'))
            self.host(f'h{n}.example.test', other)
        with mock.patch.dict(os.environ, {'CVENGINE_SUBDIR_MAX_HOSTS': '2'}):
            summary = self.run_subdirs()
        self.assertEqual(summary['hosts'], 2)

    def test_every_request_waits_for_the_pace(self):
        counting = slow_web.Pace(sleep=lambda s: None, per_host=0, overall=0)
        self.run_subdirs(pace=counting)
        self.assertEqual(counting.requests, len(self.site.calls))

    def test_a_challenge_is_recorded_and_never_retried_or_pushed_against(self):
        challenge = {**page(403, 'Attention Required! | Cloudflare', 'blocked', {'Server': 'cloudflare'}), 'challenge': 'Cloudflare'}
        self.site.table[subdir_apps.BASELINE_PATH] = challenge
        summary = self.run_subdirs()
        self.assertEqual(summary['challenged'], 1)
        self.assertEqual(self.site.paths(), [subdir_apps.BASELINE_PATH])  # nothing else was asked of it
        row = ProbeObservation.objects.get(probe=subdir_apps.PROBE)
        self.assertEqual((row.outcome, row.product, row.evidence['edge']), ('challenged', 'Cloudflare', 'Cloudflare'))
        self.assertIn('Allow the scanner', row.evidence['hint'])
        self.run_subdirs()
        self.assertEqual(self.site.paths(), [subdir_apps.BASELINE_PATH])  # and not again before the window is over

    def test_a_challenge_midway_stops_the_host(self):
        self.site.table['/jira/'] = {**page(403, 'Just a moment...', '', {'cf-mitigated': 'challenge'}), 'challenge': 'Cloudflare'}
        self.run_subdirs()
        self.assertEqual(self.site.paths()[-1], '/jira/')
        self.assertNotIn('/grafana/', self.site.paths())

    def test_a_busy_server_ends_the_host_and_leaves_it_due(self):
        self.site.table['/confluence/'] = page(429, 'Too Many Requests', 'slow down')
        self.run_subdirs()
        self.assertEqual(self.site.paths()[-1], '/confluence/')
        self.assertFalse(ServiceRun.objects.filter(service=subdir_apps.SERVICE).exists())

    def test_a_host_that_does_not_answer_is_not_an_error(self):
        self.site.table = {path: OSError('timed out') for path in EXPECTED_PATHS}
        summary = self.run_subdirs()
        self.assertEqual((summary['confirmed'], summary['leads']), (0, 0))

    def test_the_status_counts_say_what_the_sweeps_found(self):
        self.run_subdirs()
        counts = subdir_apps.status_counts([self.project.id])
        self.assertEqual(counts['subdirectory_apps'], {'enabled': True, 'confirmed': 3, 'with_version': 1, 'leads': 1, 'challenged': 0})


class VirtualHostCarrierTests(SubdirFixture, TestCase):
    """A name the virtual host sweep added is asked at the address it was found on, with its own name: never at what its DNS says."""

    def test_a_distinct_virtual_host_is_asked_at_its_own_address_with_its_own_name(self):
        vhost_scan.sweep(self.project.id, fetch=self.server, pace=pace())
        self.site = Site({'/jenkins/': page(403, 'Authentication required', '', {'X-Jenkins': '2.400'}, url='https://portal.example.test/')})
        self.run_subdirs()
        portal_calls = [c for c in self.site.calls if c[0] == 'portal.example.test']
        self.assertTrue(portal_calls)
        self.assertEqual({ip for _h, _p, ip in portal_calls}, {self.ADDRESS})
        self.assertEqual({ip for host, _p, ip in self.site.calls if host == 'www.example.test'}, {None})
        row = ProbeObservation.objects.get(probe=subdir_apps.PROBE, host='portal.example.test', url='/jenkins/')
        self.assertEqual((row.product, row.version, row.evidence['ip']), ('Jenkins', '2.400', self.ADDRESS))
        self.assertEqual(sorted(t.name for t in Subdomain.objects.get(name='portal.example.test', scan_history__isnull=True).technologies.all()),
                         ['Jenkins:2.400', 'PHP:8.1.2', 'nginx:1.25.3'])

    def test_the_vetting_of_the_address_applies_to_a_virtual_host_too(self):
        vhost_scan.sweep(self.project.id, fetch=self.server, pace=pace())
        self.site = Site()
        self.run_subdirs(vet_ip=lambda address: False)
        self.assertEqual([c for c in self.site.calls if c[0] == 'portal.example.test'], [])

    def test_an_excluded_virtual_host_name_is_never_asked_even_though_its_address_is_fine(self):
        vhost_scan.sweep(self.project.id, fetch=self.server, pace=pace())
        HostExclusion.objects.create(org=self.org, host='portal.example.test')
        self.site = Site()
        self.run_subdirs()
        self.assertEqual([c for c in self.site.calls if c[0] == 'portal.example.test'], [])
        self.assertTrue([c for c in self.site.calls if c[0] == 'www.example.test'])  # its neighbour is still asked
