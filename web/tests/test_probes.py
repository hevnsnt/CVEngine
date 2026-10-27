"""Version and identity probes: what they read, what they record, how they are planned without an AI, and the gates they keep."""
from unittest import mock
from urllib.parse import urlsplit

from django.test import SimpleTestCase, TestCase

from cveFeed import probes
from cveFeed.models import ProbeObservation, ServiceRun
from startScan.models import IpAddress, Port, Subdomain, Technology
from tests.test_route_auth import RouteFixture


def page(status=200, headers=None, body='', title='', content_type='text/html', url='https://www.rt.test/'):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    return {'status': status, 'headers': headers, 'body': body, 'title': title, 'content_type': content_type, 'server': headers.get('server', ''),
            'powered_by': headers.get('x-powered-by', ''), 'final_url': url, 'url': url, 'location': '', 'challenge': ''}


def answers(table):
    """A ``get(url)`` that answers by path from ``table`` and 404s the rest."""
    def get(url):
        path = '/' + url.split('://', 1)[1].split('/', 1)[1]
        return table.get(path, page(404, body='not found'))
    return get


NGINX_404 = '<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.24.0</center></body></html>'
NGINX_404_HIDDEN = NGINX_404.replace('nginx/1.24.0', 'nginx')


class RuleTests(SimpleTestCase):
    def run_probe(self, probe_id, table):
        return probes.run_http_probe(probe_id, 'https://www.rt.test', {'www.rt.test'}, get=answers(table), sleep=lambda s: None)

    def test_the_nginx_error_page_footer_states_a_version(self):
        found = self.run_probe('error-page', {probes.PROBE_PATH: page(404, body=NGINX_404)})
        self.assertEqual([(o['kind'], o['product'], o['version'], o['outcome']) for o in found], [('version', 'nginx', '1.24.0', 'found')])

    def test_a_footer_without_a_version_is_hidden_not_guessed(self):
        found = self.run_probe('error-page', {probes.PROBE_PATH: page(404, body=NGINX_404_HIDDEN)})
        kinds = {(o['kind'], o['outcome'], o['version'], o['variant']) for o in found}
        self.assertEqual(kinds, {('version', 'hidden', '', ''), ('identity', 'found', '', 'nginx')})

    def test_the_kubernetes_default_backend_is_not_plain_nginx(self):
        found = self.run_probe('error-page', {probes.PROBE_PATH: page(404, body='default backend - 404', content_type='text/plain')})
        self.assertEqual([(o['product'], o['variant']) for o in found], [('nginx', 'kubernetes-ingress')])

    def test_apache_tomcat_jetty_and_iis_pages(self):
        self.assertEqual(self.run_probe('error-page', {probes.PROBE_PATH: page(404, body='<address>Apache/2.4.41 (Ubuntu) Server at x Port 80</address>')})[0]['version'], '2.4.41')
        self.assertEqual(self.run_probe('error-page', {probes.PROBE_PATH: page(404, body='<h3>Apache Tomcat/9.0.50</h3>')})[0]['version'], '9.0.50')
        self.assertEqual(self.run_probe('error-page', {probes.PROBE_PATH: page(404, body='<hr>Powered by Jetty:// 9.4.51.v20230217<hr>')})[0]['version'], '9.4.51.v20230217')
        self.assertEqual(self.run_probe('error-page', {probes.PROBE_PATH: page(404, body='x', title='IIS 10.0 Detailed Error - 404.0')})[0]['version'], '10.0')

    def test_nginx_ui_and_proxy_manager_are_told_apart(self):
        found = self.run_probe('nginx-variants', {'/': page(title='Nginx UI')})
        self.assertEqual([(o['kind'], o['variant']) for o in found], [('identity', 'nginx-ui')])
        found = self.run_probe('nginx-variants', {'/api/': page(body='{"status":"OK","setup":true,"version":{"major":2,"minor":10,"revision":4}}')})
        self.assertEqual([(o['product'], o['version']) for o in found], [('Nginx Proxy Manager', '2.10.4')])

    def test_a_challenge_page_is_not_read_as_the_site(self):
        blocked = page(503, body=NGINX_404)
        blocked['challenge'] = 'Cloudflare'
        found = self.run_probe('error-page', {probes.PROBE_PATH: blocked})
        self.assertEqual([(o['kind'], o['outcome']) for o in found], [('edge', 'challenged')])  # the edge is noted; its page is not read as the site

    def test_the_nextjs_version_comes_from_its_framework_script(self):
        html = '<script src="/_next/static/chunks/main-app-0123456789abcdef.js"></script>'
        chunk = 'var a=1;window.next={version:"14.1.0",appDir:!0};'
        found = self.run_probe('nextjs-version', {'/': page(body=html), '/_next/static/chunks/main-app-0123456789abcdef.js': page(body=chunk)})
        self.assertEqual([(o['product'], o['version'], o['outcome']) for o in found], [('Next.js', '14.1.0', 'found')])
        hidden = self.run_probe('nextjs-version', {'/': page(body=html), '/_next/static/chunks/main-app-0123456789abcdef.js': page(body='nothing')})
        self.assertEqual([(o['version'], o['outcome']) for o in hidden], [('', 'hidden')])

    def test_script_urls_and_banners_give_library_versions(self):
        html = '<script src="/js/jquery-3.4.1.min.js"></script><script src="/js/app.js"></script>'
        found = self.run_probe('html-libraries', {'/': page(body=html), '/js/app.js': page(body='/*! Bootstrap v3.3.7 (https://getbootstrap.com) */')})
        self.assertEqual({(o['product'], o['version']) for o in found}, {('jQuery', '3.4.1'), ('Bootstrap', '3.3.7')})

    def test_the_front_page_reads_headers_modules_edges_and_generators(self):
        front = page(headers={'Server': 'Apache/2.4.6 (CentOS) PHP/5.4.16', 'CF-Ray': 'abc-AMS', 'X-AspNet-Version': '4.0.30319'},
                     body='<meta name="generator" content="Drupal 10 (https://www.drupal.org)">')
        found = self.run_probe('headers-root', {'/': front})
        names = {(o['product'], o['version']) for o in found if o['kind'] == 'version'}
        self.assertTrue({('Apache HTTP Server', '2.4.6'), ('PHP', '5.4.16'), ('ASP.NET', '4.0.30319')} <= names)
        self.assertFalse([o for o in found if o['product'] == 'Drupal' and o['version']])  # "Drupal 10" states no version: a bare major is never evidence
        self.assertEqual([(o['product'], o['outcome']) for o in found if o['kind'] == 'edge'], [('Cloudflare', 'edge')])

    def test_hostile_pages_cannot_inject_names_or_overflow(self):
        found = self.run_probe('headers-root', {'/': page(headers={'Server': 'nginx/1.2 ' + 'Z' * 9000}, body='<meta name="generator" content="' + 'x' * 5000 + '">')})
        self.assertTrue(all(len(o['product']) <= 120 for o in found))


class WordPressProbeTests(SimpleTestCase):
    def detect(self, table, base='https://www.rt.test'):
        found = probes.run_http_probe('wordpress-detect', base, {'www.rt.test', 'rt.test'}, get=answers(table), sleep=lambda s: None)
        return found[0]

    def test_a_header_only_signature_is_a_positive_detection(self):
        link = {'Link': '<https://www.rt.test/wp-json/>; rel="https://api.w.org/"'}
        found = self.detect({'/': page(200, headers=link, body='<html>welcome</html>')})
        self.assertEqual((found['outcome'], found['source']), ('found', 'header:link-api.w.org'))

    def test_the_login_page_the_rest_api_and_the_generator_each_detect_it(self):
        self.assertEqual(self.detect({'/wp-login.php': page(body='<form id="loginform">')})['outcome'], 'found')
        self.assertEqual(self.detect({'/wp-json/': page(401, body='{"code":"rest_forbidden","message":"x"}')})['outcome'], 'found')
        found = self.detect({'/': page(body='<meta name="generator" content="WordPress 6.4.2">'), '/readme.html': page(body='WordPress Version 6.4.2')})
        self.assertEqual((found['outcome'], found['version']), ('found', '6.4.2'))

    def test_an_edge_that_challenges_every_request_is_recorded_as_challenged_with_a_hint(self):
        challenge = page(403, body='<title>Just a moment...</title> cloudflare _cf_chl_opt')
        challenge['challenge'] = 'Cloudflare'
        found = self.detect({'/': challenge, '/wp-login.php': challenge, '/wp-json/': challenge})
        self.assertEqual(found['outcome'], 'challenged')
        self.assertIn('Allow the scanner', found['evidence']['hint'])

    def test_a_clean_site_that_is_not_wordpress_is_absent(self):
        found = self.detect({'/': page(body='<html>plain</html>')})
        self.assertEqual(found['outcome'], 'absent')

    def test_challenge_detection(self):
        self.assertEqual(probes.challenge_of(page(403, headers={'cf-mitigated': 'challenge'})), 'Cloudflare')
        self.assertEqual(probes.challenge_of(page(200, body='<h1>Just a moment...</h1> cloudflare')), 'Cloudflare')
        self.assertEqual(probes.challenge_of(page(503, headers={'server': 'cloudflare'}, title='')), 'Cloudflare')
        self.assertEqual(probes.challenge_of(page(404, headers={'server': 'nginx'})), '')


class FetchTests(SimpleTestCase):
    def test_redirects_stay_inside_the_group_and_the_gate(self):
        calls = []

        def fake(url, **kwargs):
            calls.append((url, kwargs.get('browser')))
            if url == 'https://rt.test/':
                return {**page(301, url=url), 'location': 'https://www.rt.test/'}
            if url == 'https://www.rt.test/':
                return {**page(301, url=url), 'location': 'https://elsewhere.example/'}
            return page(200, url=url)
        with mock.patch('cveFeed.route_auth.host_allowed', return_value=True):
            got = probes.fetch('https://rt.test/', probe=fake, sleep=lambda s: None, allowed={'rt.test', 'www.rt.test'})
        self.assertEqual([c[0] for c in calls], ['https://rt.test/', 'https://www.rt.test/'])
        self.assertTrue(all(c[1] for c in calls))  # browser-like headers
        self.assertEqual(got['final_url'], 'https://www.rt.test/')

    def test_a_blocked_destination_is_refused_before_any_request(self):
        with mock.patch('cveFeed.route_auth.host_allowed', return_value=False):
            with self.assertRaises(ValueError):
                probes.fetch('https://internal.rt.test/', probe=mock.Mock(), sleep=lambda s: None)

    def test_an_edge_challenge_is_returned_at_once_and_never_pushed_against(self):
        challenge = {**page(503, headers={'server': 'cloudflare', 'cf-ray': 'x'}, title=''), 'challenge': ''}
        probe = mock.Mock(return_value=challenge)
        pauses = []
        with mock.patch('cveFeed.route_auth.host_allowed', return_value=True):
            got = probes.fetch('https://rt.test/', probe=probe, sleep=pauses.append)
        self.assertEqual((probe.call_count, pauses), (1, []))
        self.assertEqual(got['challenge'], 'Cloudflare')

    def test_a_plain_try_later_is_asked_again_once_after_a_pause(self):
        probe = mock.Mock(return_value=page(503, headers={'server': 'nginx'}))
        pauses = []
        with mock.patch('cveFeed.route_auth.host_allowed', return_value=True):
            got = probes.fetch('https://rt.test/', probe=probe, sleep=pauses.append)
        self.assertEqual(probe.call_count, len(probes.RETRY_DELAYS) + 1)
        self.assertEqual(pauses, list(probes.RETRY_DELAYS))
        self.assertEqual(got['challenge'], '')

    def test_a_redirect_to_an_excluded_name_is_not_followed(self):
        redirect = {**page(301), 'location': 'https://rt.test/'}
        probe = mock.Mock(return_value=redirect)
        with mock.patch('cveFeed.route_auth.host_allowed', return_value=True), \
                mock.patch('cveFeed.archive_rediscovery.archived_names', return_value=frozenset()), \
                mock.patch('cveFeed.exclusions.is_excluded', side_effect=lambda project, host: host == 'rt.test'):
            with self.assertRaises(ValueError):
                probes.fetch('https://www.rt.test/', probe=probe, sleep=lambda s: None, allowed={'www.rt.test', 'rt.test'}, project=1)


NMAP_PROBE_XML = """<?xml version="1.0"?><nmaprun><scaninfo protocol="tcp" services="443"/><host><address addr="203.0.113.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" version="1.24.0" extrainfo="Ubuntu" tunnel="ssl" method="probed" conf="10">
<cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe></service>
<script id="http-generator" output="WordPress 6.4.2"/><script id="http-server-header" output="nginx/1.24.0 (Ubuntu)&#10;OpenSSL/3.0.2"/></port></ports></host></nmaprun>"""


class NmapProbeTests(SimpleTestCase):
    def test_the_command_is_rendered_by_the_application_from_reviewed_scripts(self):
        argv = probes.nmap_argv('203.0.113.5', 443, 'https')
        self.assertEqual(argv[1:6], ['-sV', '--version-all', '-Pn', '-p', '443'])
        scripts = argv[argv.index('--script') + 1].split(',')
        from cveFeed import nmap_scan
        self.assertTrue(set(scripts) <= nmap_scan.NSE_SCRIPT_SET)
        self.assertNotIn('--script=', ' '.join(argv))
        self.assertEqual(argv[-1], '203.0.113.5')

    def test_the_probe_reads_the_service_the_server_header_and_the_generator(self):
        found, inventory = probes.run_nmap_probe('203.0.113.5', 443, 'https', runner=lambda argv: NMAP_PROBE_XML)
        got = {(o['product'], o['version'], o['source']) for o in found}
        self.assertIn(('nginx', '1.24.0', 'nmap:-sV --version-all'), got)
        self.assertIn(('nginx', '1.24.0', 'nmap:http-server-header'), got)
        self.assertIn(('WordPress', '6.4.2', 'nmap:http-generator'), got)
        self.assertEqual(inventory[0]['ports'][0]['tunnel'], 'ssl')

    def test_a_service_that_names_no_version_is_hidden(self):
        xml = NMAP_PROBE_XML.replace(' version="1.24.0"', '').replace('<cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe>', '')
        found, _ = probes.run_nmap_probe('203.0.113.5', 443, 'https', runner=lambda argv: xml)
        self.assertEqual([(o['outcome'], o['version']) for o in found if o['source'] == 'nmap:-sV --version-all'], [('hidden', '')])

    def test_a_closed_port_gives_nothing(self):
        found, _ = probes.run_nmap_probe('203.0.113.5', 80, 'http', runner=lambda argv: NMAP_PROBE_XML)
        self.assertEqual(found, [])


class PlanTests(RouteFixture, TestCase):
    def host(self, technologies=('nginx',), product=None):
        scan = self.scan()
        sub = Subdomain.objects.get(scan_history=scan)
        for name in technologies:
            sub.technologies.add(Technology.objects.create(name=name))
        if product:
            port = sub.ip_addresses.first().ports.first()
            port.product, port.service_name = product, 'http'
            port.save()
        return scan, Subdomain.objects.filter(pk=sub.pk).prefetch_related('technologies', 'ip_addresses__ports').get()

    def test_an_unversioned_nginx_gets_probes_without_any_ai(self):
        _scan, sub = self.host()
        plan = probes.plan_for_host(sub)
        ids = [p['probe'] for p in plan]
        self.assertIn('headers-root', ids)
        self.assertIn('error-page', ids)
        self.assertIn('nginx-variants', ids)
        self.assertLessEqual(len(plan), probes.MAX_PROBES_PER_HOST)
        self.assertTrue(all(urlsplit(p['target']['base']).hostname == 'www.rt.test' for p in plan if p['family'] == 'http'))

    def test_a_version_found_removes_the_lead(self):
        _scan, sub = self.host(technologies=('nginx:1.24.0',))
        self.assertEqual(probes.plan_for_host(sub), [])

    def test_a_port_lead_gets_the_nmap_probe_unless_an_edge_answers(self):
        _scan, sub = self.host(technologies=(), product='nginx')
        self.assertIn('nmap-version-all', [p['probe'] for p in probes.plan_for_host(sub)])
        self.assertNotIn('nmap-version-all', [p['probe'] for p in probes.plan_for_host(sub, edge_fronted=True)])

    def test_the_display_command_is_something_a_person_can_repeat(self):
        text = probes.display_for('error-page', {'base': 'https://www.rt.test'})
        self.assertIn("curl -sS -i --max-time 6 https://www.rt.test/.cvengine-probe/404", text)

    def test_a_kernel_advisory_says_it_needs_the_inventory_reporter(self):
        cve = mock.Mock(title='Local kernel flaw', original_description='A local kernel driver issue.')
        self.assertIn('inventory reporter', probes.unaddressable(None, cve))
        self.assertEqual(probes.unaddressable(None, mock.Mock(title='x', original_description='remote flaw')), '')


class RecordingTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan()
        self.sub = Subdomain.objects.get(scan_history=self.scan_obj)
        self.sub.technologies.add(Technology.objects.create(name='nginx'))

    def run_one(self, table, probe_id='error-page'):
        sub = Subdomain.objects.filter(pk=self.sub.pk).prefetch_related('technologies', 'ip_addresses__ports').select_related('target_domain').get()
        entry = {'probe': probe_id, 'target': {'base': 'https://www.rt.test'}}
        with mock.patch('cveFeed.probes.recorrelate') as correlate:
            found = probes.run_one(self.project.id, self.domain.id, sub, entry, get=answers(table), sleep=lambda s: None)
        return found, correlate

    def test_a_found_version_is_stored_with_its_source_and_becomes_a_technology(self):
        found, correlate = self.run_one({probes.PROBE_PATH: page(404, body=NGINX_404)})
        row = ProbeObservation.objects.get(project=self.project, host='www.rt.test', probe='error-page')
        self.assertEqual((row.product, row.version, row.outcome, row.source, row.confidence), ('nginx', '1.24.0', 'found', 'body:nginx-error-page', 0.95))
        self.assertTrue(self.sub.technologies.filter(name='nginx:1.24.0').exists())
        correlate.assert_called_once()

    def test_a_hidden_version_adds_no_technology_and_is_recorded_as_hidden(self):
        _found, correlate = self.run_one({probes.PROBE_PATH: page(404, body=NGINX_404_HIDDEN)})
        self.assertFalse(self.sub.technologies.filter(name__contains=':').exists())
        self.assertEqual(ProbeObservation.objects.get(probe='error-page', kind='version').outcome, 'hidden')
        correlate.assert_not_called()

    def test_a_later_probe_replaces_the_earlier_answer_for_the_same_product(self):
        self.run_one({probes.PROBE_PATH: page(404, body=NGINX_404)})
        self.run_one({probes.PROBE_PATH: page(404, body=NGINX_404_HIDDEN)})
        self.assertEqual(ProbeObservation.objects.filter(probe='error-page', kind='version').count(), 1)
        self.assertEqual(ProbeObservation.objects.get(probe='error-page', kind='version').version, '')

    def test_an_identity_that_is_a_product_of_its_own_becomes_a_technology(self):
        self.run_one({'/': page(title='Nginx UI')}, 'nginx-variants')
        self.assertTrue(self.sub.technologies.filter(name='nginx-ui').exists())

    def test_known_observations_are_carried_onto_a_fresh_scan_row(self):
        self.run_one({probes.PROBE_PATH: page(404, body=NGINX_404)})
        fresh = Subdomain.objects.create(name='www.rt.test', target_domain=self.domain, scan_history=self.scan_obj)
        self.assertEqual(probes.apply_known(self.scan_obj), 1)
        self.assertTrue(fresh.technologies.filter(name='nginx:1.24.0').exists())

    def test_observations_of_one_project_never_reach_another(self):
        from dashboard.models import Org, Project
        from django.utils import timezone
        self.run_one({probes.PROBE_PATH: page(404, body=NGINX_404)})
        other = Project.objects.create(name='O', slug='other', insert_date=timezone.now(), org=Org.objects.create(name='O', slug='o'))
        self.assertFalse(ProbeObservation.objects.filter(project=other).exists())


class StageTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'plain.rt.test'))
        for sub in Subdomain.objects.filter(scan_history=self.scan_obj):
            sub.technologies.add(Technology.objects.get_or_create(name='nginx')[0])
        self.requests = []
        self.page_404 = NGINX_404

    def get(self, url):
        self.requests.append(url)
        return answers({probes.PROBE_PATH: page(404, body=self.page_404)})(url)

    def stage(self, **kw):
        with mock.patch('cveFeed.probes.recorrelate'), mock.patch('cveFeed.route_auth.host_allowed', return_value=True):
            return probes.run_for_scan(self.scan_obj.id, get=self.get, sleep=lambda s: None, **kw)

    def test_the_stage_probes_leads_records_versions_and_uses_the_ledger(self):
        out = self.stage()
        self.assertGreater(out['probes'], 0)
        self.assertGreaterEqual(out['versions'], 1)
        self.assertTrue(ServiceRun.objects.filter(service=probes.SERVICE, status='done').exists())
        asked = len(self.requests)
        again = self.stage()
        self.assertEqual((again['probes'], len(self.requests)), (0, asked))  # inside the TTL nothing is asked again

    def test_force_ignores_the_ledger_for_a_lead_that_is_still_open(self):
        self.page_404 = NGINX_404_HIDDEN  # the version stays hidden, so the lead stays
        self.assertGreater(self.stage()['probes'], 0)
        self.assertEqual(self.stage()['probes'], 0)
        self.assertGreater(self.stage(force=True)['probes'], 0)

    def test_an_excluded_host_is_never_probed(self):
        from cveFeed.models import HostExclusion
        HostExclusion.objects.create(org=self.project.org, host='plain.rt.test')
        self.stage()
        self.assertFalse([u for u in self.requests if 'plain.rt.test' in u])

    def test_a_stopped_scan_or_a_pause_ends_the_stage(self):
        with mock.patch('reNgine.resources.abort_requested', return_value=True):
            self.assertEqual(self.stage()['probes'], 0)
        with mock.patch('reNgine.resources.global_pause_requested', return_value=True):
            self.assertEqual(self.stage()['probes'], 0)

    def test_one_failing_probe_is_recorded_failed_and_the_rest_run(self):
        def boom(url):
            raise OSError('connection reset')
        with mock.patch('cveFeed.probes.recorrelate'), mock.patch('cveFeed.route_auth.host_allowed', return_value=True):
            out = probes.run_for_scan(self.scan_obj.id, get=boom, sleep=lambda s: None)
        self.assertEqual(out['errors'], 0)  # a request error inside a probe is an unanswered request, not a crashed probe
        self.assertEqual(ProbeObservation.objects.filter(kind='version', outcome='found').count(), 0)

    def test_the_per_scan_host_cap_is_honoured(self):
        with mock.patch('cveFeed.probes.max_hosts', return_value=1):
            out = self.stage()
        self.assertEqual(out['hosts'], 1)
