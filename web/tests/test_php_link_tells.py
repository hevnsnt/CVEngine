"""A link to a ``.php`` URL is never by itself evidence that a host runs PHP (``cveFeed.php_tells``).

The reported host: an ASP.NET site on IIS behind Cloudflare (``X-AspNet-Version: 4.0.30319``) whose front page links to one ``.php`` page was listed
with "PHP, language, seen via page:.php link", "PHP, version not stated, headers-root, page:.php link", counted on the threat card as "runs PHP,
version unknown" and given PHP's CVEs as version-unknown candidates."""
from datetime import timedelta

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import archive_urls, correlation, php_tells, probes, report_threats
from cveFeed import route_auth as ra
from cveFeed.models import CVEEntry, CVEMatch, HostArchive, ProbeObservation, RouteAuth
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import (
    IpAddress,
    ScanHistory,
    Subdomain,
    SubdomainTechnology,
    Technology,
)
from targetApp.models import Domain
from tests.test_probes import page
from tests.test_route_auth import probe

SITE = 'https://www.site.test/'
ASPNET = {'x-aspnet-version': '4.0.30319', 'x-powered-by': 'ASP.NET', 'server': 'Microsoft-IIS/10.0'}


def fingerprints(evidence):
    return {(f['name'], f['source']) for f in evidence.get('fingerprints') or []}


def php_of(evidence):
    return {f for f in fingerprints(evidence) if f[0].split(':')[0] == 'PHP'}


class RouteClassifyTests(SimpleTestCase):
    """The route check's front page, read by the server (``route_auth.classify``, the page in hand)."""

    def classify(self, body, **kw):
        return ra.classify(probe(url=SITE, body=body, **kw))[1]

    def test_a_link_to_a_php_page_on_another_site_gives_no_php_and_no_lead(self):
        evidence = self.classify('<html><a href="https://donate.example.org/give.php?x=1">Give</a><form action="//forms.other.test/s.php"></form></html>')
        self.assertEqual(php_of(evidence), set())
        self.assertNotIn('leads', evidence)
        self.assertNotIn('PHP', evidence.get('fingerprint_names', []))

    def test_a_same_origin_link_with_nothing_from_the_server_is_a_lead_only(self):
        evidence = self.classify('<html><a href="/contact.php">Contact</a></html>')
        self.assertEqual(php_of(evidence), set())
        self.assertEqual([(x['name'], x['state'], x['paths']) for x in evidence['leads']], [('PHP', 'unverified', ['/contact.php'])])
        self.assertNotIn('PHP', evidence['fingerprint_names'])

    def test_x_powered_by_php_gives_php(self):
        evidence = self.classify('<a href="/contact.php">x</a>', powered_by='PHP/8.2.30')
        self.assertEqual(php_of(evidence), {('PHP:8.2.30', 'header:x-powered-by')})
        self.assertNotIn('leads', evidence)

    def test_a_phpsessid_cookie_gives_php(self):
        evidence = self.classify('<a href="/contact.php">x</a>', cookies=['PHPSESSID'])
        self.assertEqual(php_of(evidence), {('PHP', 'cookie:PHPSESSID')})
        self.assertNotIn('leads', evidence)

    def test_a_php_error_on_the_page_gives_php(self):
        body = '<a href="/a.php">a</a><br /><b>Warning</b>:  include(x): Failed to open stream in <b>/var/www/a.php</b> on line <b>3</b><br />'
        self.assertEqual(php_of(self.classify(body)), {('PHP', 'body:php-error')})

    def test_aspnet_headers_and_a_php_link_give_no_php(self):
        evidence = self.classify('<a href="/legacy/form.php">Form</a>', headers=ASPNET, powered_by='ASP.NET', server='Microsoft-IIS/10.0')
        self.assertEqual(php_of(evidence), set())
        self.assertEqual([(x['state'], x['reason']) for x in evidence['leads']], [('contradicted', 'header:x-aspnet-version')])


class ProbeObservationTests(SimpleTestCase):
    """The ``headers-root`` probe: what the server reads of a page, and what a Sentinel's answer (observations only) carries."""

    def test_cross_origin_link_gives_no_observation(self):
        found = probes.observations_from_page(page(200, body='<a href="https://shop.partner.test/cart.php">Shop</a>', url=SITE))
        self.assertEqual([o for o in found if o['product'] == 'PHP'], [])

    def test_same_origin_link_is_a_lead_not_a_version_reading(self):
        found = probes.observations_from_page(page(200, body='<a href="index.php?p=2">Next</a>', url=SITE))
        php = [o for o in found if o['product'] == 'PHP']
        self.assertEqual([(o['kind'], o['variant'], o['source']) for o in php], [('lead', 'unverified', php_tells.LINK_SOURCE)])
        self.assertEqual(probes.technology_names(found), [])

    def test_aspnet_headers_make_the_lead_contradicted(self):
        found = probes.observations_from_page(page(200, headers=ASPNET, body='<a href="/form.php">x</a>', url=SITE))
        self.assertEqual([(o['kind'], o['variant']) for o in found if o['product'] == 'PHP'], [('lead', 'contradicted')])

    def test_a_sentinel_answer_with_the_marker_and_aspnet_is_a_contradicted_lead(self):
        sentinel = [probes._observation('version', '.NET Framework CLR', '4.0.30319', confidence=0.9, source='header:x-aspnet-version', url='/'),
                    probes._observation('version', 'PHP', outcome='hidden', confidence=0.7, source=php_tells.LINK_SOURCE, url='/')]
        judged = php_tells.judge_observations(sentinel)
        self.assertEqual([(o['kind'], o['variant']) for o in judged if o['product'] == 'PHP'], [('lead', 'contradicted')])
        confirmed = php_tells.judge_observations(sentinel, confirmed='cookie:PHPSESSID on /')
        self.assertEqual([(o['kind'], o['outcome'], o['source']) for o in confirmed if o['product'] == 'PHP'], [('version', 'hidden', 'cookie:PHPSESSID on /')])

    def test_host_confirmation_needs_a_real_answer_with_php_signs(self):
        results = [('https://a.test/x.php', {'status': 200, 'state': 'open', 'evidence': {}}),  # a .php URL that answers 200 with nothing of PHP
                   ('https://b.test/x.php', {'status': 200, 'state': 'catch_all', 'evidence': {'cookies': ['PHPSESSID']}}),  # the catch-all page
                   ('https://c.test/x.php', {'status': 404, 'state': 'not_found', 'evidence': {'powered_by': 'PHP/8.1.2'}}),
                   ('https://d.test/x.php', {'status': 200, 'state': 'open', 'evidence': {'cookies': ['PHPSESSID']}})]
        self.assertEqual(php_tells.host_confirmation(results), {'d.test': 'cookie:PHPSESSID on /x.php'})


class Fixture:
    def setUp(self):
        org = Org.objects.create(name='O', slug='o')
        self.project = Project.objects.create(name='P', slug='pphp', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='site.test', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now() - timedelta(hours=1), scan_status=2, tasks=[])
        self.sub = Subdomain.objects.create(name='www.site.test', target_domain=self.domain, scan_history=self.scan)
        self.sub.ip_addresses.add(IpAddress.objects.create(address='203.0.113.80'))

    def sentinel_answer(self, url=SITE, cookies=(), status=200, state='open', fps=None, headers=None):
        """A route answer as a Sentinel reports it (``probe_dispatch._route_answers``): evidence already classified there, no body."""
        fps = fps if fps is not None else [{'name': 'Cloudflare', 'source': 'header:server'}, {'name': 'PHP', 'source': php_tells.LINK_SOURCE}]
        evidence = {'markers': [], 'cookies': list(cookies), 'headers': headers or {}, 'fingerprints': fps, 'fingerprint_names': [f['name'] for f in fps],
                    'provider': '', 'redirect_to': ''}
        return {'credentials': [], 'credential_context': [], 'status': status, 'title': 'Home', 'content_type': 'text/html', 'state': state,
                'evidence': evidence, 'sensitive': {}, 'sensitive_score': 0, 'fp': None, 'bytes': 100}

    def technologies(self):
        return sorted(t.name for t in Subdomain.objects.get(pk=self.sub.pk).technologies.all())


class RoutePersistTests(Fixture, TestCase):
    def test_a_sentinel_marker_is_stored_as_a_lead_and_links_no_technology(self):
        ra._persist(self.scan, self.project.pk, {SITE: self.sentinel_answer()}, timezone.now())
        row = RouteAuth.objects.get(url=SITE)
        self.assertEqual(php_of(row.evidence), set())
        self.assertEqual(row.evidence['leads'][0]['state'], 'unverified')
        self.assertEqual(self.technologies(), ['Cloudflare'])

    def test_a_phpsessid_on_another_route_of_the_host_confirms_php(self):
        probed = {SITE: self.sentinel_answer(),
                  SITE + 'shop/cart.php': self.sentinel_answer(SITE + 'shop/cart.php', cookies=['PHPSESSID'], fps=[])}
        ra._persist(self.scan, self.project.pk, probed, timezone.now())
        self.assertEqual(php_of(RouteAuth.objects.get(url=SITE).evidence), {('PHP', 'cookie:PHPSESSID on /shop/cart.php')})
        self.assertEqual(self.technologies(), ['Cloudflare', 'PHP'])

    def test_aspnet_headers_with_the_marker_give_no_php(self):
        ra._persist(self.scan, self.project.pk, {SITE: self.sentinel_answer(headers={'x-aspnet-version': '4.0.30319'})}, timezone.now())
        self.assertEqual(RouteAuth.objects.get(url=SITE).evidence['leads'][0]['state'], 'contradicted')
        self.assertEqual(self.technologies(), ['Cloudflare'])

    def test_a_probe_marker_from_a_sentinel_is_stored_as_a_lead(self):
        found = [probes._observation('version', 'PHP', outcome='hidden', confidence=0.7, source=php_tells.LINK_SOURCE, url='/')]
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.site.test', probe='headers-root', kind='version', product='PHP',
                                        outcome='hidden', source=php_tells.LINK_SOURCE)  # what an earlier run stored
        probes.apply_remote(self.project.pk, self.domain.pk, self.sub, {'probe': 'headers-root'}, found)
        rows = list(ProbeObservation.objects.filter(host='www.site.test', product='PHP').values_list('kind', 'variant'))
        self.assertEqual(rows, [('lead', 'unverified')])
        self.assertEqual(self.technologies(), [])


class ArchiveTests(Fixture, TestCase):
    def test_an_archived_php_url_is_history_not_a_current_technology(self):
        found = archive_urls.classify(['https://www.site.test/old/index.php'], 'site.test', {'www.site.test'})
        self.assertIn('PHP', found['www.site.test']['technologies'])
        HostArchive.objects.create(project=self.project, domain=self.domain, host='www.site.test', technologies=found['www.site.test']['technologies'],
                                   tech_text='php', url_count=1)
        self.assertEqual(self.technologies(), [])
        cve = CVEEntry.objects.create(cve_id='CVE-2099-7001', cvss=9.8, published_at=timezone.now(), affected=[{'product': 'PHP', 'ranges': [{'fixed': '8.3.0'}]}])
        cve_by_id, index = correlation.cve_pool()
        correlation.correlate_subdomains([Subdomain.objects.get(pk=self.sub.pk)], index, cve_by_id)
        self.assertFalse(CVEMatch.objects.filter(subdomain=self.sub, cve_entry=cve).exists())
        self.assertEqual(report_threats.impact([self.project.pk], [cve])[cve.id]['product_only'], set())
        from django.contrib.auth.models import User

        from tests.test_agentapi import call
        root = User.objects.create_user('root-php', password='x', is_superuser=True)
        self.assertEqual(call(root, 'GET', '/api/v1/projects/pphp/search?q=tech:php&facets=none')[1]['count'], 0)  # tech: is what runs now
        self.assertEqual(call(root, 'GET', '/api/v1/projects/pphp/search?q=php&facets=none')[1]['count'], 1)  # the bare word still finds the history


class BackfillTests(Fixture, TestCase):
    def setUp(self):
        super().setUp()
        self.php = Technology.objects.create(name='PHP')
        # the reported host: a route answer with the marker, the PHP link it made, the probe reading and a version-unknown candidate
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.site.test', url=SITE, path='/', auth_state='open', http_status=200,
                                 evidence=self.sentinel_answer(headers={'x-aspnet-version': '4.0.30319'})['evidence'])
        SubdomainTechnology.objects.create(subdomain=self.sub, technology=self.php, source='route')
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.site.test', probe='headers-root', kind='version', product='PHP',
                                        outcome='hidden', confidence=0.7, source=php_tells.LINK_SOURCE)
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-7002', kev=True, cvss=9.8, published_at=timezone.now(),
                                           affected=[{'product': 'PHP', 'ranges': [{'introduced': '8.0.0', 'fixed': '8.3.0'}]}])
        CVEMatch.objects.create(cve_entry=self.cve, subdomain=self.sub, matched_product='PHP', matched_version='', confidence=0.4, source='tech')
        # a host whose server confirms PHP keeps its link
        self.real = Subdomain.objects.create(name='shop.site.test', target_domain=self.domain, scan_history=self.scan)
        self.real.ip_addresses.add(IpAddress.objects.create(address='203.0.113.81'))
        SubdomainTechnology.objects.create(subdomain=self.real, technology=self.php, source='route')
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='shop.site.test', url='https://shop.site.test/', path='/', auth_state='open',
                                 http_status=200, evidence={**self.sentinel_answer('https://shop.site.test/')['evidence'], 'cookies': ['PHPSESSID']})

    def test_the_backfill_demotes_link_only_php_and_is_idempotent(self):
        self.assertEqual(report_threats.impact([self.project.pk], [self.cve])[self.cve.id]['matched'] != set(), True)
        dry = php_tells.catch_up(apply=False)
        self.assertEqual((dry['routes'], dry['probes'], dry['links']), (2, 1, 1))
        self.assertTrue(SubdomainTechnology.objects.filter(subdomain=self.sub, technology=self.php).exists())  # a dry run writes nothing
        out = php_tells.catch_up(apply=True)
        self.assertEqual((out['links'], out['hosts']), (1, 1))
        self.assertEqual(self.technologies(), [])
        self.assertEqual(sorted(t.name for t in self.real.technologies.all()), ['PHP'])
        route = RouteAuth.objects.get(url=SITE)
        self.assertEqual((php_of(route.evidence), route.evidence['leads'][0]['state']), (set(), 'contradicted'))
        self.assertEqual(php_of(RouteAuth.objects.get(host='shop.site.test').evidence), {('PHP', 'cookie:PHPSESSID')})
        self.assertEqual(list(ProbeObservation.objects.filter(host='www.site.test', product='PHP').values_list('kind', 'variant')), [('lead', 'contradicted')])
        self.assertFalse(CVEMatch.objects.filter(subdomain=self.sub, cve_entry=self.cve, remediation_status='open').exclude(ai_verdict='not_affected').exists())
        row = report_threats.impact([self.project.pk], [self.cve])[self.cve.id]
        self.assertEqual((row['matched'], len(row['product_only'])), (set(), 1))  # shop.site.test, where the server says PHP, is the one left
        again = php_tells.catch_up(apply=True)
        self.assertEqual((again['routes'], again['probes'], again['links'], again['hosts']), (0, 0, 0, 0))

    def test_the_command_is_an_update_step(self):
        from io import StringIO

        from django.core.management import call_command

        from cveFeed import upgrade_backfills
        self.assertIn('backfill_php_link_tells', upgrade_backfills.BACKFILLS)
        out = StringIO()
        call_command('backfill_php_link_tells', stdout=out)
        self.assertIn('Dry run', out.getvalue())
        call_command('backfill_php_link_tells', apply=True, stdout=out)
        self.assertIn('1 PHP technology links removed', out.getvalue())
