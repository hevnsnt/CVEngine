"""``tech:<name>`` answers "which hosts run X, at which version, and which have none known" for any product (cveFeed.tech_search, the host search's
``tech:`` filter in agentapi.services): every source a host's software is recorded in counts, a name matches through correlation's product name
normalisation and the aliases, a platform is found through the products that run on it (data/runs_on.json), and ``@unknown``, ``@known`` and
``@<release>`` select the version state."""
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import services
from agentapi.auth import create_token
from cveFeed import tech_search
from cveFeed.models import JavaRuntime, ProbeObservation, RouteAuth
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain, Technology
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

NOW = timezone.now()
APACHE = ['cpe.ts.example', 'generic.ts.example', 'port.ts.example', 'reading.ts.example', 'reported.ts.example', 'techrow.ts.example',
          'web.ts.example']


class SpecTests(SimpleTestCase):
    def test_every_spelling_of_apache_httpd_is_one_product(self):
        keys = {tech_search.parse(name).keys for name in ('apache httpd', 'Apache HTTP Server', 'apachegeneric', 'apache2')}
        self.assertEqual(len(keys), 1)
        spec = tech_search.parse('apache http server')
        for stored in ('Apache httpd', 'Apache', 'apachegeneric', 'Apache HTTP Server:2.4.52', 'apache2', 'Apache/2.4.52 (Ubuntu)'):
            self.assertTrue(spec.matches('name', stored), stored)
        for other in ('Apache Tomcat', 'Oracle HTTP Server', 'HTTP Server'):  # a different product, and a name only Oracle's also has
            self.assertFalse(spec.matches('name', other), other)
        self.assertTrue(spec.matches('cpe', 'cpe:/a:apache:http_server:2.4.52'))
        self.assertFalse(spec.matches('cpe', 'cpe:/a:oracle:http_server:12.2.1'))

    def test_a_vendor_in_front_and_an_edition_behind_are_the_same_product_but_a_longer_name_is_not(self):
        self.assertTrue(tech_search.parse('tomcat').matches('name', 'Apache Tomcat:10.1.48'))
        self.assertTrue(tech_search.parse('grafana').matches('name', 'Grafana OSS'))
        self.assertTrue(tech_search.parse('nginx').matches('name', 'nginx version'))  # a detector's template word
        self.assertFalse(tech_search.parse('php').matches('name', 'phpMyAdmin'))
        self.assertFalse(tech_search.parse('nginx').matches('name', 'ingress-nginx'))

    def test_the_qualifier_after_at(self):
        self.assertEqual(tech_search.parse('php@unknown').state, tech_search.UNKNOWN)
        self.assertEqual(tech_search.parse('php@none').state, tech_search.UNKNOWN)
        self.assertEqual(tech_search.parse('php@known').state, tech_search.KNOWN)
        spec = tech_search.parse('wordpress@7.1')
        self.assertEqual((spec.state, spec.release), (tech_search.RELEASE, '7.1'))
        self.assertTrue(spec.version_ok('7.1') and spec.version_ok('7.1.4'))
        self.assertFalse(spec.version_ok('7.10'))
        self.assertEqual(tech_search.parse('java@1.8.0_392').release, '8u392')  # Java's own legacy spelling
        for bad in ('php@banana!', '@7.1', ''):
            self.assertIsNone(tech_search.parse(bad), bad)

    def test_a_protocol_version_is_never_the_products(self):
        spec = tech_search.parse('tomcat@known')
        self.assertTrue(spec.matches('name', 'Apache Tomcat/Coyote JSP engine'))  # still Tomcat
        self.assertFalse(spec.matches('stating', 'Apache Tomcat/Coyote JSP engine'))  # its 1.1 is the HTTP/1.1 connector's

    def test_every_platform_has_its_products(self):
        for name, product in (('java', 'Apache Tomcat'), ('jdk', 'Jenkins'), ('php', 'WordPress'), ('php', 'phpMyAdmin'), ('php', 'Nextcloud'),
                              ('dotnet', 'Microsoft SharePoint'), ('asp.net', 'Outlook Web App'), ('.net', 'Umbraco'), ('nodejs', 'Express'),
                              ('node.js', 'Next.js'), ('node', 'Strapi'), ('python', 'Django'), ('python', 'gunicorn'), ('ruby', 'GitLab'),
                              ('ruby', 'Ruby on Rails'), ('ruby', 'Redmine')):
            spec = tech_search.parse(name)
            self.assertIsNotNone(spec.platform, name)
            self.assertTrue(spec.matches('platform', product), (name, product))
        self.assertFalse(tech_search.parse('nodejs').matches('platform', 'Microsoft SQL Server Express'))  # Express only as the whole name
        self.assertFalse(tech_search.parse('dotnet').matches('platform', 'Microsoft IIS httpd'))  # IIS alone serves PHP and static files too
        self.assertIsNone(tech_search.parse('wordpress').platform)

    def test_java_reuses_the_runtime_rule(self):
        from cveFeed import java_runtime
        self.assertEqual(tech_search.platforms()['java'].py_pattern, java_runtime.JAVA_PRODUCT_RE.pattern)


class TechSearchTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        org_a, org_b = Org.objects.create(name='TA', slug='ts-a'), Org.objects.create(name='TB', slug='ts-b')
        cls.pa = Project.objects.create(name='TA', slug='ts-a', insert_date=NOW, org=org_a)
        cls.pb = Project.objects.create(name='TB', slug='ts-b', insert_date=NOW, org=org_b)
        cls.da = Domain.objects.create(name='ts.example', project=cls.pa, insert_date=NOW)
        cls.db = Domain.objects.create(name='other.example', project=cls.pb, insert_date=NOW)
        alice, bob = User.objects.create_user('ts-alice', password='x'), User.objects.create_user('ts-bob', password='x')
        ProjectMembership.objects.create(user=alice, project=cls.pa, role='user')
        OrgMembership.objects.create(user=bob, org=org_b, role='admin')
        _, cls.token = create_token(alice, 'ts')
        _, cls.token_b = create_token(bob, 'ts-b')
        cls.ip = 0

        def host(name, domain=None, tech=(), ports=(), **fields):
            sub = Subdomain.objects.create(name=name, target_domain=domain or cls.da, **fields)
            for t in tech:
                sub.technologies.add(Technology.objects.get_or_create(name=t)[0])
            if ports:
                cls.ip += 1
                addr = IpAddress.objects.create(address=f'198.51.100.{cls.ip}')
                sub.ip_addresses.add(addr)
                for number, product, version, extra in ports:
                    addr.ports.add(Port.objects.create(number=number, product=product, version=version, service_name='http', **extra))
            return sub

        def reading(name, product, version, probe='vsrc:nmap', kind='version', component='', project=None, domain=None):
            evidence = {'version_source': True, 'component': component or product.lower(), 'confidence': 'exact'}
            if kind == 'reported':
                evidence.update(reported=True, provider='shodan_idb')
            ProbeObservation.objects.create(project=project or cls.pa, domain=domain or cls.da, host=name, probe=probe, kind=kind, product=product,
                                            version=version, outcome='found' if kind != 'reported' else 'reported', evidence=evidence)

        # Apache httpd, as each source records it
        host('techrow.ts.example', tech=['Apache HTTP Server:2.4.52'])
        host('port.ts.example', ports=[(80, 'Apache httpd', '2.4.58', {})])
        host('generic.ts.example', tech=['apachegeneric'])  # no version anywhere
        host('cpe.ts.example', ports=[(8081, '', '', {'cpe': 'cpe:/a:apache:http_server:2.4.41'})])
        host('web.ts.example', webserver='Apache/2.4.62 (Debian)')
        host('reading.ts.example')
        reading('reading.ts.example', 'Apache HTTP Server', '2.4.57')
        host('reported.ts.example')
        reading('reported.ts.example', 'Apache HTTP Server', '2.4.49', probe='vsrc:shodan-idb', kind='reported')
        host('closed.ts.example', ports=[(80, 'Apache httpd', '2.4.58', {'state': 'closed'})])  # a closed port is not on the host
        host('oracle.ts.example', ports=[(7777, 'Oracle HTTP Server', '12.2.1', {})])  # a different product with the same words
        # the platforms, through what runs on them
        host('wp.ts.example', tech=['WordPress:6.4.2'])
        host('wpphp.ts.example', tech=['WordPress:6.5'])
        reading('wpphp.ts.example', 'PHP', '8.2.12', probe='vsrc:passive', kind='runtime', component='php')
        host('wp71.ts.example', tech=['WordPress:7.1.4'])
        host('wp710.ts.example', tech=['WordPress:7.10.0'])
        host('tomcat.ts.example', tech=['Apache Tomcat:10.1.48'])
        host('coyote.ts.example', ports=[(8080, 'Apache Tomcat/Coyote JSP engine', '1.1', {})])
        host('jdwp.ts.example')
        JavaRuntime.objects.create(project=cls.pa, domain=cls.da, host='jdwp.ts.example', key='jdwp:5005', version='17.0.9', major=17, source='jdwp')
        host('sharepoint.ts.example', tech=['Microsoft SharePoint'])
        host('next.ts.example', tech=['Next.js:14.2.3'])
        host('gunicorn.ts.example', ports=[(8000, 'Gunicorn', '20.1.0', {})])
        gitlab = host('gitlab.ts.example')
        RouteAuth.objects.create(project=cls.pa, domain=cls.da, host=gitlab.name, url='https://gitlab.ts.example/', path='/', auth_state='login',
                                 evidence={'fingerprint_names': ['GitLab'], 'fingerprints': [{'name': 'GitLab', 'source': 'body'}]})
        host('plain.ts.example')
        # another project: never in project A's results, not even under the all-projects view of someone who cannot see B
        host('wp.other.example', domain=cls.db, tech=['WordPress:6.4.2', 'Apache HTTP Server:2.4.52'])
        host('plain.ts.example', domain=cls.db)  # the same name in project B, with readings of its own
        reading('plain.ts.example', 'PHP', '8.3.0', probe='vsrc:passive', kind='runtime', component='php', project=cls.pb, domain=cls.db)
        JavaRuntime.objects.create(project=cls.pb, domain=cls.db, host='plain.ts.example', key='jdwp:5005', version='21.0.1', major=21, source='jdwp')

    def setUp(self):
        from django.core.cache import cache
        cache.clear()  # the whole-match counts are a shared snapshot

    def search(self, q, slug='ts-a', token=None, **extra):
        status, data = call(token or self.token, 'GET', f'/api/v1/projects/{slug}/search?' + urlencode({'q': q, **extra}))
        self.assertEqual(status, 200, data)
        return data

    def names(self, q, **kw):
        return sorted(h['host'] for h in self.search(q, **kw)['results'])

    def why(self, q):
        return {h['host']: h['matched'] for h in self.search(q)['results']}

    # ------------------------------------------------------------------ sources and names
    def test_every_source_counts_and_every_spelling_finds_the_same_hosts(self):
        for q in ('tech:"apache httpd"', 'tech:"apache http server"', 'tech:apachegeneric', 'tech:"Apache HTTP Server"'):
            self.assertEqual(self.names(q), APACHE, q)

    def test_each_result_says_what_showed_it_and_its_version(self):
        why = self.why('tech:"apache http server"')
        self.assertEqual(why['techrow.ts.example'], ['technology Apache HTTP Server:2.4.52'])
        self.assertEqual(why['port.ts.example'], ['port 80 Apache httpd 2.4.58'])
        self.assertEqual(why['web.ts.example'], ['web server Apache/2.4.62 (Debian)'])
        self.assertEqual(why['reading.ts.example'], ['version source Apache HTTP Server 2.4.57 (nmap)'])
        self.assertEqual(why['reported.ts.example'], ['version source Apache HTTP Server 2.4.49 (shodan-idb)'])
        self.assertEqual(why['generic.ts.example'], ['technology apachegeneric', 'apache http server version not known'])

    def test_substring_matching_is_kept(self):
        self.assertIn('oracle.ts.example', self.names('tech:oracle'))
        self.assertIn('tomcat.ts.example', self.names('tech:apache'))  # "apache" still finds every Apache product as text

    def test_version_state(self):
        self.assertEqual(self.names('tech:"apache httpd@unknown"'), ['generic.ts.example'])
        self.assertEqual(self.names('tech:"apache httpd@none"'), ['generic.ts.example'])
        self.assertEqual(self.names('tech:"apache httpd@known"'), [n for n in APACHE if n != 'generic.ts.example'])
        self.assertEqual(self.names('tech:"apache httpd@2.4.58"'), ['port.ts.example'])
        self.assertEqual(self.names('tech:"apache httpd@2.4"'), [n for n in APACHE if n != 'generic.ts.example'])
        self.assertEqual(self.names('tech:wordpress@7.1'), ['wp71.ts.example'])  # 7.1 finds 7.1.4, never 7.10
        self.assertEqual(self.names('tech:wordpress@7.10'), ['wp710.ts.example'])
        self.assertEqual(self.names('wordpress 7.1'), ['wp71.ts.example'])  # the bare form is the same search
        self.assertEqual(self.why('tech:wordpress@7.1')['wp71.ts.example'], ['technology WordPress:7.1.4'])

    def test_a_protocol_version_does_not_make_a_version_known(self):
        self.assertIn('coyote.ts.example', self.names('tech:tomcat'))
        self.assertIn('coyote.ts.example', self.names('tech:tomcat@unknown'))
        self.assertNotIn('coyote.ts.example', self.names('tech:tomcat@1.1'))
        self.assertEqual(self.names('tech:tomcat@10.1'), ['tomcat.ts.example'])

    # ------------------------------------------------------------------ platforms
    def test_php_through_what_runs_on_it(self):
        php = ['wp.ts.example', 'wp71.ts.example', 'wp710.ts.example', 'wpphp.ts.example']
        self.assertEqual(self.names('tech:php'), php)
        why = self.why('tech:php')
        self.assertEqual(why['wp.ts.example'], ['runs PHP (WordPress 6.4.2)', 'PHP version not known'])
        self.assertEqual(why['wpphp.ts.example'], ['runtime PHP 8.2.12 (passive)', 'runs PHP (WordPress 6.5)'])
        self.assertEqual(self.names('tech:php@unknown'), ['wp.ts.example', 'wp71.ts.example', 'wp710.ts.example'])  # WordPress's own version is not PHP's
        self.assertEqual(self.names('tech:php@known'), ['wpphp.ts.example'])
        self.assertEqual(self.names('tech:php@8.2'), ['wpphp.ts.example'])
        self.assertEqual(self.names('tech:php@8.20'), [])

    def test_java_and_its_aliases(self):
        java = ['coyote.ts.example', 'jdwp.ts.example', 'tomcat.ts.example']
        self.assertEqual(self.names('tech:java'), java)
        self.assertEqual(self.names('java:any'), java)
        self.assertEqual(self.names('tech:java@unknown'), ['coyote.ts.example', 'tomcat.ts.example'])
        self.assertEqual(self.names('java:unknown'), ['coyote.ts.example', 'tomcat.ts.example'])
        self.assertEqual(self.names('tech:java@17'), ['jdwp.ts.example'])
        self.assertEqual(self.names('tech:java@known'), ['jdwp.ts.example'])
        self.assertEqual(self.names('java:17'), ['jdwp.ts.example'])  # a line still selects the runtime read
        why = self.why('java:any')
        self.assertEqual(why['tomcat.ts.example'], ['runs Java (Apache Tomcat 10.1.48)', 'Java version not known'])
        self.assertEqual(why['jdwp.ts.example'], ['Java runtime 17.0.9 (jdwp)'])

    def test_every_other_platform(self):
        for q, expected in (('tech:dotnet', ['sharepoint.ts.example']), ('tech:asp.net', ['sharepoint.ts.example']),
                            ('tech:nodejs', ['next.ts.example']), ('tech:node.js', ['next.ts.example']),
                            ('tech:python', ['gunicorn.ts.example']), ('tech:ruby', ['gitlab.ts.example'])):
            self.assertEqual(self.names(q), expected, q)
        self.assertEqual(self.why('tech:ruby')['gitlab.ts.example'], ['runs Ruby (GitLab)', 'Ruby version not known'])
        self.assertEqual(self.why('tech:python')['gunicorn.ts.example'], ['runs Python (Gunicorn 20.1.0)', 'Python version not known'])

    # ------------------------------------------------------------------ the search language
    def test_negation_and_a_comma_list(self):
        self.assertEqual(self.names('tech:php,java'), sorted(self.names('tech:php') + self.names('tech:java')))
        why = self.why('tech:php,java')
        self.assertEqual(why['wp.ts.example'], ['runs PHP (WordPress 6.4.2)', 'PHP version not known'])  # the item that found it, only
        self.assertEqual(why['jdwp.ts.example'], ['Java runtime 17.0.9 (jdwp)'])
        rest = self.names('-tech:php')
        self.assertIn('plain.ts.example', rest)
        self.assertIn('tomcat.ts.example', rest)
        self.assertFalse(set(rest) & set(self.names('tech:php')))
        self.assertEqual(self.names('tech:wordpress -tech:php@unknown'), ['wpphp.ts.example'])
        self.assertEqual(self.names('tech:java,php@known'), ['coyote.ts.example', 'jdwp.ts.example', 'tomcat.ts.example', 'wpphp.ts.example'])

    def test_a_bad_qualifier_is_a_400(self):
        status, data = call(self.token, 'GET', '/api/v1/projects/ts-a/search?' + urlencode({'q': 'tech:php@banana!'}))
        self.assertEqual(status, 400)
        self.assertIn('@unknown', data['error'] if isinstance(data, dict) and 'error' in data else str(data))

    def test_other_filters_keep_their_meaning(self):
        self.assertEqual(self.names('product:"apache httpd"'), ['port.ts.example'])  # a port row's product, as text
        self.assertEqual(self.names('runtime:php'), ['wpphp.ts.example'])
        self.assertEqual(self.names('component:any'), ['reading.ts.example', 'reported.ts.example', 'wpphp.ts.example'])
        self.assertEqual(self.names('vsource:reported'), ['reported.ts.example'])

    # ------------------------------------------------------------------ tenancy and the MCP path
    def test_another_projects_hosts_and_readings_never_count(self):
        for q in ('tech:php', 'tech:wordpress', 'tech:java', 'tech:"apache httpd"', 'tech:php@known', 'tech:java@21'):
            for slug in ('ts-a', '_all'):
                found = self.names(q, slug=slug)
                self.assertNotIn('wp.other.example', found, (q, slug))
                self.assertNotIn('plain.ts.example', found, (q, slug))  # project B's PHP and Java readings of a host of the same name
        self.assertEqual(self.names('tech:php@known', slug='_all', token=self.token_b), ['plain.ts.example'])  # B's own reading, for B's host
        self.assertEqual(self.names('tech:java@21', slug='_all', token=self.token_b), ['plain.ts.example'])
        self.assertEqual(self.names('tech:wordpress', slug='_all', token=self.token_b), ['wp.other.example'])

    def test_the_mcp_tool(self):
        is_error, data = tool_call(self.token, 'search_hosts', {'project': 'ts-a', 'q': 'tech:php@unknown', 'facets': 'none'})
        self.assertFalse(is_error, data)
        self.assertEqual(sorted(h['host'] for h in data['results']), ['wp.ts.example', 'wp71.ts.example', 'wp710.ts.example'])
        self.assertIn('PHP version not known', data['results'][0]['matched'])
        self.assertTrue(tool_call(self.token, 'search_hosts', {'project': 'ts-a', 'q': 'tech:php@banana!'})[0])

    def test_a_saved_search_is_checked_when_it_is_saved(self):
        self.assertEqual(len(services.check_search('tech:php@unknown -tech:java')), 2)
        with self.assertRaises(services.ApiError):
            services.check_search('tech:php@banana!')


class QueryCostTests(TestCase):
    """The query a search issues does not grow with the hosts: every source is one subquery, and each page reads its rows once."""

    @classmethod
    def setUpTestData(cls):
        org = Org.objects.create(name='TC', slug='ts-cost')
        cls.project = Project.objects.create(name='TC', slug='ts-cost', insert_date=NOW, org=org)
        cls.domain = Domain.objects.create(name='cost.example', project=cls.project, insert_date=NOW)
        user = User.objects.create_user('ts-cost', password='x')
        ProjectMembership.objects.create(user=user, project=cls.project, role='user')
        _, cls.token = create_token(user, 'cost')
        cls.made = 0
        cls.addresses = 0

    def add_hosts(self, n):
        wordpress = Technology.objects.get_or_create(name='WordPress:6.4.2')[0]
        tomcat = Technology.objects.get_or_create(name='Apache Tomcat:10.1.48')[0]
        for _ in range(n):
            self.made += 1
            name = f'h{self.made}.cost.example'
            sub = Subdomain.objects.create(name=name, target_domain=self.domain)
            sub.technologies.add(wordpress, tomcat)
            QueryCostTests.addresses += 1
            addr = IpAddress.objects.create(address=f'10.20.{self.addresses // 250}.{self.addresses % 250 + 1}')
            sub.ip_addresses.add(addr)
            addr.ports.add(Port.objects.create(number=80, product='Apache httpd', version='2.4.58', service_name='http'))
            ProbeObservation.objects.create(project=self.project, domain=self.domain, host=name, probe='vsrc:passive', kind='runtime', product='PHP',
                                            version='8.2.12', evidence={'version_source': True, 'component': 'php'})

    def queries(self, q):
        from django.core.cache import cache
        cache.clear()
        with CaptureQueriesContext(connection) as captured:
            status, data = call(self.token, 'GET', '/api/v1/projects/ts-cost/search?' + urlencode({'q': q, 'page_size': 50}))
        self.assertEqual(status, 200, data)
        return len(captured), data['count']

    def test_the_number_of_queries_does_not_grow_with_the_hosts(self):
        for q in ('tech:php', 'tech:java@unknown', 'tech:"apache http server@2.4" -tech:ruby', 'java:any'):
            self.made = 0
            Subdomain.objects.filter(target_domain=self.domain).delete()
            ProbeObservation.objects.filter(project=self.project).delete()
            self.add_hosts(3)
            few, n_few = self.queries(q)
            self.add_hosts(30)
            many, n_many = self.queries(q)
            self.assertLessEqual(many, few, (q, few, many))
            self.assertEqual((n_few, n_many), (3, 33), q)

