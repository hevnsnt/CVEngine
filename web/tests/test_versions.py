"""Version parsing end to end, on real-format samples: a version present in tool output must be kept, a version the output does not state must
never be invented."""
import xmltodict
from django.test import SimpleTestCase

from cveFeed import fingerprint, versions
from reNgine.nmap_service import extract_nmap_inventory, parse_ssl_cert


class ServerHeaderTests(SimpleTestCase):
    def names(self, value):
        return [c['name'] for c in versions.parse_server_header(value)['components']]

    def test_nginx_with_a_distribution_comment(self):
        parsed = versions.parse_server_header('nginx/1.24.0 (Ubuntu)')
        self.assertEqual([c['name'] for c in parsed['components']], ['nginx:1.24.0'])
        self.assertEqual(parsed['distro'], 'ubuntu')

    def test_apache_lists_the_modules_and_runtimes_it_runs(self):
        self.assertEqual(self.names('Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f mod_wsgi/4.6.8 Python/3.8'),
                         ['Apache HTTP Server:2.4.41', 'OpenSSL:1.1.1f', 'mod_wsgi:4.6.8', 'Python:3.8'])
        self.assertEqual(self.names('Apache/2.4.6 (CentOS) PHP/5.4.16'), ['Apache HTTP Server:2.4.6', 'PHP:5.4.16'])

    def test_a_protocol_version_is_not_a_tomcat_version(self):
        self.assertEqual(self.names('Apache-Coyote/1.1'), ['Apache Tomcat'])
        self.assertEqual(self.names('Microsoft-HTTPAPI/2.0'), [])

    def test_tomcat_and_jetty_forms(self):
        self.assertEqual(self.names('Apache Tomcat/9.0.50'), ['Apache Tomcat:9.0.50'])
        self.assertEqual(self.names('Jetty(9.4.51.v20230217)'), ['Jetty:9.4.51.v20230217'])

    def test_a_banner_that_states_no_version_gives_none(self):
        self.assertEqual(self.names('nginx'), ['nginx'])
        self.assertEqual(self.names('cloudflare'), ['Cloudflare'])
        self.assertEqual(self.names('Apache'), ['Apache HTTP Server'])

    def test_hostile_values_are_bounded(self):
        found = versions.parse_server_header('nginx/1.1 ' + 'a/1 ' * 500 + '(' + 'x' * 5000 + ')')
        self.assertLessEqual(len(found['components']), versions.MAX_COMPONENTS)
        self.assertEqual(self.names('<script>alert(1)</script>/9'), [])


class HeaderFactsTests(SimpleTestCase):
    def test_aspnet_and_framework_headers(self):
        found = {f['name']: f['source'] for f in versions.parse_headers({
            'Server': 'Microsoft-IIS/10.0', 'X-Powered-By': 'ASP.NET', 'X-AspNet-Version': '4.0.30319', 'X-AspNetMvc-Version': '5.2',
            'X-Nextjs-Cache': 'HIT', 'Via': '1.1 varnish (Varnish/6.0)'})}
        self.assertIn('Microsoft IIS:10.0', found)
        self.assertIn('ASP.NET:4.0.30319', found)  # the version header names it; the bare "ASP.NET" is replaced
        self.assertNotIn('ASP.NET', found)
        self.assertIn('ASP.NET MVC:5.2', found)
        self.assertIn('Next.js', found)
        self.assertIn('Varnish:6.0', found)

    def test_the_rest_api_link_header_names_wordpress_without_a_version(self):
        found = versions.parse_headers({'Link': '<https://example.test/wp-json/>; rel="https://api.w.org/"'})
        self.assertEqual(found, [{'name': 'WordPress', 'source': 'header:link'}])

    def test_edges_are_named_from_headers_and_the_server_value(self):
        self.assertEqual(versions.edges_from_headers({'CF-Ray': '8a1b-AMS', 'Server': 'cloudflare'}), ['Cloudflare'])
        self.assertEqual(versions.edges_from_headers({'Server': 'nginx/1.24.0'}), [])
        self.assertEqual(versions.edges_from_headers({'Via': '1.1 abc.cloudfront.net (CloudFront)'}), ['Amazon CloudFront'])

    def test_only_listed_headers_are_kept_and_never_cookies(self):
        kept = versions.keep_headers([('Server', 'nginx'), ('Set-Cookie', 'session=secret'), ('Authorization', 'x'), ('X-Pingback', 'https://e.test/xmlrpc.php')])
        self.assertEqual(sorted(kept), ['server', 'x-pingback'])


class GeneratorTests(SimpleTestCase):
    HTML = ('<meta name="generator" content="WordPress 6.4.2"><meta content="Elementor 3.18.3; features: e_dom_optimization" name="generator">'
            '<meta name="generator" content="WooCommerce 8.4.0"><!-- This site is optimized with the Yoast SEO plugin v21.7 - https://yoast.com -->')

    def test_every_generator_tag_and_plugin_comment_is_read(self):
        self.assertEqual(versions.generator_tags(self.HTML), [('WordPress', '6.4.2'), ('Elementor', '3.18.3'), ('WooCommerce', '8.4.0'),
                                                               ('Yoast SEO', '21.7')])

    def test_a_tag_with_no_version_gives_none(self):
        self.assertEqual(versions.generator_tags('<meta name="generator" content="Joomla! - Open Source Content Management">'), [('Joomla', '')])

    def test_the_fingerprint_names_follow(self):
        names = [f['name'] for f in fingerprint.from_response(body=self.HTML, content_type='text/html')]
        self.assertIn('WordPress:6.4.2', names)
        self.assertIn('Elementor:3.18.3', names)


class TechnologyNameTests(SimpleTestCase):
    def test_normalization(self):
        n = versions.normalize_technology
        self.assertEqual(n('Bootstrap:v3.3.7'), 'Bootstrap:3.3.7')
        self.assertEqual(n('cpe:/a:apache:http_server:2.4.41'), 'http server:2.4.41')
        self.assertEqual(n('cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*'), 'nginx:1.24.0')
        self.assertEqual(n('cpe:/a:igor_sysoev:nginx'), 'nginx')
        self.assertEqual(n('nginx:'), 'nginx')
        self.assertEqual(n('jQuery:3.6.0'), 'jQuery:3.6.0')
        self.assertEqual(n('Node.js:v18.0.0'), 'Node.js:18.0.0')


NMAP_XML = """<?xml version="1.0"?>
<nmaprun><scaninfo protocol="tcp" services="22,443,8444"/>
<host><address addr="192.0.2.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="8444"><state state="open"/>
<service name="http" product="nginx" version="1.24.0" extrainfo="Ubuntu" tunnel="ssl" method="probed" conf="10" hostname="web.example.test">
<cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service>
<script id="ssl-cert" output="&#10;Subject: commonName=web.example.test/organizationName=Example&#10;Subject Alternative Name: DNS:web.example.test, DNS:www.example.test&#10;Issuer: commonName=R3/organizationName=Let's Encrypt&#10;Public Key type: rsa&#10;Public Key bits: 2048&#10;Signature Algorithm: sha256WithRSAEncryption&#10;Not valid before: 2024-01-01T00:00:00&#10;Not valid after:  2024-04-01T00:00:00"/>
<script id="http-server-header" output="&#10;nginx/1.24.0 (Ubuntu)"/>
</port>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.6" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10">
<cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service></port>
</ports>
<os><osmatch name="Linux 5.15" accuracy="97"><osclass type="general purpose" osfamily="Linux" accuracy="97"><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass></osmatch>
<osmatch name="Linux 4.15" accuracy="94"/></os></host></nmaprun>"""


class NmapParsingTests(SimpleTestCase):
    def setUp(self):
        self.host = extract_nmap_inventory(xmltodict.parse(NMAP_XML))[0]
        self.ports = {p['number']: p for p in self.host['ports']}

    def test_product_version_extrainfo_cpe_and_tunnel_are_all_kept(self):
        web = self.ports[8444]
        self.assertEqual((web['product'], web['version'], web['service_extra'], web['tunnel'], web['hostname'], web['confidence']),
                         ('nginx', '1.24.0', 'Ubuntu', 'ssl', 'web.example.test', '10'))
        self.assertEqual(web['cpes'][0], 'cpe:/a:igor_sysoev:nginx:1.24.0')
        ssh = self.ports[22]
        self.assertEqual(ssh['version'], '8.9p1 Ubuntu 3ubuntu0.6')  # the distribution's own release string survives for the distro check

    def test_the_certificate_is_parsed_from_ssl_cert(self):
        tls = self.ports[8444]['tls']
        self.assertEqual(tls['subject'], 'commonName=web.example.test/organizationName=Example')
        self.assertEqual(tls['sans'], ['DNS:web.example.test', 'DNS:www.example.test'])
        self.assertEqual((tls['key_type'], tls['key_bits'], tls['not_after']), ('rsa', '2048', '2024-04-01T00:00:00'))
        self.assertEqual(parse_ssl_cert('not a certificate'), {})

    def test_os_runners_up_are_kept(self):
        self.assertEqual([m['name'] for m in self.host['os_matches']], ['Linux 5.15', 'Linux 4.15'])
        self.assertEqual(self.host['os_matches'][0]['cpe'], 'cpe:/o:linux:linux_kernel:5')
