"""A Server-header token stored as a name ("nginx/1.28.3", "awselb/2.0", "Microsoft-HTTPAPI/2.0"), nuclei's tech-detect names that reached no
product, and the names that are not software (the coverage report's ``services``): the gaps the technology_coverage report showed on a
production install.

The split (``correlation.split_slash_version``) and its negatives, the ingest of a port scan and of a technology, the read of rows stored
before, each new alias and rename of cveFeed/data/product_aliases.json, the services list (cveFeed/data/service_names.json) and the update
backfill (``backfill_name_versions``)."""
import io
import json
import os

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import correlation, tech_coverage, upgrade_backfills
from tests.test_tech_normalisation import Pool, item


class SplitTests(SimpleTestCase):
    def test_a_server_header_token_is_the_product_and_its_version(self):
        split = correlation.split_name_version
        self.assertEqual(split('nginx/1.28.3'), ('nginx', '1.28.3'))
        self.assertEqual(split('awselb/2.0'), ('awselb', '2.0'))
        self.assertEqual(split('Bootstrap/v5.3.2'), ('Bootstrap', '5.3.2'))
        self.assertEqual(split('nginx/1.24.0 (Ubuntu)'), ('nginx', '1.24.0'))
        self.assertEqual(correlation.split_slash_version('nginx/1.24.0 (Ubuntu)'), ('nginx', '1.24.0', 'Ubuntu'))
        self.assertEqual(correlation.split_port_product('Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k')[:2], ('Apache', '2.4.37'))

    def test_a_path_a_url_or_a_word_after_the_slash_is_never_split(self):
        for text in ('/api/v2', 'foo/bar', 'https://cdn.example.test/1.2.3', 'a/b/1.2', 'nginx/1.2.3/x', 'jquery/3.5.1-beta', 'IPOffice/',
                     'org.apache.logging.log4j/log4j-core', 'HTTP/1.1', 'http/3'):
            with self.subTest(text=text):
                self.assertIsNone(correlation.split_slash_version(text))
                self.assertEqual(correlation.split_name_version(text), (text, ''))
                self.assertEqual(correlation.split_port_product(text), (text, '', ''))
                self.assertEqual(correlation.stored_technology_name(text), text)

    def test_a_bare_major_or_a_sku_is_no_version(self):
        self.assertEqual(correlation.split_name_version('Microsoft-Azure-Application-Gateway/v2'), ('Microsoft-Azure-Application-Gateway', ''))
        self.assertEqual(correlation.split_name_version('ZBA/1'), ('ZBA', ''))

    def test_microsoft_httpapis_version_is_the_apis_never_the_products(self):
        self.assertEqual(correlation.split_name_version('Microsoft-HTTPAPI/2.0'), ('Microsoft-HTTPAPI', ''))
        self.assertEqual(correlation.split_name_version('microsoft httpapi:2.0'), ('microsoft httpapi', ''))
        self.assertEqual(correlation.split_port_product('Microsoft HTTPAPI httpd', '2.0'), ('Microsoft HTTPAPI httpd', '', ''))
        self.assertEqual(correlation.stored_technology_name('Microsoft-HTTPAPI/2.0'), 'Microsoft-HTTPAPI')
        self.assertEqual(correlation.split_port_product('nginx', '1.2.3'), ('nginx', '1.2.3', ''))  # any other product keeps its version

    def test_the_scanners_own_version_column_wins(self):
        self.assertEqual(correlation.split_port_product('nginx/1.24.0', '1.24.1'), ('nginx', '1.24.1', ''))

    def test_the_stored_technology_form(self):
        self.assertEqual(correlation.stored_technology_name('nginx/1.28.3'), 'nginx:1.28.3')
        self.assertEqual(correlation.stored_technology_name('nginx:1.28.3'), 'nginx:1.28.3')

    def test_the_port_record_is_split_as_nmaps_fingerprint_would_store_it(self):
        from cveFeed.port_inventory import split_header_product
        rec = {'number': 443, 'product': 'nginx/1.24.0 (Ubuntu)', 'version': '', 'service_extra': ''}
        self.assertEqual(split_header_product(rec), {**rec, 'product': 'nginx', 'version': '1.24.0', 'service_extra': 'Ubuntu'})
        kept = {'number': 80, 'product': 'nginx', 'version': '1.24.0'}
        self.assertIs(split_header_product(kept), kept)
        path = {'number': 80, 'product': 'foo/bar'}
        self.assertIs(split_header_product(path), path)


class AliasTests(SimpleTestCase):
    """Each new name reaches its product's records, and nothing of another vendor."""

    def test_nucleis_generic_matches_reach_apache_nginx_and_aspnet(self):
        pool = Pool(item('Apache Software Foundation', 'Apache HTTP Server'), item('F5', 'nginx'), item('Microsoft', 'ASP.NET'),
                    item('Microsoft', 'Windows 10 Version 1809'), item('Unrelated Widgets Inc', 'ASP.NET'))
        self.assertEqual(pool.reach('apachegeneric'), {1})
        self.assertEqual(pool.reach('nginxgeneric'), {2})
        self.assertEqual(pool.reach('aspgeneric'), {3})

    def test_a_split_server_header_reaches_its_product(self):
        pool = Pool(item('F5', 'nginx', '1.25.0', '1.29.0'), item('Microsoft Corporation', 'IIS Server', '10.0', '10.1'))
        name, version = correlation.split_name_version('nginx/1.28.3')
        self.assertEqual(pool.matches(name, version), {1: True})
        name, version, _rest = correlation.split_port_product('Microsoft-IIS/10.0')
        self.assertEqual(pool.reach(name), {2})

    def test_microsoft_httpapi_under_every_name_is_one_product_and_never_windows(self):
        pool = Pool(item('Microsoft', 'HTTP.sys'), item('Microsoft', 'Windows 10 Version 1809'), item('Microsoft', 'Windows Server 2019'),
                    item('Unrelated Widgets Inc', 'HTTP.sys'))
        for name in ('Microsoft-HTTPAPI', 'ms-httpapi', 'Microsoft HTTPAPI', 'Microsoft HTTPAPI httpd'):
            with self.subTest(name=name):
                self.assertEqual(pool.reach(name), {1})
        self.assertEqual(pool.reach('Microsoft HTTPAPI httpd', cpe='cpe:/o:microsoft:windows'), {1})

    def test_aspnet_version_disclosure_is_the_clr_line_and_never_windows(self):
        name, version = correlation.read_technology('AspNet Version Disclosure:4.0.30319')
        self.assertEqual((name, version), ('.NET Framework CLR', '4.0.30319'))
        self.assertEqual(correlation.read_technology('AspNet Version Disclosure'), ('ASP.NET', ''))
        self.assertEqual(correlation.read_technology('ASP.NET:2.0.50727'), ('.NET Framework CLR', '2.0.50727'))  # as before
        pool = Pool(item('Microsoft', 'Windows 10 Version 1809', '10.0.0', '10.0.99999'), item('Microsoft', 'Windows 10 Version 1607', '1.0', '99.0'),
                    item('Microsoft', 'Windows Server 2019', '1.0', '99.0'))
        for stored in ('AspNet Version Disclosure:4.0.30319', 'AspNet Version Disclosure:2.0.50727', 'AspNet Version Disclosure'):
            name, version = correlation.read_technology(stored)
            with self.subTest(stored=stored):
                self.assertEqual(pool.reach(name), set())
                self.assertEqual(pool.matches(name, version), {})
        sighting = tech_coverage.normalise_sighting('AspNet Version Disclosure:4.0.30319')
        self.assertEqual((sighting['name'], sighting['version']), ('.NET Framework CLR', '4.0.30319'))

    def test_the_tables_are_read_from_the_file(self):
        self.assertEqual(correlation.TECH_RENAMES['aspnetversiondisclosure'], 'ASP.NET')
        self.assertIn('microsofthttpapi', correlation.PROTOCOL_VERSION_NAMES)
        self.assertIn('mshttpapi', correlation.PROTOCOL_VERSION_NAMES)
        self.assertIn('nginx', correlation.PRODUCT_ALIASES['nginxgeneric'])
        self.assertIn('httpserver', correlation.PRODUCT_ALIASES['apachegeneric'])
        self.assertIn('aspnet', correlation.PRODUCT_ALIASES['aspgeneric'])
        self.assertIn('httpsys', correlation.PRODUCT_ALIASES['mshttpapi'])

    def test_the_connected_names_are_left_alone(self):
        pool = Pool(item('Apache Software Foundation', 'Apache Tomcat'), item('F5', 'BIG-IP'), item('vercel', 'next.js'), item('nuxt', 'nuxt'),
                    item('Microsoft', 'ASP.NET'))
        self.assertEqual(pool.reach('apache-tomcat'), {1})
        self.assertEqual(pool.reach('bigip'), {2})
        self.assertEqual(pool.reach('Next.js'), {3})
        self.assertEqual(pool.reach('microsoft-asp.net'), {5})


class ServicesTests(SimpleTestCase):
    def test_every_name_of_the_list_is_a_service(self):
        with open(tech_coverage.SERVICES_FILE, encoding='utf-8') as fh:
            doc = json.load(fh)
        for entry in doc['services']:
            for name in entry['names']:
                self.assertEqual(tech_coverage.service_kind(name), entry['kind'], name)

    def test_the_report_lists_services_apart_from_unmatched(self):
        pool = Pool(item('Initech', 'Frobnicator'), item('mecanik', 'Cloudflare Image Resizing'))
        s = tech_coverage.normalise_sighting
        names = ['AWS Elastic Load Balancing', 'Amazon CloudFront httpd', 'cloud platform', 'cloudflare', 'Cloudflare', 'Google Frontend',
                 'google-tag-manager', 'hsts', 'http/3', 'Hotjar RUM', 'AWS Service', 'Detect websites using Google bucket storage',
                 'google cloud', 'google cloud cdn', 'akamai', 'akamai cdn', 'Akamai', 'UploadServer', 'Google frontend HttpServer', 'awselb']
        sightings = [s(n) for n in names] + [s('awselb/2.0', source='port', hosts=60), s('Frobnicator Ultra'), s('Frobnicator:1.0')]
        out = tech_coverage.report(sightings, pool.by_id, pool.index)
        self.assertEqual([r['name'] for r in out['unmatched']], ['Frobnicator Ultra'])
        services = {r['name'] for r in out['services']}
        self.assertEqual(services, set(names) | {'awselb'})
        self.assertEqual(out['services_count'], len(services))
        self.assertEqual(next(r for r in out['services'] if r['name'] == 'awselb')['hosts'], 61)  # the port token and the tech name are one name
        self.assertEqual(out['connected_names'], 1)

    def test_a_service_name_never_matches_a_cve(self):
        pool = Pool(item('Cloudflare', 'cloudflare', '1.0', '99.0'))
        for name in ('awselb', 'UploadServer', 'Google Frontend', 'hsts'):
            self.assertEqual(pool.reach(name), set())


class IngestAndBackfillTests(TestCase):
    def setUp(self):
        from cveFeed.models import CVEEntry
        from dashboard.models import Org, Project
        from scanEngine.models import EngineType
        from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology
        from targetApp.models import Domain
        correlation._INDEX_CACHE.update(key=None, value=None)
        self.org = Org.objects.create(name='A', slug='a')
        project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=self.org)
        domain = Domain.objects.create(name='hdr.test', project=project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-1001', cvss=7.5, published_at=timezone.now(), affected=[item('F5', 'nginx', '1.25.0', '1.29.0')])
        CVEEntry.objects.create(cve_id='CVE-2022-21907', cvss=9.8, published_at=timezone.now(),
                                affected=[item('Microsoft', 'Windows 10 Version 1809', '1.0', '99.0'), item('Microsoft', 'HTTP.sys', '1.0', '99.0')])
        self.web = Subdomain.objects.create(name='web.hdr.test', target_domain=domain, scan_history=scan)
        self.ip = IpAddress.objects.create(address='192.0.2.40')
        self.web.ip_addresses.add(self.ip)
        self.port = Port.objects.create(number=443, product='nginx/1.28.3 (Ubuntu)', version='', state='open')
        self.api = Port.objects.create(number=5985, product='Microsoft-HTTPAPI/2.0', version='', state='open')
        self.ip.ports.add(self.port, self.api)
        self.tech = Technology.objects.create(name='nginx/1.28.3')
        self.web.technologies.add(self.tech)
        self.win = Subdomain.objects.create(name='win.hdr.test', target_domain=domain, scan_history=scan)
        self.win.technologies.add(Technology.objects.create(name='AspNet Version Disclosure:4.0.30319'))

    def test_the_port_scan_stores_the_product_and_its_version(self):
        from cveFeed import port_inventory
        from startScan.models import IpAddress
        port_inventory.persist_inventory([{'ip': '198.51.100.40', 'ports': [
            {'number': 80, 'state': 'open', 'product': 'nginx/1.24.0 (Ubuntu)', 'version': '', 'service_name': 'http', 'method': 'probed'},
            {'number': 8080, 'state': 'open', 'product': 'Microsoft-HTTPAPI/2.0', 'version': '', 'service_name': 'http', 'method': 'probed'},
            {'number': 8443, 'state': 'open', 'product': 'foo/bar', 'version': '', 'service_name': 'http', 'method': 'probed'}]}], org_id=self.org.pk)
        ports = {p.number: p for p in IpAddress.objects.get(address='198.51.100.40').ports.all()}
        self.assertEqual((ports[80].product, ports[80].version, ports[80].service_extra), ('nginx', '1.24.0', 'Ubuntu'))
        self.assertEqual((ports[8080].product, ports[8080].version), ('Microsoft-HTTPAPI', ''))
        self.assertEqual(ports[8443].product, 'foo/bar')

    def test_a_technology_is_stored_in_the_name_version_form(self):
        from cveFeed.nuclei_scan import tech_name_from
        self.assertEqual(tech_name_from({'template-id': 'tech-detect', 'matcher-name': 'nginx/1.28.3'}), 'nginx:1.28.3')
        self.assertEqual(tech_name_from({'template-id': 'tech-detect', 'matcher-name': 'ms-httpapi'}), 'ms-httpapi')

    def test_correlation_reads_the_rows_stored_before(self):
        from cveFeed.models import CVEMatch
        cve_by_id, index = correlation.cve_pool()
        correlation.correlate_subdomains([self.web, self.win], index, cve_by_id)
        rows = set(CVEMatch.objects.values_list('subdomain__name', 'cve_entry__cve_id', 'matched_version'))
        self.assertEqual(rows, {('web.hdr.test', 'CVE-2099-1001', '1.28.3')})
        self.assertFalse(CVEMatch.objects.filter(cve_entry__cve_id='CVE-2022-21907').exists())  # HTTPAPI 2.0 is no Windows build

    def test_the_backfill_splits_the_stored_rows_and_correlates_their_hosts(self):
        from cveFeed.models import CVEMatch
        out = io.StringIO()
        call_command('backfill_name_versions', stdout=out)
        self.assertIn('dry run: 2 port products and 1 technology names', out.getvalue())
        self.assertIn('2 current hosts', out.getvalue())
        self.port.refresh_from_db()
        self.assertEqual(self.port.product, 'nginx/1.28.3 (Ubuntu)')  # a dry run changes nothing
        call_command('backfill_name_versions', apply=True, stdout=out)
        self.port.refresh_from_db()
        self.api.refresh_from_db()
        self.tech.refresh_from_db()
        self.assertEqual((self.port.product, self.port.version, self.port.service_extra), ('nginx', '1.28.3', 'Ubuntu'))
        self.assertEqual((self.api.product, self.api.version), ('Microsoft-HTTPAPI', ''))
        self.assertEqual((self.tech.name, self.tech.version), ('nginx:1.28.3', '1.28.3'))
        self.assertEqual(set(CVEMatch.objects.values_list('subdomain__name', 'cve_entry__cve_id', 'matched_version')),
                         {('web.hdr.test', 'CVE-2099-1001', '1.28.3')})
        count = CVEMatch.objects.count()
        self.assertFalse(CVEMatch.objects.filter(cve_entry__cve_id='CVE-2022-21907').exists())
        again = io.StringIO()
        call_command('backfill_name_versions', apply=True, stdout=again)  # again: nothing left to split, nothing changes
        self.assertIn('0 port products and 0 technology names split', again.getvalue())
        self.assertEqual(CVEMatch.objects.count(), count)

    def test_the_backfill_runs_with_the_update_before_the_rescore(self):
        names = upgrade_backfills.BACKFILLS
        self.assertIn('backfill_name_versions', names)
        self.assertLess(names.index('backfill_name_versions'), names.index('rerate_findings'))

    def test_the_coverage_report_reads_the_stored_rows_split(self):
        rows = {(s['name'], s['source']): s for s in tech_coverage.sightings_from_db()}
        self.assertEqual(rows[('nginx', 'port')]['version'], '1.28.3')
        self.assertEqual(rows[('nginx', 'tech')]['version'], '1.28.3')
        self.assertEqual(rows[('Microsoft-HTTPAPI', 'port')]['version'], '')
        self.assertEqual(rows[('.NET Framework CLR', 'tech')]['version'], '4.0.30319')
        self.assertTrue(os.path.exists(tech_coverage.SERVICES_FILE))
