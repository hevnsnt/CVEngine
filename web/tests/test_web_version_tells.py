"""Version tells in web pages (contract 9, the ``version_rows`` Sentinel kind): Apache's ``/server-status?auto`` and a phpinfo page a scan already
found, read row by row (real-shaped answers, and the catch-all, soft-404 and wrong-shaped pages that never read); the gates (an Apache host only,
a found page only, never a guessed path); what is stored and filed; that an older Sentinel is never sent a rows read; and the error-page rules
the version probes run on a page they already fetch."""
import json
from pathlib import Path

from django.test import SimpleTestCase, TestCase

from agentapi import probe_results, sentinel_contract, sentinel_dispatch
from agentapi import sentinel_broker as broker
from agentapi.models import SentinelTask
from cveFeed import probes, version_sources
from cveFeed import version_catalogue as catalogue
from cveFeed.models import ProbeObservation
from startScan.models import EndPoint, Vulnerability
from tests.fake_scanner import FakeScanner, assert_ran_nowhere_locally, fixture
from tests.test_version_sources import VersionFixture, by_path, read, responder

STATUS = {'path': '/server-status?auto', 'status': 200, 'content_type': 'text/plain', 'bytes': 1004, 'truncated': False, 'headers': {'server': 'Apache'},
          'rows': {'ServerVersion': 'Apache/2.4.57 (Debian) OpenSSL/3.0.11'}}
PHPINFO_ROWS = {'PHP Version': '8.2.12', 'OpenSSL Library Version': 'OpenSSL 3.0.11 19 Sep 2023', 'cURL Information': '7.88.1',
                'libXML Loaded Version': '20914', 'libXML Compiled Version': '2.9.14', 'PCRE Library Version': '10.42 2022-12-11', 'SQLite Library': '3.40.1',
                'Apache Version': 'Apache/2.4.57 (Debian)'}
PHPINFO = {'path': '/info.php', 'status': 200, 'content_type': 'text/html', 'bytes': 3478, 'truncated': False, 'headers': {}, 'rows': PHPINFO_ROWS}


def found(result):
    return [(r['component'], r['label'], r['version'], r['kind'], r['confidence']) for r in result['readings']]


class ServerStatusReaderTests(SimpleTestCase):
    def test_the_server_version_row_names_apache_and_each_module_release(self):
        result = read('apache-server-status', STATUS)
        self.assertEqual(found(result), [('apache-http-server', 'Apache HTTP Server', '2.4.57', 'product', 'exact'),
                                         ('openssl', 'OpenSSL', '3.0.11', 'product', 'exact')])
        self.assertTrue(result['exposed'])
        mods = {**STATUS, 'rows': {'ServerVersion': 'Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/7.4.33 mod_wsgi/4.6.4 Python/3.6.8'}}
        self.assertEqual(found(read('apache-server-status', mods)),
                         [('apache-http-server', 'Apache HTTP Server', '2.4.6', 'product', 'exact'), ('openssl', 'OpenSSL', '1.0.2k', 'product', 'exact'),
                          ('mod_fcgid', 'mod_fcgid', '2.3.9', 'product', 'exact'), ('php', 'PHP', '7.4.33', 'runtime', 'exact'),
                          ('mod_wsgi', 'mod_wsgi', '4.6.4', 'product', 'exact'), ('python', 'Python', '3.6.8', 'runtime', 'exact')])

    def test_a_catch_all_or_soft_404_page_and_other_shapes_read_nothing(self):
        for answer in ({**STATUS, 'rows': {}},                                           # the front page for every path: no such row
                       {**STATUS, 'content_type': 'text/html'},                          # an HTML page that happens to say it
                       {**STATUS, 'status': 403, 'rows': {}},                            # the usual: restricted to localhost
                       {**STATUS, 'rows': {'ServerVersion': 'nginx/1.24.0'}},            # not Apache's description
                       {**STATUS, 'rows': {'ServerVersion': 'Apache'}},                  # ServerTokens never applies here, but a bare name states nothing
                       {**STATUS, 'rows': {'ServerVersion': 'Apache/2.4.57 <script>'}},
                       {k: v for k, v in STATUS.items() if k != 'rows'}):               # an older Sentinel's answer: no rows
            with self.subTest(answer=str(answer)[:90]):
                self.assertEqual(read('apache-server-status', answer)['readings'], [])
        self.assertEqual(read('apache-server-status', {**STATUS, 'rows': {}})['state'], 'absent')
        self.assertFalse(read('apache-server-status', {**STATUS, 'rows': {}})['exposed'])
        self.assertEqual(read('apache-server-status', {'path': '/server-status?auto', 'status': 0, 'error': 'TimeoutError'})['state'], 'unknown')


class PhpinfoReaderTests(SimpleTestCase):
    def test_the_php_release_and_the_libraries_it_states(self):
        self.assertEqual(found(read('phpinfo', PHPINFO)), [
            ('php', 'PHP', '8.2.12', 'runtime', 'exact'), ('openssl', 'OpenSSL', '3.0.11', 'product', 'exact'), ('curl', 'curl', '7.88.1', 'product', 'exact'),
            ('libxml2', 'libxml2', '2.9.14', 'product', 'exact'), ('pcre2', 'PCRE2', '10.42', 'product', 'exact'), ('sqlite', 'SQLite', '3.40.1', 'product', 'exact'),
            ('apache-http-server', 'Apache HTTP Server', '2.4.57', 'product', 'exact')])

    def test_a_distribution_build_and_older_libraries(self):
        rows = {'PHP Version': '7.4.3-4ubuntu2.19', 'OpenSSL Library Version': 'OpenSSL 1.1.1f  31 Mar 2020', 'PCRE Library Version': '8.39 2016-06-14',
                'libXML Compiled Version': '2.9.10'}
        self.assertEqual(found(read('phpinfo', {**PHPINFO, 'rows': rows})), [
            ('php', 'PHP', '7.4.3-4ubuntu2.19', 'runtime', 'exact'), ('openssl', 'OpenSSL', '1.1.1f', 'product', 'exact'),
            ('libxml2', 'libxml2', '2.9.10', 'product', 'inferred'),  # the headers PHP was built with, not the loaded library
            ('pcre', 'PCRE', '8.39', 'product', 'exact')])

    def test_no_php_version_row_reads_nothing(self):
        for answer in ({**PHPINFO, 'rows': {k: v for k, v in PHPINFO_ROWS.items() if k != 'PHP Version'}}, {**PHPINFO, 'rows': {}},
                       {**PHPINFO, 'rows': {**PHPINFO_ROWS, 'PHP Version': '8'}}, {**PHPINFO, 'status': 404}):
            with self.subTest(answer=str(answer)[:80]):
                self.assertEqual(read('phpinfo', answer)['readings'], [])


class EntryTests(SimpleTestCase):
    def test_both_entries_are_the_rows_kind_and_their_requests_are_in_contract(self):
        from jsonschema import Draft202012Validator
        for source_id in ('apache-server-status', 'phpinfo'):
            self.assertEqual(catalogue.BY_ID[source_id].task_kind, 'version_rows')
        self.assertEqual(catalogue.request_specs(catalogue.BY_ID['apache-server-status'], '0123456789ab'),
                         [{'path': '/server-status?auto', 'read': 'rows', 'headers': list(catalogue.COMMON_HEADERS), 'fields': ['ServerVersion']}])
        spec, = catalogue.request_specs(catalogue.BY_ID['phpinfo'].at_page('/old/phpinfo.php'), '0123456789ab')
        self.assertEqual((spec['path'], spec['fields']), ('/old/phpinfo.php', list(catalogue.PHPINFO_ROWS)))
        self.assertNotIn('System', spec['fields'])  # the host name and kernel are never asked for
        target = json.loads((Path(__file__).with_name('fixtures') / 'sentinel_targets' / 'version_rows.json').read_text())
        self.assertEqual(list(Draft202012Validator(sentinel_contract.target_schema('version_rows')).iter_errors(target)), [])
        for kind in ('version_read', 'version_digest'):  # an older kind's schema never takes a rows read
            self.assertTrue(list(Draft202012Validator(sentinel_contract.target_schema(kind)).iter_errors(target)))

    def test_server_status_is_asked_only_of_an_apache_host(self):
        wanted = version_sources.wanted
        bases = ['https://h.rt.test']
        self.assertEqual([s.id for s, _b in wanted('h.rt.test', [('Apache HTTP Server', '')], [], bases)], ['apache-server-status'])
        self.assertEqual([s.id for s, _b in wanted('h.rt.test', [('Apache', '2.4.57')], [], bases)], ['apache-server-status'])
        for other in ('Apache Tomcat', 'nginx', 'Apache Traffic Server', 'OpenResty', 'Microsoft IIS'):
            with self.subTest(other=other):
                self.assertNotIn('apache-server-status', [s.id for s, _b in wanted('h.rt.test', [(other, '')], [], bases)])

    def test_phpinfo_is_asked_only_at_a_page_found_on_the_host(self):
        wanted = version_sources.wanted
        bases = ['https://h.rt.test']
        self.assertEqual(wanted('h.rt.test', [('PHP', '8.2.12')], [], bases), [])  # PHP alone never guesses a phpinfo path
        got = wanted('h.rt.test', [], [], bases, {'phpinfo': ['https://h.rt.test/old/info.php', 'https://h.rt.test/second.php',
                                                              'http://h.rt.test:8080/phpinfo.php']})
        self.assertEqual([(s.id, s.requests[0].path, b) for s, b in got],
                         [('phpinfo', '/old/info.php', 'https://h.rt.test'), ('phpinfo', '/phpinfo.php', 'http://h.rt.test:8080')])
        for url in ('https://other.rt.test/info.php', 'https://h.rt.test/a/../info.php', 'ftp://h.rt.test/info.php', 'https://u:p@h.rt.test/i.php',
                    'https://h.rt.test/"onload.php'):
            with self.subTest(url=url):
                self.assertEqual(wanted('h.rt.test', [], [], bases, {'phpinfo': [url]}), [])


class ContractTests(SimpleTestCase):
    def test_only_a_contract_nine_sentinel_is_offered_the_rows_kind(self):
        self.assertEqual(sentinel_contract.kind_since('version_rows'), 9)
        self.assertFalse(sentinel_contract.can_run(8, 'version_rows'))
        self.assertTrue(sentinel_contract.can_run(9, 'version_rows'))
        self.assertTrue(sentinel_contract.can_run(8, 'version_digest'))
        self.assertIn('version_rows', SentinelTask.KINDS)
        self.assertIn('version_rows', sentinel_dispatch.NEVER_LOCAL)
        self.assertIn('version_rows', sentinel_dispatch.COMPLETION_CEILING)

    def test_the_cleaner_keeps_rows_never_a_body_and_binds_only_what_was_asked(self):
        sent = fixture('version_rows')
        stored = broker.clean_result('version_rows', sent)
        self.assertEqual(stored['reads'][0]['answers'][0]['rows'], {'ServerVersion': 'Apache/2.4.57 (Debian) OpenSSL/3.0.11'})
        hostile = {'reads': [{'id': 'a', 'answers': [{'path': '/info.php', 'status': 200, 'body': 'DB_PASSWORD=x', 'text': 'x',
                                                      'rows': {'PHP Version': '8.2.12', 'DB_PASSWORD': 'p@ss"word', '<td>': '1.2', 'Long': 'x' * 121}}]}],
                   'touched': [], 'refused': []}
        got = probe_results.clean_version_rows(hostile)['reads'][0]['answers'][0]
        self.assertEqual(got['rows'], {'PHP Version': '8.2.12'})
        self.assertNotIn('body', got)
        self.assertNotIn('rows', probe_results.clean_version_read(hostile)['reads'][0]['answers'][0])  # version_read never keeps rows
        self.assertNotIn('rows', probe_results.clean_version_digest(hostile)['reads'][0]['answers'][0])
        target = json.loads((Path(__file__).with_name('fixtures') / 'sentinel_targets' / 'version_rows.json').read_text())
        task = SentinelTask(kind='version_rows', target=target)
        extra = {**sent, 'reads': sent['reads'] + [{'id': 'stranger', 'answers': []}]}
        bound = probe_results.bind('version_rows', broker.clean_result('version_rows', extra), task)
        self.assertEqual([r['id'] for r in bound['reads']], [r['id'] for r in target['reads']])
        self.assertIn('www.example.com', broker.task_hosts(task)[0])


class ReadTests(VersionFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.rguard = assert_ran_nowhere_locally(self, 'version_rows')
        self.rtasks = []

    def scanner(self, table, contract_version=None):
        return FakeScanner(kinds=['version_read', 'version_rows'], contract_version=contract_version,
                           responders={'version_read': responder(self.vtasks, by_path(table)), 'version_rows': responder(self.rtasks, by_path(table))})

    def test_an_apache_host_is_read_through_the_rows_kind_and_the_exposure_filed(self):
        scan = self.host_scan(techs=('Apache HTTP Server',))
        with self.scanner({'/server-status?auto': STATUS}):
            result = version_sources.run_for_scan(scan.id)
        self.assertEqual((result['asked'], result['exposed']), (1, 1))
        self.assertEqual(sorted({t.kind for t in SentinelTask.objects.all()}), ['version_rows'])
        entry, = self.rtasks[0]['target']['reads']
        self.assertEqual([(r['path'], r['read'], r['fields']) for r in entry['requests']], [('/server-status?auto', 'rows', ['ServerVersion'])])
        names = set(scan.subdomain_set.get().technologies.values_list('name', flat=True))
        self.assertTrue({'Apache HTTP Server:2.4.57', 'OpenSSL:3.0.11'} <= names)
        vuln = Vulnerability.objects.get(source=version_sources.FINDING_SOURCE)
        self.assertEqual((vuln.template_id, vuln.severity, vuln.http_url), ('apache-server-status-exposed', 1, 'https://app.rt.test/server-status?auto'))
        with self.scanner({'/server-status?auto': {**STATUS, 'status': 403, 'rows': {}}}):
            version_sources.run_for_scan(scan.id, force=True)
        vuln.refresh_from_db()
        self.assertFalse(vuln.open_status)  # a later complete read that is refused: the exposure is gone

    def test_the_template_checks_finding_is_not_doubled(self):
        scan = self.host_scan(techs=('Apache HTTP Server',))
        Vulnerability.objects.create(target_domain=self.domain, scan_history=scan, subdomain=scan.subdomain_set.get(), source='nuclei',
                                     template_id='apache-server-status', name='Apache Server Status Disclosure', severity=1, open_status=True)
        with self.scanner({'/server-status?auto': STATUS}):
            result = version_sources.run_for_scan(scan.id)
        self.assertEqual(result['exposed'], 0)
        self.assertTrue(ProbeObservation.objects.filter(probe='vsrc:apache-server-status', product='OpenSSL', version='3.0.11').exists())

    def test_a_contract_eight_sentinel_is_never_sent_a_rows_read(self):
        scan = self.host_scan(techs=('Apache HTTP Server',))
        with FakeScanner(kinds=['version_read', 'version_digest'], contract_version=8, responders={'version_read': responder(self.vtasks, by_path({}))}):
            result = version_sources.run_for_scan(scan.id)
        self.assertTrue(result.get('rows_waiting'))
        self.assertFalse(SentinelTask.objects.filter(kind='version_rows').exists())

    def test_a_phpinfo_page_a_template_check_found_is_read_and_the_finding_not_doubled(self):
        scan = self.host_scan(techs=('PHP',))
        sub = scan.subdomain_set.get()
        Vulnerability.objects.create(target_domain=self.domain, scan_history=scan, subdomain=sub, source='nuclei', template_id='phpinfo-files',
                                     name='PHPinfo Page - Detect', severity=1, open_status=True, http_url='https://app.rt.test/info.php')
        self.assertEqual(version_sources.discovered_pages(sub), {'phpinfo': ['https://app.rt.test/info.php']})
        with self.scanner({'/info.php': PHPINFO}):
            result = version_sources.run_for_scan(scan.id)
        self.assertEqual((result['asked'], result['exposed']), (1, 0))
        entry, = self.rtasks[0]['target']['reads']
        self.assertEqual([r['path'] for r in entry['requests']], ['/info.php'])
        php = ProbeObservation.objects.get(host='app.rt.test', probe='vsrc:phpinfo', kind='runtime')
        self.assertEqual((php.product, php.version), ('PHP', '8.2.12'))
        names = set(sub.technologies.values_list('name', flat=True))
        self.assertTrue({'OpenSSL:3.0.11', 'curl:7.88.1', 'libxml2:2.9.14', 'PCRE2:10.42', 'SQLite:3.40.1'} <= names)

    def test_a_crawled_phpinfo_page_is_read_and_filed_but_a_guess_is_never_asked(self):
        scan = self.host_scan(techs=('PHP',))
        sub = scan.subdomain_set.get()
        self.assertEqual(version_sources.discovered_pages(sub), {})
        with self.scanner({}) as fake:
            version_sources.run_for_scan(scan.id)
        self.assertNotIn('version_rows', fake.served_kinds())  # no page found: nothing guessed
        EndPoint.objects.create(scan_history=scan, target_domain=self.domain, subdomain=sub, http_url='https://app.rt.test/blog/', http_status=200,
                                page_title='PHP is great')
        EndPoint.objects.create(scan_history=scan, target_domain=self.domain, subdomain=sub, http_url='https://app.rt.test/t.php?x=1', http_status=200,
                                page_title='PHP 8.2.12 - phpinfo()')
        EndPoint.objects.create(scan_history=scan, target_domain=self.domain, subdomain=sub, http_url='https://app.rt.test/phpinfo.php', http_status=404)
        self.assertEqual(version_sources.discovered_pages(sub), {'phpinfo': ['https://app.rt.test/t.php']})
        with self.scanner({'/t.php': {**PHPINFO, 'path': '/t.php'}}):
            result = version_sources.run_for_scan(scan.id, force=True)
        self.assertEqual(result['exposed'], 1)
        self.assertEqual(Vulnerability.objects.get(source=version_sources.FINDING_SOURCE).template_id, 'phpinfo-exposed')


class ErrorPageMirrorTests(SimpleTestCase):
    """The server's copy of the probe table (``cveFeed.probes``) reads the error page as the Sentinel's does."""

    def test_apache_footer_with_modules_and_jboss_web(self):
        probe = probes.BY_ID['error-page']
        body = '<hr>\n<address>Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/7.4.33 Server at www.example.com Port 443</address>\n'
        got = [(o['product'], o['version']) for o in probes.apply_rules(probe, [{'body': body, 'title': '', 'headers': {}}]) if o['kind'] == 'version']
        self.assertEqual(got, [('Apache HTTP Server', '2.4.6'), ('OpenSSL', '1.0.2k'), ('PHP', '7.4.33')])
        got = [(o['product'], o['version']) for o in probes.apply_rules(probe, [{'body': '<h3>JBoss Web/7.0.13.Final</h3>', 'title': '', 'headers': {}}])]
        self.assertEqual(got, [('JBoss Web', '7.0.13')])

    def test_the_server_and_sentinel_tables_agree(self):
        from cvengine_scanner.probes import version_probes
        strip = lambda rules: [{k: v for k, v in r.items() if k != '_re'} for r in rules]  # noqa: E731
        self.assertEqual(strip(probes.BY_ID['error-page']['rules']), strip(version_probes.BY_ID['error-page']['rules']))
        self.assertEqual(probes.BY_ID['error-page']['leads'], version_probes.BY_ID['error-page']['leads'])
