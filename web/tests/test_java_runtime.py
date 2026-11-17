"""The Java runtime of a host, read from outside (cveFeed.java_runtime, the ``java_runtime`` Sentinel kind of contract version 6): the bundled-JDK
table, the readings the stored data gives away, the active reads and their gates, the JDWP exposure, the runtime CVE correlation, search and the
host payload."""
import json
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import probe_results, sentinel_dispatch, sentinel_policy
from agentapi import sentinel_broker as broker
from agentapi.models import SentinelTask
from cveFeed import check_coverage, correlation, java_runtime, match_explain, match_policy, setup_flow, threat, triage, work_planner
from cveFeed.models import CVEEntry, CVEMatch, HostExclusion, JavaRuntime
from startScan.models import IpAddress, Port, Technology, Vulnerability
from tests.fake_scanner import FakeScanner, assert_ran_nowhere_locally, fixture
from tests.test_route_auth import RouteFixture


def reading(version, source='actuator', vendor='Eclipse Temurin', confidence='exact', url='/actuator/info', port=0, line_only=False):
    from cvengine_scanner import java
    norm = java.normalize_version(version)
    return {'version': norm['version'], 'major': norm['major'], 'vendor': vendor, 'runtime': '', 'build': norm['build'], 'line_only': line_only or norm['line_only'],
            'source': source, 'confidence': confidence, 'url': url, 'port': port, 'evidence': f'java.version={version}'}


class TableTests(SimpleTestCase):
    """The bundled-JDK table: every entry cites its source, and a lookup is an inference, never an exact reading."""

    def test_every_entry_cites_a_vendor_source_and_infers(self):
        doc = java_runtime.table()
        for entry in doc['products']:
            with self.subTest(product=entry['id']):
                self.assertIn(entry['confidence'], ('inferred', 'weak'))
                for rng in entry.get('ranges') or ():
                    self.assertTrue(rng['source'].startswith('https://'), rng)
                if entry.get('releases'):
                    self.assertTrue(entry['source'].startswith('https://'))
        self.assertTrue(doc['jenkins_minimum']['source'].startswith('https://www.jenkins.io/'))

    def test_atlassian_installers_bundle_a_known_build(self):
        (key, got), = java_runtime.infer('Confluence', '8.5.3')
        self.assertEqual((key, got['version'], got['vendor'], got['source'], got['confidence']),
                         ('bundled:confluence', '17.0.8.1', 'Eclipse Temurin', 'bundled_inference', 'inferred'))
        self.assertIn('confluence.atlassian.com', got['detail']['source'])
        self.assertEqual(java_runtime.infer('Jira', '9.1.0')[0][1]['major'], 11)
        self.assertEqual(java_runtime.infer('Jira', '9.12.0')[0][1]['version'], '17.0.7')
        self.assertEqual(java_runtime.infer('Bitbucket', '10.3.0')[0][1]['version'], '21.0.6')

    def test_a_release_the_table_does_not_list_gets_its_lines_shared_major_only(self):
        (_key, got), = java_runtime.infer('Confluence', '8.5.99')
        self.assertEqual((got['version'], got['line_only']), ('17', True))

    def test_elasticsearch_and_opensearch_bundle_a_jdk_per_release(self):
        self.assertEqual(java_runtime.infer('Elasticsearch', '8.11.1')[0][1]['version'], '21.0.1')
        self.assertEqual(java_runtime.infer('Elasticsearch', '7.17.0')[0][1]['version'], '17.0.1')
        self.assertEqual(java_runtime.infer('OpenSearch', '2.12.0')[0][1]['version'], '21.0.2')

    def test_jenkins_minimum_and_docker_default(self):
        got = dict(java_runtime.infer('Jenkins', '2.479.1'))
        self.assertEqual(got['jenkins:minimum']['major'], 17)
        self.assertEqual((got['jenkins:minimum']['source'], got['jenkins:minimum']['confidence']), ('jenkins_minimum', 'weak'))
        self.assertEqual(got['bundled:jenkins-docker']['major'], 17)
        self.assertEqual(dict(java_runtime.infer('Jenkins', '2.462.3'))['jenkins:minimum']['major'], 11)  # the last LTS on Java 11
        self.assertEqual(dict(java_runtime.infer('Jenkins', '2.463'))['jenkins:minimum']['major'], 17)  # the first weekly that needs 17
        self.assertEqual(dict(java_runtime.infer('Jenkins', '2.361.1'))['jenkins:minimum']['major'], 11)
        self.assertEqual(dict(java_runtime.infer('Jenkins', '2.555.1'))['jenkins:minimum']['major'], 21)
        self.assertEqual(dict(java_runtime.infer('Jenkins', '2.509'))['bundled:jenkins-docker']['major'], 21)

    def test_container_images_and_supported_lines(self):
        self.assertEqual(java_runtime.infer('Keycloak', '24.0.1')[0][1]['major'], 17)
        self.assertEqual(java_runtime.infer('SonarQube', '10.4.1')[0][1]['major'], 17)
        bamboo = java_runtime.infer('Bamboo', '10.2.1')[0][1]
        self.assertEqual((bamboo['confidence'], bamboo['detail']['possible_majors']), ('weak', [17, 21]))

    def test_nothing_for_an_unknown_product_or_no_version(self):
        self.assertEqual(java_runtime.infer('nginx', '1.24.0'), [])
        self.assertEqual(java_runtime.infer('Confluence', ''), [])


def port(number, service='', product='', version='', protocol='tcp', state='open', extra=None):
    return SimpleNamespace(number=number, service_name=service, product=product, version=version, protocol=protocol, state=state, extra=extra or {})


class PortTests(SimpleTestCase):
    def test_jdwp_ports(self):
        self.assertEqual(java_runtime.jdwp_kind(port(9999, 'jdwp', 'Java Debug Wire Protocol (Reference Implementation) version 17.0', '17.0.9')), 'nmap')
        self.assertEqual(java_runtime.jdwp_kind(port(5005, 'tcpwrapped')), 'debug')
        self.assertEqual(java_runtime.jdwp_kind(port(8000, '')), 'debug')
        self.assertEqual(java_runtime.jdwp_kind(port(8000, 'http', 'nginx')), '')  # a debug port number nmap identified as something else: not sent
        self.assertEqual(java_runtime.jdwp_kind(port(5005, 'tcpwrapped', protocol='udp')), '')
        self.assertEqual(java_runtime.jdwp_kind(port(5005, 'tcpwrapped', state='closed')), '')
        self.assertEqual(java_runtime.jdwp_kind(port(22, 'ssh')), '')

    def test_web_checks_follow_the_products(self):
        self.assertEqual(java_runtime.web_checks([('Spring Boot', ''), ('Apache Tomcat', '10.1.48')]), ['actuator', 'jolokia'])
        self.assertEqual(java_runtime.web_checks([('Apache Solr', '9.4.0')]), ['solr'])
        self.assertEqual(java_runtime.web_checks([('Elasticsearch REST API', '8.11.1')]), ['elasticsearch'])
        self.assertEqual(java_runtime.web_checks([('Apache Tomcat', '10.1.48'), ('Jenkins', '2.479.1')]), [])  # Java, but no endpoint of these
        self.assertEqual(java_runtime.web_checks([('nginx', '1.24.0')]), [])


class WiringTests(SimpleTestCase):
    def test_the_kind_has_no_local_path_a_budget_a_label_and_a_family(self):
        self.assertIn('java_runtime', SentinelTask.KINDS)
        self.assertIn('java_runtime', sentinel_dispatch.NEVER_LOCAL)
        self.assertIn('java_runtime', sentinel_dispatch.COMPLETION_CEILING)
        self.assertEqual(sentinel_policy.label('java_runtime'), 'Java runtime reads')
        self.assertIn('java_runtime', {f[0]: f[3] for f in setup_flow.FAMILIES}['web'])
        self.assertIn('java_runtime', work_planner.specs())
        self.assertIn('java-runtime', check_coverage.BY_ID)

    def test_only_a_contract_six_sentinel_is_offered_the_kind(self):
        from agentapi import sentinel_contract
        self.assertEqual(sentinel_contract.kind_since('java_runtime'), 6)
        self.assertFalse(sentinel_contract.can_run(5, 'java_runtime'))
        self.assertTrue(sentinel_contract.can_run(6, 'java_runtime'))

    def test_the_fixture_goes_through_the_cleaner_and_task_hosts_name_every_host_and_address(self):
        sent = fixture('java_runtime')
        stored = broker.clean_result('java_runtime', sent)
        self.assertEqual(stored['web'][0]['readings'][0]['version'], '17.0.9')
        self.assertTrue(stored['jdwp'][0]['speaks'])
        task = SentinelTask(kind='java_runtime', target=json.loads(json.dumps(fixture('java_runtime') and _target())))
        names, ips = broker.task_hosts(task)
        self.assertIn('app.example.com', names)
        self.assertIn('192.0.2.10', ips)


def _target():
    from pathlib import Path
    return json.loads((Path(__file__).with_name('fixtures') / 'sentinel_targets' / 'java_runtime.json').read_text())


class CleanTests(SimpleTestCase):
    def test_a_reading_is_normalised_again_and_a_bad_one_dropped(self):
        got = probe_results.clean_java_runtime({'web': [{'id': 'a', 'readings': [
            {**reading('17.0.9'), 'version': '1.8.0_392'}, {**reading('17.0.9'), 'version': 'not a version'}, {**reading('17.0.9'), 'source': 'bundled_inference'},
            {**reading('17.0.9'), 'evidence': 'x' * 900, 'vendor': 'Azul Systems, Inc.'}]}], 'jdwp': []})
        rows = got['web'][0]['readings']
        self.assertEqual([r['version'] for r in rows], ['8u392', '17.0.9'])  # a Sentinel never reports an inference: the server makes those
        self.assertLessEqual(len(rows[1]['evidence']), 300)
        self.assertEqual(rows[1]['vendor'], 'Azul')

    def test_a_jdwp_row_that_did_not_speak_keeps_no_reading(self):
        got = probe_results.clean_java_runtime({'web': [], 'jdwp': [{'id': 'x', 'speaks': None, 'reading': reading('17.0.9', 'jdwp')},
                                                                     {'id': 'y', 'speaks': True, 'reading': reading('17.0.9', 'actuator')}]})
        self.assertEqual([(r['speaks'], r['reading']) for r in got['jdwp']], [(None, None), (True, None)])

    def test_the_result_is_cut_to_what_the_task_asked(self):
        task = SentinelTask(kind='java_runtime', target={'web': [{'id': 'a'}], 'jdwp': [{'id': '192.0.2.1:5005'}]})
        result = broker.clean_result('java_runtime', {'outcome': 'done', 'touched': [], 'refused': [],
                                                      'web': [{'id': 'a', 'readings': []}, {'id': 'b', 'readings': []}],
                                                      'jdwp': [{'id': '192.0.2.1:5005', 'speaks': False}, {'id': '192.0.2.1:5006', 'speaks': True}]}, task)
        self.assertEqual([r['id'] for r in result['web']], ['a'])
        self.assertEqual([r['id'] for r in result['jdwp']], ['192.0.2.1:5005'])
        self.assertEqual(result['dropped'], 2)


def responder(tasks, web=None, jdwp=None):
    """A fake Sentinel's ``java_runtime`` answer: ``web(entry)`` and ``jdwp(entry)`` give each entry's row."""
    def answer(task):
        tasks.append(task)
        target = task['target']
        return {'outcome': 'done', 'web': [{'id': e['id'], 'readings': (web or (lambda e: []))(e), 'asked': []} for e in target.get('web') or []],
                'jdwp': [{'id': e['id'], **(jdwp or (lambda e: {'speaks': False, 'reading': None}))(e)} for e in target.get('jdwp') or []],
                'touched': [], 'refused': []}
    return answer


class JavaFixture(RouteFixture):
    ADDRESS = '203.0.113.5'

    def setUp(self):
        super().setUp()
        self.java_guard = assert_ran_nowhere_locally(self, 'java_runtime')
        self.java_tasks = []

    def java_scan(self, techs=(), ports=(), names=('app.rt.test',), web=True, address=None):
        address = address or self.ADDRESS
        scan = self.scan(names=names, ports=((443, 'https'),) if web else (), ip=address)
        ip = IpAddress.objects.get(address=address)
        for number, service, product, version in ports:
            ip.ports.add(Port.objects.create(number=number, service_name=service, product=product, version=version, state='open'))
        for sub in scan.subdomain_set.all():
            if web:
                sub.http_url = f'https://{sub.name}'
                sub.save(update_fields=['http_url'])
            for name in techs:
                tech, _ = Technology.objects.get_or_create(name=name)
                sub.technologies.add(tech)
        return scan

    def sentinel(self, web=None, jdwp=None, **kw):
        return FakeScanner(kinds=['java_runtime'], responders={'java_runtime': responder(self.java_tasks, web, jdwp)}, **kw)


class ReadTests(JavaFixture, TestCase):
    def test_a_spring_host_is_asked_its_actuator_and_the_reading_is_stored(self):
        scan = self.java_scan(techs=('Spring Boot', 'Apache Tomcat:10.1.48'))
        with self.sentinel(web=lambda e: [reading('17.0.9')]):
            result = java_runtime.run_for_scan(scan.id)
        self.assertEqual(result['asked'], 1)
        entry = self.java_tasks[0]['target']['web'][0]
        self.assertEqual((entry['host'], entry['base'], entry['checks']), ('app.rt.test', 'https://app.rt.test', ['actuator', 'jolokia']))
        self.assertNotIn('jdwp', self.java_tasks[0]['target'])  # nothing to ask on a debug port: not sent at all
        row = JavaRuntime.objects.get(host='app.rt.test', source='actuator')
        self.assertEqual((row.version, row.major, row.vendor, row.confidence), ('17.0.9', 17, 'Eclipse Temurin', 'exact'))

    def test_a_host_that_is_not_identified_as_the_product_is_not_asked_the_path(self):
        scan = self.java_scan(techs=('Apache Tomcat:10.1.48',))  # Java, but nothing says Spring, Solr ... : no web check
        self.assertEqual(java_runtime.candidates(scan), {})
        with self.sentinel() as fake:
            java_runtime.run_for_scan(scan.id)
        self.assertEqual(fake.served_kinds(), [])

    def test_only_the_fixed_checks_are_ever_sent(self):
        scan = self.java_scan(techs=('Spring Boot', 'Apache Solr:9.4.0', 'GeoServer:2.24.1', 'Apache Druid:28.0.0', 'Elasticsearch:8.11.1'))
        with self.sentinel():
            java_runtime.run_for_scan(scan.id)
        target = self.java_tasks[0]['target']
        self.assertEqual(set(target), {'web', 'scope'})
        self.assertEqual(target['web'][0]['checks'], ['actuator', 'jolokia', 'solr', 'geoserver', 'druid', 'elasticsearch'])
        from agentapi import sentinel_contract
        from jsonschema import Draft202012Validator
        self.assertEqual(list(Draft202012Validator(sentinel_contract.target_schema('java_runtime')).iter_errors(target)), [])

    def test_an_open_jdwp_port_is_asked_and_is_a_critical_exposure(self):
        scan = self.java_scan(ports=((5005, 'tcpwrapped', '', ''),), web=False)
        with self.sentinel(jdwp=lambda e: {'speaks': True, 'reading': reading('11.0.21', 'jdwp', 'OpenJDK', url='', port=5005)}):
            result = java_runtime.run_for_scan(scan.id)
        self.assertEqual(self.java_tasks[0]['target']['jdwp'], [{'id': f'{self.ADDRESS}:5005', 'address': self.ADDRESS, 'port': 5005}])
        self.assertEqual(result['exposed'], 1)
        vuln = Vulnerability.objects.get(source=java_runtime.FINDING_SOURCE)
        self.assertEqual((vuln.severity, vuln.template_id, vuln.http_url), (4, 'jdwp-exposed', f'jdwp://{self.ADDRESS}:5005'))
        self.assertTrue(vuln.open_status)
        self.assertEqual(JavaRuntime.objects.get(source='jdwp').version, '11.0.21')
        # a later complete check where something else answered closes it
        with self.sentinel(jdwp=lambda e: {'speaks': False, 'reading': None}):
            java_runtime.run_for_scan(scan.id, force=True)
        vuln.refresh_from_db()
        self.assertFalse(vuln.open_status)

    def test_a_port_nmap_identified_as_jdwp_is_an_exposure_and_a_reading_without_a_request(self):
        scan = self.java_scan(ports=((9999, 'jdwp', 'Java Debug Wire Protocol (Reference Implementation) version 17.0', '17.0.9'),), web=False)
        with self.sentinel(jdwp=lambda e: {'speaks': None, 'reading': None}):
            java_runtime.run_for_scan(scan.id)
        row = JavaRuntime.objects.get(key='jdwp:9999')
        self.assertEqual((row.version, row.source, row.confidence), ('17.0.9', 'jdwp', 'exact'))
        self.assertTrue(Vulnerability.objects.filter(source=java_runtime.FINDING_SOURCE, template_id='jdwp-exposed', severity=4).exists())

    def test_an_excluded_host_is_never_sent(self):
        scan = self.java_scan(techs=('Spring Boot',))
        HostExclusion.objects.create(org=self.project.org, host='app.rt.test')
        with self.sentinel() as fake:
            java_runtime.run_for_scan(scan.id)
        self.assertEqual(fake.served_kinds(), [])

    def test_a_bug_bounty_host_outside_the_programs_scope_is_never_sent(self):
        scan = self.java_scan(techs=('Spring Boot',), ports=((5005, 'tcpwrapped', '', ''),))
        with mock.patch('cveFeed.bounty_gate.Gate.refusal', return_value='not in the program\'s scope'), self.sentinel() as fake:
            java_runtime.run_for_scan(scan.id)
        self.assertEqual(fake.served_kinds(), [])

    def test_the_planner_path_waits_for_the_engagements_confirmation(self):
        scan = self.java_scan(techs=('Spring Boot',))
        with mock.patch('cveFeed.bounty_gate.Gate.project_blocked', return_value=True), self.sentinel() as fake:
            result = java_runtime.run_for_hosts(self.project, ['app.rt.test'])
        self.assertEqual(fake.served_kinds(), [])
        self.assertEqual(result['hosts'], 0)
        with self.sentinel(web=lambda e: [reading('21.0.2')]):
            result = java_runtime.run_for_hosts(self.project, ['app.rt.test'])
        self.assertEqual(result['asked'], 1)
        self.assertTrue(scan)

    def test_a_host_is_asked_weekly_and_a_failed_read_again_after_a_day(self):
        scan = self.java_scan(techs=('Spring Boot',))
        with self.sentinel(web=lambda e: [reading('17.0.9')]):
            java_runtime.run_for_scan(scan.id)
            java_runtime.run_for_scan(scan.id)
        self.assertEqual(len(self.java_tasks), 1)

    def test_no_scanner_leaves_the_reads_due_and_runs_nothing_here(self):
        scan = self.java_scan(techs=('Spring Boot',))
        from reNgine.resources import ScannerUnavailable
        with self.assertRaises(ScannerUnavailable):
            java_runtime.run_for_scan(scan.id)
        self.assertFalse(JavaRuntime.objects.filter(source='actuator').exists())


class PassiveTests(JavaFixture, TestCase):
    def test_stored_headers_products_and_inferences(self):
        scan = self.java_scan(techs=('Confluence:8.5.3', 'Jenkins:2.479.1'), web=True)
        sub = scan.subdomain_set.get()
        sub.webserver = 'GlassFish Server Open Source Edition 4.1'
        sub.save(update_fields=['webserver'])
        ip = IpAddress.objects.get(address=self.ADDRESS)
        ip.ports.add(Port.objects.create(number=8080, service_name='http', state='open',
                                         extra={'scripts': {'http-headers': 'Server: Payara\nX-Powered-By: Servlet/4.0 JSP/2.3 (Payara Server 5.2022.5 Java/Azul Systems, Inc./17)'}}))
        java_runtime.refresh_host(sub)
        keys = dict(JavaRuntime.objects.filter(host='app.rt.test').values_list('key', 'version'))
        self.assertEqual(keys['bundled:confluence'], '17.0.8.1')
        self.assertEqual(keys['jenkins:minimum'], '17')
        self.assertEqual(keys['header:8080'], '17')
        header = JavaRuntime.objects.get(key='header:8080')
        self.assertEqual((header.vendor, header.line_only, header.confidence), ('Azul', True, 'exact'))
        # the product is gone: what was derived from it goes too
        sub.technologies.clear()
        java_runtime.refresh_host(sub)
        self.assertFalse(JavaRuntime.objects.filter(key='bundled:confluence').exists())


def cve(cve_id, items, kev=False, cvss=9.8):
    return CVEEntry.objects.create(cve_id=cve_id, title=cve_id, affected=items, kev=kev, cvss=cvss, published_at=timezone.now())


JDK17_RANGE = [{'vendor': 'Oracle', 'product': 'OpenJDK', 'ranges': [{'type': 'ECOSYSTEM', 'introduced': '17.0.6', 'fixed': '18.0.0'}]}]


class CorrelationTests(JavaFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.cve = cve('CVE-2026-114938', JDK17_RANGE)

    def correlate(self, scan):
        cve_by_id, index = correlation.cve_pool()
        subs = correlation.candidate_subdomains(index).filter(scan_history=scan)
        correlation.correlate_subdomains(list(subs), index, cve_by_id, min_confidence=0.4)
        return list(CVEMatch.objects.filter(cve_entry=self.cve, source='java'))

    def add(self, sub, key, r):
        java_runtime.store(self.project.pk, self.domain.pk, sub.name, key, r)

    def test_runtime_products_are_named_as_the_feeds_name_them(self):
        for item in ({'vendor': 'oracle', 'product': 'jdk'}, {'vendor': 'oracle', 'product': 'jre'}, {'vendor': 'Oracle Corporation', 'product': 'Java SE JDK and JRE'},
                     {'vendor': 'oracle', 'product': 'java_se'}, {'product': 'OpenJDK'}, {'vendor': 'eclipse', 'product': 'temurin'},
                     {'vendor': 'azul', 'product': 'zulu'}, {'vendor': 'amazon', 'product': 'corretto'}, {'vendor': 'Red Hat', 'product': 'Red Hat build of OpenJDK'},
                     {'vendor': 'redhat', 'product': 'openjdk'}, {'vendor': 'Red Hat', 'product': 'x', 'packageName': 'java-17-openjdk'},
                     {'product': 'x', 'package': 'openjdk-17'}):
            with self.subTest(item=item):
                self.assertTrue(java_runtime.is_runtime_item(item))
        for item in ({'vendor': 'apache', 'product': 'tomcat'}, {'vendor': 'acme', 'product': 'jdk'}, {'vendor': 'jenkins', 'product': 'jenkins'},
                     {'vendor': 'apache', 'product': 'log4j'}, {'product': 'javascript'}):
            with self.subTest(item=item):
                self.assertFalse(java_runtime.is_runtime_item(item))

    def test_an_exact_reading_inside_the_range_is_a_version_match_and_outside_none(self):
        scan = self.java_scan(techs=('Spring Boot',))
        sub = scan.subdomain_set.get()
        self.add(sub, 'actuator:/actuator/info', reading('17.0.9'))
        match, = self.correlate(scan)
        self.assertEqual((match.version_in_range, match.matched_version, match.matched_product), (True, '17.0.9', 'Java runtime'))
        self.assertFalse(match_policy.version_unknown(match))
        self.assertTrue(match_policy.is_version_only(match))  # a version, not proof of the flaw: needs validation at most (triage's ceiling)
        self.assertFalse(match_policy.version_proven(match))
        JavaRuntime.objects.update(version='17.0.5')
        self.assertEqual([m for m in self.correlate(scan) if m.ai_verdict != 'not_affected'], [])  # the stale match closes
        JavaRuntime.objects.update(version='21.0.2', major=21)
        self.assertEqual([m for m in self.correlate(scan) if m.ai_verdict != 'not_affected'], [])

    def test_java_8_updates_are_compared_as_updates(self):
        self.cve.affected = [{'vendor': 'oracle', 'product': 'jre', 'ranges': [{'type': 'ECOSYSTEM', 'introduced': '1.8.0', 'fixed': '1.8.0_401'}]}]
        self.cve.save()
        scan = self.java_scan(techs=('Spring Boot',))
        self.add(scan.subdomain_set.get(), 'jolokia:x', reading('1.8.0_392', 'jolokia'))
        match, = self.correlate(scan)
        self.assertTrue(match.version_in_range)

    def test_an_inferred_reading_is_never_more_than_a_version_unknown_candidate(self):
        scan = self.java_scan(techs=('Confluence:8.5.3',))
        sub = scan.subdomain_set.get()
        java_runtime.refresh_host(sub)  # Confluence 8.5.3 bundles Temurin 17.0.8.1: inside 17.0.6 to 18
        match, = self.correlate(scan)
        self.assertIsNone(match.version_in_range)
        self.assertTrue(match.evidence['java_unknown'])
        self.assertTrue(match_policy.version_unknown(match))
        self.assertEqual(match.confidence, java_runtime.INFERRED_IN_RANGE_CONFIDENCE)
        self.assertIn('inside the affected range', match.evidence['java_note'])
        self.assertEqual(threat.match_heat(match), threat.ICE)  # never fire on its own
        self.assertEqual(threat.heat_reason(match), threat.REASON_JAVA_UNKNOWN)

    def test_a_java_host_of_unknown_version_is_a_needs_validation_candidate_with_a_plan(self):
        scan = self.java_scan(techs=('Apache Tomcat:10.1.48',))
        match, = self.correlate(scan)
        self.assertTrue(match.evidence['java_unknown'])
        self.assertEqual(match.confidence, java_runtime.UNKNOWN_CONFIDENCE)
        facts = triage.describe_cve_match(CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=match.pk))['facts']
        self.assertTrue(facts['version_unknown'] and facts['java_unknown'])
        self.assertEqual(triage.version_unknown_outcome(True)['classification'], 'needs_validation')
        self.assertEqual(triage.version_unknown_outcome(True)['reason'], match_policy.REASON_JAVA_UNKNOWN)
        explained = match_explain.explain(match)
        self.assertEqual(explained['basis'], 'java_unknown')
        self.assertTrue(explained['why'].startswith('What an outside check could not see'))
        commands = [s['command'] for s in explained['steps']]
        self.assertIn('jcmd <PID> VM.version', commands)
        self.assertTrue(any('readlink -f /proc/<PID>/exe' in c and '-version' in c for c in commands))
        self.assertTrue(any('/release' in c for c in commands))
        plan = match_explain.validate_plan([CVEMatch.objects.select_related('cve_entry', 'subdomain').get(pk=match.pk)])
        self.assertEqual(plan[0]['key'], 'java:runtime')
        self.assertEqual(plan[0]['cves'], ['CVE-2026-114938'])
        from cveFeed import confirm_guide
        guide = confirm_guide.match_guide(CVEMatch.objects.select_related('cve_entry', 'subdomain').get(pk=match.pk))
        self.assertEqual(guide['class'], 'java_runtime')
        self.assertIn('jcmd <PID> VM.version', [c['command'] for c in guide['local'][0]['commands']])

    def test_a_line_or_minimum_that_excludes_every_affected_line_is_no_candidate(self):
        scan = self.java_scan(techs=('Jenkins:2.555.1',))  # starts only on Java 21 or later
        self.assertEqual(self.correlate(scan), [])
        other = self.java_scan(names=('glass.rt.test',), address='203.0.113.7')
        sub = other.subdomain_set.get()
        self.add(sub, 'header:server', reading('1.8', 'header', 'Oracle', line_only=True))
        self.assertEqual(self.correlate(other), [])  # the host states Java 8; the CVE is in 17

    def test_a_distribution_build_is_judged_by_the_distribution(self):
        from cveFeed.models import DistroFix
        DistroFix.objects.create(distro='rhel', release='9', package='java-17-openjdk', cve_id='CVE-2026-114938', fixed_version='1:17.0.10.0.7-2.el9',
                                 status='fixed')
        scan = self.java_scan(techs=('Spring Boot',))
        self.add(scan.subdomain_set.get(), 'actuator:/actuator/env', reading('17.0.9+9-LTS', vendor='Red Hat'))
        match, = self.correlate(scan)
        self.assertTrue(match.version_in_range)
        self.assertEqual(match.distro_status, 'backport')  # Red Hat ships a fixed build; the installed build is not known
        self.assertLessEqual(match.confidence, correlation.BACKPORT_CONFIDENCE)
        self.assertEqual(match.evidence['distro']['package'], 'java-17-openjdk')

    def test_a_host_with_no_java_is_never_matched(self):
        scan = self.java_scan(techs=('nginx:1.24.0', 'PHP:8.2.1'))
        self.assertEqual(self.correlate(scan), [])

    def test_a_runtime_cve_is_correlated_the_moment_it_is_ingested(self):
        scan = self.java_scan(techs=('Apache Tomcat:11.0.25',))
        scan.scan_status = 2
        scan.save(update_fields=['scan_status'])
        fresh = cve('CVE-2026-200001', JDK17_RANGE, cvss=3.1)  # not hot: it would not be fire-correlated
        from cveFeed.tasks import auto_fire_new_cves
        with mock.patch('cveFeed.notify.fire_matches'):
            auto_fire_new_cves([fresh.pk])
        self.assertTrue(CVEMatch.objects.filter(cve_entry=fresh, source='java', subdomain__name='app.rt.test').exists())
