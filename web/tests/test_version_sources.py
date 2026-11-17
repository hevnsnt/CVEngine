"""Version sources (cveFeed.version_catalogue, cveFeed.version_sources, the ``version_read`` Sentinel kind of contract version 7): each catalogue
entry's reader on a real-shaped answer and on wrong-shaped and catch-all ones, the control path, the gates, what is stored, the exposures, the
language runtime correlation, search and the host payload."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import probe_results, sentinel_dispatch, sentinel_policy
from agentapi import sentinel_broker as broker
from agentapi.models import SentinelTask
from cveFeed import check_coverage, correlation, match_explain, match_policy, setup_flow, threat, triage, version_sources, work_planner
from cveFeed import version_catalogue as catalogue
from cveFeed.models import CVEEntry, CVEMatch, HostExclusion, JavaRuntime, ProbeObservation
from startScan.models import IpAddress, Port, Technology, Vulnerability
from tests.fake_scanner import FakeScanner, assert_ran_nowhere_locally, fixture
from tests.test_route_auth import RouteFixture

HTML_LOGIN = {'path': '/', 'status': 200, 'content_type': 'text/html', 'headers': {}, 'json': None, 'text': '<html><title>Sign in</title></html>'}


def ok(fields=None, status=200, headers=None, text=None, lines=None, path='/', content_type='application/json'):
    out = {'path': path, 'status': status, 'content_type': content_type, 'bytes': 100, 'truncated': False, 'headers': headers or {}}
    if fields is not None or (text is None and lines is None):
        out['json'] = fields
    if text is not None:
        out['text'] = text
    if lines is not None:
        out['lines'] = lines
    return out


def read(source_id, *answers):
    return catalogue.read_entry(catalogue.BY_ID[source_id], list(answers))


def versions(result):
    return [(r['component'], r['version'], r['kind'], r['confidence']) for r in result['readings']]


class CatalogueTests(SimpleTestCase):
    """Every entry: GET only, a few requests, a verification source, and a reader that takes only its own answer's shape."""

    def test_every_entry_is_a_few_gets_of_fixed_paths_with_a_source(self):
        for source in catalogue.SOURCES:
            with self.subTest(source=source.id):
                specs = catalogue.request_specs(source, '0123456789ab')
                self.assertLessEqual(len(specs), catalogue.MAX_REQUESTS)
                for spec in specs:
                    self.assertTrue(spec['path'].startswith('/') and '..' not in spec['path'])
                    self.assertNotIn('method', spec)
                    self.assertFalse(set(spec['headers']) & {'cookie', 'set-cookie', 'authorization'})
                self.assertTrue(source.verified)
                self.assertTrue(source.leads or source.ports)  # never asked of every host
                self.assertEqual(source.reader([None] * len(source.requests)), [])  # no answer, no reading
                self.assertEqual(source.reader([HTML_LOGIN] * len(source.requests)), [])  # a login or catch-all page, no reading

    def test_the_specs_are_in_contract(self):
        from jsonschema import Draft202012Validator
        from agentapi import sentinel_contract
        scope = json.loads((Path(__file__).with_name('fixtures') / 'sentinel_targets' / 'version_read.json').read_text())['scope']
        for kind in ('version_read', catalogue.DIGEST_KIND):  # an entry with a digest read is the version_digest kind's (contract 8)
            reads = [{'id': f'h|{s.id}', 'host': 'h.rt.test', 'base': 'https://h.rt.test', 'allowed': ['h.rt.test'],
                      'requests': catalogue.request_specs(s, '0123456789ab')} for s in catalogue.SOURCES if s.task_kind == kind]
            target = {'reads': reads, 'scope': scope}
            self.assertEqual(list(Draft202012Validator(sentinel_contract.target_schema(kind)).iter_errors(target)), [], kind)

    def test_jira(self):
        good = ok({'version': '9.12.2', 'versionNumbers': {'type': 'array', 'size': 3}, 'buildNumber': 9120002, 'deploymentType': 'Server'})
        self.assertEqual(versions(read('jira', good)), [('jira', '9.12.2', 'product', 'exact')])
        self.assertEqual(read('jira', {**good, 'json': {**good['json'], 'deploymentType': 'Cloud'}})['readings'], [])
        self.assertEqual(read('jira', ok({'version': '9.12.2'}))['readings'], [])  # not serverInfo's shape
        self.assertEqual(read('jira', ok({'errorMessages': ['You are not authenticated']}, status=401))['state'], 'absent')

    def test_atlassian_applinks_manifest(self):
        xml = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><manifest><id>1a2b</id><name>Wiki</name><typeId>confluence</typeId>'
               '<version>8.5.4</version><buildNumber>9012</buildNumber><applinksVersion>9.1.3</applinksVersion></manifest>')
        self.assertEqual(versions(read('atlassian-applinks', ok(text=xml, content_type='application/xml'))), [('confluence', '8.5.4', 'product', 'exact')])
        stash = xml.replace('<typeId>confluence</typeId>', '<typeId>stash</typeId>').replace('8.5.4', '8.9.10')
        self.assertEqual(versions(read('atlassian-applinks', ok(text=stash))), [('bitbucket', '8.9.10', 'product', 'exact')])
        self.assertEqual(read('atlassian-applinks', ok(text='<html><manifest><version>1.2.3</version></manifest>'))['readings'], [])
        self.assertEqual(read('atlassian-applinks', ok(text=xml.replace('confluence', 'mystery')))['readings'], [])

    def test_grafana(self):
        self.assertEqual(versions(read('grafana', ok({'commit': '1e84fede5', 'database': 'ok', 'version': '10.2.3'}))),
                         [('grafana', '10.2.3', 'product', 'exact')])
        self.assertEqual(read('grafana', ok({'version': '10.2.3'}))['readings'], [])  # another product's {"version"}
        self.assertEqual(read('grafana', ok({'commit': '', 'database': 'ok', 'version': ''}))['readings'], [])  # a hidden version

    def test_kibana_full_and_redacted(self):
        full = ok({'version.number': '8.11.1', 'version.build_number': 68920, 'status': {'type': 'object', 'size': 2}})
        self.assertEqual(versions(read('kibana', full)), [('kibana', '8.11.1', 'product', 'exact')])
        self.assertEqual(read('kibana', ok({'status': {'type': 'object', 'size': 1}}))['readings'], [])  # the unauthenticated, redacted status

    def test_sonarqube_plain_text_and_its_control_path(self):
        good, control = ok(text='10.3.0.82913', content_type='text/plain'), ok(text='', status=404, content_type='text/html')
        self.assertEqual(versions(read('sonarqube', good, control)), [('sonarqube', '10.3.0', 'product', 'exact')])
        catch_all = read('sonarqube', good, good)  # the control path answered the same: every path answers this way
        self.assertEqual((catch_all['state'], catch_all['readings']), ('catch_all', []))
        self.assertEqual(read('sonarqube', ok(text='10.3.0.82913', content_type='text/html'), control)['readings'], [])
        self.assertEqual(read('sonarqube', good, {'path': '/x', 'status': 0, 'error': 'TimeoutError'})['state'], 'unknown')

    def test_nexus_server_header(self):
        self.assertEqual(versions(read('nexus', ok(headers={'server': 'Nexus/3.61.0-02 (OSS)'}))), [('nexus', '3.61.0', 'product', 'exact')])
        self.assertEqual(read('nexus', ok(headers={'server': 'nginx/1.24.0'}))['readings'], [])

    def test_gitea_forgejo_and_a_catch_all_json_api(self):
        control = ok({}, status=404)
        self.assertEqual(versions(read('gitea', ok({'version': '1.21.4'}), control)), [('gitea', '1.21.4', 'product', 'exact')])
        self.assertEqual(versions(read('gitea', ok({'version': '7.0.0+gitea-1.22.0'}), control)), [('forgejo', '7.0.0', 'product', 'exact')])
        echo = ok({'version': '1.0.0'})
        self.assertEqual(read('gitea', echo, echo)['state'], 'catch_all')
        self.assertEqual(read('gitea', ok({'version': '1.21.4', 'name': 'x'}), control)['readings'], [])  # more than the one field: not Gitea's

    def test_consul_never_needs_its_debug_config(self):
        self.assertNotIn('DebugConfig', catalogue.BY_ID['consul'].requests[0].fields)
        self.assertEqual(versions(read('consul', ok({'Config.Version': '1.17.1', 'Config.Revision': 'a9f3b8e1', 'Member': {'type': 'object', 'size': 9}}))),
                         [('consul', '1.17.1', 'product', 'exact')])
        self.assertEqual(read('consul', ok({'Config.Version': '1.17.1'}))['readings'], [])
        self.assertEqual(read('consul', ok({'error': 'Permission denied'}, status=403))['state'], 'absent')

    def test_vault_reads_every_health_status(self):
        body = {'version': '1.15.2+ent', 'initialized': True, 'sealed': True, 'standby': False}
        for status in (200, 429, 503, 501):
            self.assertEqual(versions(read('vault', ok(body, status=status))), [('vault', '1.15.2', 'product', 'exact')])
        self.assertEqual(read('vault', ok(body, status=404))['readings'], [])

    def test_traefik_envoy_jenkins_artifactory(self):
        self.assertEqual(versions(read('traefik', ok({'Version': '2.10.4', 'Codename': 'saintmarcelin', 'startDate': '2024-01-01T00:00:00Z'}))),
                         [('traefik', '2.10.4', 'product', 'exact')])
        envoy = ok({'version': 'b050513e840aa939a01f89b07c162f00ab3150eb/1.28.0/Clean/RELEASE/BoringSSL', 'state': 'LIVE',
                    'command_line_options': {'type': 'object', 'size': 20}})
        self.assertEqual(versions(read('envoy-admin', envoy)), [('envoy', '1.28.0', 'product', 'exact')])
        self.assertTrue(read('envoy-admin', envoy)['exposed'])
        self.assertEqual(versions(read('jenkins', ok(status=403, headers={'x-jenkins': '2.426.1'}, content_type='text/html'))),
                         [('jenkins', '2.426.1', 'product', 'exact')])
        self.assertEqual(read('jenkins', ok(headers={'x-jenkins': 'yes'}))['readings'], [])
        self.assertEqual(versions(read('artifactory', ok({'version': '7.71.5', 'revision': '77105900', 'addons': {'type': 'array', 'size': 3}}))),
                         [('artifactory', '7.71.5', 'product', 'exact')])

    def test_platform_apis_are_exposures_and_name_their_go_release(self):
        k8s = ok({'major': '1', 'minor': '27', 'gitVersion': 'v1.27.3-eks-a5565ad', 'goVersion': 'go1.20.5', 'platform': 'linux/amd64'})
        got = read('kubernetes-api', k8s)
        self.assertEqual(versions(got), [('kubernetes', '1.27.3-eks-a5565ad', 'product', 'exact'), ('go', '1.20.5', 'runtime', 'exact')])
        self.assertTrue(got['exposed'])
        docker = ok({'Version': '24.0.7', 'ApiVersion': '1.43', 'GoVersion': 'go1.20.10', 'Os': 'linux', 'Arch': 'amd64'})
        self.assertEqual(versions(read('docker-api', docker)), [('docker', '24.0.7', 'product', 'exact'), ('go', '1.20.10', 'runtime', 'exact')])
        self.assertEqual(catalogue.BY_ID['docker-api'].exposure.severity, 4)
        self.assertEqual(read('docker-api', ok({'message': 'page not found'}, status=404)), {'state': 'absent', 'readings': [], 'exposed': False})
        self.assertEqual(versions(read('etcd', ok({'etcdserver': '3.5.9', 'etcdcluster': '3.5.0'}))), [('etcd', '3.5.9', 'product', 'exact')])
        nomad = ok({'config.Version.Version': '1.6.2', 'config.ACL.Enabled': False, 'member.Tags.build': '1.6.2'})
        self.assertEqual(versions(read('nomad', nomad)), [('nomad', '1.6.2', 'product', 'exact')])
        self.assertFalse(catalogue.nomad_acl_enabled([nomad]))
        self.assertEqual(read('nomad', {'path': '/v1/agent/self', 'status': 0, 'error': 'ConnectionRefusedError'})['exposed'], None)  # unknown

    def test_metrics_info_samples(self):
        lines = ['go_info{version="go1.21.5"}', 'jvm_info{runtime="OpenJDK Runtime Environment",vendor="Eclipse Adoptium",version="17.0.9+9"}',
                 'node_exporter_build_info{goversion="go1.21.5",revision="7333465",version="1.7.0"}',
                 'python_info{implementation="CPython",version="3.11.4"}', 'nodejs_version_info{version="v18.17.0"}',
                 'rabbitmq_build_info{erlang_version="26",prometheus_client_version="4.11.0",rabbitmq_version="3.12.10"}',
                 'weird_info{version="go1.21.5"}', 'node_uname_info{}']
        got = read('prometheus-metrics', ok(lines=lines, content_type='text/plain'), ok(status=404, lines=[], content_type='text/plain'))
        self.assertEqual(versions(got), [('go', '1.21.5', 'runtime', 'exact'), ('java', '17.0.9+9', 'java', 'exact'),
                                         ('node_exporter', '1.7.0', 'product', 'exact'), ('python', '3.11.4', 'runtime', 'exact'),
                                         ('nodejs', '18.17.0', 'runtime', 'exact'), ('rabbitmq', '3.12.10', 'product', 'exact'),
                                         ('erlang', '26', 'runtime', 'exact')])
        self.assertTrue([r for r in got['readings'] if r['component'] == 'erlang'][0]['line_only'])
        self.assertTrue(got['exposed'])
        same = ok(lines=lines, content_type='text/plain')
        self.assertEqual(read('prometheus-metrics', same, same)['state'], 'catch_all')
        self.assertEqual(catalogue.metric_lines(ok(lines=['go_info{version="go1.21.5",token="abc"}', 'bad line'])), [])  # read strictly again

    def test_expvar_states_go_only_and_never_its_command_line(self):
        got = read('go-expvar', ok({'cmdline': {'type': 'array', 'size': 4}, 'memstats': {'type': 'object', 'size': 30}}))
        self.assertEqual(versions(got), [('go', '', 'runtime', 'weak')])
        self.assertEqual(read('go-expvar', ok({'cmdline': '/bin/app --password=x', 'memstats': {'type': 'object', 'size': 1}}))['readings'], [])

    def test_the_aspnet_error_page_names_the_framework_line(self):
        text = 'Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.8.4718.0'
        got = read('aspnet-error', ok(text=text, status=404, content_type='text/html'))
        self.assertEqual(versions(got), [('dotnet-framework', '4.8', 'runtime', 'inferred')])
        self.assertTrue(got['readings'][0]['line_only'])
        self.assertEqual(versions(read('aspnet-error', ok(text=text.replace('4.8.4718', '4.8.9032'))))[0][1], '4.8.1')
        self.assertEqual(read('aspnet-error', ok(text='', status=404))['readings'], [])


class HeaderTests(SimpleTestCase):
    def test_runtimes_and_products_a_header_states(self):
        def one(headers):
            return [(r['component'], r['version'], r['confidence']) for r in catalogue.from_headers(headers)]
        self.assertEqual(one({'Server': 'Werkzeug/2.3.7 Python/3.11.4'}), [('python', '3.11.4', 'exact')])
        self.assertEqual(one({'server': 'SimpleHTTP/0.6 Python/3.8.10'}), [('python', '3.8.10', 'exact')])
        self.assertEqual(one({'server': 'gunicorn'}), [('python', '', 'inferred')])
        self.assertEqual(one({'server': 'uvicorn'}), [('python', '', 'inferred')])
        self.assertEqual(one({'server': 'WEBrick/1.6.0 (Ruby/2.7.2/2020-10-01)'}), [('ruby', '2.7.2', 'exact')])
        self.assertEqual(one({'x-powered-by': 'Phusion Passenger(R) 6.0.18'}), [('ruby', '', 'weak')])
        self.assertEqual(one({'x-powered-by': 'PHP/8.1.2-1ubuntu2.14'}), [('php', '8.1.2-1ubuntu2.14', 'exact')])
        self.assertEqual(one({'x-aspnet-version': '4.0.30319', 'x-powered-by': 'ASP.NET'}), [('dotnet-framework', '4', 'inferred')])
        self.assertEqual(one({'x-powered-by': 'ASP.NET'}), [('dotnet-framework', '', 'weak')])
        self.assertEqual(one({'x-jenkins': '2.426.1'}), [('jenkins', '2.426.1', 'exact')])
        self.assertEqual(one({'server': 'Nexus/3.61.0-02 (OSS)'}), [('nexus', '3.61.0', 'exact')])
        self.assertEqual(one({'server': 'nginx/1.24.0', 'x-powered-by': 'Express'}), [])  # Express states no Node.js release: nothing

    def test_a_stored_technology_is_a_runtime_reading(self):
        self.assertEqual(catalogue.from_technology('Python', '3.11.4')['component'], 'python')
        self.assertEqual(catalogue.from_technology('.NET Framework CLR', '4.0.30319')['version'], '4')
        self.assertIsNone(catalogue.from_technology('nginx', '1.24.0'))
        self.assertIsNone(catalogue.from_technology('PHP', ''))

    def test_hostile_header_text_is_clipped_and_cleaned(self):
        got = catalogue.from_headers({'server': 'Werkzeug/2.3.7 Python/3.11.4\x1b[31m' + 'x' * 1000})
        self.assertLessEqual(len(got[0]['evidence']), 300)
        self.assertNotIn('\x1b', got[0]['evidence'])


class RuntimeItemTests(SimpleTestCase):
    def test_the_runtime_is_named_by_its_own_vendor_and_product(self):
        for item, want in (({'vendor': 'Go standard library', 'product': 'net/http', 'package': 'net/http'}, 'go'),
                           ({'vendor': 'golang', 'product': 'go'}, 'go'), ({'vendor': 'python', 'product': 'python'}, 'python'),
                           ({'vendor': 'Python Software Foundation', 'product': 'CPython'}, 'python'), ({'vendor': 'nodejs', 'product': 'node.js'}, 'nodejs'),
                           ({'vendor': 'php', 'product': 'php'}, 'php'), ({'vendor': 'ruby-lang', 'product': 'ruby'}, 'ruby'),
                           ({'vendor': 'microsoft', 'product': '.net_framework'}, 'dotnet-framework'), ({'vendor': 'Erlang', 'product': 'OTP'}, 'erlang')):
            with self.subTest(item=item):
                self.assertEqual(catalogue.runtime_of_item(item), want)
        for item in ({'vendor': 'Go toolchain', 'product': 'cmd/go'}, {'vendor': 'Go standard library', 'product': 'cmd/cgo'},
                     {'vendor': 'acme', 'product': 'python'}, {'vendor': 'python', 'product': 'pip'}, {'vendor': 'microsoft', 'product': 'exchange_server'},
                     {'product': 'python'}, {'vendor': 'rubyonrails', 'product': 'rails'}):
            with self.subTest(item=item):
                self.assertIsNone(catalogue.runtime_of_item(item))


def port(number, service='', product='', version='', extra=None):
    return SimpleNamespace(number=number, service_name=service, product=product, version=version, protocol='tcp', state='open', extra=extra or {})


class WantedTests(SimpleTestCase):
    def ids(self, products=(), ports=(), bases=('https://h.rt.test',)):
        return [(s.id, b) for s, b in version_sources.wanted('h.rt.test', list(products), list(ports), list(bases))]

    def test_a_product_warrants_its_entry_on_its_web_base_or_its_port(self):
        self.assertEqual(self.ids([('Grafana', '')]), [('grafana', 'https://h.rt.test')])
        self.assertEqual(self.ids([('Grafana', '')], [port(3000, 'http', 'Grafana http')]), [('grafana', 'http://h.rt.test:3000')])
        self.assertEqual(self.ids([('nginx', '1.24.0')]), [])  # no version source of its own: not asked anything

    def test_an_own_port_with_a_generic_service_warrants_it_and_a_named_other_service_does_not(self):
        self.assertEqual(self.ids(ports=[port(2375, '')]), [('docker-api', 'http://h.rt.test:2375')])
        self.assertEqual(self.ids(ports=[port(2376, 'ssl/unknown')]), [('docker-api', 'https://h.rt.test:2376')])
        self.assertEqual(self.ids(ports=[port(2375, 'http', 'nginx')]), [])
        self.assertEqual(self.ids(ports=[port(9100, 'http')], bases=()), [('prometheus-metrics', 'http://h.rt.test:9100')])

    def test_a_host_is_asked_at_most_a_few_entries(self):
        products = [(n, '') for n in ('Grafana', 'Kibana', 'Jenkins', 'Consul', 'Vault', 'Traefik', 'Jira', 'SonarQube')]
        self.assertEqual(len(self.ids(products)), version_sources.MAX_ENTRIES_PER_HOST)


class WiringTests(SimpleTestCase):
    def test_the_kind_has_no_local_path_a_budget_a_label_a_family_a_planner_and_a_check(self):
        self.assertIn('version_read', SentinelTask.KINDS)
        self.assertIn('version_read', sentinel_dispatch.NEVER_LOCAL)
        self.assertIn('version_read', sentinel_dispatch.COMPLETION_CEILING)
        self.assertEqual(sentinel_policy.label('version_read'), 'version source reads')
        self.assertIn('version_read', {f[0]: f[3] for f in setup_flow.FAMILIES}['web'])
        self.assertIn('version_read', work_planner.specs())
        self.assertIn('version-sources', check_coverage.BY_ID)

    def test_only_a_contract_seven_sentinel_is_offered_the_kind(self):
        from agentapi import sentinel_contract
        self.assertEqual(sentinel_contract.kind_since('version_read'), 7)
        self.assertFalse(sentinel_contract.can_run(6, 'version_read'))
        self.assertTrue(sentinel_contract.can_run(7, 'version_read'))

    def test_the_cleaner_keeps_only_the_contract_and_bind_only_what_was_asked(self):
        sent = fixture('version_read')
        stored = broker.clean_result('version_read', sent)
        self.assertEqual(stored['reads'][0]['answers'][0]['json']['version'], '10.2.3')
        hostile = {'reads': [{'id': 'a', 'answers': [{'path': '/api/health', 'status': 200, 'body': '<secret>', 'json': {'version': 'x' * 900, 'a b': 1},
                                                      'headers': {'set-cookie': 'sid=1', 'server': 'nginx'}}]}], 'touched': [], 'refused': []}
        got = probe_results.clean_version_read(hostile)['reads'][0]['answers'][0]
        self.assertNotIn('body', got)
        self.assertEqual(len(got['json']['version']), 200)
        self.assertNotIn('a b', got['json'])
        self.assertEqual(got['headers'], {'server': 'nginx'})
        target = json.loads((Path(__file__).with_name('fixtures') / 'sentinel_targets' / 'version_read.json').read_text())
        task = SentinelTask(kind='version_read', target=target)
        bound = probe_results.bind('version_read', broker.clean_result('version_read', {**sent, 'reads': sent['reads'] + [{'id': 'stranger', 'answers': []}]}), task)
        self.assertEqual([r['id'] for r in bound['reads']], [r['id'] for r in target['reads']])
        names, _ips = broker.task_hosts(task)
        self.assertIn('grafana.example.com', names)


def responder(tasks, answer_for):
    """A fake Sentinel's ``version_read`` answer: ``answer_for(entry, request)`` gives each request's answer."""
    def answer(task):
        tasks.append(task)
        return {'outcome': 'done', 'reads': [{'id': e['id'], 'answers': [{'path': r['path'], **answer_for(e, r)} for r in e['requests']]}
                                             for e in task['target']['reads']], 'touched': [], 'refused': []}
    return answer


def by_path(table, default=None):
    default = default or {'status': 404, 'content_type': 'text/html', 'headers': {}, 'json': None}

    def answer_for(_entry, request):
        got = table.get(request['path'])
        if got is None:
            return {**default, **({'json': None} if request['read'] == 'json' else {'text': ''} if request['read'] == 'text' else {'lines': []}
                                  if request['read'] == 'metrics' else {})}
        return got
    return answer_for


class VersionFixture(RouteFixture):
    ADDRESS = '203.0.113.5'

    def setUp(self):
        super().setUp()
        self.vguard = assert_ran_nowhere_locally(self, 'version_read')
        self.vtasks = []

    def host_scan(self, techs=(), ports=(), names=('app.rt.test',), web=True, address=None):
        address = address or self.ADDRESS
        scan = self.scan(names=names, ports=((443, 'https'),) if web else (), ip=address)
        ip = IpAddress.objects.get(address=address)
        for number, service, product, version, *extra in ports:
            ip.ports.add(Port.objects.create(number=number, service_name=service, product=product, version=version, state='open',
                                             extra=extra[0] if extra else {}))
        for sub in scan.subdomain_set.all():
            if web:
                sub.http_url = f'https://{sub.name}'
                sub.save(update_fields=['http_url'])
            for name in techs:
                tech, _ = Technology.objects.get_or_create(name=name)
                sub.technologies.add(tech)
        return scan

    def sentinel(self, table=None, **kw):
        return FakeScanner(kinds=['version_read'], responders={'version_read': responder(self.vtasks, by_path(table or {}))}, **kw)


GRAFANA = {'status': 200, 'content_type': 'application/json', 'headers': {}, 'json': {'commit': '1e84fede5', 'database': 'ok', 'version': '10.2.3'}}
DOCKER = {'status': 200, 'content_type': 'application/json', 'headers': {},
          'json': {'Version': '24.0.7', 'ApiVersion': '1.43', 'GoVersion': 'go1.20.10', 'Os': 'linux', 'Arch': 'amd64'}}


class ReadTests(VersionFixture, TestCase):
    def test_a_grafana_host_is_asked_its_health_and_the_version_is_a_technology(self):
        scan = self.host_scan(techs=('Grafana',))
        with self.sentinel({'/api/health': GRAFANA}):
            result = version_sources.run_for_scan(scan.id)
        self.assertEqual(result['asked'], 1)
        entry, = self.vtasks[0]['target']['reads']
        self.assertEqual((entry['host'], entry['base'], [r['path'] for r in entry['requests']]), ('app.rt.test', 'https://app.rt.test', ['/api/health']))
        from jsonschema import Draft202012Validator
        from agentapi import sentinel_contract
        self.assertEqual(list(Draft202012Validator(sentinel_contract.target_schema('version_read')).iter_errors(self.vtasks[0]['target'])), [])
        row = ProbeObservation.objects.get(host='app.rt.test', probe='vsrc:grafana')
        self.assertEqual((row.kind, row.product, row.version, row.evidence['confidence']), ('version', 'Grafana', '10.2.3', 'exact'))
        self.assertIn('Grafana:10.2.3', set(scan.subdomain_set.get().technologies.values_list('name', flat=True)))
        payload = version_sources.readings_for([self.project.pk], {'app.rt.test'})[(self.project.pk, 'app.rt.test')]
        self.assertEqual((payload[0]['product'], payload[0]['version'], payload[0]['source']), ('Grafana', '10.2.3', 'grafana'))

    def test_a_host_that_is_not_identified_as_the_product_is_not_asked(self):
        scan = self.host_scan(techs=('nginx:1.24.0',))
        self.assertEqual(version_sources.candidates(scan), {})
        with self.sentinel() as fake:
            version_sources.run_for_scan(scan.id)
        self.assertEqual(fake.served_kinds(), [])

    def test_an_open_docker_api_is_a_critical_exposure_closed_by_a_later_complete_read(self):
        scan = self.host_scan(ports=((2375, '', '', ''),), web=False)
        with self.sentinel({'/version': DOCKER}):
            result = version_sources.run_for_scan(scan.id)
        self.assertEqual(result['exposed'], 1)
        vuln = Vulnerability.objects.get(source=version_sources.FINDING_SOURCE)
        self.assertEqual((vuln.severity, vuln.template_id, vuln.http_url), (4, 'docker-api-exposed', 'http://app.rt.test:2375/version'))
        go = ProbeObservation.objects.get(host='app.rt.test', kind='runtime', product='Go')
        self.assertEqual((go.version, go.port), ('1.20.10', 2375))
        with self.sentinel({'/version': {'status': 401, 'content_type': 'text/plain', 'headers': {}, 'json': None}}):
            version_sources.run_for_scan(scan.id, force=True)
        vuln.refresh_from_db()
        self.assertFalse(vuln.open_status)

    def test_an_unanswered_read_is_unknown_and_due_again_after_a_day(self):
        from cveFeed import ledger
        scan = self.host_scan(ports=((2375, '', '', ''),), web=False)
        with self.sentinel({'/version': {'status': 0, 'error': 'TimeoutError'}}):
            version_sources.run_for_scan(scan.id)
        self.assertTrue(ledger.fresh(version_sources.FAILED_SERVICE, ['app.rt.test'], self.project.pk))
        self.assertFalse(Vulnerability.objects.filter(source=version_sources.FINDING_SOURCE).exists())

    def test_a_metrics_page_feeds_the_java_family(self):
        lines = ['jvm_info{runtime="OpenJDK Runtime Environment",vendor="Eclipse Adoptium",version="17.0.9+9"}', 'go_info{version="go1.21.5"}']
        scan = self.host_scan(ports=((9100, 'http', '', ''),), web=False)
        with self.sentinel({'/metrics': {'status': 200, 'content_type': 'text/plain', 'headers': {}, 'lines': lines}}):
            version_sources.run_for_scan(scan.id)
        java = JavaRuntime.objects.get(host='app.rt.test', source='metrics')
        self.assertEqual((java.version, java.vendor, java.confidence, java.port), ('17.0.9', 'Eclipse Temurin', 'exact', 9100))
        self.assertTrue(Vulnerability.objects.filter(template_id='prometheus-metrics-exposed', severity=0).exists())

    def test_a_template_check_that_already_reports_the_exposure_is_not_doubled(self):
        scan = self.host_scan(ports=((2375, '', '', ''),), web=False)
        sub = scan.subdomain_set.get()
        Vulnerability.objects.create(target_domain=self.domain, scan_history=scan, subdomain=sub, source='nuclei', template_id='docker-api',
                                     name='Docker API exposed', severity=4, open_status=True)
        with self.sentinel({'/version': DOCKER}):
            result = version_sources.run_for_scan(scan.id)
        self.assertEqual(result['exposed'], 0)

    def test_an_excluded_host_and_one_outside_a_bounty_scope_are_never_sent(self):
        scan = self.host_scan(techs=('Grafana',))
        HostExclusion.objects.create(org=self.project.org, host='app.rt.test')
        with self.sentinel() as fake:
            version_sources.run_for_scan(scan.id)
        self.assertEqual(fake.served_kinds(), [])
        HostExclusion.objects.all().delete()
        with mock.patch('cveFeed.bounty_gate.Gate.refusal', return_value='not in the program\'s scope'), self.sentinel() as fake:
            version_sources.run_for_scan(scan.id)
        self.assertEqual(fake.served_kinds(), [])

    def test_the_planner_path_waits_for_the_engagements_confirmation(self):
        self.host_scan(techs=('Grafana',))
        with mock.patch('cveFeed.bounty_gate.Gate.project_blocked', return_value=True), self.sentinel() as fake:
            result = version_sources.run_for_hosts(self.project, ['app.rt.test'])
        self.assertEqual((fake.served_kinds(), result['hosts']), ([], 0))
        with self.sentinel({'/api/health': GRAFANA}):
            self.assertEqual(version_sources.run_for_hosts(self.project, ['app.rt.test'])['asked'], 1)

    def test_a_host_pointing_at_an_address_a_scanner_may_not_use_is_left_out(self):
        scan = self.host_scan(techs=('Grafana',))
        with mock.patch('targetApp.target_types.is_scannable_ip', return_value=False):
            self.assertEqual(version_sources.candidates(scan), {})

    def test_a_host_is_asked_weekly(self):
        scan = self.host_scan(techs=('Grafana',))
        with self.sentinel({'/api/health': GRAFANA}):
            version_sources.run_for_scan(scan.id)
            version_sources.run_for_scan(scan.id)
        self.assertEqual(len(self.vtasks), 1)

    def test_no_scanner_leaves_the_reads_due_and_runs_nothing_here(self):
        scan = self.host_scan(techs=('Grafana',))
        from reNgine.resources import ScannerUnavailable
        with self.assertRaises(ScannerUnavailable):
            version_sources.run_for_scan(scan.id)
        self.assertFalse(ProbeObservation.objects.filter(probe='vsrc:grafana').exists())


class PassiveTests(VersionFixture, TestCase):
    def test_stored_headers_give_runtimes_and_products_without_a_request(self):
        headers = 'Server: Werkzeug/2.3.7 Python/3.11.4\nX-Jenkins: 2.426.1\nContent-Type: text/html'
        scan = self.host_scan(ports=((8080, 'http', '', '', {'scripts': {'http-headers': headers}}),))
        sub = scan.subdomain_set.get()
        sub.webserver = 'gunicorn'
        sub.save(update_fields=['webserver'])
        version_sources.refresh_host(sub)
        rows = {(r.kind, r.product, r.port): (r.version, r.evidence['confidence']) for r in ProbeObservation.objects.filter(probe='vsrc:passive')}
        self.assertEqual(rows[('runtime', 'Python', 8080)], ('3.11.4', 'exact'))
        self.assertEqual(rows[('runtime', 'Python', 0)], ('', 'inferred'))
        self.assertEqual(rows[('version', 'Jenkins', 8080)], ('2.426.1', 'exact'))
        sub.webserver = ''
        sub.save(update_fields=['webserver'])
        version_sources.refresh_host(sub)
        self.assertFalse(ProbeObservation.objects.filter(probe='vsrc:passive', port=0).exists())  # gone with what it was read from

    def test_the_catch_up_stores_and_correlates(self):
        cve('CVE-2026-200001', PY_RANGE)
        self.host_scan(techs=('Python:3.11.4',))
        out = version_sources.catch_up(apply=True)
        self.assertEqual(out['hosts'], 1)
        self.assertGreaterEqual(out['readings'], 1)
        self.assertEqual(version_sources.catch_up(apply=False)['hosts'], 1)


def cve(cve_id, items, kev=False, cvss=9.8):
    return CVEEntry.objects.create(cve_id=cve_id, title=cve_id, affected=items, kev=kev, cvss=cvss, published_at=timezone.now())


GO_RANGE = [{'vendor': 'Go standard library', 'product': 'net/http', 'package': 'net/http',
             'ranges': [{'type': 'SEMVER', 'introduced': '1.20.0', 'fixed': '1.20.12'}]}]
PY_RANGE = [{'vendor': 'Python Software Foundation', 'product': 'CPython', 'ranges': [{'type': 'ECOSYSTEM', 'introduced': '3.11.0', 'fixed': '3.11.8'}]}]


class CorrelationTests(VersionFixture, TestCase):
    def correlate(self, scan, cve_row):
        cve_by_id, index = correlation.cve_pool()
        subs = correlation.candidate_subdomains(index).filter(scan_history=scan)
        correlation.correlate_subdomains(list(subs), index, cve_by_id, min_confidence=0.4)
        return list(CVEMatch.objects.filter(cve_entry=cve_row, source='runtime'))

    def runtime(self, sub, label, version, confidence='exact', line_only=False, port=0, source='prometheus-metrics'):
        component = {'Go': 'go', 'Python': 'python', '.NET Framework': 'dotnet-framework', 'Ruby': 'ruby'}[label]
        version_sources.store_readings(sub, f'vsrc:{source}', [catalogue.reading(component, label, version, kind='runtime', confidence=confidence,
                                                                                  line_only=line_only, source=source)], port=port)

    def test_an_exact_go_release_inside_the_range_is_a_version_match_and_outside_none(self):
        row = cve('CVE-2026-200010', GO_RANGE)
        scan = self.host_scan(web=False, ports=((9100, 'http', '', ''),))
        sub = scan.subdomain_set.get()
        self.runtime(sub, 'Go', '1.20.10', port=9100)
        match, = self.correlate(scan, row)
        self.assertEqual((match.version_in_range, match.matched_version, match.matched_product), (True, '1.20.10', 'Go'))
        self.assertTrue(match_policy.is_version_only(match))
        self.assertFalse(match_policy.version_proven(match))
        ProbeObservation.objects.filter(kind='runtime').update(version='1.20.12')
        self.assertEqual([m for m in self.correlate(scan, row) if m.ai_verdict != 'not_affected'], [])  # the stale match closes

    def test_a_runtime_present_with_no_version_is_a_version_unknown_candidate_with_a_plan(self):
        row = cve('CVE-2026-200001', PY_RANGE)
        scan = self.host_scan()
        sub = scan.subdomain_set.get()
        sub.webserver = 'gunicorn'
        sub.save(update_fields=['webserver'])
        version_sources.refresh_host(sub)
        match, = self.correlate(scan, row)
        self.assertIsNone(match.version_in_range)
        self.assertTrue(match.evidence['runtime_unknown'])
        self.assertTrue(match_policy.version_unknown(match))
        self.assertEqual(match.confidence, version_sources.UNKNOWN_CONFIDENCE)
        self.assertEqual(threat.match_heat(match), threat.ICE)
        self.assertEqual(threat.heat_reason(match), threat.REASON_RUNTIME_UNKNOWN)
        loaded = CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=match.pk)
        facts = triage.describe_cve_match(loaded)['facts']
        self.assertTrue(facts['version_unknown'] and facts['runtime_unknown'])
        self.assertEqual(triage.version_unknown_outcome(runtime_unknown=True)['reason'], match_policy.REASON_RUNTIME_UNKNOWN)
        explained = match_explain.explain(match)
        self.assertEqual(explained['basis'], 'runtime_unknown')
        self.assertIn('python3 -VV', [s['command'] for s in explained['steps']])
        plan = match_explain.validate_plan([loaded])
        self.assertEqual((plan[0]['key'], plan[0]['cves']), ('runtime:python', ['CVE-2026-200001']))
        from cveFeed import confirm_guide
        guide = confirm_guide.match_guide(loaded)
        self.assertEqual(guide['class'], 'language_runtime')

    def test_a_weak_presence_matches_nothing_and_an_inferred_line_is_never_in_range(self):
        row = cve('CVE-2026-200020', [{'vendor': 'microsoft', 'product': '.net_framework', 'ranges': [{'type': 'ECOSYSTEM', 'introduced': '4.8', 'fixed': '4.8.1'}]}])
        scan = self.host_scan()
        sub = scan.subdomain_set.get()
        self.runtime(sub, '.NET Framework', '', confidence='weak', source='passive')
        self.assertEqual(self.correlate(scan, row), [])
        self.runtime(sub, '.NET Framework', '4.8', confidence='inferred', line_only=True, source='aspnet-error')
        match, = self.correlate(scan, row)
        self.assertIsNone(match.version_in_range)
        self.assertTrue(match.evidence['runtime_unknown'])

    def test_a_cve_the_technology_already_matched_is_not_matched_twice(self):
        row = cve('CVE-2026-200001', [{'vendor': 'python', 'product': 'python', 'ranges': PY_RANGE[0]['ranges']}])
        scan = self.host_scan(techs=('Python:3.11.4',))
        version_sources.refresh_host(scan.subdomain_set.get())
        self.assertEqual(self.correlate(scan, row), [])
        self.assertTrue(CVEMatch.objects.filter(cve_entry=row, source='tech').exists())


class SearchTests(VersionFixture, TestCase):
    def test_component_runtime_and_source_filters(self):
        scan = self.host_scan(techs=('Grafana',))
        sub = scan.subdomain_set.get()
        version_sources.store_readings(sub, 'vsrc:grafana', [catalogue.reading('grafana', 'Grafana', '10.2.3', source='grafana')], port=443)
        version_sources.store_readings(sub, 'vsrc:prometheus-metrics', [catalogue.reading('go', 'Go', '1.21.5', kind='runtime', source='prometheus-metrics')])
        for field, value, hit in (('component', 'grafana', True), ('component', 'grafana@10.2', True), ('component', 'grafana@10.20', False),
                                  ('runtime', 'go', True), ('runtime', 'golang@1.21', True), ('runtime', 'python', False), ('runtime', 'any', True),
                                  ('vsource', 'grafana', True), ('vsource', 'jira', False)):
            with self.subTest(field=field, value=value):
                self.assertEqual(version_sources.search_rows(field, value).exists(), hit)
        for field, value in (('runtime', 'cobol'), ('vsource', 'nope'), ('component', 'x@1.a')):
            with self.subTest(field=field, value=value):
                self.assertIsNone(version_sources.search_rows(field, value))
