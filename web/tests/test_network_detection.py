"""The network detection pass (cveFeed.network_detection): nuclei's network/detection templates on a host's non-web ports, through a Sentinel that runs
the pass (contract 10), and what their results put on the port rows.

The realistic nuclei result lines are the Sentinel library's own fixture (``cvengine_scanner/fixtures/nuclei/network_detection.jsonl``: openssh, dropbear,
redis, rdp-detection, rdp-detect, mssql-detect, vnc, mongodb, rabbitmq, activemq, proftpd, exim, rsyncd, jdwp), so both sides read the same lines. These tests
need the Sentinel library of the pull request that adds the pass (``flags.NUCLEI_DETECTION_SINCE``): web/requirements.txt pins it.
"""
import contextlib
import json
import tempfile
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase
from django.utils import timezone
from jsonschema import Draft202012Validator

from cvengine_scanner import contract
from cvengine_scanner import flags as scan_flags

from agentapi import sentinel_broker, sentinel_contract
from agentapi import sentinel_dispatch as dispatch
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from agentapi.services import Ctx
from cveFeed import correlation, ledger, network_detection, source_versions
from cveFeed.models import CVEEntry, CVEMatch, ProbeObservation
from reNgine.resources import ScannerUnavailable
from startScan.models import IpAddress, Port, Subdomain
from tests.test_sentinel_dispatch import DispatchBase

FIXTURE_HOST = 'svc.example.com'  # the host of the library's fixture lines
HOST = 'www.example.test'  # the host of the scan (a .test name: the tests resolve nothing)


def fixture_lines():
    path = contract.FIXTURES / 'nuclei' / 'network_detection.jsonl'
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def line_of(template_id):
    return next(row for row in fixture_lines() if row['template-id'] == template_id)


def as_sent(row, host=FIXTURE_HOST):
    """A fixture line as the server reads it after a Sentinel parsed and reported it (``parse_nuclei_jsonl``, then ``_finding_to_nuclei_line``), about ``host``."""
    from cvengine_scanner import parsers
    row = json.loads(json.dumps(row).replace(FIXTURE_HOST, host))
    (finding,) = parsers.parse_nuclei_jsonl(json.dumps(row))
    return dispatch._finding_to_nuclei_line(finding)


class ReadingTests(SimpleTestCase):
    """What one result line says: the product, and a version only when the value is the product's own and shaped like a version."""

    def test_the_real_lines_read_as_their_product_and_version(self):
        got = {row['template-id']: network_detection.reading(as_sent(row)) for row in fixture_lines()}
        self.assertEqual(got, {
            'openssh-detect': ('OpenSSH', '8.9p1'),  # SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6: never the protocol's 2.0
            'sshd-dropbear-detect': ('Dropbear sshd', '2020.81'),
            'redis-detect': ('Redis', ''),
            'rdp-detection': ('Microsoft Terminal Services', ''),  # the matcher (win2016) is an OS hint, not a version
            'rdp-detect': ('Microsoft Terminal Services', ''),
            'mssql-detect': ('Microsoft SQL Server', ''),
            'vnc-service-detect': ('VNC', ''),  # RFB 003.008 is the protocol's version
            'mongodb-detect': ('MongoDB', ''),
            'rabbitmq-detect': ('RabbitMQ', ''),  # the response names 3.12.13, but no template extracted it: nothing is guessed from a response
            'apache-activemq-detect': ('Apache ActiveMQ', ''),
            'proftpd-server-detect': ('ProFTPD', '1.3.5e'),
            'exim-detect': ('Exim', '4.96'),
            'rsyncd-service-detect': ('Rsyncd', ''),  # RSYNCD: 31.0 is the protocol's
            'jdwp-detect': ('Java Debug Wire Protocol', ''),  # the JVM's version is a Java runtime reading, not this product's
        })

    def test_the_technology_name_is_the_stored_form(self):
        self.assertEqual(network_detection.technology_name(as_sent(line_of('openssh-detect'))), 'OpenSSH:8.9p1')
        self.assertEqual(network_detection.technology_name(as_sent(line_of('redis-detect'))), 'Redis')
        self.assertEqual(correlation.split_name_version(network_detection.technology_name(as_sent(line_of('exim-detect')))), ('Exim', '4.96'))

    def test_a_value_is_a_version_only_when_it_looks_like_one(self):
        for value, ok in (('8.9p1', True), ('1.3.5e', True), ('2020.81', True), ('12.2.1.3.0', True), ('4.0.0-beta1', True), ('3.0.3', True),
                          ('003.008', False), ('2', False), ('20200704', False), ('V2R1', False), ('abc', False), ('', False), ('1.' + '2' * 40, False),
                          ('1.2 <script>', False)):
            with self.subTest(value=value):
                self.assertEqual(bool(network_detection._VERSION.match(value)), ok)

    def test_a_title_or_an_odd_value_never_makes_up_a_version(self):
        line = {'template-id': 'some-new-detect', 'info': {'name': 'Acme Widget Server - Detect'}, 'matched-at': f'{HOST}:7777',
                'extracted-results': ['SSH-2.0-Acme', 'protocol 2.0', 'build 20200704', 'Acme Widget Server 5.1.2']}
        self.assertEqual(network_detection.reading(line), ('Acme Widget Server', '5.1.2'))  # only the value after the product's own name
        self.assertEqual(network_detection.reading({**line, 'extracted-results': ['SSH-2.0-Acme', 'HTTP/1.1']}), ('Acme Widget Server', ''))
        self.assertEqual(network_detection.reading({**line, 'extracted-results': ['9.9.9'], 'template-id': 'vnc-service-detect'})[1], '')  # NO_VERSION
        several = {**as_sent(line_of('openssh-detect')), 'extracted-results': ['SSH-2.0-OpenSSH_8.4p1', 'SSH-2.0-OpenSSH_9.6p1']}
        self.assertEqual(network_detection.reading(several), ('OpenSSH', '9.6p1'))  # the highest, every run

    def test_the_port_a_line_matched(self):
        self.assertEqual(network_detection.target_of(as_sent(line_of('redis-detect'))), f'{FIXTURE_HOST}:6379')
        self.assertEqual(network_detection.target_of({'matched-at': 'tls://SVC.Example.com.:6380'}), f'{FIXTURE_HOST}:6380')
        self.assertIsNone(network_detection.target_of({'matched-at': 'https://svc.example.com/', 'host': 'svc.example.com'}))
        self.assertIsNone(network_detection.target_of({'matched-at': f'{FIXTURE_HOST}:0'}))


class Base(DispatchBase):
    """One host (``www.example.test`` on 192.0.2.10) with the ports a real host has."""

    PORTS = ((22, 'ssh', 'OpenSSH', '8.4p1'), (2222, 'ssh', 'Acme sshd', '1.2'), (6379, 'redis', '', ''), (3389, 'ms-wbt-server', '', ''),
             (5900, 'vnc', '', ''), (21, 'ftp', 'ProFTPD', ''), (25, 'smtp', '', ''), (61613, 'unknown', '', ''), (443, 'https', 'nginx', '1.24.0'),
             (8080, 'http-proxy', 'Apache httpd', ''), (993, 'imaps', 'Dovecot imapd', ''), (445, 'microsoft-ds', '', ''), (1433, 'ms-sql-s', '', ''),
             (5432, 'postgresql', 'PostgreSQL DB', ''))

    def setUp(self):
        super().setUp()
        self.ip = IpAddress.objects.get(address='192.0.2.10')
        self.ports = {}
        for number, service, product, version in self.PORTS:
            port = Port.objects.create(number=number, service_name=service, product=product, version=version, state='open', protocol='tcp')
            self.ip.ports.add(port)
            self.ports[number] = port
        self.sub = Subdomain.objects.get(scan_history=self.scan)
        self.sub.name, self.sub.target_domain = HOST, self.domain
        self.sub.save()

    def port(self, number):
        return Port.objects.get(pk=self.ports[number].pk)

    def dispatched(self, targets, capable=True, **kwargs):
        """The task targets the light stream really sends for ``targets`` with ``network_detection``: the dispatcher captured."""
        sent = []

        def capture(project, kind_, chunks, prepare=None, **kw):
            for chunk in chunks:
                sent.append(prepare(chunk)[0])
            return (x for x in ())
        with tempfile.NamedTemporaryFile('w', suffix='.txt') as handle, mock.patch('agentapi.sentinel_dispatch.any_scanner_for', return_value=True), \
                mock.patch('agentapi.sentinel_broker.network_detection_scanner', return_value=capable), \
                mock.patch('agentapi.sentinel_dispatch.resolvable_targets', side_effect=lambda chunk, **kw: list(chunk)), \
                mock.patch('agentapi.sentinel_dispatch.dispatch_many', side_effect=capture), \
                mock.patch('cveFeed.validation.all_templates_allowed', return_value=False):
            handle.write('\n'.join(targets) + '\n')
            handle.flush()
            with contextlib.closing(dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light')(handle.name, network_detection=True, **kwargs)) as lines:
                list(lines)
        return sent


class TargetTests(Base):
    """What is sent: only the open non-web ports of a class the pass has a template for, in tasks a light task's time covers."""

    def test_only_the_non_web_ports_of_a_detectable_class_are_targets(self):
        targets, labels = network_detection.candidate_targets(self.scan)
        self.assertEqual(sorted(targets), sorted(f'{HOST}:{n}' for n in (21, 22, 25, 2222, 3389, 5900, 6379, 61613)))
        for left_out in (443, 8080, 993, 445, 1433, 5432):  # web, tls, smb, mssql, postgres: no network/detection template speaks to them
            self.assertNotIn(f'{HOST}:{left_out}', targets)
        self.assertNotIn(HOST, targets)  # never a bare host: that is a web target
        self.assertEqual(labels[f'{HOST}:61613'], 'unknown')

    def test_a_closed_or_udp_port_or_an_excluded_host_is_not_a_target(self):
        Port.objects.filter(pk=self.ports[6379].pk).update(state='closed')
        Port.objects.filter(pk=self.ports[3389].pk).update(protocol='udp')
        targets, _labels = network_detection.candidate_targets(self.scan)
        self.assertNotIn(f'{HOST}:6379', targets)
        self.assertNotIn(f'{HOST}:3389', targets)
        with mock.patch('cveFeed.exclusions.excluded_names', return_value={HOST}):
            self.assertEqual(network_detection.candidate_targets(self.scan)[0], [])

    def test_the_task_is_the_detection_pass_with_its_budget_and_at_most_three_ports(self):
        targets, labels = network_detection.candidate_targets(self.scan)
        sent = self.dispatched(targets)
        self.assertEqual(sorted(t for task in sent for t in task['targets']), sorted(targets))  # none dropped
        schema = Draft202012Validator(sentinel_contract.target_schema('nuclei_light'))
        for task in sent:
            self.assertLessEqual(len(task['targets']), scan_flags.NUCLEI_DETECTION_MAX_PORTS)
            self.assertIs(task['network_detection'], True)
            self.assertEqual(task['tags'], [])  # never the tech filter, never a tag: the Sentinel runs the class's network/detection templates
            self.assertEqual(task['severities'], ['info'])
            self.assertIn('dos', task['etags'])
            self.assertEqual(task['budget'], scan_flags.NUCLEI_DETECTION_BUDGET)
            self.assertEqual(task['services'], {t: labels[t] for t in task['targets']})
            self.assertNotIn('web', task['services'].values())
            self.assertEqual(list(schema.iter_errors(task)), [])

    def test_the_light_pass_is_unchanged(self):
        captured = []

        def capture(project, kind_, chunks, prepare=None, **kw):
            captured.extend(prepare(chunk)[0] for chunk in chunks)
            return (x for x in ())
        with tempfile.NamedTemporaryFile('w', suffix='.txt') as handle, mock.patch('agentapi.sentinel_dispatch.any_scanner_for', return_value=True), \
                mock.patch('agentapi.sentinel_dispatch.resolvable_targets', side_effect=lambda chunk, **kw: list(chunk)), \
                mock.patch('agentapi.sentinel_dispatch.dispatch_many', side_effect=capture), \
                mock.patch('cveFeed.validation.all_templates_allowed', return_value=False):
            handle.write(f'{HOST}\n{HOST}:22\n')
            handle.flush()
            list(dispatch.wrap_nuclei_stream(self.scan, 'nuclei_light')(handle.name))
        (task,) = captured
        self.assertEqual((task['tags'], task['severities'], task['budget']), (['tech'], ['info'], scan_flags.NUCLEI_SERVICE_BUDGET))
        self.assertNotIn('network_detection', task)

    def test_no_sentinel_that_runs_the_pass_means_the_stage_waits_and_nothing_is_queued(self):
        with self.assertRaises(ScannerUnavailable) as raised:
            self.dispatched([f'{HOST}:6379'], capable=False)
        self.assertIn('contract 10', str(raised.exception))
        self.assertFalse(SentinelTask.objects.exists())


class BrokerTests(Base):
    """The broker hands a detection task only to a Sentinel that declared contract 10 or later: an older one would ignore the field and check nothing."""

    def sentinel(self, name, contract_version):
        user = User.objects.create_superuser(f'owner-{name}', f'{name}@example.test', 'x')
        token, _raw = create_token(user, f'token-{name}')
        return Agent.objects.create(token=token, name=name, kind='scanner', status='active', scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                    capabilities=['nuclei_light'], last_seen=timezone.now(),
                                    info={'features': ['credential_filter'], 'contract_version': contract_version})

    def claim(self, agent):
        return sentinel_broker.next_task(Ctx(user=agent.token.user, token=agent.token), {'kinds': ['nuclei_light'], 'wait': 0})['task']

    def queue(self, **target):
        return SentinelTask.objects.create(project=self.project, kind='nuclei_light', scan=self.scan,
                                           target={'targets': [f'{HOST}:6379'], 'tags': [], 'severities': ['info'], 'etags': ['dos'],
                                                   'template_policy': {'rev': 'r', 'read_only': True, 'bundle_sha256': None}, **target})

    def test_an_older_sentinel_is_never_handed_the_pass_and_a_current_one_is(self):
        old, new = self.sentinel('old', 9), self.sentinel('new', 10)
        task = self.queue(network_detection=True)
        self.assertIsNone(self.claim(old))
        self.assertEqual(sentinel_broker.effective(old).refusal(task), ('capability', sentinel_broker.NETWORK_DETECTION))
        self.assertIsNone(sentinel_broker.effective(new).refusal(task))
        self.assertEqual(self.claim(new)['id'], task.pk)

    def test_an_older_sentinel_still_takes_the_ordinary_light_pass(self):
        old = self.sentinel('old', 9)
        task = self.queue()
        self.assertEqual(self.claim(old)['id'], task.pk)

    def test_a_sentinel_that_never_said_its_contract_is_older(self):
        self.assertFalse(sentinel_broker.runs_network_detection(self.sentinel('silent', None)))
        self.assertFalse(sentinel_broker.runs_network_detection(self.sentinel('bool', True)))
        self.assertTrue(sentinel_broker.runs_network_detection(self.sentinel('newer', scan_flags.NUCLEI_DETECTION_SINCE + 3)))

    def test_the_stage_asks_for_a_live_sentinel_that_runs_it(self):
        self.assertFalse(sentinel_broker.network_detection_scanner(self.project))
        self.sentinel('old', 9)
        self.assertFalse(sentinel_broker.network_detection_scanner(self.project))
        self.sentinel('new', 10)
        self.assertTrue(sentinel_broker.network_detection_scanner(self.project))


class IngestTests(Base):
    """What a result puts on the port rows: what nmap left out is filled, nmap's product and version are never overwritten."""

    def ingest(self, *template_ids, port=None, targets=None):
        lines = []
        for tid in template_ids:
            line = as_sent(line_of(tid), HOST)
            if port is not None:
                line = {**line, 'matched-at': f'{HOST}:{port}'}
            lines.append(line)
        targets = targets if targets is not None else network_detection.candidate_targets(self.scan)[0]
        return network_detection.ingest(self.scan, lines, targets)

    def test_a_port_nmap_named_nothing_on_gets_the_product(self):
        got = self.ingest('redis-detect', 'mongodb-detect', 'apache-activemq-detect')
        self.assertEqual((self.port(6379).product, self.port(6379).version), ('Redis', ''))
        self.assertEqual(self.port(6379).extra['nuclei_detect'], {'template': 'redis-detect', 'product': 'Redis', 'version': '', 'filled': 'product'})
        self.assertEqual(self.port(61613).product, 'Apache ActiveMQ')
        self.assertEqual(got['ports'], 2)  # mongodb's 27017 is not a port of this host: nothing is written for it

    def test_a_version_fills_the_same_product_nmap_left_unversioned(self):
        self.ingest('proftpd-server-detect')
        self.assertEqual((self.port(21).product, self.port(21).version), ('ProFTPD', '1.3.5e'))
        self.assertEqual(self.port(21).extra['nuclei_detect']['filled'], 'version')

    def test_nmap_product_and_version_are_never_overwritten(self):
        got = self.ingest('openssh-detect')  # 8.9p1 on a port nmap read as OpenSSH 8.4p1
        self.assertEqual((self.port(22).product, self.port(22).version), ('OpenSSH', '8.4p1'))
        self.assertNotIn('nuclei_detect', self.port(22).extra)
        self.assertEqual(got['ports'], 0)
        self.assertFalse(ProbeObservation.objects.filter(probe=source_versions.NUCLEI_PROBE).exists())  # the same product: no second reading either

    def test_another_versioned_product_on_a_port_nmap_named_is_a_reading_not_an_overwrite(self):
        got = self.ingest('sshd-dropbear-detect', port=2222)
        self.assertEqual((self.port(2222).product, self.port(2222).version), ('Acme sshd', '1.2'))
        row = ProbeObservation.objects.get(probe=source_versions.NUCLEI_PROBE, port=2222)
        self.assertEqual((row.product, row.version, row.host), ('Dropbear sshd', '2020.81', HOST))
        self.assertIn('Dropbear sshd:2020.81', {t.name for t in Subdomain.objects.get(pk=self.sub.pk).technologies.all()})
        self.assertEqual(got['readings'], 1)

    def test_an_unversioned_product_on_a_port_nmap_named_changes_nothing(self):
        self.ingest('vnc-service-detect', port=22)
        self.assertEqual(self.port(22).product, 'OpenSSH')
        self.assertFalse(ProbeObservation.objects.filter(probe=source_versions.NUCLEI_PROBE).exists())

    def test_a_line_about_a_port_the_task_did_not_name_is_not_read(self):
        got = self.ingest('redis-detect', targets=[f'{HOST}:22'])
        self.assertEqual(self.port(6379).product, '')
        self.assertEqual(got['ports'], 0)
        got = self.ingest('redis-detect', port=6380)  # a template that went to its own port: not a port this pass was asked about
        self.assertEqual(got, {'ports': 0, 'readings': 0, 'hosts': {}, 'changed': []})

    def test_a_filled_port_is_matched_by_correlation(self):
        CVEEntry.objects.create(cve_id='CVE-2099-0001', title='x', cvss=9.8, published_at=timezone.now(),
                                affected=[{'vendor': 'proftpd', 'product': 'proftpd', 'ranges': [{'type': 'ECOSYSTEM', 'introduced': '1.3.5', 'fixed': '1.3.6'}]}])
        sub = Subdomain.objects.get(pk=self.sub.pk)
        cve_by_id, index = correlation.cve_pool()
        correlation.correlate_subdomain(sub, index, cve_by_id)
        before = CVEMatch.objects.filter(subdomain=sub, cve_entry__cve_id='CVE-2099-0001').first()
        self.assertTrue(before is None or not before.version_in_range)  # nmap said ProFTPD, no version: never a version in range
        self.ingest('proftpd-server-detect')
        sub = Subdomain.objects.get(pk=self.sub.pk)
        cve_by_id, index = correlation.cve_pool()
        correlation.correlate_subdomain(sub, index, cve_by_id)
        match = CVEMatch.objects.get(subdomain=sub, cve_entry__cve_id='CVE-2099-0001')
        self.assertEqual(match.matched_version, '1.3.5e')


class StageTests(Base):
    """The pipeline stage: what is due is sent, what comes back is stored, the ledger is written, and a bug bounty project's rules hold."""

    def stream(self, lines=()):
        calls = []

        def fake(path, **kwargs):
            with open(path, encoding='utf-8') as handle:
                calls.append(([t.strip() for t in handle if t.strip()], kwargs))
            fake.unreached, fake.not_checked, fake.refused = set(), [], set()
            yield from [as_sent(line_of(t), HOST) for t in lines]
        fake.calls = calls
        return fake

    def test_the_stage_sends_the_due_ports_stores_and_records_them(self):
        stream = self.stream(['redis-detect', 'proftpd-server-detect'])
        out = network_detection.run_for_scan(self.scan.id, stream)
        (targets, kwargs), = stream.calls
        self.assertEqual(kwargs, {'network_detection': True})
        self.assertEqual(sorted(targets), sorted(network_detection.candidate_targets(self.scan)[0]))
        self.assertEqual((out['ports'], self.port(6379).product, self.port(21).version), (2, 'Redis', '1.3.5e'))
        self.assertEqual(set(ledger.fresh(network_detection.SERVICE, targets, self.project.pk)), set(targets))
        again = self.stream()
        network_detection.run_for_scan(self.scan.id, again)
        self.assertEqual(again.calls, [])  # covered for a week
        network_detection.run_for_scan(self.scan.id, again, force=True)
        self.assertEqual(len(again.calls), 1)

    def test_an_unattended_scan_of_an_unconfirmed_bounty_project_sends_nothing(self):
        stream = self.stream(['redis-detect'])
        with mock.patch('cveFeed.bounty_gate.Gate.project_blocked', return_value=True):
            out = network_detection.run_for_scan(self.scan.id, stream)
        self.assertEqual(stream.calls, [])
        self.assertEqual(out['skipped'], network_detection.BOUNTY_REASON)
        self.assertEqual(self.port(6379).product, '')
        self.scan.initiated_by = User.objects.create_user('a-person', password='x')
        self.scan.save()
        with mock.patch('cveFeed.bounty_gate.Gate.project_blocked', return_value=True):
            network_detection.run_for_scan(self.scan.id, stream)
        self.assertEqual(len(stream.calls), 1)  # a scan a person started is their decision; the host scope still applies (scan_targets)

    def test_a_host_outside_the_bounty_scope_is_never_a_target(self):
        with mock.patch('cveFeed.bounty_gate.Gate.allows', return_value=False):
            self.assertEqual(network_detection.candidate_targets(self.scan)[0], [])

    def test_a_scanner_that_goes_away_keeps_what_came_back_and_records_nothing(self):
        def stream(path, **kwargs):
            yield as_sent(line_of('redis-detect'), HOST)
            raise ScannerUnavailable('nuclei_light', 'gone')
        out = network_detection.run_for_scan(self.scan.id, stream)
        self.assertIn('gone', out['skipped'])
        self.assertEqual(self.port(6379).product, 'Redis')
        self.assertFalse(ledger.fresh(network_detection.SERVICE, [f'{HOST}:6379'], self.project.pk))

    def test_the_adopted_result_of_a_detection_task_fills_the_ports(self):
        from agentapi import sentinel_adopt
        from cvengine_scanner import parsers
        task = SentinelTask.objects.create(project=self.project, kind='nuclei_light', scan=self.scan,
                                           target={'targets': [f'{HOST}:6379'], 'network_detection': True})
        findings = parsers.parse_nuclei_jsonl(json.dumps(line_of('redis-detect')).replace(FIXTURE_HOST, HOST))
        out = sentinel_adopt._nuclei(task, {'findings': findings}, None)
        self.assertEqual(out['ports'], 1)
        self.assertEqual(self.port(6379).product, 'Redis')
