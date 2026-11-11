"""A nuclei task sends each port only the templates of the protocol that speaks there, with a bounded budget per service.

Production: one nuclei_deep task (no tag filter) sent the whole template set to ``name:22``, ``name:25``, ``name:143`` and the rest, and the scanned host's sshd
logged 34,000 "banner exchange: invalid format" lines in 20 minutes and throttled (and so refused) its own administrator's logins.

These tests need the Sentinel library from the Sentinel pull request that adds ``cvengine_scanner.flags.NUCLEI_SERVICES`` and the optional ``services`` and
``budget`` of the nuclei targets in the contract: web/requirements.txt must pin that commit or a later one on the Sentinel's main.
"""
import contextlib
import json
import tempfile
from unittest import mock

from django.test import SimpleTestCase
from jsonschema import Draft202012Validator

from cvengine_scanner import contract
from cvengine_scanner import flags as scan_flags

from agentapi import sentinel_dispatch as dispatch
from cveFeed import nuclei_scan, nuclei_services
from startScan.models import IpAddress, Port, Subdomain
from tests.test_sentinel_dispatch import DispatchBase

HOST = 'www.example.test'


class ClassifyTests(SimpleTestCase):
    """What speaks on a port, from the evidence the server holds (nmap's service name, the http probe, the port number)."""

    def test_a_port_that_speaks_http_is_web_whatever_its_number(self):
        for number, service, product, http, tunnel in ((443, 'https', '', None, ''), (8080, 'http-proxy', '', None, ''), (8443, 'http', '', None, 'ssl'),
                                                       (9000, 'ssl/http', '', None, ''), (22, 'http', '', None, ''), (7001, 'unknown', 'Oracle WebLogic httpd', None, ''),
                                                       (9000, '', '', {'status': 200}, ''), (3000, '', '', None, ''), (8888, 'tcpwrapped', '', None, '')):
            self.assertEqual(nuclei_services.classify(number, service, product, http, tunnel), 'web', (number, service))

    def test_a_service_nmap_named_is_its_protocol_and_a_tls_tunnel_makes_it_tls(self):
        for number, service, tunnel, klass in ((22, 'ssh', '', 'ssh'), (25, 'smtp', '', 'smtp'), (587, 'submission', '', 'smtp'), (143, 'imap', '', 'imap'),
                                               (110, 'pop3', '', 'pop3'), (3306, 'mysql', '', 'mysql'), (5432, 'postgresql', '', 'postgres'),
                                               (993, 'imaps', '', 'tls'), (993, 'ssl/imap', '', 'tls'), (993, 'imap', 'ssl', 'tls'), (2222, 'ssh', '', 'ssh')):
            self.assertEqual(nuclei_services.classify(number, service, '', None, tunnel), klass, (number, service, tunnel))

    def test_a_port_nothing_named_is_read_by_its_number_and_an_odd_one_is_unknown(self):
        self.assertEqual(nuclei_services.classify(22), 'ssh')
        self.assertEqual(nuclei_services.classify(25, 'unknown'), 'smtp')
        self.assertEqual(nuclei_services.classify(8081), 'web')
        self.assertEqual(nuclei_services.classify(9999), 'unknown')
        self.assertEqual(nuclei_services.classify(9999, 'some-odd-daemon'), 'unknown')  # a named service this server has no protocol class for: nothing is sent

    def test_the_name_nmap_gave_wins_over_the_port_number(self):
        self.assertEqual(nuclei_services.classify(8080, 'ssh'), 'ssh')
        self.assertEqual(nuclei_services.classify(22, 'smtp'), 'smtp')

    def test_every_class_it_returns_is_one_a_sentinel_knows(self):
        known = set(scan_flags.NUCLEI_SERVICES) | {'web', 'unknown'}
        for number in range(1, 65536):
            self.assertIn(nuclei_services.classify(number), known)
        for klass in scan_flags.NUCLEI_SERVICE_NAMES.values():
            self.assertIn(klass, scan_flags.NUCLEI_SERVICES)


class DeepTaskTests(DispatchBase):
    """A deep task for a host with ports 22, 25, 143 and 443 (and the web ports a real host has besides)."""

    PORTS = ((22, 'ssh', 'OpenSSH'), (25, 'smtp', 'Postfix smtpd'), (143, 'imap', 'Dovecot imapd'), (443, 'https', 'nginx'), (587, 'submission', 'Postfix smtpd'),
             (993, 'imaps', 'Dovecot imapd'), (8080, 'http-proxy', 'Apache httpd'), (8443, 'ssl/http', 'nginx'), (9999, 'unknown', ''))

    def setUp(self):
        super().setUp()
        self.ip = IpAddress.objects.get(address='192.0.2.10')
        for number, service, product in self.PORTS:
            self.ip.ports.add(Port.objects.create(number=number, service_name=service, product=product, state='open', protocol='tcp'))
        self.sub = Subdomain.objects.get(scan_history=self.scan)
        self.sub.name = HOST
        self.sub.save()

    def targets(self):
        """The targets of the weekly deep pass (cveFeed.tasks.weekly_deep_nuclei) and of the per-scan passes (nuclei_scan.build_targets): both lists."""
        built = nuclei_scan.build_targets(*nuclei_scan.scan_targets(self.scan))
        weekly = [HOST] + [f'{HOST}:{port}' for host, port in sorted(nuclei_scan.scan_targets(self.scan)[2]) if host == HOST and port not in scan_flags.NUCLEI_DEFAULT_PORTS]
        return built, weekly

    def dispatched(self, kind, targets, **kwargs):
        """The task targets the stream really sends for ``targets``: ``wrap_nuclei_stream`` with the dispatcher captured."""
        sent = []

        def capture(project, kind_, chunks, prepare=None, **kw):
            for chunk in chunks:
                task = prepare(chunk)
                sent.append(task[0])
            return (x for x in ())
        with tempfile.NamedTemporaryFile('w', suffix='.txt') as handle, mock.patch('agentapi.sentinel_dispatch.any_scanner_for', return_value=True), \
                mock.patch('agentapi.sentinel_dispatch.resolvable_targets', side_effect=lambda chunk: list(chunk)), \
                mock.patch('agentapi.sentinel_dispatch.dispatch_many', side_effect=capture), \
                mock.patch('cveFeed.validation.all_templates_allowed', return_value=False):
            handle.write('\n'.join(targets) + '\n')
            handle.flush()
            with contextlib.closing(dispatch.wrap_nuclei_stream(self.scan, kind)(handle.name, **kwargs)) as lines:
                list(lines)
        return sent

    def test_the_task_says_what_speaks_on_every_port_and_no_target_is_dropped(self):
        built, weekly = self.targets()
        for targets in (built, weekly):
            self.assertEqual({HOST, f'{HOST}:22', f'{HOST}:25', f'{HOST}:143', f'{HOST}:587', f'{HOST}:993', f'{HOST}:8080', f'{HOST}:8443', f'{HOST}:9999'} - set(targets), set())
            (task,) = self.dispatched('nuclei_deep', targets)
            self.assertEqual(task['targets'], targets)  # the server drops nothing: every target of today's list is still sent
            self.assertEqual(task['services'], {f'{HOST}:22': 'ssh', f'{HOST}:25': 'smtp', f'{HOST}:143': 'imap', f'{HOST}:587': 'smtp', f'{HOST}:993': 'tls',
                                                f'{HOST}:8080': 'web', f'{HOST}:8443': 'web', f'{HOST}:9999': 'unknown'})

    def test_http_templates_reach_the_web_ports_only(self):
        (task,) = self.dispatched('nuclei_deep', self.targets()[1])
        classes = {target: task['services'].get(target, 'web') for target in task['targets']}
        self.assertEqual({t for t, klass in classes.items() if klass == 'web'}, {HOST, f'{HOST}:8080', f'{HOST}:8443'})  # the ports that speak http, and the bare host
        for target, klass in classes.items():
            if klass not in ('web', 'unknown'):  # what the Sentinel runs on it: its own protocol's template types, never http
                types = scan_flags.NUCLEI_SERVICES[klass][1]
                self.assertNotIn('http', types, target)
                self.assertTrue(set(types) <= {'tcp', 'javascript', 'ssl'}, (target, types))

    def test_the_ssh_port_gets_only_ssh_templates_and_a_web_port_keeps_every_template(self):
        (task,) = self.dispatched('nuclei_deep', self.targets()[1])
        self.assertEqual(scan_flags.NUCLEI_SERVICES[task['services'][f'{HOST}:22']], (('ssh', 'openssh'), ('tcp', 'javascript')))
        self.assertEqual(scan_flags.nuclei_service_tags('ssh', task['tags']), ['openssh', 'ssh'])  # a deep pass names no tags
        self.assertEqual(task['tags'], [])
        self.assertEqual(task['services'][f'{HOST}:8080'], 'web')

    def test_the_per_service_budget_is_in_the_task(self):
        for kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            (task,) = self.dispatched(kind, [HOST, f'{HOST}:22'])
            self.assertEqual(task['budget'], {'rate': 2, 'concurrency': 2, 'seconds': 120}, kind)
            self.assertEqual(task['budget'], scan_flags.NUCLEI_SERVICE_BUDGET)
            self.assertLess(task['budget']['concurrency'], 10)  # sshd's default MaxStartups is 10:30:100

    def test_the_task_validates_against_the_contract(self):
        check = Draft202012Validator(contract.target_schema('nuclei_deep'))
        for kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            (task,) = self.dispatched(kind, self.targets()[1])
            self.assertEqual(list(Draft202012Validator(contract.target_schema(kind)).iter_errors(task)), [], kind)
            json.dumps(task)
        self.assertTrue(check.is_valid(self.dispatched('nuclei_deep', [HOST])[0]))  # a task of bare hosts has no services at all

    def test_a_bare_host_and_an_address_have_no_label_and_stay_web(self):
        (task,) = self.dispatched('nuclei_deep', [HOST, '192.0.2.10'])
        self.assertNotIn('services', task)

    def test_a_port_that_two_of_a_hosts_addresses_describe_differently_gets_nothing(self):
        other = IpAddress.objects.create(address='192.0.2.11')
        other.ports.add(Port.objects.create(number=22, service_name='http', state='open', protocol='tcp'))
        self.sub.ip_addresses.add(other)
        self.assertEqual(nuclei_services.labels_for(self.scan, [f'{HOST}:22'])[f'{HOST}:22'], 'unknown')

    def test_a_closed_or_filtered_port_is_not_read_as_evidence(self):
        self.ip.ports.add(Port.objects.create(number=8000, service_name='ssh', state='closed', protocol='tcp'))
        self.assertEqual(nuclei_services.labels_for(self.scan, [f'{HOST}:8000'])[f'{HOST}:8000'], 'web')  # no open port row: read by number, 8000 is a web port


class SelectionKeepsEveryWebFindingClassTests(DispatchBase):
    """Proof that no web coverage is lost: whatever the targets of a pass are today, the web ones are labelled web (or unlabelled) and all of them are still sent."""

    def test_every_port_that_has_web_evidence_is_labelled_web(self):
        for number, service, product, http, extra in ((8080, 'http', '', {}, {}), (8443, 'https-alt', '', {}, {}), (3000, '', 'Node.js Express framework', {}, {}),
                                                      (9000, 'unknown', '', {'status': 200, 'title': 'x'}, {}), (10443, 'http', '', {}, {'tunnel': 'ssl'}),
                                                      (8888, '', '', {}, {}), (8000, 'tcpwrapped', '', {}, {})):
            ip = IpAddress.objects.get(address='192.0.2.10')
            ip.ports.add(Port.objects.create(number=number, service_name=service, product=product, http=http, extra=extra, state='open', protocol='tcp'))
        sub = Subdomain.objects.get(scan_history=self.scan)
        sub.name = HOST
        sub.save()
        targets = nuclei_scan.build_targets(*nuclei_scan.scan_targets(self.scan))
        labels = nuclei_services.labels_for(self.scan, targets)
        self.assertEqual({t for t in targets if ':' in t}, {f'{HOST}:{n}' for n in (8080, 8443, 3000, 9000, 10443, 8888, 8000)})
        self.assertEqual(set(labels.values()), {'web'})
