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
                                                       (9000, '', '', {'status': 200}, ''), (3000, '', '', None, ''), (8888, '', '', None, '')):
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
        self.assertEqual(nuclei_services.classify(9999, 'some-odd-daemon'), 'unknown')  # a named service this server has no protocol class for: the generic network templates

    def test_tcpwrapped_is_never_web(self):
        """nmap's name for a port that accepted the connection and closed it: nothing was seen to speak http, so no http template is sent to it."""
        for number in (80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 9443, 3000):
            self.assertEqual(nuclei_services.classify(number, 'tcpwrapped'), 'unknown', number)
        self.assertEqual(nuclei_services.classify(22, 'tcpwrapped'), 'ssh')  # a service port is still read by its number
        self.assertEqual(nuclei_services.classify(8080, 'tcpwrapped', 'Apache httpd'), 'unknown')
        self.assertEqual(nuclei_services.classify(8080, 'tcpwrapped', '', {'status': 200}), 'web')  # a stored http answer is evidence
        self.assertEqual(nuclei_services.classify(8080, 'unknown'), 'web')  # no name at all on a well-known web port: still the heuristic

    def test_the_name_nmap_gave_wins_over_the_port_number(self):
        self.assertEqual(nuclei_services.classify(8080, 'ssh'), 'ssh')
        self.assertEqual(nuclei_services.classify(22, 'smtp'), 'smtp')

    def test_every_class_it_returns_is_one_a_sentinel_knows(self):
        known = set(scan_flags.NUCLEI_SERVICES) | {'web', 'unknown'}
        for number in range(1, 65536):
            self.assertIn(nuclei_services.classify(number), known)
        for klass in scan_flags.NUCLEI_SERVICE_NAMES.values():
            self.assertIn(klass, scan_flags.NUCLEI_SERVICES)


class DeepBase(DispatchBase):
    """A scan of one host with the ports a real host has (22, 25, 143, 443 and web ports besides), and the dispatch of a task over it."""

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



class DeepTaskTests(DeepBase):
    """A deep task for a host with ports 22, 25, 143 and 443."""

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
        self.assertEqual(scan_flags.nuclei_service_selection('ssh', task['tags'])['tags'], ['openssh', 'ssh'])  # a deep pass names no tags
        self.assertEqual(task['tags'], [])
        self.assertEqual(task['services'][f'{HOST}:8080'], 'web')

    def test_the_per_service_budget_is_in_the_task(self):
        for kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            (task,) = self.dispatched(kind, [HOST, f'{HOST}:22'])
            self.assertEqual(task['budget'], {'pause_ms': 500, 'seconds': 300, 'web_rate': 25}, kind)
            self.assertEqual(task['budget'], scan_flags.NUCLEI_SERVICE_BUDGET)
            self.assertGreaterEqual(task['budget']['pause_ms'], 500)  # one template run at a time on a service, at least this long between two
            self.assertLess(task['budget']['web_rate'], 150)  # one web host never gets the whole global rate

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
                                                      (8888, '', '', {}, {})):
            ip = IpAddress.objects.get(address='192.0.2.10')
            ip.ports.add(Port.objects.create(number=number, service_name=service, product=product, http=http, extra=extra, state='open', protocol='tcp'))
        sub = Subdomain.objects.get(scan_history=self.scan)
        sub.name = HOST
        sub.save()
        targets = nuclei_scan.build_targets(*nuclei_scan.scan_targets(self.scan))
        labels = nuclei_services.labels_for(self.scan, targets)
        self.assertEqual({t for t in targets if ':' in t}, {f'{HOST}:{n}' for n in (8080, 8443, 3000, 9000, 10443, 8888)})
        self.assertEqual(set(labels.values()), {'web'})


class ManyPortsTests(DeepBase):
    """A task with many ports that are not web is split: a Sentinel checks each of them one template at a time, so one task holds at most six (30 slow
    ports would not fit the Sentinel's task time)."""

    def setUp(self):
        super().setUp()
        for number in range(30000, 30030):
            self.ip.ports.add(Port.objects.create(number=number, service_name='some-odd-daemon', state='open', protocol='tcp'))

    def test_thirty_service_ports_go_in_tasks_of_at_most_six_and_none_is_dropped(self):
        targets = [HOST] + [f'{HOST}:{n}' for n in range(30000, 30030)]
        tasks = self.dispatched('nuclei_deep', targets)
        self.assertEqual(len(tasks), 5)
        for task in tasks:
            self.assertLessEqual(len([t for t in task['targets'] if task['services'].get(t, 'web') != 'web']), scan_flags.NUCLEI_SERVICE_MAX_PORTS)
        self.assertEqual([t for task in tasks for t in task['targets']], targets)  # every target of the list is sent, in order, once
        self.assertEqual(nuclei_services.MAX_SERVICE_PORTS, scan_flags.NUCLEI_SERVICE_MAX_PORTS)

    def test_web_targets_do_not_count_against_the_port_limit(self):
        labels = {f'{HOST}:{n}': 'web' for n in range(8000, 8100)}
        self.assertEqual([len(c) for c in nuclei_services.chunks([HOST, *labels], labels, 64)], [64, 37])
        labels = {f'{HOST}:{n}': 'ssh' for n in range(1, 14)}
        self.assertEqual([len(c) for c in nuclei_services.chunks(list(labels), labels, 64)], [6, 6, 1])

    def test_the_labels_are_read_once_for_the_whole_stream_not_once_per_chunk(self):
        targets = [HOST] + [f'{HOST}:{n}' for n in range(30000, 30030)]
        with mock.patch('cveFeed.nuclei_services.labels_for', wraps=nuclei_services.labels_for) as reads:
            self.dispatched('nuclei_deep', targets)
        self.assertEqual(reads.call_count, 1)  # five tasks, one read of the inventory

    def test_labelling_a_scan_costs_a_fixed_number_of_queries_however_many_ports(self):
        few, many = [f'{HOST}:22'], [f'{HOST}:{n}' for n in range(30000, 30030)] + [f'{HOST}:22']
        with self.assertNumQueries(3):  # the hosts, their addresses, their ports
            nuclei_services.labels_for(self.scan, few)
        with self.assertNumQueries(3):
            nuclei_services.labels_for(self.scan, many)

    def test_the_inventory_of_other_hosts_is_not_loaded(self):
        other = Subdomain.objects.create(scan_history=self.scan, name='other.example.test')
        ip = IpAddress.objects.create(address='192.0.2.99')
        ip.ports.add(Port.objects.create(number=22, service_name='http', state='open', protocol='tcp'))
        other.ip_addresses.add(ip)
        self.assertEqual(nuclei_services.labels_for(self.scan, [f'{HOST}:22'])[f'{HOST}:22'], 'ssh')  # the other host's port 22 is not this host's
        self.assertEqual(nuclei_services.labels_for(self.scan, ['OTHER.example.test:22'])['OTHER.example.test:22'], 'web')  # matched in lower case: its own http row


class NotCheckedTests(DispatchBase):
    """A port the Sentinel did not fully check is named in its result, kept by the server and said in the activity feed, never skipped in silence."""

    def test_the_result_keeps_each_port_not_checked_with_its_reason(self):
        from agentapi import sentinel_broker
        body = {'findings': [], 'not_checked': [{'target': 'www.example.test:22', 'reason': 'nothing answered on this port'}, {'target': 5}, 'x',
                                                  {'target': 'www.example.test:25', 'reason': 'r' * 500}]}
        clean = sentinel_broker._clean_nuclei_result(body)
        self.assertEqual(clean['not_checked'][0], {'target': 'www.example.test:22', 'reason': 'nothing answered on this port'})
        self.assertEqual(len(clean['not_checked']), 2)
        self.assertEqual(len(clean['not_checked'][1]['reason']), 200)
        self.assertNotIn('not_checked', sentinel_broker._clean_nuclei_result({'findings': []}))  # an older Sentinel sends none

    def test_an_unreachable_service_port_is_that_target_alone(self):
        chunk = ['www.example.test', 'www.example.test:22', 'www.example.test:443']
        self.assertEqual(dispatch._unreachable_of({'unreachable': ['www.example.test:22']}, chunk), {'www.example.test:22'})
        self.assertEqual(dispatch._unreachable_of({'unreachable': ['www.example.test']}, chunk), {'www.example.test'})  # a bare host is itself
        self.assertEqual(dispatch._unreachable_of({'unreachable': ['WWW.example.test:22']}, chunk), {'www.example.test:22'})

    def test_the_ports_not_checked_are_said_in_the_activity_feed(self):
        from cveFeed.models import AgentActivity
        stream = mock.Mock(unreached={f'{HOST}:22'}, not_checked=[{'target': f'{HOST}:22', 'reason': 'nothing answered on this port'},
                                                                  {'target': f'{HOST}:25', 'reason': 'its time ran out after 3 of 13 templates'}])
        nuclei_scan.record_reached('nuclei_deep', [HOST, f'{HOST}:22', f'{HOST}:25'], self.project, self.scan, stream)
        text = ' '.join(AgentActivity.objects.values_list('message', flat=True))
        self.assertIn(f'{HOST}:22 (nothing answered on this port)', text)
        self.assertIn(f'{HOST}:25 (its time ran out after 3 of 13 templates)', text)
        self.assertEqual(stream.not_checked, [])  # said once
