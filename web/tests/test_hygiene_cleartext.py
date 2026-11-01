import os
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import cleartext, hygiene, report_data
from cveFeed.models import HostExclusion, HostState, HygieneFinding, RouteAuth
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call

MEDIUM, HIGH = hygiene.MEDIUM, hygiene.HIGH
SSL_CERT = {'scripts': {'ssl-cert': 'Subject: commonName=ftp.example.test'}}


def run(domain, hosts=None):
    """The hygiene run with no network: no certificates to read and no mail domains."""
    return hygiene.run_hygiene(domain.id, probe=lambda host, port: None, emailer=lambda name: ([], False), mx=lambda n, t: False, hosts=hosts)


def open_checks(domain):
    return {(h.host, h.check_name): h for h in HygieneFinding.objects.filter(domain=domain, status='open')}


class Base(TestCase):
    def setUp(self):
        now = timezone.now()
        self.org = Org.objects.create(name='CT', slug='ct')
        self.project = Project.objects.create(name='CT', slug='ctp', insert_date=now, org=self.org)
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=now)
        mock.patch.dict(os.environ, {}, clear=False).start()
        os.environ.pop('CVENGINE_HYGIENE_CLEARTEXT', None)
        self.addCleanup(mock.patch.stopall)

    def host(self, name, address, *ports, **ip_kw):
        """A host with one address and ``ports``: ``(number, service)`` or ``(number, service, {Port fields})``."""
        sub = Subdomain.objects.create(name=name, target_domain=self.domain)
        ip = IpAddress.objects.get_or_create(address=address, defaults=ip_kw)[0]
        sub.ip_addresses.add(ip)
        for spec in ports:
            number, service, *rest = spec
            fields = {'state': 'open', 'protocol': 'tcp', **(rest[0] if rest else {})}
            ip.ports.add(Port.objects.create(number=number, service_name=service, extra=fields.pop('extra', {'method': 'probed'}), **fields))
        return sub, ip


class EvaluationTests(Base):
    def test_open_telnet_and_ftp_on_an_internal_host_are_medium(self):
        self.host('router.example.test', '192.168.88.1', (23, 'telnet'), (21, 'ftp'), (80, 'http'))
        run(self.domain)
        rows = open_checks(self.domain)
        self.assertEqual(set(rows), {('router.example.test', 'cleartext_telnet'), ('router.example.test', 'cleartext_ftp')})
        telnet = rows[('router.example.test', 'cleartext_telnet')]
        self.assertEqual((telnet.severity, telnet.evidence['exposure'], telnet.evidence['ports'], telnet.evidence['addresses']),
                         (MEDIUM, 'internal', [23], ['192.168.88.1']))
        self.assertEqual(rows[('router.example.test', 'cleartext_ftp')].severity, MEDIUM)
        self.assertIn('Telnet', telnet.title)
        self.assertIn('Fix:', telnet.detail)
        self.assertTrue(telnet.evidence['severity_basis'] and telnet.evidence['remediation'])

    def test_the_same_services_on_a_public_host_are_high(self):
        self.host('gw.example.test', '8.8.8.7', (23, 'telnet'), (21, 'ftp'))
        run(self.domain)
        rows = open_checks(self.domain)
        self.assertEqual({k[1]: r.severity for k, r in rows.items()}, {'cleartext_telnet': HIGH, 'cleartext_ftp': HIGH})
        self.assertEqual(rows[('gw.example.test', 'cleartext_telnet')].evidence['exposure'], 'public')

    def test_a_host_with_a_public_and_an_internal_address_is_judged_by_the_address_that_has_the_service(self):
        sub, _ = self.host('dual.example.test', '8.8.8.8', (443, 'https'))
        internal = IpAddress.objects.create(address='10.0.0.8')
        internal.ports.add(Port.objects.create(number=23, service_name='telnet', state='open', protocol='tcp', extra={'method': 'probed'}))
        sub.ip_addresses.add(internal)
        run(self.domain)
        self.assertEqual(open_checks(self.domain)[('dual.example.test', 'cleartext_telnet')].severity, MEDIUM)
        public = IpAddress.objects.get(address='8.8.8.8')
        public.ports.add(Port.objects.create(number=2323, service_name='telnet', state='open', protocol='tcp', extra={'method': 'probed'}))
        run(self.domain)
        row = open_checks(self.domain)[('dual.example.test', 'cleartext_telnet')]
        self.assertEqual((row.severity, row.evidence['ports']), (HIGH, [23, 2323]))

    def test_telnet_on_another_port_is_found_by_its_service_name(self):
        self.host('odd.example.test', '192.168.1.5', (2323, 'telnet'), (2121, 'ftp'))
        run(self.domain)
        self.assertEqual(open_checks(self.domain)[('odd.example.test', 'cleartext_telnet')].evidence['ports'], [2323])
        self.assertEqual(open_checks(self.domain)[('odd.example.test', 'cleartext_ftp')].evidence['ports'], [2121])

    def test_rlogin_rsh_and_rexec_are_one_finding_at_the_same_grade(self):
        self.host('old.example.test', '192.168.1.6', (512, 'exec'), (513, 'login'), (514, 'shell'))
        run(self.domain)
        row = open_checks(self.domain)[('old.example.test', 'cleartext_rservices')]
        self.assertEqual((row.severity, row.evidence['ports']), (MEDIUM, [512, 513, 514]))
        self.host('old2.example.test', '8.8.8.9', (513, 'login'))
        run(self.domain)
        self.assertEqual(open_checks(self.domain)[('old2.example.test', 'cleartext_rservices')].severity, HIGH)

    def test_a_service_called_login_or_shell_off_the_r_ports_is_not_an_r_service(self):
        self.host('web.example.test', '192.168.1.7', (8080, 'login'), (2222, 'shell'))
        run(self.domain)
        self.assertEqual(open_checks(self.domain), {})

    def test_udp_514_is_syslog_not_rsh(self):
        self.host('log.example.test', '192.168.1.8', (514, 'syslog', {'protocol': 'udp'}), (514, 'shell', {'protocol': 'udp'}))
        run(self.domain)
        self.assertEqual(open_checks(self.domain), {})

    def test_a_port_named_from_the_port_table_is_flagged_and_says_so(self):
        self.host('quiet.example.test', '192.168.1.9', (23, 'telnet', {'extra': {'method': 'table'}}))
        run(self.domain)
        row = open_checks(self.domain)[('quiet.example.test', 'cleartext_telnet')]
        self.assertEqual(row.evidence['identified'], 'port number')
        self.assertIn('did not fingerprint', row.detail)
        self.host('seen.example.test', '192.168.1.10', (23, 'telnet'))
        run(self.domain)
        self.assertEqual(open_checks(self.domain)[('seen.example.test', 'cleartext_telnet')].evidence['identified'], 'fingerprint')


class NotFlaggedTests(Base):
    def test_closed_filtered_and_unanswered_ports_are_not_findings(self):
        self.host('shut.example.test', '192.168.1.20', (23, 'telnet', {'state': 'closed'}), (21, 'ftp', {'state': 'filtered'}),
                  (513, 'login', {'state': 'open|filtered'}))
        run(self.domain)
        self.assertEqual(open_checks(self.domain), {})

    def test_tcpwrapped_is_not_a_service(self):
        self.host('wrapped.example.test', '192.168.1.21', (23, 'tcpwrapped'), (21, 'tcpwrapped'))
        run(self.domain)
        self.assertEqual(open_checks(self.domain), {})

    def test_ftp_whose_certificate_nmap_read_over_auth_tls_is_not_flagged(self):
        self.host('tls.example.test', '8.8.8.20', (21, 'ftp', {'extra': {'method': 'probed', **SSL_CERT}}), (23, 'telnet'))
        self.host('tls2.example.test', '8.8.8.21', (21, 'ftp', {'tls': {'subject': 'ftp.example.test'}}))
        run(self.domain)
        self.assertEqual(set(open_checks(self.domain)), {('tls.example.test', 'cleartext_telnet')})

    def test_implicit_tls_services_are_not_flagged(self):
        self.host('ftps.example.test', '8.8.8.22', (990, 'ftps'), (992, 'telnets'),
                  (2121, 'ftp', {'extra': {'method': 'probed', 'tunnel': 'ssl'}}))
        run(self.domain)
        self.assertEqual(open_checks(self.domain), {})

    def test_a_cdn_edge_and_a_tailnet_address_are_left_alone(self):
        self.host('edge.example.test', '8.8.8.30', (23, 'telnet'), (21, 'ftp'), is_cdn=True)
        self.host('device.example.test', '100.64.1.2', (23, 'telnet'))  # the Tailscale checks own this (ts_remote_admin_exposed)
        run(self.domain)
        self.assertEqual(open_checks(self.domain), {})

    def test_an_excluded_or_archived_host_gets_no_finding(self):
        self.host('gone.example.test', '192.168.1.40', (23, 'telnet'))
        self.host('shelved.example.test', '192.168.1.41', (23, 'telnet'))
        self.host('kept.example.test', '192.168.1.42', (23, 'telnet'))
        HostExclusion.objects.create(org=self.org, host='gone.example.test')
        HostState.objects.create(project=self.project, domain=self.domain, host='shelved.example.test', archived_at=timezone.now())
        run(self.domain)
        self.assertEqual({h for h, _ in open_checks(self.domain)}, {'kept.example.test'})

    def test_a_target_in_no_project_has_no_findings(self):
        orphan = Domain.objects.create(name='orphan.test', insert_date=timezone.now())
        self.assertEqual(cleartext.findings_for(orphan), [])


class SwitchTests(Base):
    def test_default_is_on_and_zero_turns_it_off(self):
        self.assertTrue(cleartext.enabled())
        for value in ('0', 'false', 'no', 'off', 'OFF'):
            with mock.patch.dict(os.environ, {'CVENGINE_HYGIENE_CLEARTEXT': value}):
                self.assertFalse(cleartext.enabled(), value)
        with mock.patch.dict(os.environ, {'CVENGINE_HYGIENE_CLEARTEXT': '1'}):
            self.assertTrue(cleartext.enabled())

    def test_switched_off_there_are_no_findings_and_open_ones_resolve(self):
        self.host('router.example.test', '192.168.88.1', (23, 'telnet'))
        run(self.domain)
        self.assertEqual(len(open_checks(self.domain)), 1)
        with mock.patch.dict(os.environ, {'CVENGINE_HYGIENE_CLEARTEXT': '0'}):
            run(self.domain)
        self.assertEqual(open_checks(self.domain), {})
        self.assertEqual(HygieneFinding.objects.get(check_name='cleartext_telnet').status, 'resolved')

    def test_a_failed_derivation_resolves_nothing(self):
        self.host('router.example.test', '192.168.88.1', (23, 'telnet'))
        run(self.domain)
        with mock.patch('cveFeed.cleartext.findings_for', side_effect=RuntimeError('boom')), self.assertLogs('cveFeed.hygiene', 'ERROR'):
            run(self.domain)
        self.assertEqual(len(open_checks(self.domain)), 1)


class LifecycleTests(Base):
    def test_two_addresses_and_two_ports_are_one_finding_and_a_rerun_adds_none(self):
        sub, _ = self.host('multi.example.test', '192.168.1.50', (23, 'telnet'), (2323, 'telnet'))
        second = IpAddress.objects.create(address='192.168.1.51')
        second.ports.add(Port.objects.create(number=23, service_name='telnet', state='open', protocol='tcp'))
        sub.ip_addresses.add(second)
        run(self.domain)
        run(self.domain)
        self.assertEqual(HygieneFinding.objects.filter(check_name='cleartext_telnet').count(), 1)
        row = HygieneFinding.objects.get(check_name='cleartext_telnet')
        self.assertEqual((row.evidence['ports'], row.evidence['addresses']), ([23, 2323], ['192.168.1.50', '192.168.1.51']))

    def test_the_finding_resolves_when_the_port_closes_and_reopens_if_it_comes_back(self):
        _, ip = self.host('router.example.test', '192.168.88.1', (23, 'telnet'))
        run(self.domain)
        ip.ports.filter(number=23).update(state='closed')
        run(self.domain)
        row = HygieneFinding.objects.get(check_name='cleartext_telnet')
        self.assertEqual(row.status, 'resolved')
        HygieneFinding.objects.filter(pk=row.pk).update(remediation_status='fixed')
        ip.ports.filter(number=23).update(state='open')
        run(self.domain)
        row.refresh_from_db()
        self.assertEqual((row.status, row.remediation_status), ('open', 'open'))  # a regression of a fixed finding is actionable again
        self.assertIn('Reopened', row.remediation_note)

    def test_an_accepted_risk_survives_the_next_run(self):
        self.host('router.example.test', '192.168.88.1', (23, 'telnet'))
        run(self.domain)
        HygieneFinding.objects.filter(check_name='cleartext_telnet').update(remediation_status='accepted_risk', remediation_note='lab router')
        run(self.domain)
        row = HygieneFinding.objects.get(check_name='cleartext_telnet')
        self.assertEqual((row.status, row.remediation_status, row.remediation_note), ('open', 'accepted_risk', 'lab router'))

    def test_the_grade_moves_when_the_address_becomes_public(self):
        _, ip = self.host('moving.example.test', '192.168.1.60', (23, 'telnet'))
        run(self.domain)
        self.assertEqual(HygieneFinding.objects.get(check_name='cleartext_telnet').severity, MEDIUM)
        ip.address = '8.8.8.60'
        ip.save()
        run(self.domain)
        self.assertEqual(HygieneFinding.objects.get(check_name='cleartext_telnet').severity, HIGH)

    def test_a_host_only_run_leaves_the_other_hosts_alone(self):
        _, ip = self.host('a.example.test', '192.168.1.70', (23, 'telnet'))
        self.host('b.example.test', '192.168.1.71', (23, 'telnet'))
        run(self.domain)
        ip.ports.filter(number=23).update(state='closed')
        self.host('c.example.test', '192.168.1.72', (21, 'ftp'))
        run(self.domain, hosts=['c.example.test'])
        self.assertEqual({h for h, _ in open_checks(self.domain)}, {'a.example.test', 'b.example.test', 'c.example.test'})  # a is not in scope of this run
        run(self.domain, hosts=['a.example.test'])
        self.assertEqual({h for h, _ in open_checks(self.domain)}, {'b.example.test', 'c.example.test'})

    def test_the_newest_row_of_a_name_decides_not_an_old_address(self):
        old, _ = self.host('moved.example.test', '192.168.1.80', (23, 'telnet'))
        new = Subdomain.objects.create(name='moved.example.test', target_domain=self.domain)
        new.ip_addresses.add(IpAddress.objects.create(address='192.168.1.81'))
        run(self.domain)
        self.assertEqual(open_checks(self.domain), {})

    def test_the_run_reports_the_findings_in_its_counts(self):
        self.host('router.example.test', '192.168.88.1', (23, 'telnet'), (21, 'ftp'))
        counts = run(self.domain)
        self.assertEqual((counts['findings'], counts['cleartext']), (2, 2))

    def test_the_host_score_counts_the_finding(self):
        self.host('router.example.test', '192.168.88.1', (23, 'telnet'))
        with mock.patch('cveFeed.scoring.rescore_quietly') as rescore:
            run(self.domain)
        self.assertIn('router.example.test', [n for call_ in rescore.call_args_list for n in call_.args[1]])


class HttpLoginTests(Base):
    def login_route(self, host, scheme='http', state='login', path='/login'):
        return RouteAuth.objects.create(project=self.project, domain=self.domain, host=host, url=f'{scheme}://{host}{path}', path=path,
                                        auth_state=state, http_status=200)

    def test_a_login_page_served_over_plain_http_with_no_https_is_flagged(self):
        self.host('app.example.test', '192.168.1.90', (80, 'http'))
        self.login_route('app.example.test')
        run(self.domain)
        row = open_checks(self.domain)[('app.example.test', 'cleartext_http_login')]
        self.assertEqual((row.severity, row.evidence['exposure'], row.evidence['urls']), (hygiene.LOW, 'internal', ['http://app.example.test/login']))
        self.assertIn('no HTTPS', row.detail)

    def test_a_public_host_is_one_grade_higher(self):
        self.host('www.example.test', '8.8.8.90', (80, 'http'))
        self.login_route('www.example.test')
        run(self.domain)
        self.assertEqual(open_checks(self.domain)[('www.example.test', 'cleartext_http_login')].severity, MEDIUM)

    def test_an_https_port_or_an_https_route_is_an_alternative(self):
        self.host('a.example.test', '8.8.8.91', (80, 'http'), (443, 'https'))
        self.login_route('a.example.test')
        self.host('b.example.test', '8.8.8.92', (80, 'http'), (8443, 'http', {'extra': {'method': 'probed', 'tunnel': 'ssl'}}))
        self.login_route('b.example.test')
        self.host('c.example.test', '8.8.8.93', (80, 'http'))
        self.login_route('c.example.test')
        self.login_route('c.example.test', scheme='https', path='/admin')
        run(self.domain)
        self.assertEqual(open_checks(self.domain), {})

    def test_only_a_live_login_page_over_http_counts(self):
        self.host('a.example.test', '8.8.8.94', (80, 'http'))
        self.login_route('a.example.test', state='open')
        self.login_route('a.example.test', state='session_required', path='/admin')
        retired = self.login_route('a.example.test', path='/old')
        RouteAuth.objects.filter(pk=retired.pk).update(retired_at=timezone.now())
        run(self.domain)
        self.assertEqual(open_checks(self.domain), {})

    def test_it_resolves_when_https_appears(self):
        _, ip = self.host('app.example.test', '192.168.1.95', (80, 'http'))
        self.login_route('app.example.test')
        run(self.domain)
        self.assertEqual(len(open_checks(self.domain)), 1)
        ip.ports.add(Port.objects.create(number=443, service_name='https', state='open', protocol='tcp'))
        run(self.domain)
        self.assertEqual(open_checks(self.domain), {})

    def test_the_switch_covers_it_too(self):
        self.host('app.example.test', '192.168.1.96', (80, 'http'))
        self.login_route('app.example.test')
        with mock.patch.dict(os.environ, {'CVENGINE_HYGIENE_CLEARTEXT': '0'}):
            run(self.domain)
        self.assertEqual(open_checks(self.domain), {})


class InternalAndGateTests(Base):
    """What a Sentinel stored for a declared internal network counts like any other stored port; nothing here sends a packet; the bounty gate holds."""

    def internal_target(self, address='10.20.0.7'):
        from cveFeed import internal_view
        from cveFeed.models import InternalRange
        InternalRange.objects.create(project=self.project, cidr='10.20.0.0/24')
        internal_view.invalidate()
        self.addCleanup(internal_view.invalidate)
        target = Domain.objects.create(name=address, project=self.project, insert_date=timezone.now())
        sub = Subdomain.objects.create(name=address, target_domain=target)
        ip = IpAddress.objects.create(address=address)
        sub.ip_addresses.add(ip)
        for number, service in ((23, 'telnet'), (21, 'ftp')):  # as the Sentinel's nmap stored them
            ip.ports.add(Port.objects.create(number=number, service_name=service, state='open', protocol='tcp', extra={'method': 'probed'}))
        return target

    def test_a_host_in_a_declared_internal_network_is_flagged_from_the_ports_its_sentinel_stored_and_is_medium(self):
        target = self.internal_target()
        probe, mail = mock.Mock(return_value=None), mock.Mock(return_value=([], False))
        hygiene.run_hygiene(target.id, probe=probe, emailer=mail, mx=lambda n, t: False)
        probe.assert_not_called()  # an internal address is no target for this server's TLS probe, and the cleartext check sends nothing at all
        rows = open_checks(target)
        self.assertEqual({k[1]: r.severity for k, r in rows.items()}, {'cleartext_telnet': MEDIUM, 'cleartext_ftp': MEDIUM})
        self.assertEqual(rows[('10.20.0.7', 'cleartext_telnet')].evidence['exposure'], 'internal')

    def test_the_check_opens_no_socket_and_makes_no_http_request(self):
        self.host('router.example.test', '192.168.88.1', (23, 'telnet'), (21, 'ftp'), (80, 'http'))
        self.host('www.example.test', '8.8.8.99', (23, 'telnet'), (80, 'http'))
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.example.test', url='http://www.example.test/login',
                                 path='/login', auth_state='login', http_status=200)
        with mock.patch('socket.socket', side_effect=AssertionError('socket opened')), \
                mock.patch('socket.getaddrinfo', side_effect=AssertionError('DNS lookup')), \
                mock.patch('http.client.HTTPConnection.connect', side_effect=AssertionError('HTTP connection')), \
                mock.patch('cveFeed.route_auth.probe_url', side_effect=AssertionError('probe')):
            found = cleartext.findings_for(self.domain)
        self.assertEqual(sorted(f.check for f in found),
                         ['cleartext_ftp', 'cleartext_http_login', 'cleartext_telnet', 'cleartext_telnet'])

    def test_the_daily_sweep_reaches_the_internal_target_but_not_a_bounty_project_that_has_not_confirmed_automated_testing(self):
        from cveFeed import tasks
        from cveFeed.models import BountyEngagement, BountyProgram
        target = self.internal_target()
        with mock.patch.object(tasks.run_hygiene_task, 'delay') as queued, mock.patch('cveFeed.ledger.sweep_claim', return_value=True):
            tasks.run_hygiene_all()
        self.assertIn(target.id, [c.args[0] for c in queued.call_args_list])
        program = BountyProgram.objects.create(platform='hackerone', handle='ex', name='Example')
        BountyEngagement.objects.create(project=self.project, program=program, status='active', automated_ok=False)
        with mock.patch.object(tasks.run_hygiene_task, 'delay') as queued, mock.patch('cveFeed.ledger.sweep_claim', return_value=True):
            tasks.run_hygiene_all()
        queued.assert_not_called()


class SurfaceTests(Base):
    """The findings are ordinary hygiene findings: the listings, the unified status and the report take them as they are."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('ctu', password='x')
        ProjectMembership.objects.create(user=self.user, project=self.project, role='user')
        self.tok = create_token(self.user, 't')[1]
        self.host('router.example.test', '192.168.88.1', (23, 'telnet'), (21, 'ftp'))
        run(self.domain)

    def test_the_rest_listing_filters_by_the_check_prefix(self):
        HygieneFinding.objects.create(domain=self.domain, host='a.test', check_name='spf_missing', severity=2, title='No SPF record')
        status, data = call(self.tok, 'GET', '/api/v1/projects/ctp/hygiene?check=cleartext')
        self.assertEqual(status, 200)
        self.assertEqual({f['check'] for f in data['results']}, {'cleartext_telnet', 'cleartext_ftp'})
        self.assertEqual([f['host'] for f in data['results']], ['router.example.test'] * 2)

    def test_the_unified_findings_list_and_status_workflow_include_it(self):
        status, data = call(self.tok, 'GET', '/api/v1/projects/ctp/findings?type=hygiene&host=router')
        self.assertEqual(status, 200)
        self.assertEqual(data['counts']['hygiene'], 2)
        row = next(r for r in data['results'] if 'Telnet' in r['title'])
        status, out = call(self.tok, 'PATCH', f'/api/v1/projects/ctp/findings/hygiene/{row["id"]}', {'status': 'in_progress', 'note': 'closing 23'})
        self.assertEqual(status, 200)
        self.assertEqual(HygieneFinding.objects.get(pk=row['id']).remediation_status, 'in_progress')
        status, detail = call(self.tok, 'GET', f'/api/v1/projects/ctp/findings/hygiene/{row["id"]}')
        self.assertEqual(status, 200)

    def test_the_mcp_tool_lists_it(self):
        from tests.test_agentapi import rpc
        status, data = rpc(self.tok, 'tools/call', {'name': 'list_hygiene_findings', 'arguments': {'project': 'ctp', 'check': 'cleartext'}})
        self.assertEqual(status, 200)
        self.assertIn('cleartext_telnet', str(data))

    def test_the_report_groups_it_apart_from_tls_and_mail(self):
        for check in ('cleartext_telnet', 'cleartext_ftp', 'cleartext_rservices', 'cleartext_http_login'):
            self.assertEqual(report_data._hygiene_group(check), 'Cleartext services', check)
        self.assertEqual(report_data._hygiene_group('tls_expired'), 'TLS and certificates')


class ClassifyTests(SimpleTestCase):
    def port(self, number, service, **kw):
        return mock.Mock(number=number, service_name=service, extra=kw.pop('extra', {}), tls=kw.pop('tls', {}), **kw)

    def test_classification(self):
        c = cleartext.classify
        self.assertEqual(c(self.port(23, 'telnet')), 'cleartext_telnet')
        self.assertEqual(c(self.port(21, 'ftp')), 'cleartext_ftp')
        self.assertEqual(c(self.port(513, 'login')), 'cleartext_rservices')
        self.assertEqual(c(self.port(514, 'rsh')), 'cleartext_rservices')
        for name in ('tftp', 'ftps', 'telnets', 'ssh', 'tcpwrapped', '', None, 'ftp-data'):
            self.assertIsNone(c(self.port(21, name)), name)
        self.assertIsNone(c(self.port(2323, 'telnet', extra={'tunnel': 'ssl'})))
