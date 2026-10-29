"""Review fixes for the OpenVAS sweep: pause, a gvmd that does not answer, verified TLS, names that share an address, a cut result set, the
project's own choice over its organization's, and the order the projects are visited in. The fixtures are the ones of tests.test_openvas."""
import os
import socket
import ssl
import tempfile
import threading
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from gvm.connections import UnixSocketConnection

from agentapi.auth import create_token
from agentapi.models import Agent
from cveFeed import openvas_scan as ov
from cveFeed.models import OpenvasOrg, OpenvasProject, OpenvasRun, ProbeObservation, ScanControl, ServiceRun
from dashboard.models import Project
from startScan.models import Subdomain
from tests.test_openvas import APACHE, OID_APACHE, Fixture


class TlsVerificationTests(SimpleTestCase):
    """GMP over TLS to a gvmd on another machine is always verified: the login and every scan result travel over it."""

    def make_cert(self, directory, name='gvm.example.test'):
        import datetime
        import ipaddress
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = os.path.join(directory, f'{name}.pem'), os.path.join(directory, f'{name}.key')
        Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        Path(key_path).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        return cert_path, key_path

    def serve(self, cert, key):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        self.addCleanup(server.close)

        def accept():
            try:
                conn, _ = server.accept()
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except Exception:  # noqa: BLE001 - the client may refuse the certificate mid-handshake
                pass
        threading.Thread(target=accept, daemon=True).start()
        return server.getsockname()[1]

    def test_a_remote_gvmd_without_a_ca_is_refused_before_anything_is_sent(self):
        with mock.patch.dict(os.environ, {'CVENGINE_OPENVAS_HOST': 'gvm.example.test'}, clear=False):
            os.environ.pop('CVENGINE_OPENVAS_CA', None)
            with self.assertRaisesRegex(ov.OpenvasError, 'CVENGINE_OPENVAS_CA'):
                ov._connection()
            with self.assertRaisesRegex(ov.OpenvasError, 'CVENGINE_OPENVAS_CA'):
                with ov.session(creds=('a', 'b')):
                    pass

    def test_the_socket_stays_the_default_and_needs_no_certificate(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('CVENGINE_OPENVAS_HOST', None)
            self.assertIsInstance(ov._connection(), UnixSocketConnection)

    def test_the_server_certificate_must_chain_to_the_ca_and_name_the_host(self):
        with tempfile.TemporaryDirectory() as directory:
            cert, key = self.make_cert(directory)
            other_cert, _other_key = self.make_cert(directory, name='other.example.test')
            good = ov._verified_tls('127.0.0.1', self.serve(cert, key), cert)
            good.connect()  # chains to the CA and 127.0.0.1 is among its names
            good.disconnect()
            with self.assertRaises(OSError):  # a CA that did not sign it
                ov._verified_tls('127.0.0.1', self.serve(cert, key), other_cert).connect()
            with self.assertRaises(OSError):  # signed by the CA, but for another name
                ov._verified_tls('127.0.0.1', self.serve(cert, key), cert, server_name='elsewhere.example.test').connect()
            named = ov._verified_tls('127.0.0.1', self.serve(cert, key), cert, server_name='gvm.example.test')  # the name to verify can be set
            named.connect()
            named.disconnect()


class ReviewFixTests(Fixture, TestCase):
    def make_sentinel(self):
        user = User.objects.create_user('sentinel-owner-rf', password='x')
        token, _raw = create_token(user, 'sentinel-token-rf')
        return Agent.objects.create(token=token, name='gvm-sentinel-rf', kind='scanner', status='active',
                                    scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []}, capabilities=['openvas'], last_seen=timezone.now())

    # --- pause (S05-1)
    def test_an_update_drain_pause_lets_the_running_task_finish_but_starts_nothing(self):
        self.tick()
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': True})
        self.assertEqual(self.tick()['status'], 'running')
        self.assertEqual(len(self.gvmd.sent('stop_task')), 0)
        self.finish_task([APACHE])
        self.assertEqual(self.tick()['status'], 'done')  # it finishes and is imported during the drain
        self.assertEqual(self.tick(), {'skipped': 'scanning is paused'})
        self.assertEqual(len(self.gvmd.sent('create_task')), 1)

    def test_pause_all_scanning_expires_a_running_sentinel_task_and_marks_no_host_failed(self):
        self.make_sentinel()
        self.assertEqual(self.tick()['via'], 'sentinel')
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        self.assertEqual(self.tick()['status'], 'failed')
        run = OpenvasRun.objects.get()
        self.assertEqual((run.status, run.sentinel_task.status), ('failed', 'expired'))
        self.assertIn('scanning is paused', run.error)
        self.assertFalse(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())

    def test_a_paused_instance_dispatches_nothing_to_a_sentinel(self):
        self.make_sentinel()
        ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
        self.assertEqual(self.tick(), {'skipped': 'scanning is paused'})
        self.assertFalse(OpenvasRun.objects.exists())

    # --- a gvmd that does not answer (S05-3)
    def test_a_gvmd_that_fails_to_answer_about_a_running_task_is_asked_again_not_given_up_on(self):
        self.tick()
        run = OpenvasRun.objects.get()
        self.gvmd.fail['get_tasks'] = ('500', 'Internal error')
        for _ in range(ov.POLL_RETRIES - 1):
            out = self.tick()
            self.assertEqual(out['status'], 'running')
            self.assertIn('did not answer', out['error'])
        self.assertEqual(OpenvasRun.objects.get().status, 'running')
        self.assertFalse(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())
        self.assertEqual(len(self.gvmd.sent('create_task')), 1)  # no second task while the first may still run
        del self.gvmd.fail['get_tasks']
        self.assertEqual(self.tick()['status'], 'running')  # it answers again: the run carries on and the count starts over
        self.gvmd.fail['get_tasks'] = ('500', 'Internal error')
        self.assertEqual(self.tick()['status'], 'running')
        self.assertEqual(OpenvasRun.objects.get(pk=run.pk).status, 'running')

    def test_a_gvmd_that_stays_silent_ends_the_run_without_blaming_the_hosts(self):
        self.tick()
        self.gvmd.fail['get_tasks'] = ('500', 'Internal error')
        for _ in range(ov.POLL_RETRIES - 1):
            self.tick()
        self.assertEqual(self.tick()['status'], 'failed')
        self.assertIn('did not answer', OpenvasRun.objects.get().error)
        self.assertFalse(ServiceRun.objects.filter(service=ov.FAILED_SERVICE).exists())
        self.assertEqual(len(self.gvmd.sent('stop_task')), 1)  # the task is told to stop before the hosts are offered again

    # --- names that share an address (S05-10)
    def test_every_name_of_a_scanned_address_is_fresh_not_just_the_one_scanned(self):
        from cveFeed import ledger
        self.scan(names=('alias.rt.test',), ip='93.184.216.5')  # a second name of the machine www.rt.test is on
        self.link.hosts = self.link.forced_hosts = ['www.rt.test']
        self.link.save()
        self.run_scan([APACHE])
        self.assertEqual(OpenvasRun.objects.get().status, 'done')
        fresh = ledger.fresh(ov.SERVICE, ['www.rt.test', 'alias.rt.test', 'api.rt.test'], self.project.id)
        self.assertEqual(set(fresh), {'www.rt.test', 'alias.rt.test'})

    # --- a truncated result set (S05-14)
    def test_a_result_set_cut_at_the_cap_is_a_partial_scan_and_resolves_nothing(self):
        self.run_scan([APACHE])
        self.assertTrue(ProbeObservation.objects.filter(outcome='found', evidence__oid=OID_APACHE).exists())
        ServiceRun.objects.all().delete()
        self.assertEqual(self.tick()['status'], 'running')
        self.finish_task([{**APACHE, 'oid': f'1.3.6.1.4.1.25623.1.0.{300000 + i}', 'cves': ['CVE-2019-0001'], 'severity': 5.0, 'qod': 90} for i in range(150)])
        with mock.patch.object(ov, 'MAX_RESULTS', 100):
            out = self.tick()
        self.assertTrue(out['partial'])
        self.assertIn('lowest-severity', OpenvasRun.objects.order_by('-id').first().error)
        self.assertTrue(ProbeObservation.objects.filter(outcome='found', evidence__oid=OID_APACHE).exists())  # not flipped to absent by the cut

    # --- the server's own address (S05-13)
    def test_a_failed_lookup_of_the_servers_own_name_is_not_remembered_for_an_hour(self):
        with mock.patch.dict(os.environ, {'CVENGINE_OWN_ADDRESSES': ''}), mock.patch.dict(ov._own, {'at': 0.0}), override_settings(DOMAIN_NAME='cve.example.test'):
            with mock.patch('socket.getaddrinfo', side_effect=socket.gaierror(-2, 'Name or service not known')):
                self.assertEqual(ov.own_addresses(), frozenset())
            with mock.patch('time.monotonic', return_value=ov._own['at'] + ov.OWN_TTL + 1), \
                    mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('198.51.100.77', 0))]):
                self.assertEqual(ov.own_addresses(), frozenset({'198.51.100.77'}))

    def test_own_addresses_are_compared_in_one_form(self):
        with mock.patch.dict(os.environ, {'CVENGINE_OWN_ADDRESSES': '2606:4700:0000:0000:0000:0000:0000:0099, 93.184.216.99'}), mock.patch.dict(ov._own, {'at': 0.0}):
            self.assertEqual(ov.refuse_reason('2606:4700::99'), 'this cvENGINE server')

    # --- a busy project cannot hold the slot (S05-11)
    def test_the_project_scanned_longest_ago_goes_first(self):
        other = Project.objects.create(name='Second', slug='second', insert_date=timezone.now(), org=self.project.org)
        second = OpenvasProject.objects.create(project=other, enabled=True)
        self.assertEqual([l.pk for l in ov.sweep_links()], [self.link.pk, second.pk])  # never run: by id
        OpenvasRun.objects.create(project=self.project, status='done')
        self.assertEqual([l.pk for l in ov.sweep_links()], [second.pk, self.link.pk])  # the first project just ran
        OpenvasRun.objects.create(project=other, status='done')
        self.assertEqual([l.pk for l in ov.sweep_links()], [self.link.pk, second.pk])

    # --- the project's own choice wins over its organization's (S05-4, S05-9)
    def test_an_excluded_project_of_an_opted_in_organization_is_not_scanned(self):
        OpenvasOrg.objects.create(org=self.project.org, enabled=True)
        self.link.enabled, self.link.excluded = False, True
        self.link.save()
        later = Project.objects.create(name='Later', slug='later', insert_date=timezone.now(), org=self.project.org)
        self.assertEqual({l.project_id for l in ov.sweep_links()}, {later.pk})
        self.assertEqual({l.project_id for l in ov.links_for([self.project.id, later.id])}, {later.pk})

    def test_a_project_with_its_own_opt_in_is_scanned_even_if_the_flag_says_excluded(self):
        OpenvasOrg.objects.create(org=self.project.org, enabled=True)
        self.link.excluded = True  # enabled stays True: the project's own opt-in wins
        self.link.save()
        self.assertIn(self.project.id, {l.project_id for l in ov.sweep_links()})

    def test_check_coverage_sees_a_project_opted_in_through_its_organization(self):
        from cveFeed import check_coverage as cc
        sub = Subdomain.objects.get(name='www.rt.test')
        self.link.delete()
        self.assertEqual(cc.load([(sub, [sub], self.project.id)]).openvas, {})
        OpenvasOrg.objects.create(org=self.project.org, enabled=True)
        self.assertIn(self.project.id, cc.load([(sub, [sub], self.project.id)]).openvas)
        OpenvasProject.objects.update_or_create(project=self.project, defaults={'enabled': False, 'excluded': True})
        self.assertEqual(cc.load([(sub, [sub], self.project.id)]).openvas, {})
