"""End-to-end: the real ``sentinel/client`` package (the actual downloadable Sentinel, not a stand-in for it) driven
against the real Django views over real HTTP (``LiveServerTestCase``), proving the client and the server agree on the
wire. ``tests.test_sentinels``'s own E2E test proves the REST contract works through Django's test client; this proves
the client package built against that contract (blob decode, bootstrap, long-poll claim, accept, report) actually
speaks it correctly over a socket. Only the tool execution itself is mocked (so this test needs no real nmap binary);
every HTTP call is real.
"""
import os
import sys
import time
from unittest import mock

from django.contrib.auth.models import User
from django.test import LiveServerTestCase
from django.utils import timezone

from agentapi import sentinel_broker as sentinels
from agentapi.models import Agent, SentinelTask
from agentapi.services import Ctx
from dashboard.models import Org, OrgMembership, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain

# The client package lives in sentinel/client at the repository root, outside web/: it has no Django dependency and
# ships as its own Docker image, so it is not on sys.path by default. Add it only for this test.
SENTINEL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'sentinel'))
if SENTINEL_ROOT not in sys.path:
    sys.path.insert(0, SENTINEL_ROOT)

from client import daemon as client_daemon  # noqa: E402 - sys.path set up just above
from client import tools as client_tools  # noqa: E402


class SentinelClientEndToEndTests(LiveServerTestCase):
    def setUp(self):
        now = timezone.now()
        self.org = Org.objects.create(name='E2E Client', slug='e2e-client')
        self.project = Project.objects.create(name='E2E Client', slug='e2e-client-p', insert_date=now, org=self.org)
        self.admin = User.objects.create_user('e2e-client-admin', password='x')
        OrgMembership.objects.create(user=self.admin, org=self.org, role='admin')
        self.domain = Domain.objects.create(name='e2e.example.test', project=self.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='e2e-client-engine', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=now, scan_status=1,
                                               results_dir='/tmp')
        sub = Subdomain.objects.create(scan_history=self.scan, name='www.e2e.example.test')
        sub.ip_addresses.add(IpAddress.objects.create(address='192.0.2.77'))

    def _blob_for_this_project(self):
        """A real enrollment, repackaged with this LiveServerTestCase's own URL as ``server_url`` (``generate_enrollment``
        would otherwise point at ``DOMAIN_NAME``, not the ephemeral test server), so the client's real HTTP calls land on
        this test's actual Django server."""
        enrollment = sentinels.generate_enrollment(Ctx(user=self.admin), self.project.slug)
        return client_daemon.blob_mod.encode_blob({**enrollment, 'server_url': self.live_server_url})

    def test_the_real_client_bootstraps_claims_executes_and_reports_over_real_http(self):
        with mock.patch.object(client_tools, 'detect_tools', return_value=['nmap', 'naabu', 'nuclei']):
            token, server_url = client_daemon.bootstrap(self._blob_for_this_project(), 'e2e-client-sentinel', 1)
        self.assertEqual(server_url, self.live_server_url)
        agent = Agent.objects.get(name='e2e-client-sentinel')
        self.assertEqual(agent.kind, 'scanner')
        self.assertEqual(agent.status, 'active')  # the enroller (self.admin) is an org admin, so it starts active
        self.assertEqual(sorted(agent.tools), ['naabu', 'nmap', 'nuclei'])

        task = SentinelTask.objects.create(project=self.project, scan=self.scan, kind='nmap',
                                           target={'addresses': ['192.0.2.77']}, host='www.e2e.example.test',
                                           ips=['192.0.2.77'])

        engine = client_daemon.Daemon(server_url, token, max_concurrent=1)
        fake_result = {'hosts': [{'ip': '192.0.2.77', 'os_guess': 'Linux 6.X',
                       'ports': [{'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh',
                                 'product': 'OpenSSH', 'version': '9.6'}]}]}
        with mock.patch.dict(client_tools.RUNNERS, {'nmap': mock.Mock(return_value=fake_result)}):
            engine._poll_once()  # real POST sentinel/tasks/next, real accept, mocked tool run, real POST .../result
            for _ in range(100):
                if not engine._active_count():
                    break
                time.sleep(0.05)
        self.assertEqual(engine._active_count(), 0)

        task.refresh_from_db()
        self.assertEqual(task.status, 'done')
        self.assertEqual(task.result, {'outcome': 'done', **fake_result})

        # The same conversion sentinel_dispatch.try_nmap applies to a dispatched result, applied here by hand to prove
        # a client's real, over-the-wire report lands in the same place a locally-run nmap pass would.
        from cveFeed.nmap_scan import persist_inventory
        inventory = [{'ip': h['ip'], 'os_guess': h.get('os_guess', ''), 'os_accuracy': None, 'ports': h['ports']}
                    for h in task.result['hosts']]
        persist_inventory(inventory)
        port = IpAddress.objects.get(address='192.0.2.77').ports.get(number=22)
        self.assertEqual((port.product, port.version, port.source), ('OpenSSH', '9.6', 'nmap'))

    def test_a_persisted_token_skips_bootstrap_on_a_later_start(self):
        with mock.patch.object(client_tools, 'detect_tools', return_value=[]):
            token, server_url = client_daemon.bootstrap(self._blob_for_this_project(), 'e2e-persist-sentinel', 1)
        # A real heartbeat with the persisted token, exactly what a restarted Sentinel does before its first poll.
        client = client_daemon.httpclient.Client(server_url, token)
        out = client.call('POST', 'sentinel/heartbeat')
        self.assertIn('agent', out)
        self.assertEqual(out['agent']['status'], 'active')
