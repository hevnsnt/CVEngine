"""Scope changes while a background scan waits for memory must precede process admission."""
from contextlib import contextmanager
from unittest import mock

from django.contrib.auth.models import User
from django.utils import timezone

from agentapi.host_manage import exclude_host
from agentapi.services import Ctx
from cveFeed import fullscan, nmap_scan
from cveFeed.models import HostExclusion, HostState
from dashboard.models import Org, OrgMembership, Project
from startScan.models import Subdomain
from targetApp.models import Domain
from tests.test_fullscan import FullScanBase


class FullScanRevocationTests(FullScanBase):
    def setUp(self):
        super().setUp()
        self.address = '192.0.2.71'
        self.host = 'revoked.fs.test'
        self.address_row = self.ip(self.address, name=self.host)
        self.actor = User.objects.create_user('scope-owner')
        OrgMembership.objects.create(user=self.actor, org=self.project.org, role='admin')

    def _exclude(self):
        exclude_host(Ctx(self.actor), self.project.slug, self.host)

    def _run_after_wait(self, transition, runner=fullscan._sweep_runner):
        @contextmanager
        def admission(*args, **kwargs):
            transition()  # Simulates a committed scope change while the job waited.
            yield mock.Mock()

        process = mock.Mock()
        process.communicate.return_value = ('<nmaprun/>', '')
        with mock.patch('reNgine.resources.heavy_job', admission), \
                mock.patch('cveFeed.nmap_scan.subprocess.Popen', return_value=process) as popen:
            try:
                return runner([self.address], nmap_scan.FULL_PORT_FLAGS, '1m'), popen
            except Exception:
                popen.assert_not_called()
                raise

    def test_exclusion_after_selection_prevents_process_start(self):
        self.assertTrue(fullscan.in_scope(self.address_row))
        with self.assertRaisesMessage(ValueError, 'no longer in scope'):
            self._run_after_wait(self._exclude)
        self.assertTrue(HostExclusion.objects.filter(org=self.project.org, host=self.host).exists())

    def test_deleted_inventory_prevents_process_start(self):
        with self.assertRaisesMessage(ValueError, 'no longer in scope'):
            self._run_after_wait(lambda: Subdomain.objects.filter(target_domain=self.domain).delete())

    def test_archiving_after_selection_prevents_process_start(self):
        def archive():
            HostState.objects.create(project=self.project, domain=self.domain, host=self.host,
                                     fingerprint='fixture', archived_at=timezone.now())
        with self.assertRaisesMessage(ValueError, 'no longer in scope'):
            self._run_after_wait(archive)

    def test_new_cdn_state_prevents_process_start(self):
        def revoke():
            type(self.address_row).objects.filter(pk=self.address_row.pk).update(is_cdn=True)
        with self.assertRaisesMessage(ValueError, 'no longer in scope'):
            self._run_after_wait(revoke)

    def test_unchanged_authority_still_launches(self):
        output, popen = self._run_after_wait(lambda: None)
        self.assertEqual(output, '<nmaprun/>')
        popen.assert_called_once()

    def test_other_org_can_independently_authorize_shared_ip(self):
        org = Org.objects.create(name='Other', slug='other-scope')
        project = Project.objects.create(name='Other', slug='other-scope', org=org, insert_date=timezone.now())
        domain = Domain.objects.create(name='other.test', project=project, insert_date=timezone.now())
        sub = Subdomain.objects.create(target_domain=domain, name='allowed.other.test')
        sub.ip_addresses.add(self.address_row)
        _, popen = self._run_after_wait(self._exclude)
        popen.assert_called_once()

    def test_exclusion_lookup_failure_prevents_process_start(self):
        with mock.patch('cveFeed.models.HostExclusion.objects.filter', side_effect=RuntimeError('lookup unavailable')):
            with self.assertRaisesMessage(RuntimeError, 'lookup unavailable'):
                self._run_after_wait(lambda: None)

    def test_fingerprint_followup_rechecks_after_its_own_wait(self):
        with self.assertRaisesMessage(ValueError, 'no longer in scope'):
            self._run_after_wait(self._exclude, runner=fullscan._fingerprint_runner)
