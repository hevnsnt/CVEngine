"""Scope changes while a background scan waits must be seen before its work is sent to a scanner."""
from unittest import mock

from django.contrib.auth.models import User
from django.utils import timezone

from agentapi.host_manage import exclude_host
from agentapi.services import Ctx
from cveFeed import fullscan
from cveFeed.models import HostExclusion, HostState
from dashboard.models import Org, OrgMembership, Project
from startScan.models import Subdomain
from targetApp.models import Domain
from startScan.models import IpAddress
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

    def _run_after_change(self, transition, step=None, row=None):
        """Change the scope, then ask for the sweep (or the follow-up pass): the scope is read again right before the work goes to a scanner."""
        transition()  # a committed scope change while the work waited
        step = step or fullscan._sentinel_sweep
        row = row or self.address_row
        with mock.patch('agentapi.sentinel_dispatch.try_nmap_full', return_value=[]) as sweep, \
                mock.patch('agentapi.sentinel_dispatch.try_nmap_verify', return_value=[]) as verify:
            args = (row, None) if step is fullscan._sentinel_sweep else (row, None, [22])
            try:
                return step(*args), sweep, verify
            except Exception:
                sweep.assert_not_called()
                verify.assert_not_called()
                raise

    def test_exclusion_after_selection_prevents_the_work_from_being_sent(self):
        self.assertTrue(fullscan.in_scope(self.address_row))
        with self.assertRaisesMessage(ValueError, 'no longer in scope'):
            self._run_after_change(self._exclude)
        self.assertTrue(HostExclusion.objects.filter(org=self.project.org, host=self.host).exists())

    def test_deleted_inventory_prevents_the_work_from_being_sent(self):
        with self.assertRaisesMessage(ValueError, 'no longer in scope'):
            self._run_after_change(lambda: Subdomain.objects.filter(target_domain=self.domain).delete())

    def test_archiving_after_selection_prevents_the_work_from_being_sent(self):
        def archive():
            HostState.objects.create(project=self.project, domain=self.domain, host=self.host,
                                     fingerprint='fixture', archived_at=timezone.now())
        with self.assertRaisesMessage(ValueError, 'no longer in scope'):
            self._run_after_change(archive)

    def test_new_cdn_state_prevents_the_work_from_being_sent(self):
        def revoke():
            type(self.address_row).objects.filter(pk=self.address_row.pk).update(is_cdn=True)
        with self.assertRaisesMessage(ValueError, 'no longer in scope'):
            self._run_after_change(revoke)

    def test_unchanged_authority_still_sends_the_work(self):
        hosts, sweep, _verify = self._run_after_change(lambda: None)
        self.assertEqual(hosts, [])
        sweep.assert_called_once()

    def test_other_org_can_independently_authorize_shared_ip(self):
        org = Org.objects.create(name='Other', slug='other-scope')
        project = Project.objects.create(name='Other', slug='other-scope', org=org, insert_date=timezone.now())
        domain = Domain.objects.create(name='other.test', project=project, insert_date=timezone.now())
        sub = Subdomain.objects.create(target_domain=domain, name='allowed.other.test')
        other_row = IpAddress.objects.create(address=self.address, org=org)  # the other organization's own row for the same address
        sub.ip_addresses.add(other_row)
        _, sweep, _verify = self._run_after_change(self._exclude, row=other_row)  # excluding the host in the first organization does not touch it
        sweep.assert_called_once()

    def test_exclusion_lookup_failure_prevents_the_work_from_being_sent(self):
        with mock.patch('cveFeed.models.HostExclusion.objects.filter', side_effect=RuntimeError('lookup unavailable')):
            with self.assertRaisesMessage(RuntimeError, 'lookup unavailable'):
                self._run_after_change(lambda: None)

    def test_fingerprint_followup_rechecks_after_its_own_wait(self):
        with self.assertRaisesMessage(ValueError, 'no longer in scope'):
            self._run_after_change(self._exclude, step=fullscan._sentinel_fingerprint)
