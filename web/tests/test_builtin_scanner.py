"""The built-in scanner's enrollment: the server writes a provisioning blob into a shared volume, the scanner redeems it, and the file goes away."""
import os
import tempfile
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import builtin_scanner as builtin
from agentapi import sentinel_broker as broker
from agentapi.models import Agent, SentinelEnrollment
from tests.test_agentapi import call


class BuiltinBase(TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        env = mock.patch.dict(os.environ, {'CVENGINE_BUILTIN_SCANNER': '1', 'CVENGINE_SCANNER_BOOTSTRAP_DIR': self.dir.name}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        self.admin = User.objects.create_superuser('root-admin', 'a@example.test', 'x')

    def blob(self):
        with open(builtin.blob_path(), encoding='utf-8') as handle:
            return broker.decode_enrollment_blob(handle.read())

    def redeem(self, **extra):
        payload = self.blob()
        status, out = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': payload['enrollment_token'], 'name': 'whatever-the-container-says',
                                                                        'capabilities': ['nmap'], **extra})
        self.assertIn(status, (200, 201), out)
        return out


class EnsureTests(BuiltinBase):
    def test_off_by_default_it_does_nothing(self):
        with mock.patch.dict(os.environ, {'CVENGINE_BUILTIN_SCANNER': ''}):
            self.assertEqual(builtin.ensure(), {'state': 'disabled'})
        self.assertFalse(SentinelEnrollment.objects.exists())
        self.assertFalse(os.path.exists(builtin.blob_path()))

    def test_it_waits_for_an_app_admin(self):
        User.objects.all().delete()
        self.assertEqual(builtin.ensure()['state'], 'no_admin')
        self.assertFalse(os.path.exists(builtin.blob_path()))

    def test_it_writes_one_private_instance_wide_blob_owned_by_the_app_admin(self):
        out = builtin.ensure()
        self.assertEqual(out['state'], 'blob_written')
        self.assertEqual(oct(os.stat(builtin.blob_path()).st_mode & 0o777), '0o600')
        payload = self.blob()
        self.assertEqual(payload['scope'], 'instance')
        self.assertEqual(payload['server_url'], 'http://web:8000')
        row = SentinelEnrollment.objects.get()
        self.assertTrue(row.builtin)
        self.assertEqual(row.created_by, self.admin)
        self.assertGreater(row.expires_at, timezone.now() + timedelta(hours=23))
        self.assertNotIn(payload['enrollment_token'], row.token_hash)  # only the hash is stored

    def test_a_good_unredeemed_blob_is_left_alone(self):
        builtin.ensure()
        first = self.blob()
        self.assertEqual(builtin.ensure()['state'], 'waiting')
        self.assertEqual(self.blob(), first)
        self.assertEqual(SentinelEnrollment.objects.count(), 1)

    def test_a_blob_close_to_expiry_is_replaced_and_the_old_secret_dies(self):
        builtin.ensure()
        old = self.blob()['enrollment_token']
        SentinelEnrollment.objects.update(expires_at=timezone.now() + timedelta(minutes=30))
        self.assertEqual(builtin.ensure()['state'], 'blob_written')
        self.assertNotEqual(self.blob()['enrollment_token'], old)
        self.assertEqual(SentinelEnrollment.objects.count(), 1)  # the stale one is gone, never valid beside the new one

    def test_a_missing_file_is_written_again(self):
        builtin.ensure()
        os.remove(builtin.blob_path())
        self.assertEqual(builtin.ensure()['state'], 'blob_written')

    def test_the_server_url_can_be_overridden(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SCANNER_SERVER_URL': 'https://scanner-host.example.test'}):
            builtin.ensure()
        self.assertEqual(self.blob()['server_url'], 'https://scanner-host.example.test')


class RedeemTests(BuiltinBase):
    def test_redeeming_it_enrolls_the_scanner_under_the_fixed_name_at_instance_scope(self):
        builtin.ensure()
        self.redeem()
        agent = Agent.objects.get()
        self.assertEqual(agent.name, builtin.NAME)  # not what the container called itself
        self.assertEqual(agent.kind, 'scanner')
        self.assertTrue(agent.scope['instance'])
        self.assertEqual(builtin.builtin_agent().pk, agent.pk)

    def test_the_blob_is_single_use_and_is_removed_on_the_next_run(self):
        builtin.ensure()
        payload = self.blob()
        self.redeem()
        status, _ = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': payload['enrollment_token'], 'name': 'again'})
        self.assertEqual(status, 403)
        self.assertEqual(builtin.ensure()['state'], 'enrolled')
        self.assertFalse(os.path.exists(builtin.blob_path()))

    def test_a_scanner_that_was_revoked_gets_a_fresh_blob(self):
        builtin.ensure()
        self.redeem()
        agent = builtin.builtin_agent()
        agent.token.revoked = True
        agent.token.save(update_fields=['revoked'])
        out = builtin.ensure()
        self.assertEqual(out['state'], 'blob_written')
        self.assertTrue(os.path.exists(builtin.blob_path()))

    def test_a_person_enrollment_never_gets_the_fixed_name(self):
        status, out = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': 'cvs_not-real', 'name': builtin.NAME})
        self.assertEqual(status, 403)

    def test_status_reports_enrolled_and_whether_it_is_heard_from(self):
        self.assertEqual(builtin.status(), {'enabled': True, 'enrolled': False})
        builtin.ensure()
        self.redeem()
        self.assertFalse(builtin.status()['live'])
        Agent.objects.update(last_seen=timezone.now())
        self.assertTrue(builtin.status()['live'])
        with mock.patch.dict(os.environ, {'CVENGINE_BUILTIN_SCANNER': ''}):
            self.assertEqual(builtin.status(), {'enabled': False})


class OwnerLifecycleTests(BuiltinBase):
    """The scanner's token belongs to the App Admin that owned the enrollment: losing that user must not strand the scanner."""

    def test_a_scanner_whose_owner_was_disabled_gets_a_new_enrollment_under_another_admin(self):
        builtin.ensure()
        self.redeem()
        second = User.objects.create_superuser('second-admin', 'b@example.test', 'x')
        self.admin.is_active = False
        self.admin.save(update_fields=['is_active'])
        out = builtin.ensure()
        self.assertEqual(out['state'], 'blob_written')
        self.assertEqual(SentinelEnrollment.objects.get(used_at__isnull=True).created_by, second)

    def test_with_no_other_active_admin_it_says_so_and_writes_nothing(self):
        builtin.ensure()
        self.redeem()
        self.admin.is_active = False
        self.admin.save(update_fields=['is_active'])
        os.remove(builtin.blob_path()) if os.path.exists(builtin.blob_path()) else None
        self.assertEqual(builtin.ensure()['state'], 'no_admin')
        self.assertFalse(os.path.exists(builtin.blob_path()))

    def test_a_scanner_whose_owner_must_enrol_in_two_step_sign_in_is_replaced_too(self):
        builtin.ensure()
        self.redeem()
        User.objects.create_superuser('second-admin', 'b@example.test', 'x')
        with mock.patch('tenancy.middleware.TenancyMiddleware.must_enrol_mfa', side_effect=lambda user: user.pk == self.admin.pk):
            self.assertEqual(builtin.ensure()['state'], 'blob_written')

    def test_a_suspended_scanner_is_an_administrators_decision_and_is_not_resurrected(self):
        builtin.ensure()
        self.redeem()
        Agent.objects.update(status='suspended')
        self.assertEqual(builtin.ensure()['state'], 'enrolled')
        self.assertFalse(os.path.exists(builtin.blob_path()))
