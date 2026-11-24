"""The built-in scanner's enrollment: the server writes a provisioning blob into a shared volume, the scanner redeems it, and the file goes away."""
import os
import tempfile
from datetime import timedelta
from io import StringIO
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
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
        # the blob's group is the application's (10002 in the image); here it is the test runner's own, which it may always give its own file
        env = mock.patch.dict(os.environ, {'CVENGINE_BUILTIN_SCANNER': '1', 'CVENGINE_SCANNER_BOOTSTRAP_DIR': self.dir.name,
                                           'CVENGINE_APP_GID': str(os.getgid())}, clear=False)
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
    def test_switched_off_it_does_nothing(self):
        with mock.patch.dict(os.environ, {'CVENGINE_BUILTIN_SCANNER': '0'}):
            self.assertEqual(builtin.ensure(), {'state': 'disabled', 'revoked': 0})
        self.assertFalse(SentinelEnrollment.objects.exists())
        self.assertFalse(os.path.exists(builtin.blob_path()))

    def test_it_waits_for_an_app_admin(self):
        User.objects.all().delete()
        self.assertEqual(builtin.ensure()['state'], 'no_admin')
        self.assertFalse(os.path.exists(builtin.blob_path()))

    def test_it_writes_one_private_instance_wide_blob_owned_by_the_app_admin(self):
        # 0640 with the group the scanner service is given (group_add 10002): the writer and the scanner read it, nobody else
        out = builtin.ensure()
        self.assertEqual(out['state'], 'blob_written')
        info = os.stat(builtin.blob_path())
        self.assertEqual(oct(info.st_mode & 0o777), '0o640')
        self.assertEqual(info.st_gid, builtin.blob_gid())
        self.assertEqual(os.listdir(self.dir.name), ['blob'], 'no temporary file is left behind')
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

    def assert_fails_closed(self, logs):
        self.assertFalse(os.path.exists(builtin.blob_path()))
        self.assertEqual(os.listdir(self.dir.name), [], 'no temporary file is left behind')
        self.assertFalse(SentinelEnrollment.objects.exists(), 'the enrollment whose secret was never handed over is deleted')
        self.assertTrue(any('built-in scanner: no enrollment written' in line for line in logs.output), logs.output)

    def test_a_blob_that_cannot_get_the_scanners_group_fails_closed_and_is_never_world_readable(self):
        modes = []
        real_fchmod, real_chmod = os.fchmod, os.chmod
        with mock.patch('os.fchown', side_effect=PermissionError(1, 'Operation not permitted')), \
                mock.patch('os.fchmod', side_effect=lambda fd, mode: (modes.append(mode), real_fchmod(fd, mode))), \
                mock.patch('os.chmod', side_effect=lambda path, mode, **kw: (modes.append(mode), real_chmod(path, mode, **kw))), \
                self.assertLogs('agentapi.builtin_scanner', 'ERROR') as logs, self.assertRaises(builtin.BlobPermissionError):
            builtin.ensure()
        self.assertFalse([m for m in modes if m & 0o007], 'no mode readable by others is ever set')
        self.assert_fails_closed(logs)

    def test_a_blob_that_does_not_come_out_0640_fails_closed(self):
        # the group is set but the mode does not take (a file system that ignores it): the check after the write refuses it
        with mock.patch('os.fchmod'), self.assertLogs('agentapi.builtin_scanner', 'ERROR') as logs, \
                self.assertRaises(builtin.BlobPermissionError):
            builtin.ensure()
        self.assert_fails_closed(logs)

    def test_after_a_refusal_the_next_run_writes_the_blob(self):
        with mock.patch('os.fchown', side_effect=PermissionError(1, 'Operation not permitted')), self.assertLogs('agentapi.builtin_scanner', 'ERROR'), \
                self.assertRaises(builtin.BlobPermissionError):
            builtin.ensure()
        self.assertEqual(builtin.ensure()['state'], 'blob_written')
        self.assertEqual(oct(os.stat(builtin.blob_path()).st_mode & 0o777), '0o640')
        self.assertEqual(SentinelEnrollment.objects.count(), 1)


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
        with mock.patch.dict(os.environ, {'CVENGINE_BUILTIN_SCANNER': '0'}):
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


class StartupEnrollmentTests(TestCase):
    """The first blob does not wait for beat: celery's entrypoint asks for it once migrations are applied, and that call can never stop the container."""
    ENTRYPOINT = Path(__file__).resolve().parent.parent / 'celery-entrypoint.sh'

    def test_the_celery_entrypoint_ensures_the_enrollment_non_fatally_after_the_migrate_wait(self):
        text = self.ENTRYPOINT.read_text()
        line = 'python3 manage.py ensure_builtin_scanner >/dev/null 2>&1 || true'
        self.assertEqual(text.count(line), 1)
        self.assertGreater(text.index(line), text.index('until python3 manage.py migrate --check'))
        self.assertLess(text.index(line), text.index('collectstatic'))

    def test_the_command_does_nothing_while_the_switch_is_off(self):
        out = StringIO()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {'CVENGINE_SCANNER_BOOTSTRAP_DIR': tmp, 'CVENGINE_BUILTIN_SCANNER': '0'}):
            User.objects.create_superuser('root-admin', 'a@example.test', 'x')
            call_command('ensure_builtin_scanner', stdout=out)
            self.assertEqual(os.listdir(tmp), [])
        self.assertEqual(out.getvalue().strip(), 'built-in scanner: disabled')
        self.assertFalse(Agent.objects.exists())
        self.assertFalse(SentinelEnrollment.objects.exists())
