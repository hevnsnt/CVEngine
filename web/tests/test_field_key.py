import os
from io import StringIO
from unittest import mock

from django.core.management import CommandError, call_command
from django.db import connection
from django.test import TestCase

from dashboard.models import AIProviderSettings
from reNgine import crypto_fields

KEY_A = 'a' * 40
KEY_B = 'b' * 40


def stored(row):
	with connection.cursor() as cursor:
		cursor.execute('SELECT api_key FROM dashboard_aiprovidersettings WHERE id = %s', [row.pk])
		return cursor.fetchone()[0]


class DedicatedKeyTests(TestCase):
	def test_without_a_dedicated_key_nothing_changes(self):
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': '', 'CVENGINE_FIELD_KEY_PREVIOUS': ''}):
			self.assertEqual(crypto_fields.dedicated_keys(), ())
			token = crypto_fields.encrypt_text('secret-value')
			self.assertEqual(crypto_fields.decrypt_text(token), 'secret-value')

	def test_a_dedicated_key_encrypts_and_the_old_derived_key_still_reads(self):
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': '', 'CVENGINE_FIELD_KEY_PREVIOUS': ''}):
			legacy = crypto_fields.encrypt_text('from-before')
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': KEY_A}):
			self.assertEqual(crypto_fields.decrypt_text(legacy), 'from-before')
			fresh = crypto_fields.encrypt_text('from-after')
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': '', 'CVENGINE_FIELD_KEY_PREVIOUS': ''}):
			self.assertEqual(crypto_fields.decrypt_text(fresh), '')  # the dedicated key is not in Django's secret

	def test_the_key_can_come_from_a_file_and_a_previous_key_still_decrypts(self):
		import tempfile
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': KEY_A}):
			old = crypto_fields.encrypt_text('rotating')
		with tempfile.NamedTemporaryFile('w', suffix='.key') as handle:
			handle.write(KEY_B + '\n')
			handle.flush()
			env = {'CVENGINE_FIELD_KEY': '', 'CVENGINE_FIELD_KEY_FILE': handle.name, 'CVENGINE_FIELD_KEY_PREVIOUS': KEY_A}
			with mock.patch.dict(os.environ, env):
				self.assertEqual(crypto_fields.dedicated_keys(), (KEY_B, KEY_A))
				self.assertEqual(crypto_fields.decrypt_text(old), 'rotating')

	def test_rotation_re_encrypts_every_stored_secret_under_the_new_key(self):
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': KEY_A}):
			row = AIProviderSettings.objects.create(api_key='sk-rotate-me')
			before = stored(row)
		env = {'CVENGINE_FIELD_KEY': KEY_B, 'CVENGINE_FIELD_KEY_PREVIOUS': KEY_A}
		with mock.patch.dict(os.environ, env):
			out = StringIO()
			call_command('rotate_field_key', stdout=out)
			self.assertIn('re-encrypted', out.getvalue())
			after = stored(row)
		self.assertNotEqual(before, after)
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': KEY_B, 'CVENGINE_FIELD_KEY_PREVIOUS': ''}):  # the old key is not needed now
			self.assertEqual(AIProviderSettings.objects.get(pk=row.pk).api_key, 'sk-rotate-me')

	def test_rotation_refuses_to_run_without_a_dedicated_key_and_can_generate_one(self):
		with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': '', 'CVENGINE_FIELD_KEY_PREVIOUS': ''}):
			with self.assertRaises(CommandError):
				call_command('rotate_field_key')
		out = StringIO()
		call_command('rotate_field_key', '--generate', stdout=out)
		self.assertGreaterEqual(len(out.getvalue().strip()), 40)

	def test_every_encrypted_column_is_found_for_rotation(self):
		names = {m.__name__ for m, _ in crypto_fields.encrypted_fields()}
		self.assertTrue({'AIProviderSettings', 'ApiCredential', 'UserProfile', 'Notification'} <= names)
