import os
import re
import shutil
import stat
import subprocess
import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase

from cveFeed.management.commands.create_admin import generate_password
from dashboard.models import UserProfile

ROOT = Path(__file__).resolve().parents[2]


def run(*args, env=None):
	out = StringIO()
	with mock.patch.dict(os.environ, {'DJANGO_SUPERUSER_PASSWORD': '', 'DJANGO_SUPERUSER_USERNAME': '', 'DJANGO_SUPERUSER_EMAIL': '',
	                                 'DOMAIN_NAME': 'scanner.example', **(env or {})}):
		call_command('create_admin', *args, stdout=out)
	return out.getvalue()


def printed_password(output):
	return re.search(r'Password\s+: (\S+)', output).group(1)


class CreateAdminTests(TestCase):
	def test_it_makes_a_superuser_with_a_generated_password_printed_once(self):
		out = run()
		password = printed_password(out)
		user = User.objects.get(username='admin')
		self.assertTrue(user.is_superuser and user.is_staff)
		self.assertTrue(user.check_password(password))
		self.assertRegex(password, r'^[A-Za-z0-9]{20}$')
		self.assertIn('https://scanner.example/', out)
		self.assertIn('shown only here', out)
		self.assertNotIn(password, ''.join(UserProfile.objects.values_list('user__username', flat=True)))

	def test_a_generated_password_must_be_changed_at_first_sign_in(self):
		password = printed_password(run())
		self.assertTrue(UserProfile.objects.get(user__username='admin').must_change_password)
		client = Client()
		self.assertTrue(client.login(username='admin', password=password))
		response = client.get('/cve/', follow=False)
		self.assertEqual((response.status_code, response['Location']), (302, '/cve/account/'))
		self.assertEqual(client.get('/cve/api/account/me').status_code, 200)  # the account page itself stays reachable

	def test_a_password_the_owner_set_is_used_and_not_forced_to_change(self):
		out = run(env={'DJANGO_SUPERUSER_PASSWORD': 'My-Own-Strong-Pass-93'})
		self.assertTrue(User.objects.get(username='admin').check_password('My-Own-Strong-Pass-93'))
		self.assertNotIn('My-Own-Strong-Pass-93', out)  # never echoed back
		self.assertFalse(UserProfile.objects.get(user__username='admin').must_change_password)

	def test_the_example_placeholder_is_not_a_password(self):
		password = printed_password(run(env={'DJANGO_SUPERUSER_PASSWORD': 'change-me'}))
		self.assertNotEqual(password, 'change-me')
		self.assertFalse(User.objects.get(username='admin').check_password('change-me'))

	def test_a_weak_chosen_password_is_refused_and_creates_nothing(self):
		with self.assertRaisesRegex(CommandError, 'not allowed'):
			run(env={'DJANGO_SUPERUSER_PASSWORD': '12345'})
		self.assertFalse(User.objects.filter(username='admin').exists())

	def test_running_it_again_leaves_the_account_alone(self):
		first = printed_password(run())
		again = run()
		self.assertIn('already exists', again)
		self.assertNotIn('Password  :', again)
		self.assertTrue(User.objects.get(username='admin').check_password(first))

	def test_reset_gives_a_new_password_and_requires_a_change(self):
		first = printed_password(run())
		UserProfile.objects.filter(user__username='admin').update(must_change_password=False)
		second = printed_password(run('--reset'))
		user = User.objects.get(username='admin')
		self.assertNotEqual(first, second)
		self.assertTrue(user.check_password(second) and not user.check_password(first))
		self.assertTrue(UserProfile.objects.get(user=user).must_change_password)

	def test_reset_ignores_the_env_password_and_needs_an_existing_account(self):
		with self.assertRaisesRegex(CommandError, 'no account'):
			run('--reset')
		run()
		out = run('--reset', env={'DJANGO_SUPERUSER_PASSWORD': 'My-Own-Strong-Pass-93'})
		self.assertFalse(User.objects.get(username='admin').check_password('My-Own-Strong-Pass-93'))
		self.assertIn('password reset', out)

	def test_username_and_email_follow_the_env_or_the_flags(self):
		run(env={'DJANGO_SUPERUSER_USERNAME': 'owner', 'DJANGO_SUPERUSER_EMAIL': 'o@example.org'})
		self.assertEqual(User.objects.get(username='owner').email, 'o@example.org')
		run('--username', 'second')
		self.assertEqual(User.objects.get(username='second').email, 'second@localhost')

	def test_the_login_page_says_where_the_password_came_from(self):
		page = Client().get('/login/')
		self.assertEqual(page.status_code, 200)
		self.assertContains(page, 'The installer printed your admin username and password')
		self.assertContains(page, 'make admin-password')

	def test_generated_passwords_are_random_and_mixed(self):
		seen = {generate_password() for _ in range(50)}
		self.assertEqual(len(seen), 50)
		for p in seen:
			self.assertTrue(re.search('[a-z]', p) and re.search('[A-Z]', p) and re.search('[0-9]', p))


class InitEnvScriptTests(TestCase):
	def setUp(self):
		self.dir = tempfile.mkdtemp()
		self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
		(Path(self.dir) / 'scripts').mkdir()
		shutil.copy(ROOT / 'scripts' / 'init-env.sh', Path(self.dir) / 'scripts' / 'init-env.sh')
		shutil.copy(ROOT / '.env.example', Path(self.dir) / '.env.example')

	def init(self, *args, **env):
		return subprocess.run(['bash', 'scripts/init-env.sh', *args], cwd=self.dir, capture_output=True, text=True, check=True,
		                      env={**os.environ, **env}).stdout

	def env(self):
		return dict(line.split('=', 1) for line in (Path(self.dir) / '.env').read_text().splitlines() if '=' in line and not line.startswith('#'))

	def test_a_fresh_env_gets_generated_database_and_certificate_passwords(self):
		out = self.init()
		env = self.env()
		for key in ('POSTGRES_PASSWORD', 'AUTHORITY_PASSWORD'):
			self.assertRegex(env[key], r'^[A-Za-z0-9]{24}$', key)
			self.assertIn(f'Generated {key}', out)
		self.assertNotEqual(env['POSTGRES_PASSWORD'], env['AUTHORITY_PASSWORD'])
		self.assertEqual(env['DJANGO_SUPERUSER_PASSWORD'], '')  # the admin password is make admin's job
		self.assertNotEqual(env['DOMAIN_NAME'], 'cvengine.example.com')  # the example name is replaced by a detected address
		self.assertEqual(env['COMPOSE_PROJECT_NAME'], 'rengine')  # nothing else is touched
		self.assertEqual(stat.S_IMODE(os.stat(Path(self.dir) / '.env').st_mode), 0o600)

	def test_running_it_again_changes_nothing(self):
		self.init()
		before = (Path(self.dir) / '.env').read_text()
		out = self.init()
		self.assertEqual((Path(self.dir) / '.env').read_text(), before)
		self.assertNotIn('Generated', out)

	def test_a_password_the_owner_set_is_never_replaced(self):
		self.init()
		path = Path(self.dir) / '.env'
		text = path.read_text().replace(f'POSTGRES_PASSWORD={self.env()["POSTGRES_PASSWORD"]}', 'POSTGRES_PASSWORD=My$Real#Pass')
		path.write_text(text.replace('AUTHORITY_PASSWORD=' + self.env()['AUTHORITY_PASSWORD'], 'AUTHORITY_PASSWORD=change-me'))
		self.init()
		env = self.env()
		self.assertEqual(env['POSTGRES_PASSWORD'], 'My$Real#Pass')
		self.assertRegex(env['AUTHORITY_PASSWORD'], r'^[A-Za-z0-9]{24}$')  # only the placeholder was filled

	def test_an_existing_env_is_used_not_recreated(self):
		(Path(self.dir) / '.env').write_text('POSTGRES_PASSWORD=\nDOMAIN_NAME=mine.example\nAUTHORITY_PASSWORD=keepme\n')
		self.init()
		env = self.env()
		self.assertEqual((env['DOMAIN_NAME'], env['AUTHORITY_PASSWORD']), ('mine.example', 'keepme'))
		self.assertRegex(env['POSTGRES_PASSWORD'], r'^[A-Za-z0-9]{24}$')  # an empty value counts as unset

	def test_the_example_domain_becomes_the_detected_address(self):
		out = self.init(CVENGINE_DETECT_IP='10.1.2.3')
		self.assertEqual(self.env()['DOMAIN_NAME'], '10.1.2.3')
		self.assertIn('Detected the address: 10.1.2.3', out)

	def test_without_a_network_address_it_falls_back_to_localhost(self):
		self.init(CVENGINE_DETECT_IP='')
		self.assertEqual(self.env()['DOMAIN_NAME'], 'localhost')

	def test_a_domain_the_owner_set_is_kept_even_when_an_address_is_detected(self):
		(Path(self.dir) / '.env').write_text('DOMAIN_NAME=scan.example.org\nPOSTGRES_PASSWORD=x\nAUTHORITY_PASSWORD=y\n')
		self.init(CVENGINE_DETECT_IP='10.1.2.3')
		self.assertEqual(self.env()['DOMAIN_NAME'], 'scan.example.org')

	def test_an_explicit_domain_wins_and_is_validated(self):
		self.init('scanner.example.com', CVENGINE_DETECT_IP='10.1.2.3')
		self.assertEqual(self.env()['DOMAIN_NAME'], 'scanner.example.com')
		self.init('10.9.9.9')  # a later run may change it on request
		self.assertEqual(self.env()['DOMAIN_NAME'], '10.9.9.9')
		bad = subprocess.run(['bash', 'scripts/init-env.sh', 'bad name;rm'], cwd=self.dir, capture_output=True, text=True)
		self.assertNotEqual(bad.returncode, 0)
		self.assertEqual(self.env()['DOMAIN_NAME'], '10.9.9.9')
