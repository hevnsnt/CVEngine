import os
import re

from django.test import SimpleTestCase, TestCase

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


def read(*parts):
	with open(os.path.join(REPO, *parts), encoding='utf-8') as handle:
		return handle.read()


class NginxTests(SimpleTestCase):
	def test_body_size_is_small_and_tls13_is_on(self):
		conf = read('config', 'nginx', 'rengine.conf')
		size = re.search(r'client_max_body_size\s+(\d+)([MKG])', conf)
		self.assertEqual(size.group(2), 'M')
		self.assertLessEqual(int(size.group(1)), 8)
		self.assertRegex(conf, r'ssl_protocols\s+TLSv1\.2 TLSv1\.3;')
		self.assertIn('client_body_timeout', conf)

	def test_scan_results_are_served_sandboxed_and_not_sniffed(self):
		conf = read('config', 'nginx', 'rengine.conf')
		block = conf[conf.index('location /protected_media/'):]
		block = block[:block.index('}')]
		self.assertIn('sandbox', block)
		self.assertIn('nosniff', block)


class ScriptTests(SimpleTestCase):
	def test_the_entrypoint_no_longer_downloads_a_template_from_a_branch(self):
		entry = read('web', 'celery-entrypoint.sh')
		self.assertNotIn('wget', entry)
		self.assertNotIn('raw.githubusercontent.com', entry)

	def test_secret_bearing_files_are_created_private(self):
		self.assertIn('umask 077', read('scripts', 'upgrade-postgres.sh'))
		self.assertIn('umask 077; cp .env.example .env', read('scripts', 'init-env.sh'))

	def test_the_installer_uses_a_private_temp_file_and_does_not_carry_the_environment(self):
		script = read('install.sh')
		self.assertNotIn('/tmp/get-docker.sh', script)
		self.assertIn('mktemp', script)
		self.assertNotIn('sudo -E', script)
		self.assertIn('-checkhost', script)
		self.assertNotIn('grep -qF "$host"', script)


class WorkflowTests(SimpleTestCase):
	def test_workflows_run_with_least_privilege_and_guard_their_inputs(self):
		self.assertRegex(read('.github', 'workflows', 'build-pr.yml'), r'(?m)^permissions:\n  contents: read')
		self.assertIn('Releases are cut from master', read('.github', 'workflows', 'release.yml'))
		cleanup = read('.github', 'workflows', 'branch-cleanup.yml')
		self.assertIn('Refusing to delete', cleanup)
		self.assertIn('not a plain branch name', cleanup)


class ComposeTests(SimpleTestCase):
	def test_the_proxy_reads_scan_results_but_cannot_write_them(self):
		compose = read('docker-compose.yml')
		proxy = compose[compose.index('\n  proxy:'):]
		self.assertIn('scan_results:/usr/src/scan_results:ro', proxy)

	def test_the_development_web_port_is_loopback_only(self):
		self.assertIn('"127.0.0.1:8000:8000"', read('docker-compose.dev.yml'))


class TemplateRefreshScheduleTests(TestCase):
	def test_the_nuclei_template_refresh_runs_every_six_hours_unless_an_admin_changed_it(self):
		import importlib

		from django_celery_beat.models import CrontabSchedule, PeriodicTask
		migration = importlib.import_module('cveFeed.migrations.0079_nuclei_templates_every_six_hours')
		task = PeriodicTask.objects.get(name='cvengine-nuclei-templates')
		self.assertEqual(task.crontab.hour, '4,10,16,22')  # the migration already ran on the test database
		daily, _ = CrontabSchedule.objects.get_or_create(minute='41', hour='4', day_of_week='*', day_of_month='*', month_of_year='*')
		task.crontab = daily
		task.save()
		from django.apps import apps
		migration.every_six_hours(apps, None)
		task.refresh_from_db()
		self.assertEqual(task.crontab.hour, '4,10,16,22')
		custom = CrontabSchedule.objects.create(minute='5', hour='1', day_of_week='*', day_of_month='*', month_of_year='*')
		task.crontab = custom
		task.save()
		migration.every_six_hours(apps, None)
		task.refresh_from_db()
		self.assertEqual(task.crontab.hour, '1')


class FieldKeyDeliveryTests(SimpleTestCase):
	def test_the_key_is_generated_for_new_installs_and_rotation_is_a_make_target(self):
		self.assertIn('CVENGINE_FIELD_KEY=', read('.env.example'))
		self.assertIn('fill CVENGINE_FIELD_KEY', read('scripts', 'init-env.sh'))
		self.assertIn('rotate-field-key:', read('Makefile'))
		self.assertIn('rotate_field_key', read('scripts', 'rotate-field-key.sh'))


class RedisPasswordTests(SimpleTestCase):
	def test_every_service_reaches_redis_with_the_password_and_redis_requires_it(self):
		for name in ('docker-compose.yml', 'docker-compose.dev.yml'):
			text = read(name)
			self.assertNotIn('redis://redis:6379', text, name)  # no client left on the open URL
			self.assertGreaterEqual(text.count('redis://:${REDIS_PASSWORD:-}@redis:6379/0'), 6, name)
			self.assertIn('--requirepass', text, name)
			self.assertIn('REDIS_PASSWORD=${REDIS_PASSWORD:-}', text, name)  # reaches the redis container

	def test_new_installs_get_a_password_and_old_ones_have_a_deliberate_switch(self):
		self.assertIn('REDIS_PASSWORD=', read('.env.example'))
		self.assertIn('fill REDIS_PASSWORD', read('scripts', 'init-env.sh'))
		self.assertIn('redis-auth:', read('Makefile'))
		script = read('scripts', 'enable-redis-auth.sh')
		self.assertIn('--force-recreate', script)
		self.assertIn('REDIS_PASSWORD', script)
		# the updater must never recreate the broker, so the switch cannot happen half way through an update
		for name in ('update.sh', 'apply-update.sh'):
			self.assertIn('--no-recreate db redis', read('scripts', name))

	def test_the_backup_docs_keep_the_keys_apart_from_the_dumps(self):
		text = read('docs', 'DEPLOYMENT.md')
		self.assertNotIn('Back up the database, `.env` and the secret file together', text)
		self.assertIn('keep the keys apart from the dump', text)


class CertificateAuthorityTests(SimpleTestCase):
	def test_a_new_ca_key_is_encrypted_private_and_the_password_stays_off_command_lines(self):
		script = read('certs', 'entrypoint.sh')
		self.assertIn('openssl genrsa -aes256 -passout env:AUTHORITY_PASSWORD -out ca.key', script)
		self.assertIn('umask 077', script)
		self.assertNotIn('pass:${AUTHORITY_PASSWORD}', script)
		self.assertEqual(script.count('-passin env:AUTHORITY_PASSWORD'), 2)  # signing the leaf and creating the CA certificate


class UpdateWatcherTests(SimpleTestCase):
	def test_the_installer_and_the_updater_installer_set_up_the_watcher_not_a_five_minute_poll(self):
		installer = read('scripts', 'install-updater.sh')
		self.assertIn('* * * * *', installer)
		self.assertIn('update-watch.sh', installer)
		self.assertNotIn('*/5', installer)
		self.assertIn('install-updater.sh', read('install.sh'))  # an install that forgets it makes Approve do nothing
		self.assertIn('cvengine-auto-deploy', read('install.sh'))  # and stays out of the way of automatic deployment

	def test_the_watcher_loops_backs_off_and_heartbeats(self):
		watcher = read('scripts', 'update-watch.sh')
		for needle in ('update-state.py heartbeat', 'flock -n 8', 'scripts/apply-update.sh', 'pause=15', 'pause=30'):
			self.assertIn(needle, watcher)


class SeedDeliveryTests(SimpleTestCase):
	def test_the_seed_is_never_committed_and_has_a_make_target_and_a_publisher(self):
		self.assertIn('web/cve-seed*', read('.gitignore'))
		self.assertIn('export-cve-seed:', read('Makefile'))
		script = read('scripts', 'publish-cve-seed.sh')
		self.assertIn('--clobber', script)
		self.assertIn('manifest.json', script)
