import os
import re

from django.test import SimpleTestCase

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


def read(*parts):
	with open(os.path.join(REPO, *parts), encoding='utf-8') as handle:
		return handle.read()


class MaintenancePageTests(SimpleTestCase):
	def test_the_proxy_answers_with_the_page_while_the_flag_exists_and_when_the_app_is_down(self):
		conf = read('config', 'nginx', 'rengine.conf')
		self.assertIn('if (-f /etc/nginx/state/maintenance) { return 503; }', conf)
		self.assertRegex(conf, r'error_page\s+502 503 504 /maintenance\.html;')
		self.assertRegex(conf, r'proxy_intercept_errors\s+on;')
		block = conf[conf.index('location = /maintenance.html'):]
		block = block[:block.index('}')]
		self.assertIn('internal;', block)
		self.assertIn('no-store', block)

	def test_the_compose_file_hands_the_proxy_the_page_and_the_flag_directory(self):
		compose = read('docker-compose.yml')
		self.assertIn('./web/static/cve/maintenance.html:/usr/share/nginx/maintenance/maintenance.html:ro', compose)
		self.assertIn('./config/nginx/state:/etc/nginx/state:ro', compose)
		self.assertTrue(os.path.isdir(os.path.join(REPO, "config", "nginx", "state")))

	def test_the_flag_is_never_committed(self):
		self.assertIn('config/nginx/state/maintenance', read('.gitignore').splitlines())

	def test_the_page_needs_nothing_from_the_application(self):
		"""The application is the thing that is down: no stylesheet, script, font or image may be fetched from it (or anywhere else)."""
		page = read('web', 'static', 'cve', 'maintenance.html')
		self.assertNotRegex(page, r'<link[^>]+href=')
		self.assertNotRegex(page, r'<script[^>]+src=')
		self.assertNotRegex(page, r'<img\b')
		self.assertNotRegex(page, r'url\(\s*["\']?(https?:|/)')
		self.assertIn('rebuilding', page.lower())
		self.assertNotRegex(page, '[–—]')

	def test_an_update_sets_the_flag_after_the_build_and_always_removes_it(self):
		script = read('scripts', 'update-deploy.sh')
		steps = script[script.index('deploy_steps() {'):]
		self.assertLess(steps.index('build web celery celery-beat'), steps.index('maintenance_on'))
		self.assertLess(steps.index('maintenance_on'), steps.index('manage.py migrate --noinput'))
		wrapper = script[script.index('deploy_current() {'):script.index('deploy_steps() {')]
		self.assertIn('deploy_steps || status=$?', wrapper)
		self.assertIn('maintenance_off', wrapper)

	def test_make_up_clears_a_flag_an_interrupted_update_left_behind(self):
		up = re.search(r'^up:.*\n((?:\t.*\n)+)', read('Makefile'), re.M).group(1)
		self.assertIn('rm -f config/nginx/state/maintenance', up)

	def test_an_administrator_waiting_for_an_update_gets_the_scene_and_is_sent_back_to_the_live_page(self):
		bar = read('web', 'static', 'cve', 'updatebar.js')
		self.assertIn('new URL("maintenance.html", import.meta.url)', bar)
		self.assertIn('location.replace("/cve/")', bar)
		self.assertNotIn('location.reload()', bar)
		self.assertIn('.update-veil', read('web', 'static', 'cve', 'cve.css'))
		# framed, the page only shows what it is told; alone, it polls for the site itself
		page = read('web', 'static', 'cve', 'maintenance.html')
		self.assertIn('window.top !== window', page)
		self.assertIn('e.origin === location.origin', page)
