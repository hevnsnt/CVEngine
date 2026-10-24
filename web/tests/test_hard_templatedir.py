import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from django.apps import apps
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from cveFeed import templategen

WEB = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class DirectoryRuleTests(unittest.TestCase):
	"""Verdict 11: generated templates never live where the blanket nuclei pass loads them."""

	def test_apart_is_fine(self):
		self.assertEqual(templategen.templates_dir_problem('/root/cvengine-generated-templates', '/root/nuclei-templates'), '')
		self.assertEqual(templategen.templates_dir_problem('/data/generated', '/data/nuclei'), '')

	def test_a_generated_dir_inside_the_root_is_refused(self):
		for generated in ('/root/nuclei-templates/generated', '/root/nuclei-templates', '/root/nuclei-templates/http/cves/x'):
			self.assertIn('inside the nuclei templates directory', templategen.templates_dir_problem(generated, '/root/nuclei-templates'), generated)

	def test_a_root_inside_the_generated_dir_is_refused(self):
		self.assertIn('factory reset', templategen.templates_dir_problem('/root', '/root/nuclei-templates'))

	def test_a_name_that_only_shares_a_prefix_is_not_inside(self):
		self.assertEqual(templategen.templates_dir_problem('/root/nuclei-templates-generated', '/root/nuclei-templates'), '')

	def test_a_symlink_into_the_root_is_followed(self):
		with tempfile.TemporaryDirectory() as base:
			root = os.path.join(base, 'root')
			os.makedirs(root)
			link = os.path.join(base, 'link')
			os.symlink(root, link)
			self.assertIn('inside the nuclei templates directory', templategen.templates_dir_problem(link, root))

	def test_dot_dot_segments_are_resolved(self):
		self.assertIn('inside', templategen.templates_dir_problem('/root/nuclei-templates/../nuclei-templates/g', '/root/nuclei-templates'))

	def test_the_defaults_are_apart(self):
		self.assertEqual(templategen.templates_dir_problem(), '')


class SaveGuardTests(SimpleTestCase):
	def test_nothing_is_written_when_the_directories_overlap(self):
		with tempfile.TemporaryDirectory() as root:
			with mock.patch.object(templategen, 'TEMPLATES_ROOT', root), mock.patch.object(templategen, 'GENERATED_DIR', os.path.join(root, 'gen')):
				with self.assertRaises(RuntimeError):
					templategen.save_template_file('cve-2099-1', 'id: x')
			self.assertEqual(os.listdir(root), [])


class StartupCheckTests(SimpleTestCase):
	def test_the_app_refuses_to_start_with_overlapping_directories(self):
		config = apps.get_app_config('cveFeed')
		with mock.patch.object(templategen, 'GENERATED_DIR', '/root/nuclei-templates/gen'), mock.patch.object(templategen, 'TEMPLATES_ROOT', '/root/nuclei-templates'):
			with self.assertRaises(ImproperlyConfigured):
				config.ready()
		config.ready()  # and starts normally otherwise

	def test_a_bad_environment_stops_django_at_setup(self):
		env = {**os.environ, 'CVENGINE_GENERATED_TEMPLATES_DIR': '/root/nuclei-templates/generated', 'NUCLEI_TEMPLATES_DIR': '/root/nuclei-templates'}
		proc = subprocess.run([sys.executable, '-c', 'import django; django.setup()'], cwd=WEB, env=env, capture_output=True, text=True, timeout=120)
		self.assertNotEqual(proc.returncode, 0)
		self.assertIn('inside the nuclei templates directory', proc.stderr)
