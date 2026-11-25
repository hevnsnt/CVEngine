"""Malformed values found by the N3b fuzz run answer 400, not 500.

An id that is not a whole number (``NaN``, a list, an object) on the scan start and hygiene run routes, and a YAML date that is not a real
date (``2026-13-45``) in a template or in secret scan rules, raised ``ValueError`` or ``TypeError`` inside the handler, which the server
answered with a 500 and an error log line. Each is the caller's mistake and now gets a 400 that says what is wrong.
"""
from unittest import mock

import yaml
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import secret_rules, templategen
from cveFeed.safeyaml import load_template
from dashboard.models import Org, Project, ProjectMembership
from targetApp.models import Domain
from tests.test_agentapi import call, create_token

BAD_IDS = ('NaN', 'abc', [1], {'a': 1}, 1e999)


class MalformedIdTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		project = Project.objects.create(name='Fz', slug='fz', insert_date=timezone.now(), org=Org.objects.create(name='Fz', slug='fz'))
		cls.domain = Domain.objects.create(name='fz.example.com', project=project, insert_date=timezone.now())
		user = User.objects.create_user('fz-user', password='x')
		ProjectMembership.objects.create(user=user, project=project, role='admin')
		cls.tok = create_token(user, 'fz')[1]

	def test_a_scan_start_with_an_id_that_is_not_a_number_is_a_400(self):
		for bad in BAD_IDS:
			with self.subTest(target_id=bad):
				status, data = call(self.tok, 'POST', '/api/v1/projects/fz/scans', {'target_id': bad})
				self.assertEqual(status, 400, data)
				self.assertIn('target_id', data['error'])
			with self.subTest(engine_id=bad):
				status, data = call(self.tok, 'POST', '/api/v1/projects/fz/scans', {'target_id': self.domain.id, 'engine_id': bad})
				self.assertEqual(status, 400, data)
				self.assertIn('engine_id', data['error'])

	def test_a_hygiene_run_with_an_id_that_is_not_a_number_is_a_400(self):
		with mock.patch('cveFeed.tasks.run_hygiene_task.delay') as queued:
			for bad in BAD_IDS:
				with self.subTest(target_id=bad):
					status, data = call(self.tok, 'POST', '/api/v1/projects/fz/hygiene/run', {'target_id': bad})
					self.assertEqual(status, 400, data)
					self.assertIn('target_id', data['error'])
			queued.assert_not_called()
			status, _ = call(self.tok, 'POST', '/api/v1/projects/fz/hygiene/run', {'target_id': self.domain.id})
			self.assertIn(status, (200, 202))


class UnbuildableYamlTests(SimpleTestCase):
	def test_a_date_that_is_not_a_date_is_invalid_yaml_for_a_template(self):
		with self.assertRaises(yaml.YAMLError):
			load_template('id: x\ninfo:\n  date: 2026-13-45\n')
		ok, reason = templategen.static_check('id: CVE-2099-0001\ninfo:\n  date: 2026-13-45\n')
		self.assertFalse(ok)
		self.assertIn('invalid YAML', reason)

	def test_a_date_that_is_not_a_date_is_invalid_yaml_for_secret_rules(self):
		with self.assertRaises(secret_rules.RulesError) as caught:
			secret_rules.check_rules('rules:\n  - id: x\n    date: 2026-13-45\n')
		self.assertIn('not valid YAML', str(caught.exception))

	def test_a_real_date_still_loads(self):
		self.assertEqual(str(load_template('d: 2026-01-02\n')['d']), '2026-01-02')
