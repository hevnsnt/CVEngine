import logging

from django.conf import settings
from django.test import Client, TestCase


class SecuritySettingsTests(TestCase):
	def test_django_errors_are_logged_in_production(self):
		# at CRITICAL the django.request 500 tracebacks and django.security.* errors (both ERROR records) were dropped
		level = logging.getLevelName(settings.LOGGING['loggers']['django']['level'])
		self.assertLessEqual(level, logging.ERROR)
		self.assertTrue(settings.LOGGING['handlers']['celery']['backupCount'] > 0)  # a size-capped log that never rotates just stops

	def test_the_form_field_count_is_finite(self):
		self.assertIsNotNone(settings.DATA_UPLOAD_MAX_NUMBER_FIELDS)
		self.assertLessEqual(settings.DATA_UPLOAD_MAX_NUMBER_FIELDS, 10000)

	def test_login_refuses_a_flood_of_form_fields_before_parsing_them(self):
		body = '&'.join(f'a{i}=' for i in range(settings.DATA_UPLOAD_MAX_NUMBER_FIELDS + 10))
		response = Client().post('/login/', body, content_type='application/x-www-form-urlencoded')
		self.assertEqual(response.status_code, 400)
