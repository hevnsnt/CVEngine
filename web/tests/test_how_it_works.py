import re

from django.conf import settings
from django.test import TestCase

from cveFeed.views import HOW_REVIEWED_VERSION
from tests.test_tenancy import client_for
from django.contrib.auth.models import User


class HowItWorksTests(TestCase):
	def test_page_is_reviewed_for_the_current_release(self):
		# The marketing page makes claims about the pipeline. Whoever moves web/.version must reread cveFeed/how.html and bump
		# HOW_REVIEWED_VERSION in cveFeed/views.py; a pre-release suffix such as -dev does not count as a new version.
		current = re.sub(r'-.*$', '', settings.RENGINE_CURRENT_VERSION)
		self.assertEqual(HOW_REVIEWED_VERSION, current, 'Reread web/cveFeed/templates/cveFeed/how.html and bump HOW_REVIEWED_VERSION in cveFeed/views.py')

	def test_page_opens_for_any_signed_in_user_and_shows_the_version(self):
		r = client_for(User.objects.create_user('reader', password='x')).get('/cve/how-it-works/')
		self.assertContains(r, 'How cvENGINE works')
		self.assertContains(r, f'Reviewed for version {HOW_REVIEWED_VERSION}')
