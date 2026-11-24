"""The credit to MailFail by Black Hills Information Security on the hygiene activity card. The email-security checks adapted from
MailFail run on a Sentinel (``cvengine_scanner.probes.mailfail``); the server keeps the credit line (``cveFeed.mailfail.CREDIT``)."""
from django.test import TestCase
from django.utils import timezone

from cveFeed import hygiene as hy
from cveFeed import mailfail as mf
from cveFeed.models import AgentActivity
from dashboard.models import Org, Project
from targetApp.models import Domain
from tests import hygiene_harness


class ActivityCreditTests(TestCase):
	def test_the_activity_card_credits_mailfail_while_and_after_it_runs(self):
		now = timezone.now()
		project = Project.objects.create(name='Acme', slug='acme', insert_date=now, org=Org.objects.create(name='Acme', slug='acme-org'))
		domain = Domain.objects.create(name='acme.example', project=project, insert_date=now)
		credited = [hy.Finding('mx_direct_send', hy.MEDIUM, 'Microsoft 365 mail: check that Direct Send is turned off', 'Read from MX only.',
		                       'acme.example', {'mx': ['acme-example.mail.protection.outlook.com'], 'credit': mf.CREDIT})]
		hygiene_harness.run_hygiene(domain.id, probe=lambda host, port: None, emailer=lambda name: (credited, True), mx=lambda n, t: False)
		entry = AgentActivity.objects.filter(kind='hygiene', message__contains='MailFail').latest('id')
		self.assertEqual(entry.status, 'done')
		self.assertIn('Black Hills Information Security', entry.message)
		self.assertIn('acme.example: 1 issue', entry.message)
		self.assertEqual(entry.detail['credit'], mf.CREDIT)
