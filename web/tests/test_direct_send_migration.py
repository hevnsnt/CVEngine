import importlib

from django.apps import apps
from django.test import TestCase
from django.utils import timezone

from cveFeed.models import HygieneFinding, Supplier, SupplierFinding
from dashboard.models import Org, Project
from targetApp.models import Domain

migration = importlib.import_module('cveFeed.migrations.0195_resolve_untested_direct_send')


class ResolveUntestedDirectSendTests(TestCase):
	def setUp(self):
		now = timezone.now()
		self.project = Project.objects.create(name='Acme', slug='acme', insert_date=now, org=Org.objects.create(name='Acme', slug='acme-org'))
		self.domain = Domain.objects.create(name='acme.example', project=self.project, insert_date=now)

	def hygiene(self, check='mx_direct_send', evidence=None, status='open', host='acme.example'):
		return HygieneFinding.objects.create(domain=self.domain, host=host, check_name=check, severity=2, title='t', evidence=evidence or {},
		                                     status=status)

	def test_untested_direct_send_is_resolved_and_tested_or_other_checks_are_left(self):
		guess = self.hygiene(evidence={'mx': ['acme-example.mail.protection.outlook.com']})
		tested = self.hygiene(evidence={'tested': True, 'reply': '250 2.1.5 Recipient OK'}, host='mail.acme.example')
		other = self.hygiene(check='dmarc_none')
		migration.resolve_untested(apps, None)
		for row in (guess, tested, other):
			row.refresh_from_db()
		self.assertEqual((guess.status, tested.status, other.status), ('resolved', 'open', 'open'))
		self.assertIsNotNone(guess.resolved_at)

	def test_supplier_direct_send_is_resolved_unless_marked_a_false_positive(self):
		supplier = Supplier.objects.create(project=self.project, name='BitSight Targets')
		rows = {status: SupplierFinding.objects.create(supplier=supplier, domain=f'{status}.example', check_name='mx_direct_send', severity=2, title='t',
		                                                  status=status, first_seen=timezone.now()) for status in ('open', 'accepted', 'false_positive')}
		migration.resolve_untested(apps, None)
		got = {status: SupplierFinding.objects.get(pk=row.pk).status for status, row in rows.items()}
		self.assertEqual(got, {'open': 'resolved', 'accepted': 'resolved', 'false_positive': 'false_positive'})
