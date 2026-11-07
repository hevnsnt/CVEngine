"""The email-security checks adapted from MailFail by Black Hills Information Security (cveFeed.mailfail): each rule on plain
records, the bounded network helpers with fakes (no DNS or HTTP leaves the test), and the credit on the activity card."""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import TestCase
from django.utils import timezone

from cveFeed import hygiene as hy
from cveFeed import mailfail as mf
from cveFeed.models import AgentActivity
from dashboard.models import Org, Project
from targetApp.models import Domain
from tests import hygiene_scanner


def checks(findings):
	return {f.check for f in findings}


def modulus(bits):
	return (1 << (bits - 1)) | 1  # any odd number of that size: only the size is read


def dkim_key(bits):
	key = rsa.RSAPublicNumbers(65537, modulus(bits)).public_key()
	der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
	return 'v=DKIM1; k=rsa; p=' + base64.b64encode(der).decode()


def dnskey(algorithm, bits=2048, protocol=3):
	raw = bytes([3]) + (65537).to_bytes(3, 'big') + modulus(bits).to_bytes(bits // 8, 'big')
	return f'257 {protocol} {algorithm} {base64.b64encode(raw).decode()}'


class Response:
	def __init__(self, status=200, body=b'', payload=None):
		self.status_code, self.body, self.payload = status, body, payload

	def json(self):
		return self.payload

	def raise_for_status(self):
		if self.status_code >= 400:
			raise RuntimeError(self.status_code)

	def iter_content(self, size):
		for i in range(0, len(self.body), size):
			yield self.body[i:i + size]










class ActivityCreditTests(TestCase):
	def test_the_activity_card_credits_mailfail_while_and_after_it_runs(self):
		now = timezone.now()
		project = Project.objects.create(name='Acme', slug='acme', insert_date=now, org=Org.objects.create(name='Acme', slug='acme-org'))
		domain = Domain.objects.create(name='acme.example', project=project, insert_date=now)
		credited = [hy.Finding('mx_outlook', hy.MEDIUM, 'Mail is delivered by Microsoft 365', 'The MX record points at a shared mail service.', 'acme.example', {'credit': mf.CREDIT})]
		hygiene_scanner.run_hygiene(domain.id, probe=lambda host, port: None, emailer=lambda name: (credited, True), mx=lambda n, t: False)
		entry = AgentActivity.objects.filter(kind='hygiene', message__contains='MailFail').latest('id')
		self.assertEqual(entry.status, 'done')
		self.assertIn('Black Hills Information Security', entry.message)
		self.assertIn('acme.example: 1 issue', entry.message)
		self.assertEqual(entry.detail['credit'], mf.CREDIT)
