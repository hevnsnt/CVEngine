import importlib

from django.apps import apps
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Org, Project
from reNgine.bbot import BbotResult, parse_event, short_title
from startScan.models import Vulnerability
from targetApp.models import Domain

BLOB = ('No DMARC record found - domain has no protection against email spoofing. Confidence: [CONFIRMED] Signature: [DMARC] '
        'Indicator: [No DMARC record] Trigger: [_dmarc.example.com] baddns Module: [DMARC]')


def finding(description, severity=None, etype='FINDING', host='example.com'):
	data = {'host': host, 'description': description}
	if severity:
		data['severity'] = severity
	return {'type': etype, 'id': 'F1', 'host': host, 'module': 'baddns', 'data': None, 'data_json': data}


class ShortTitleTests(TestCase):
	def test_baddns_blob_gets_a_short_name_and_keeps_the_description(self):
		result = BbotResult()
		parse_event(finding(BLOB), result, {})
		f = result.findings[0]
		self.assertEqual(f['name'], 'No DMARC record found')
		self.assertEqual(f['description'], BLOB)

	def test_title_rules(self):
		self.assertEqual(short_title('Open S3 bucket: http://a.s3.amazonaws.com'), 'Open S3 bucket')
		self.assertEqual(short_title('Something. More text'), 'Something')
		self.assertEqual(short_title(''), 'Finding')
		long = short_title('word ' * 60)
		self.assertLessEqual(len(long), 81)
		self.assertTrue(long.endswith('…'))
		self.assertEqual(short_title('plain'), 'Plain')


class ShortenMigrationTests(TestCase):
	def test_existing_bbot_names_are_shortened_and_others_untouched(self):
		now = timezone.now()
		project = Project.objects.create(name='P', slug='p-e', insert_date=now, org=Org.objects.create(name='O', slug='o-e'))
		domain = Domain.objects.create(name='example.com', project=project, insert_date=now)
		kw = dict(target_domain=domain, severity=0, http_url='x')
		bb = Vulnerability.objects.create(name=BLOB[:200], description=BLOB, source='bbot', **kw)
		nuc = Vulnerability.objects.create(name='Long nuclei: name', description='Long nuclei: name', source='nuclei', **kw)
		mod = importlib.import_module('startScan.migrations.0011_shorten_bbot_names')
		mod.shorten(apps, None)
		mod.shorten(apps, None)  # idempotent
		bb.refresh_from_db()
		nuc.refresh_from_db()
		self.assertEqual(bb.name, 'No DMARC record found')
		self.assertEqual(bb.description, BLOB)
		self.assertEqual(nuc.name, 'Long nuclei: name')
