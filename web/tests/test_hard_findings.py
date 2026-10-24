import importlib

from django.apps import apps
from django.db import connection
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Org, Project
from reNgine.tasks import parse_nuclei_result, save_vulnerability
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


def _line(date, matcher='version', url='https://www.f.test/x'):
	return {'host': 'https://www.f.test', 'matched-at': url, 'template-id': 'cve-2099-1', 'template': 't.yaml', 'type': 'http',
		'matcher-name': matcher, 'request': 'GET /x HTTP/1.1', 'response': f'HTTP/1.1 200 OK\nDate: {date}\n\nbody',
		'curl-command': f'curl {url}', 'extracted-results': ['1.0'],
		'info': {'name': 'Example', 'severity': 'high', 'tags': ['cve'], 'classification': {'cve-id': ['cve-2099-1']}}}


class FindingDedupeTests(TestCase):
	"""Review 2.3: the finding key is where and what, not the response body."""

	def setUp(self):
		org = Org.objects.create(name='A', slug='a')
		project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='f.test', project=project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
		self.sub = Subdomain.objects.create(name='www.f.test', target_domain=self.domain, scan_history=self.scan)

	def _save(self, line, subdomain=None):
		data = parse_nuclei_result(line)
		return save_vulnerability(target_domain=self.domain, scan_history=self.scan, subdomain=subdomain or self.sub,
			http_url=line['matched-at'], **data)

	def test_same_finding_twice_with_different_date_headers_is_one_row(self):
		first, created = self._save(_line('Mon, 01 Jan 2026 10:00:00 GMT'))
		second, created_again = self._save(_line('Mon, 01 Jan 2026 10:00:09 GMT'))
		self.assertTrue(created)
		self.assertFalse(created_again)
		self.assertEqual(first.pk, second.pk)
		self.assertEqual(Vulnerability.objects.count(), 1)
		self.assertIn('10:00:09', Vulnerability.objects.get().response)  # the newest evidence wins

	def test_a_different_matcher_url_or_host_is_a_different_finding(self):
		self._save(_line('d'))
		self._save(_line('d', matcher='other'))
		self._save(_line('d', url='https://www.f.test/y'))
		other = Subdomain.objects.create(name='api.f.test', target_domain=self.domain, scan_history=self.scan)
		self._save(_line('d'), subdomain=other)
		self.assertEqual(Vulnerability.objects.count(), 4)

	def test_a_finding_seen_again_is_open_again_and_keeps_its_first_seen_date(self):
		first, _ = self._save(_line('d'))
		discovered = first.discovered_date
		Vulnerability.objects.filter(pk=first.pk).update(open_status=False)
		again, _ = self._save(_line('e'))
		again.refresh_from_db()
		self.assertTrue(again.open_status)
		self.assertEqual(again.discovered_date, discovered)

	def test_the_database_refuses_a_second_row_for_the_same_finding(self):
		from django.db import IntegrityError, transaction
		vuln, _ = self._save(_line('d'))
		with self.assertRaises(IntegrityError), transaction.atomic():
			Vulnerability.objects.create(target_domain=self.domain, scan_history=self.scan, subdomain=self.sub, source=vuln.source,
				template_id=vuln.template_id, name=vuln.name, http_url=vuln.http_url, matcher_name=vuln.matcher_name, severity=3)

	def test_the_migration_keeps_the_oldest_row_of_each_duplicate_group(self):
		module = importlib.import_module('startScan.migrations.0008_unique_vulnerability_finding')
		constraint = next(c for c in Vulnerability._meta.constraints if c.name == 'uniq_vulnerability_finding')
		with connection.schema_editor() as editor:
			editor.remove_constraint(Vulnerability, constraint)
		fields = dict(target_domain=self.domain, scan_history=self.scan, subdomain=self.sub, source='nuclei', name='n', severity=2,
			http_url='https://www.f.test/', template_id='t', matcher_name='m')
		oldest = Vulnerability.objects.create(response='a', **fields)
		Vulnerability.objects.create(response='b', **fields)
		Vulnerability.objects.create(response='c', **fields)
		keep = Vulnerability.objects.create(response='d', **{**fields, 'name': 'other'})
		with connection.schema_editor() as editor:
			module.merge_duplicate_findings(apps, editor)  # the test transaction rolls the dropped constraint back
		self.assertEqual(sorted(Vulnerability.objects.values_list('id', flat=True)), sorted([oldest.pk, keep.pk]))
