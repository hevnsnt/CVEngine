import importlib

from django.apps import apps
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.services import Ctx, host_group, list_vulnerabilities
from cveFeed.labels import record_label
from cveFeed.models import HostLabel
from dashboard.models import Org, Project
from reNgine.bbot import BbotResult, is_informational, label_for, parse_event
from reNgine.tasks import _persist_bbot_findings
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_bbot_findings import BLOB, finding


def _scene(slug):
	now = timezone.now()
	project = Project.objects.create(name=slug, slug=slug, insert_date=now, org=Org.objects.create(name=slug, slug=f'o-{slug}'))
	domain = Domain.objects.create(name='example.com', project=project, insert_date=now)
	scan = ScanHistory.objects.create(start_scan_date=now, scan_status=2, domain=domain,
		scan_type=EngineType.objects.create(engine_name=slug, yaml_configuration='x'))
	sub = Subdomain.objects.create(name='www.example.com', target_domain=domain, scan_history=scan)
	return project, domain, scan, sub


class InformationalCutoffTests(TestCase):
	def test_cutoff_rules(self):
		self.assertTrue(is_informational('WAF Detection', 'WAF Detection', 0, True))
		self.assertTrue(is_informational('Nginx version detect', 'x', 0, True))
		self.assertFalse(is_informational('Nginx version detect', 'x', 1, True))  # low and up is always a finding
		self.assertFalse(is_informational('Exposed .git directory', 'x', 0, True))  # info, but reads as an exposure
		self.assertFalse(is_informational('No DMARC record found', 'x', 0, False))  # no severity, not a detection
		self.assertTrue(is_informational('Target uses federated authentication', 'x', 0, False))
		self.assertEqual(label_for('WAF Detection'), 'WAF')
		self.assertEqual(label_for('Nginx version detect'), 'nginx version')
		self.assertEqual(label_for('Target uses federated authentication'), 'federated auth')
		self.assertEqual(label_for('HTTP response (body) contains file upload'), 'response body match')
		self.assertLessEqual(len(label_for('Some very long detection name that goes on and on ' * 3)), 40)

	def test_info_detection_is_a_label_and_real_findings_stay(self):
		project, domain, scan, sub = _scene('lab')
		result = BbotResult()
		for ev in (finding('WAF Detection', 'INFO'), finding('WAF Detection', 'INFO'), finding('Nginx version detect: 1.2', 'INFO'),
				finding('Missing HSTS header', 'LOW'), finding(BLOB), finding('Leaked credential in page', 'INFO'),
				finding('Admin panel exposed', 'HIGH', 'VULNERABILITY')):
			parse_event(ev, result, {})
		_persist_bbot_findings(result, {'scan_history_id': scan.id, 'domain_id': domain.id}, {'www.example.com': sub})
		self.assertEqual(sorted(HostLabel.objects.filter(project=project).values_list('host', 'label')),
			[('example.com', 'WAF'), ('example.com', 'nginx version')])  # deduped, host lowercased
		names = sorted(Vulnerability.objects.filter(source='bbot').values_list('name', flat=True))
		self.assertEqual(names, ['Admin panel exposed', 'Leaked credential in page', 'Missing HSTS header', 'No DMARC record found'])

	def test_findings_with_the_same_short_name_are_not_merged(self):
		project, domain, scan, sub = _scene('lab5')
		result = BbotResult()
		for ev in (finding('Open S3 bucket: http://a.s3.amazonaws.com', 'MEDIUM'), finding('Open S3 bucket: http://b.s3.amazonaws.com', 'MEDIUM')):
			parse_event(ev, result, {})
		_persist_bbot_findings(result, {'scan_history_id': scan.id, 'domain_id': domain.id}, {'www.example.com': sub})
		_persist_bbot_findings(result, {'scan_history_id': scan.id, 'domain_id': domain.id}, {'www.example.com': sub})  # a rescan
		self.assertEqual(Vulnerability.objects.filter(name='Open S3 bucket').count(), 2)

	def test_host_serializer_returns_labels(self):
		project, domain, scan, sub = _scene('lab2')
		record_label(project.id, domain.id, 'WWW.example.com', 'WAF', detail='WAF Detection')
		self.assertEqual(host_group(project, sub)['labels'], [{'label': 'WAF', 'detail': 'WAF Detection'}])

	def test_labels_are_bounded(self):
		project, domain, scan, sub = _scene('lab3')
		for i in range(HostLabel.MAX_PER_HOST + 5):
			record_label(project.id, domain.id, 'www.example.com', f'l{i}')
		self.assertEqual(HostLabel.objects.count(), HostLabel.MAX_PER_HOST)

	def test_vulnerability_list_hides_info_for_the_actionable_view(self):
		project, domain, scan, sub = _scene('lab4')
		kw = dict(target_domain=domain, subdomain=sub, http_url='x')
		Vulnerability.objects.create(name='noise', severity=0, **kw)
		Vulnerability.objects.create(name='real', severity=2, **kw)
		ctx = Ctx(user=User.objects.create_user('lab4', password='x', is_superuser=True))

		def names(p):
			return sorted(v['name'] for v in list_vulnerabilities(ctx, 'lab4', p)['results'])
		self.assertEqual(names({'severity': 'actionable'}), ['real'])
		self.assertEqual(names({}), ['noise', 'real'])  # the API's own default is unchanged
		self.assertEqual(names({'severity': 'info'}), ['noise'])


class InfoToLabelsMigrationTests(TestCase):
	def test_moves_detections_and_leaves_everything_else(self):
		project, domain, scan, sub = _scene('mig')
		kw = dict(target_domain=domain, subdomain=sub, http_url='x', source='bbot')
		waf = Vulnerability.objects.create(name='WAF Detection', description='WAF Detection', severity=0, **kw)
		nginx = Vulnerability.objects.create(name='Nginx version detect', description='d', severity=0, **kw)
		dmarc = Vulnerability.objects.create(name='No DMARC record found', description=BLOB, severity=0, **kw)
		leak = Vulnerability.objects.create(name='Leaked token detected', description='d', severity=0, **kw)
		low = Vulnerability.objects.create(name='WAF Detection', description='d', severity=1, template_id='other', **kw)
		nuclei = Vulnerability.objects.create(name='WAF Detection', description='d', severity=0, **{**kw, 'source': 'nuclei'})
		mod = importlib.import_module('cveFeed.migrations.0041_bbot_info_to_labels')
		mod.to_labels(apps, None)
		mod.to_labels(apps, None)  # idempotent
		self.assertFalse(Vulnerability.objects.filter(pk__in=[waf.pk, nginx.pk]).exists())
		for kept in (dmarc, leak, low, nuclei):
			self.assertTrue(Vulnerability.objects.filter(pk=kept.pk).exists(), kept.name)
		self.assertEqual(sorted(HostLabel.objects.values_list('label', flat=True)), ['WAF', 'nginx version'])
