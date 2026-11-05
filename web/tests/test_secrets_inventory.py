"""The secrets inventory (cveFeed.secrets_inventory): one row per project and secret, the value never stored, the feeders (route check, nuclei
token templates, bbot), retirement, a person's decisions, scoring and tenancy (docs/SECRETS-PLAN.md sections 7, 8 and 13)."""
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import scoring, secrets_inventory as inv
from cveFeed.models import SecretFinding, SecretFingerprintKey, SecretOccurrence
from dashboard.models import Org, Project
from reNgine.tasks import save_vulnerability
from startScan.models import ScanHistory, Subdomain, Vulnerability
from scanEngine.models import EngineType
from targetApp.models import Domain

GOOGLE = 'AIzaSyA1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUVw'
GITHUB = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'


class Base(TestCase):
    def setUp(self):
        inv.reset_key_cache()
        self.addCleanup(inv.reset_key_cache)
        self.org = Org.objects.create(name='S', slug='sec')
        self.project = Project.objects.create(name='S', slug='sec-p', insert_date=timezone.now(), org=self.org)
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e-sec', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2, results_dir='/tmp')
        self.sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='www.example.com')

    def record(self, value=GOOGLE, url='https://www.example.com/', rule='betterleaks.gcp-api-key', source='kingfisher', project=None, **kw):
        return inv.record((project or self.project).pk, host=None, url=url, source=source, rule_id=rule, value=value, domain_id=self.domain.pk,
                          scan_id=self.scan.pk, **kw)


class RecordTests(Base):
    def test_one_row_per_secret_across_hosts_detectors_and_quotes(self):
        a = self.record(url='https://www.example.com/?token=x')
        b = self.record(value=f'"{GOOGLE}"', url='https://api.example.com/app.js', rule='nuclei:google-api-key', source='nuclei')
        self.assertEqual(a.pk, b.pk)
        row = SecretFinding.objects.get()
        self.assertEqual((row.provider, row.kind, row.klass, row.masked, row.length), ('Google', 'google-api-key', 'P', 'AIza…TUVw', 39))
        self.assertEqual(row.rule_ids, ['betterleaks.gcp-api-key', 'nuclei:google-api-key'])
        self.assertEqual((row.occurrence_count, row.host_count, row.severity), (2, 2, 0))
        self.assertIn('likely public by design', row.severity_basis)
        self.assertEqual(set(SecretOccurrence.objects.values_list('url', flat=True)),
                         {'https://www.example.com/', 'https://api.example.com/app.js'})  # no query string kept

    def test_the_value_is_stored_nowhere(self):
        self.record()
        self.record(value=GITHUB, rule='betterleaks.github-pat')
        for model in (SecretFinding, SecretOccurrence):
            for row in model.objects.values():
                self.assertNotIn(GOOGLE, repr(row))
                self.assertNotIn(GITHUB, repr(row))
                self.assertNotIn(GITHUB[4:], repr(row))

    def test_the_fingerprint_survives_a_field_key_rotation(self):
        """The install key is stored encrypted under the field key, never derived from it: rotate_field_key re-encrypts it and every fingerprint
        stays the same (docs/SECRETS-PLAN.md 7), and it is not a plain hash anyone can recompute from a guess."""
        import hashlib
        import os
        from io import StringIO

        from django.core.management import call_command
        from tests.test_field_key import KEY_A, KEY_B
        with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': KEY_A}):
            fp = inv.fingerprint(GOOGLE)
        with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': KEY_B, 'CVENGINE_FIELD_KEY_PREVIOUS': KEY_A}):
            call_command('rotate_field_key', stdout=StringIO())
        inv.reset_key_cache()
        with mock.patch.dict(os.environ, {'CVENGINE_FIELD_KEY': KEY_B, 'CVENGINE_FIELD_KEY_PREVIOUS': ''}):
            self.assertEqual(inv.fingerprint(GOOGLE), fp)
        self.assertEqual(SecretFingerprintKey.objects.count(), 1)
        self.assertNotEqual(fp, hashlib.sha256(GOOGLE.encode()).hexdigest())

    def test_one_secret_in_two_projects_is_two_rows(self):
        other = Project.objects.create(name='O', slug='sec-o', insert_date=timezone.now(), org=self.org)
        self.record()
        self.record(project=other)
        self.assertEqual(SecretFinding.objects.count(), 2)
        self.assertEqual(SecretFinding.objects.filter(project=other).count(), 1)

    def test_what_cannot_be_a_secret_is_refused(self):
        self.assertIsNone(self.record(value='short'))
        self.assertIsNone(self.record(rule='Not A Rule!'))
        self.assertIsNone(self.record(source='elsewhere'))
        self.assertIsNone(self.record(value='x' * 9000))
        self.assertFalse(SecretFinding.objects.exists())

    def test_validation_keeps_only_allow_listed_metadata_and_sets_the_status(self):
        row = self.record(value=GITHUB, rule='betterleaks.github-pat', outcome='verified_active',
                          meta={'account_type': 'User', 'token': GITHUB, 'email': 'a@example.com'})
        self.assertEqual((row.status, row.severity, row.validation_meta), ('live', 4, {'account_type': 'User'}))

    def test_a_server_secret_read_by_a_second_rule_replaces_a_browser_reading(self):
        self.record(value='sk_live_' + 'a' * 24, rule='nuclei:stripe-key', source='nuclei')
        row = SecretFinding.objects.get()
        self.assertEqual((row.kind, row.klass), ('stripe-secret-key', 'S'))


class RetireAndDecideTests(Base):
    def test_a_url_read_again_without_the_secret_retires_it_and_a_secret_seen_nowhere_is_fixed(self):
        row = self.record(url='https://www.example.com/a.js')
        n = inv.retire_missing(self.project.pk, 'kingfisher', {'https://www.example.com/a.js': set()})
        self.assertEqual(n, 1)
        row.refresh_from_db()
        self.assertEqual((row.occurrence_count, row.remediation_status), (0, 'fixed'))
        self.record(url='https://www.example.com/a.js')
        row.refresh_from_db()
        self.assertEqual((row.occurrence_count, row.remediation_status), (1, 'open'))  # served again: reopened

    def test_a_secret_seen_elsewhere_keeps_its_other_occurrence(self):
        row = self.record(url='https://www.example.com/a.js')
        self.record(url='https://www.example.com/b.js')
        inv.retire_missing(self.project.pk, 'kingfisher', {'https://www.example.com/a.js': set(), 'https://www.example.com/b.js': {row.pk}})
        row.refresh_from_db()
        self.assertEqual(row.occurrence_count, 1)

    def test_a_persons_status_is_checked_and_a_quiet_one_leaves_the_score(self):
        user = User.objects.create_user('p', password='x')
        row = self.record(value=GITHUB, rule='betterleaks.github-pat')
        with self.assertRaises(inv.StatusError):
            inv.set_status(row, 'live', user)  # only validation sets live
        with mock.patch('cveFeed.scoring.rescore_quietly') as rescore:
            inv.set_status(row, 'false_positive', user, note='a test value')
        rescore.assert_called_once_with(self.project.pk, ['www.example.com'])
        row.refresh_from_db()
        self.assertEqual((row.status, row.remediation_status, row.status_by, row.status_note), ('false_positive', 'false_positive', user, 'a test value'))
        secrets, covered = inv.host_secrets(self.project.pk, ['www.example.com'])
        self.assertEqual((secrets, covered), ({}, {'www.example.com'}))


class FeederTests(Base):
    def nuclei(self, extracted, tags=('token', 'google'), template='http/exposures/tokens/google/google-api-key.yaml'):
        return save_vulnerability(target_domain=self.domain, scan_history=self.scan, subdomain=self.sub, http_url='https://www.example.com/',
                                  name='Google API Key', severity=0, source='nuclei', template=template, template_id='google-api-key', type='http',
                                  extracted_results=list(extracted), tags=list(tags),
                                  response='HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>key="%s"</script>' % extracted[0])

    def test_a_token_template_finding_keeps_only_the_mask_and_feeds_the_inventory(self):
        with mock.patch('reNgine.tasks.VulnerabilityTags.objects.get_or_create', return_value=(None, False)):
            vuln, created = self.nuclei([GOOGLE])
        vuln.refresh_from_db()
        self.assertTrue(created)
        self.assertEqual(vuln.extracted_results, ['AIza…TUVw'])
        self.assertNotIn(GOOGLE, vuln.response)
        self.assertIn('HTTP/1.1 200 OK', vuln.response)
        row = SecretFinding.objects.get()
        self.assertEqual(row.rule_ids, ['nuclei:google-api-key'])
        self.assertEqual(row.occurrences.get().vulnerability_id, vuln.pk)
        self.assertEqual([s.pk for s in inv.tracked(vuln.pk)], [row.pk])
        with mock.patch('reNgine.tasks.VulnerabilityTags.objects.get_or_create', return_value=(None, False)):
            again, created = self.nuclei([GOOGLE])  # seen again: same row, nothing changes, nothing filed twice
        self.assertFalse(created)
        self.assertEqual((again.pk, SecretFinding.objects.count(), SecretOccurrence.objects.count()), (vuln.pk, 1, 1))

    def test_a_template_that_extracts_no_secret_is_left_alone(self):
        data = {'source': 'nuclei', 'template': 'http/technologies/nginx.yaml', 'template_id': 'nginx-version', 'extracted_results': ['nginx/1.25.3']}
        self.assertEqual(inv.take_from_finding(data, ['tech']), [])
        self.assertEqual(data['extracted_results'], ['nginx/1.25.3'])

    def test_a_mask_is_never_filed_again(self):
        data = {'source': 'nuclei', 'template_id': 'google-api-key', 'extracted_results': ['AIza…TUVw']}
        self.assertEqual(inv.take_from_finding(data, ['token']), [])

    def test_a_bbot_badsecrets_finding_keeps_the_mask_in_its_description(self):
        data = {'source': 'bbot', 'template_id': 'badsecrets', 'description': 'Known Secret Found. Secret: [s3cr3t-signing-key-123] Product: [x]'}
        found = inv.take_from_finding(data)
        self.assertEqual(found, [('bbot:badsecrets', 's3cr3t-signing-key-123')])
        self.assertNotIn('s3cr3t-signing-key-123', data['description'])
        self.assertIn('…-123', data['description'])

    def test_the_route_check_files_what_a_body_served_and_drops_the_values(self):
        from cveFeed import route_auth
        result = route_auth.analyse({'url': 'https://www.example.com/', 'status': 200, 'content_type': 'text/html',
                                     'body': f'<script>var k="{GOOGLE}"; var g="{GITHUB}";</script>', 'headers': {}})
        self.assertEqual({t for t, _ in result['credentials']}, {'google_key', 'github_token'})
        probed = {'https://www.example.com/': result}
        route_auth._feed_inventory(self.scan, self.project.pk, probed, timezone.now())
        self.assertNotIn('credentials', probed['https://www.example.com/'])
        self.assertEqual(set(SecretFinding.objects.values_list('kind', flat=True)), {'google-api-key', 'github-token'})
        self.assertEqual(set(SecretOccurrence.objects.values_list('source', flat=True)), {'route'})


class ScoringTests(Base):
    def score(self, routes=(), secrets=(), covered=False):
        return scoring._sensitive_line(list(routes), list(secrets), covered)

    def test_a_browser_key_alone_scores_five_and_a_server_secret_twenty_five(self):
        route = {'path': '/', 'sensitive_score': 25, 'sensitive': {'google_key': {'count': 1, 'sample': 'x'}}}
        self.assertEqual(self.score([route]), [{'label': 'Credentials served on /', 'points': 25}])  # not covered: as before
        self.assertEqual(self.score([route], [{'severity': 0, 'klass': 'P', 'path': '/'}], True),
                         [{'label': 'Browser key served on /', 'points': 5}])
        self.assertEqual(self.score([route], [{'severity': 3, 'klass': 'S', 'path': '/app.js'}], True),
                         [{'label': 'Server credential served on /app.js', 'points': 25}])

    def test_personal_data_on_a_covered_host_still_counts(self):
        route = {'path': '/team', 'sensitive_score': 25, 'sensitive': {'google_key': {'count': 1}, 'email': {'count': 9}}}
        self.assertEqual(self.score([route], [{'severity': 0, 'klass': 'P', 'path': '/'}], True),
                         [{'label': 'Personal data served on /team', 'points': 15}])

    def test_a_quiet_secret_covers_the_host_and_scores_nothing(self):
        user = User.objects.create_user('q', password='x')
        row = self.record()
        with mock.patch('cveFeed.scoring.rescore_quietly'):
            inv.set_status(row, 'public_by_design', user)
        self.assertEqual(inv.host_secrets(self.project.pk, ['www.example.com']), ({}, {'www.example.com'}))


class BackfillTests(Base):
    def test_stored_token_findings_are_filed_and_masked_once(self):
        from io import StringIO

        from django.core.management import call_command
        from startScan.models import VulnerabilityTags
        vuln = Vulnerability.objects.create(target_domain=self.domain, scan_history=self.scan, subdomain=self.sub, name='Google API Key', severity=0,
                                            source='nuclei', template='http/exposures/tokens/google/google-api-key.yaml', template_id='google-api-key',
                                            http_url='https://www.example.com/', extracted_results=[GOOGLE],
                                            response=f'HTTP/1.1 200 OK\r\n\r\nkey={GOOGLE}')
        vuln.tags.add(VulnerabilityTags.objects.create(name='token'))
        out = StringIO()
        call_command('backfill_secrets_inventory', stdout=out)
        self.assertIn('would file and mask 1 secret(s) from 1 finding(s)', out.getvalue())
        self.assertFalse(SecretFinding.objects.exists())
        call_command('backfill_secrets_inventory', '--apply', stdout=StringIO())
        vuln.refresh_from_db()
        self.assertEqual(vuln.extracted_results, ['AIza…TUVw'])
        self.assertNotIn(GOOGLE, vuln.response)
        self.assertEqual(SecretFinding.objects.get().occurrences.get().vulnerability_id, vuln.pk)
        out = StringIO()
        call_command('backfill_secrets_inventory', '--apply', stdout=out)
        self.assertIn('filed and masked 0 secret(s)', out.getvalue())

    def test_it_is_an_automatic_backfill(self):
        from cveFeed import upgrade_backfills
        self.assertIn('backfill_secrets_inventory', upgrade_backfills.BACKFILLS)
        self.assertLess(upgrade_backfills.BACKFILLS.index('backfill_secrets_inventory'), upgrade_backfills.BACKFILLS.index('rerate_findings'))
