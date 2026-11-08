"""The CVE seed leaves nothing of the instance that wrote it, and an App Admin can create, download and import one from the Settings page.

Every sensitive string below is planted in a place the export reads (a project, a domain, a host, an address, a detection record's
model-written text, a summary, a reference, a manual record) and the output is searched for each of them."""
import copy
import gzip
import hashlib
import io
import json
import os
import tempfile
import time
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from cveFeed import detection, detection_author, seed, seed_admin, seed_scrub
from cveFeed.models import CVEDetection, CVEEntry
from dashboard.models import AuditLog, Org, Project
from startScan.models import IpAddress, Subdomain
from targetApp.models import Domain

NGINX = [{'vendor': 'f5', 'product': 'nginx', 'package': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]
VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
HOST, HOST2, IP, IP2 = 'vpn.acme-internal.example.com', 'billing.acme-internal.example.com', '192.0.2.44', '192.0.2.45'
ORG, PROJECT, PROJECT_SLUG = 'Initech Holdings', 'Skunkworks Recon', 'skunkworks-recon'
TOKEN, AWS = 'tok_live_9f8e7d6c5b4a39281706f5e4d3c2b1a0', 'AKIAIOSFODNN7EXAMPLE'
ASSIGNED, PRIVATE, PATH = 'api_key=Zk3pQ9vLm2XwR7tY4uB8nC1d', '10.20.30.40', '/home/jsmith/scans/acme'
MANUAL_NOTE = 'manual note about the vpn'
SENSITIVE = [HOST, HOST2, 'acme-internal.example.com', IP, IP2, ORG, PROJECT, PROJECT_SLUG, TOKEN, AWS, ASSIGNED, 'Zk3pQ9vLm2', PRIVATE, PATH, MANUAL_NOTE]


def plant():
    """A tenant (example.com, 192.0.2.x) and CVEs that carry its strings in every place the export reads. Returns the CVE ids by role."""
    now = timezone.now()
    org = Org.objects.create(name=ORG, slug='initech-holdings')
    project = Project.objects.create(name=PROJECT, slug=PROJECT_SLUG, insert_date=now, org=org)
    domain = Domain.objects.create(name='acme-internal.example.com', project=project, insert_date=now)
    Subdomain.objects.create(name=HOST, target_domain=domain)
    Subdomain.objects.create(name=HOST2, target_domain=domain)
    IpAddress.objects.create(address=IP)
    IpAddress.objects.create(address=IP2)
    ids = {}
    for role, number in (('host_ai', 9001), ('manual', 9002), ('aws_ai', 9003), ('clean', 9004), ('reference', 9005), ('summary', 9006), ('assigned_ai', 9007)):
        ids[role] = CVEEntry.objects.create(cve_id=f'CVE-2099-{number}', title=f'title {number}', affected=NGINX, published_at=now, cvss=9.8, kev=True,
                                            cvss_vector=VECTOR, original_description='public text')
    CVEEntry.objects.filter(pk=ids['reference'].pk).update(references=[{'url': f'https://{HOST}/status', 'source': 'x'}])
    CVEEntry.objects.filter(pk=ids['summary'].pk).update(summary=f'Written by the model for {PROJECT}: the admin token is {TOKEN}')
    with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
        detection_author.author_rules()

    def edit(role, source, **changes):
        row = CVEDetection.objects.get(cve_entry=ids[role])
        strategy = copy.deepcopy(row.strategy)
        strategy.update(changes)
        CVEDetection.objects.filter(pk=row.pk).update(strategy=strategy, source=source)

    edit('host_ai', 'ai', identify=f'Seen on {HOST} ({IP}), nginx behind the VPN', confirm_steps=[f'Log in to {HOST2} and check the version'],
         scope_reason=f'{ORG} runs this on {IP2}')
    edit('manual', 'manual', identify=f'{MANUAL_NOTE} {HOST} and {IP}')
    edit('aws_ai', 'ai', identify=f'Use key {AWS} and {PATH} to look at it')
    edit('assigned_ai', 'ai', revision_note=f'internal ref {ASSIGNED} and host {PRIVATE}')
    return {role: cve.cve_id for role, cve in ids.items()}


class NoScrub:
    """Stands in for the scrub the way the export was before it existed: nothing is checked."""
    names = hosts = addresses = ()

    def check_record(self, record):
        return set(), set()


def read_seed(path):
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        return f.read()


class LeakTests(TestCase):
    def setUp(self):
        self.ids = plant()
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'seed.jsonl.gz')

    def test_the_old_export_would_have_leaked_every_planted_string(self):
        """Proves the fixture reaches the export: with the scrub switched off every sensitive string is in the file."""
        seed.export_seed(self.path, scrub=NoScrub())
        text = read_seed(self.path)
        for needle in SENSITIVE:
            if needle in (PROJECT_SLUG, MANUAL_NOTE):
                continue  # a slug is in no text; a manual record is withheld by the export itself, not by the scrub
            self.assertIn(needle, text, needle)

    def test_no_planted_string_is_in_the_output(self):
        manifest = seed.export_seed(self.path)
        text = read_seed(self.path)
        for needle in SENSITIVE:
            self.assertNotIn(needle, text, needle)
        self.assertGreater(len(text.splitlines()), 1)  # the file is not empty
        manifest_text = open(self.path + '.manifest.json').read()
        for needle in SENSITIVE:
            self.assertNotIn(needle, manifest_text, needle)  # the manifest says how many and why, never what
        self.assertEqual(manifest['manual_withheld'], 1)

    def test_what_is_dropped_is_counted_by_kind_and_reason(self):
        manifest = seed.export_seed(self.path)
        dropped = manifest['dropped']
        by_id = {(d['cve_id'], d['what']): set(d['reasons']) for d in dropped['ids']}
        ids = self.ids
        self.assertEqual(by_id[(ids['reference'], 'record')], {'tenant_host'})
        self.assertEqual(by_id[(ids['summary'], 'record')], {'secret', 'tenant_name'})
        self.assertIn('tenant_host', by_id[(ids['host_ai'], 'detection')])
        self.assertIn('tenant_name', by_id[(ids['host_ai'], 'detection')])
        self.assertIn('tenant_address', by_id[(ids['host_ai'], 'detection')])
        self.assertEqual(by_id[(ids['aws_ai'], 'detection')], {'secret', 'internal_path'})
        self.assertEqual(by_id[(ids['assigned_ai'], 'detection')], {'secret', 'private_address'})
        self.assertEqual((dropped['records'], dropped['detections']), (2, 3))
        self.assertEqual(manifest['count'], 5)  # seven CVEs, two dropped whole
        written = [json.loads(line) for line in read_seed(self.path).splitlines()[1:]]
        self.assertEqual(len(written), manifest['count'])
        self.assertEqual(sum('detection' in r for r in written), manifest['with_detection'])
        by_cve = {r['cve_id']: r for r in written}
        self.assertNotIn('detection', by_cve[ids['host_ai']])  # kept the CVE, left out the record that named the host
        self.assertIn('detection', by_cve[ids['clean']])  # a clean record keeps its detection
        self.assertNotIn(ids['reference'], by_cve)
        self.assertNotIn('detection', by_cve[ids['manual']])

    def test_the_manifest_agrees_with_the_file(self):
        manifest = seed.export_seed(self.path)
        on_disk = json.load(open(self.path + '.manifest.json'))
        self.assertEqual(on_disk, manifest)
        self.assertEqual(manifest['sha256'], hashlib.sha256(open(self.path, 'rb').read()).hexdigest())
        self.assertEqual(manifest['bytes'], os.path.getsize(self.path))
        self.assertEqual(manifest['count'], sum(manifest['tiers'].values()))
        self.assertEqual(seed.verify_seed(self.path, manifest), manifest)

    def test_a_clean_catalog_drops_nothing(self):
        CVEEntry.objects.exclude(cve_id=self.ids['clean']).delete()
        manifest = seed.export_seed(self.path)
        self.assertEqual((manifest['count'], manifest['dropped']['records'], manifest['dropped']['detections']), (1, 0, 0))

    def test_a_name_that_is_all_over_public_text_is_ignored_in_the_feed_fields_only(self):
        """A project named after a vendor must not empty the seed: public feed text mentions it, so it is ignored there, but it is still
        refused in the model-written fields."""
        Project.objects.create(name='Nginxcorp', slug='nginxcorp', insert_date=timezone.now())
        CVEEntry.objects.bulk_create([CVEEntry(cve_id=f'CVE-2098-{n}', title='a Nginxcorp advisory', published_at=timezone.now()) for n in range(60)])
        manifest = seed.export_seed(self.path)
        text = read_seed(self.path)
        self.assertEqual(text.count('Nginxcorp'), 60)  # public text kept
        CVEEntry.objects.filter(pk=CVEEntry.objects.get(cve_id=self.ids['clean']).pk).update(summary='model text about Nginxcorp')
        seed.export_seed(self.path)
        self.assertNotIn('model text about Nginxcorp', read_seed(self.path))


class ScrubUnitTests(TestCase):
    def setUp(self):
        self.scrub = seed_scrub.Scrub(names=['Initech Holdings', 'abc'], hosts=['acme-internal.example.com'], addresses=['192.0.2.44', '2001:db8::7'])

    def test_tenant_strings_in_every_shape(self):
        for text, reason in (('see Initech Holdings', 'tenant_name'), ('initech holdings', 'tenant_name'), ('at vpn.acme-internal.example.com:8443/x', 'tenant_host'),
                             ('ACME-INTERNAL.EXAMPLE.COM.', 'tenant_host'), ('from 192.0.2.44.', 'tenant_address'), ('[2001:db8::7]:443', 'tenant_address')):
            self.assertIn(reason, self.scrub.check(text, strict=True), text)
        self.assertEqual(self.scrub.check({'nested': [{'k': 'Initech Holdings'}]}, strict=False), {'tenant_name'})
        self.assertEqual(self.scrub.check({'Initech Holdings': 1}, strict=False), {'tenant_name'})  # keys too

    def test_ordinary_text_passes(self):
        for text in ('The nginx version is older than 10.3.183.67', 'example.com and 192.0.2.99', 'Initech Holdingsx', 'abc', 'version-github-com-0xjacky-nginx',
                     'the password parameter is not validated', 'http://user:password@host/', '10.3.6.0 through 10.3.6.0;'):
            self.assertEqual(self.scrub.check(text, strict=True), set(), text)

    def test_secret_shapes(self):
        for text in (TOKEN, AWS, ASSIGNED, '-----BEGIN RSA PRIVATE KEY-----', 'ghp_' + 'aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5', 'xoxb-1234567890-abcdefghij',
                     'sk-ant-api03-abcdefghijklmnop', 'Bearer abcdefghijklmnopqrstuvwxyz0123456789', 'postgres://app:S3cretPassw0rd@db/x',
                     'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk', 'aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5hJ7k'):
            self.assertIn('secret', self.scrub.check(text, strict=True), text)

    def test_strict_checks_only_apply_to_model_written_fields(self):
        text = 'proof of concept uses password=hunter2hunter2 against 10.0.0.5:80 in /home/user/x'
        self.assertEqual(self.scrub.check(text, strict=False), set())
        self.assertEqual(self.scrub.check(text, strict=True), {'secret', 'private_address', 'internal_path'})


def admin_client(test):
    test.admin = User.objects.create_user('seed-admin', password='x', is_superuser=True)
    test.client.force_login(test.admin)


class SeedPageApiTests(TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        patcher = mock.patch('cveFeed.seed_admin.seed_dir', return_value=self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        cache.delete(seed_admin.LOCK)
        cache.delete(seed_admin.JOB)
        admin_client(self)
        self.ids = plant()
        self.api = '/cve/api/settings/cve_seed'

    def post(self, path, **kw):
        return self.client.post(f'{self.api}/{path}', **kw)

    def create(self):
        with mock.patch('cveFeed.tasks.build_cve_seed.delay') as delay:
            self.assertEqual(self.post('build', content_type='application/json').status_code, 200)
        delay.assert_called_once_with(self.admin.pk)
        seed_admin.run_export(self.admin.pk)

    def test_create_runs_one_at_a_time_and_reports_the_numbers(self):
        with mock.patch('cveFeed.tasks.build_cve_seed.delay') as delay:
            first = self.post('build', content_type='application/json')
            second = self.post('build', content_type='application/json')
        self.assertEqual((first.status_code, second.status_code), (200, 409))
        self.assertEqual(delay.call_count, 1)
        self.assertTrue(first.json()['building'])
        self.assertEqual(first.json()['job']['kind'], 'export')
        self.assertEqual(self.post('import', data=gzip.compress(b'{"format": 1}\n'), content_type='application/octet-stream').status_code, 409)  # an import waits for the export as well
        seed_admin.run_export(self.admin.pk)
        status = self.client.get(self.api).json()
        self.assertFalse(status['building'])
        self.assertEqual(status['job']['state'], 'done')
        manifest = status['built']
        self.assertEqual((manifest['count'], manifest['dropped']['records'], manifest['dropped']['detections']), (5, 2, 3))
        self.assertEqual(status['job']['result']['count'], manifest['count'])
        self.assertEqual(manifest['sha256'], hashlib.sha256(open(os.path.join(self.dir, seed_admin.SEED_NAME), 'rb').read()).hexdigest())
        self.assertTrue(status['expires_at'])

    def test_a_failed_export_says_so_and_frees_the_lock(self):
        with mock.patch('cveFeed.tasks.build_cve_seed.delay'):
            self.post('build', content_type='application/json')
        with mock.patch('cveFeed.seed.export_seed', side_effect=RuntimeError('boom')):
            with self.assertRaises(RuntimeError):
                seed_admin.run_export(self.admin.pk)
        status = self.client.get(self.api).json()
        self.assertEqual((status['building'], status['job']['state']), (False, 'failed'))
        self.assertNotIn('boom', status['job']['error'])  # an exception's text can hold a path or a name
        with mock.patch('cveFeed.tasks.build_cve_seed.delay'):
            self.assertEqual(self.post('build', content_type='application/json').status_code, 200)

    def test_download_headers_stream_and_audit(self):
        self.assertEqual(self.client.get(f'{self.api}/download/seed').status_code, 404)  # nothing created yet
        self.create()
        manifest = self.client.get(self.api).json()['built']
        got = self.client.get(f'{self.api}/download/seed')
        self.assertEqual(got.status_code, 200)
        self.assertTrue(got.streaming)
        self.assertEqual(got['Content-Type'], 'application/gzip')
        self.assertIn('attachment; filename="cve-seed.jsonl.gz"', got['Content-Disposition'])
        self.assertEqual(got['Cache-Control'], 'no-store')
        self.assertEqual(got['X-Content-Type-Options'], 'nosniff')
        body = b''.join(got.streaming_content)
        self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), (manifest['bytes'], manifest['sha256']))
        for needle in SENSITIVE:
            self.assertNotIn(needle, gzip.decompress(body).decode(), needle)
        got = self.client.get(f'{self.api}/download/manifest')
        self.assertEqual(got['Content-Type'], 'application/json')
        self.assertIn('cve-seed.jsonl.gz.manifest.json', got['Content-Disposition'])
        self.assertEqual(json.loads(b''.join(got.streaming_content))['sha256'], manifest['sha256'])
        actions = list(AuditLog.objects.filter(actor=self.admin).values_list('action', flat=True).order_by('id'))
        self.assertEqual(actions, ['cve_seed.build', 'cve_seed.created', 'cve_seed.download', 'cve_seed.download'])
        entry = AuditLog.objects.get(action='cve_seed.created')
        self.assertEqual((entry.detail['count'], entry.detail['dropped_records'], entry.detail['dropped_detections']), (5, 2, 3))
        self.assertEqual(AuditLog.objects.filter(action='cve_seed.download').first().detail['sha256'], manifest['sha256'])
        for needle in SENSITIVE:
            self.assertNotIn(needle, json.dumps([a.detail for a in AuditLog.objects.all()]), needle)

    def test_only_an_app_admin_and_only_with_a_session(self):
        self.create()
        self.client.force_login(User.objects.create_user('plain', password='x'))
        for method, path in (('get', ''), ('post', '/build'), ('post', '/import'), ('get', '/download/seed'), ('get', '/download/manifest')):
            self.assertEqual(getattr(self.client, method)(self.api + path).status_code, 403, path)
        staff = User.objects.create_user('staff', password='x', is_staff=True)
        self.client.force_login(staff)
        self.assertEqual(self.client.get(self.api + '/download/seed').status_code, 403)
        self.client.logout()
        for method, path in (('get', ''), ('post', '/build'), ('get', '/download/seed')):
            self.assertIn(getattr(self.client, method)(self.api + path).status_code, (302, 401, 403), path)
        self.assertEqual(AuditLog.objects.filter(action='cve_seed.download').count(), 0)

    def test_post_needs_the_csrf_token(self):
        from django.test import Client
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.admin)
        for path in ('/build', '/import'):
            self.assertEqual(strict.post(self.api + path, data={}).status_code, 403, path)
        self.assertFalse(cache.get(seed_admin.LOCK))

    def test_no_path_in_the_request_picks_a_file(self):
        self.create()
        for which in ('../seed', 'seed/../../etc/passwd', '%2e%2e/seed', 'other'):
            self.assertEqual(self.client.get(f'{self.api}/download/{which}').status_code, 404, which)

    def test_the_file_is_removed_after_24_hours_and_by_the_next_export(self):
        self.create()
        seed_file = os.path.join(self.dir, seed_admin.SEED_NAME)
        first_sha = self.client.get(self.api).json()['built']['sha256']
        old = time.time() - 23 * 3600
        for path in (seed_file, seed_file + '.manifest.json'):
            os.utime(path, (old, old))
        self.assertIsNotNone(self.client.get(self.api).json()['built'])  # not yet
        old = time.time() - 25 * 3600
        for path in (seed_file, seed_file + '.manifest.json'):
            os.utime(path, (old, old))
        status = self.client.get(self.api).json()
        self.assertEqual((status['built'], status['file']), (None, None))
        self.assertFalse(os.path.exists(seed_file))
        self.assertEqual(self.client.get(f'{self.api}/download/seed').status_code, 404)
        self.create()
        CVEEntry.objects.filter(cve_id=self.ids['clean']).update(title='changed')
        with mock.patch('cveFeed.seed_admin.prune', wraps=seed_admin.prune) as prune:
            seed_admin.begin('export', self.admin)
            seed_admin.run_export(self.admin.pk)
        self.assertIn(mock.call(force=True), prune.call_args_list)
        self.assertNotEqual(self.client.get(self.api).json()['built']['sha256'], first_sha)
        self.assertEqual(sorted(os.listdir(self.dir)), ['cve-seed.jsonl.gz', 'cve-seed.jsonl.gz.manifest.json'])

    def test_a_stale_upload_is_pruned(self):
        stale = os.path.join(self.dir, 'incoming-seed-abc')
        open(stale, 'wb').write(b'x')
        old = time.time() - 3 * 3600
        os.utime(stale, (old, old))
        seed_admin.prune()
        self.assertFalse(os.path.exists(stale))


class SeedFolderTests(TestCase):
    def test_the_folder_is_private_and_outside_the_source_tree(self):
        from django.conf import settings
        base = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {'CVENGINE_SEED_DIR': os.path.join(base, 'private')}):
            folder = seed_admin.seed_dir()
        self.assertEqual(oct(os.stat(folder).st_mode & 0o777), '0o700')
        self.assertFalse(os.path.abspath(folder).startswith(os.path.abspath(settings.RENGINE_HOME) + os.sep))
        with mock.patch.dict(os.environ, {'CVENGINE_SEED_DIR': ''}), mock.patch('os.makedirs'), mock.patch('os.chmod'):
            self.assertTrue(seed_admin.seed_dir().endswith('/.config/cvengine/seed'))


class SeedImportTests(TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        patcher = mock.patch('cveFeed.seed_admin.seed_dir', return_value=self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        cache.delete(seed_admin.LOCK)
        cache.delete(seed_admin.JOB)
        admin_client(self)
        self.api = '/cve/api/settings/cve_seed'
        now = timezone.now()
        for n in range(3):
            CVEEntry.objects.create(cve_id=f'CVE-2099-80{n}', title=f't{n}', affected=NGINX, published_at=now, cvss=9.8, kev=True, cvss_vector=VECTOR)
        with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
            detection_author.author_rules()
        self.src = os.path.join(tempfile.mkdtemp(), 'cve-seed.jsonl.gz')
        self.manifest = seed.export_seed(self.src)
        self.manifest_file = self.src + '.manifest.json'
        CVEEntry.objects.all().delete()

    def upload(self, seed_bytes=None, manifest=None, with_manifest=True, raw_manifest=None):
        body = seed_bytes if seed_bytes is not None else open(self.src, 'rb').read()
        headers = {'HTTP_X_SEED_NAME': 'cve-seed.jsonl.gz'}
        if raw_manifest is not None:
            headers['HTTP_X_SEED_MANIFEST'] = raw_manifest
        elif with_manifest:
            headers['HTTP_X_SEED_MANIFEST'] = json.dumps({k: (manifest or self.manifest)[k] for k in ('format', 'count', 'bytes', 'sha256')})
        with mock.patch('cveFeed.tasks.import_cve_seed_file.delay') as delay:
            response = self.client.post(f'{self.api}/import', data=body, content_type='application/octet-stream', **headers)
        return response, delay

    def run_queued(self, delay, verified=True):
        path, user_id, was_verified = delay.call_args.args
        self.assertEqual((user_id, was_verified), (self.admin.pk, verified))
        self.assertTrue(os.path.exists(path))
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o600')
        return seed_admin.run_import(path, user_id, was_verified), path

    def test_import_with_its_manifest_loads_the_catalog_and_removes_the_upload(self):
        response, delay = self.upload()
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()['building'])
        created, path = self.run_queued(delay)
        self.assertEqual(created, self.manifest['count'])
        self.assertFalse(os.path.exists(path))
        self.assertEqual((CVEEntry.objects.count(), CVEDetection.objects.count()), (self.manifest['count'], self.manifest['with_detection']))
        status = self.client.get(self.api).json()
        self.assertEqual((status['building'], status['job']['state'], status['job']['result']['verified']), (False, 'done', True))
        self.assertEqual(os.listdir(self.dir), [])
        actions = list(AuditLog.objects.values_list('action', flat=True).order_by('id'))
        self.assertEqual(actions, ['cve_seed.import', 'cve_seed.imported'])
        self.assertEqual(AuditLog.objects.get(action='cve_seed.imported').detail['created'], self.manifest['count'])

    def test_a_second_import_is_idempotent(self):
        self.run_queued(self.upload()[1])
        before = list(CVEEntry.objects.order_by('cve_id').values_list('cve_id', 'synced_at'))
        response, delay = self.upload()
        self.assertEqual(response.status_code, 200)
        self.run_queued(delay)
        result = self.client.get(self.api).json()['job']['result']
        self.assertEqual((result['created'], result['skipped'], result['detections']), (0, self.manifest['count'], 0))
        self.assertEqual(list(CVEEntry.objects.order_by('cve_id').values_list('cve_id', 'synced_at')), before)

    def test_import_without_a_manifest_still_validates_and_says_the_checksum_was_not_checked(self):
        response, delay = self.upload(with_manifest=False)
        self.assertEqual(response.status_code, 200)
        self.run_queued(delay, verified=False)
        self.assertFalse(self.client.get(self.api).json()['job']['result']['verified'])

    def test_a_manifest_that_disagrees_is_refused_before_anything_is_imported(self):
        for change in ({'sha256': '0' * 64}, {'bytes': 1}, {'count': self.manifest['count'] + 1}):
            response, delay = self.upload(manifest={**self.manifest, **change})
            self.assertEqual(response.status_code, 400, change)
            delay.assert_not_called()
            self.assertEqual(CVEEntry.objects.count(), 0)
            self.assertFalse(self.client.get(self.api).json()['building'])  # the lock is released
            self.assertEqual(os.listdir(self.dir), [])
        response, _ = self.upload(raw_manifest='not json')
        self.assertEqual(response.status_code, 400)
        self.assertFalse(self.client.get(self.api).json()['building'])

    def test_a_file_that_is_not_a_seed_is_refused(self):
        for body in (b'plain text, not gzip', gzip.compress(b'{"format": 99}\n'), gzip.compress(b'not json\n')):
            response, delay = self.upload(seed_bytes=body, with_manifest=False)
            self.assertEqual(response.status_code, 400, body)
            delay.assert_not_called()
            self.assertEqual(os.listdir(self.dir), [])
        self.assertEqual(self.client.post(f'{self.api}/import', data={}).status_code, 400)  # no file chosen

    def test_the_upload_size_is_capped(self):
        with mock.patch.object(seed_admin, 'MAX_UPLOAD', 100):
            response, delay = self.upload()
        self.assertEqual(response.status_code, 413)
        self.assertIn('limit', response.json()['error'])
        delay.assert_not_called()
        self.assertEqual(os.listdir(self.dir), [])
        self.assertFalse(cache.get(seed_admin.LOCK))

    def test_a_body_longer_than_it_said_is_cut_off_and_removed(self):
        class Lying:
            META = {'CONTENT_LENGTH': '10'}

            def __init__(self):
                self.left = 1000

            def read(self, n):
                chunk, self.left = b'x' * min(n, self.left), max(0, self.left - n)
                return chunk
        with self.assertRaises(ValueError):
            seed_admin.save_stream(Lying(), 100, 'incoming-seed')
        self.assertEqual(os.listdir(self.dir), [])

    def test_a_bad_line_is_counted_and_never_stops_the_import(self):
        lines = read_seed(self.src).splitlines()
        lines.insert(2, json.dumps({'cve_id': '../../etc/passwd'}))
        bad = gzip.compress(('\n'.join(lines) + '\n').encode())
        response, delay = self.upload(seed_bytes=bad, with_manifest=False)
        self.assertEqual(response.status_code, 200, response.content)
        self.run_queued(delay, verified=False)
        result = self.client.get(self.api).json()['job']['result']
        self.assertEqual((result['created'], result['invalid']), (self.manifest['count'], 1))


class CommandLineTests(TestCase):
    def test_import_checks_the_manifest_beside_the_file(self):
        now = timezone.now()
        CVEEntry.objects.create(cve_id='CVE-2099-8500', title='t', published_at=now)
        path = os.path.join(tempfile.mkdtemp(), 'seed.jsonl.gz')
        manifest = seed.export_seed(path)
        CVEEntry.objects.all().delete()
        out = io.StringIO()
        call_command('import_cve_seed', path, stdout=out)
        self.assertIn('size, sha256 and count agree', out.getvalue())
        self.assertEqual(CVEEntry.objects.count(), 1)
        CVEEntry.objects.all().delete()
        json.dump({**manifest, 'sha256': '1' * 64}, open(path + '.manifest.json', 'w'))
        from django.core.management.base import CommandError
        with self.assertRaises(CommandError):
            call_command('import_cve_seed', path, stdout=io.StringIO())
        self.assertEqual(CVEEntry.objects.count(), 0)

    def test_export_command_reports_what_was_withheld(self):
        plant()
        path = os.path.join(tempfile.mkdtemp(), 'seed.jsonl.gz')
        out = io.StringIO()
        call_command('export_cve_seed', '--out', path, '--no-detections', stdout=out)
        self.assertIn('the scrub dropped 2 CVE record(s) and 3 detection record(s)', out.getvalue())
        for needle in SENSITIVE:
            self.assertNotIn(needle, out.getvalue() + read_seed(path), needle)
