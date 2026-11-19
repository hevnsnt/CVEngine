"""A Sentinel's discovery screenshot can never become a page of this site (security review of develop @ 36d63dfa, HIGH 1).

Before the fix a Sentinel could post a screenshot named ``x.html`` (or ``x.svg``) whose bytes merely started with the PNG signature: it was accepted,
written as ``sentinel-x.html``, and the host screenshot route served it as ``text/html`` from this origin. Now: the name must carry the type's extension
(``sentinel_stream._screenshot``), the file is written under a name of the server's own (``discovery.persist_screenshot_blobs``), the route serves only
a PNG or JPEG read from the file's bytes with ``nosniff``, ``inline`` and a sandboxing CSP (``views._cacheable_file``), and the upgrade backfill
``neutralise_screenshots`` renames or removes what an older version stored."""
import base64
import io
import os
import shutil
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_stream
from cveFeed import discovery, shots, upgrade_backfills
from cveFeed.models import RdpScreenshot
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import Subdomain
from targetApp.models import Domain
from tests.test_tenancy import client_for

PNG = b'\x89PNG\r\n\x1a\n'
JPEG = b'\xff\xd8\xff\xe0'
HOSTILE = PNG + b'<html><script>document.title="XSS:"+document.cookie</script></html>'
SAFE_HEADERS = {'X-Content-Type-Options': 'nosniff', 'Content-Disposition': 'inline', 'Content-Security-Policy': "default-src 'none'; sandbox"}


def shot(filename, data=HOSTILE, kind='image/png', host='www.example.test'):
    return {'host': host, 'filename': filename, 'content_type': kind, 'data': base64.b64encode(data).decode()}


def batch(*screenshots):
    task = SimpleNamespace(target={'scope': {'in_scope_domains': ['example.test']}})
    return sentinel_stream.clean_partial(task, {'seq': 1, 'screenshots': list(screenshots)})['screenshots']


class Base(TestCase):
    def setUp(self):
        org = Org.objects.create(name='S', slug='s-x')
        self.project = Project.objects.create(name='P', slug='px', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
        EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
            self.scan = discovery.start_discovery(self.domain)
        self.sub = Subdomain.objects.create(scan_history=self.scan, name='www.example.test', target_domain=self.domain)
        self.media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media, ignore_errors=True)
        media = self.settings(MEDIA_ROOT=self.media)
        media.enable()
        self.addCleanup(media.disable)
        self.viewer = User.objects.create_user('viewer', password='x')
        ProjectMembership.objects.create(user=self.viewer, project=self.project, role='user')

    def get(self, sub=None, query='?row=1'):
        return client_for(self.viewer).get(f'/cve/px/hosts/{(sub or self.sub).id}/screenshot/{query}')

    def plant(self, rel, data):
        full = os.path.join(self.media, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'wb') as handle:
            handle.write(data)
        return full


class SentinelScreenshotTests(Base):
    def test_the_reported_html_screenshot_is_never_stored_or_served_as_a_page(self):
        """The reproduction: ``x.html`` with PNG magic up front, posted in a discovery batch."""
        self.assertEqual(batch(shot('x.html')), [])  # refused at the door
        discovery.persist_screenshot_blobs(self.scan, [shot('x.html')])  # and even a batch stored by an older version is written under the server's name
        self.sub.refresh_from_db()
        self.assertRegex(self.sub.screenshot_path, r'/sentinel-[0-9a-f]{32}\.png$')
        response = self.get()
        self.assertEqual((response.status_code, response['Content-Type']), (200, 'image/png'))
        for header, value in SAFE_HEADERS.items():
            self.assertEqual(response[header], value, header)
        self.assertEqual(b''.join(response.streaming_content), HOSTILE)  # the bytes, as a picture the browser will not render as HTML

    def test_a_name_must_carry_its_types_extension(self):
        kept = batch(shot('a.png'), shot('b.PNG'), shot('c.jpg', JPEG + b'x', 'image/jpeg'), shot('d.jpeg', JPEG + b'x', 'image/jpeg'))
        self.assertEqual([s['filename'] for s in kept], ['a.png', 'b.PNG', 'c.jpg', 'd.jpeg'])
        for name, data, kind in (('x.html', HOSTILE, 'image/png'), ('x.svg', HOSTILE, 'image/png'), ('x.htm', HOSTILE, 'image/png'),
                                 ('x.jpg', HOSTILE, 'image/png'), ('x.png', JPEG + b'x', 'image/jpeg'), ('noextension', HOSTILE, 'image/png'),
                                 ('x.png.html', HOSTILE, 'image/png'), ('x.png', b'<svg/>', 'image/png')):
            self.assertEqual(batch(shot(name, data, kind)), [], name)

    def test_two_hosts_whose_files_share_a_name_keep_their_own_pictures(self):
        other = Subdomain.objects.create(scan_history=self.scan, name='api.example.test', target_domain=self.domain)
        discovery.persist_screenshot_blobs(self.scan, batch(shot('screenshot.png', PNG + b'one'), shot('screenshot.png', PNG + b'two', host='api.example.test')))
        self.sub.refresh_from_db()
        other.refresh_from_db()
        self.assertNotEqual(self.sub.screenshot_path, other.screenshot_path)
        self.assertEqual(b''.join(self.get().streaming_content), PNG + b'one')
        self.assertEqual(b''.join(self.get(other).streaming_content), PNG + b'two')

    def test_a_new_picture_of_the_host_replaces_this_scans_earlier_file(self):
        discovery.persist_screenshot_blobs(self.scan, batch(shot('a.png', PNG + b'one')))
        self.sub.refresh_from_db()
        first = os.path.join(self.media, self.sub.screenshot_path)
        discovery.persist_screenshot_blobs(self.scan, batch(shot('b.png', PNG + b'two')))
        self.sub.refresh_from_db()
        self.assertFalse(os.path.exists(first))
        self.assertTrue(os.path.isfile(os.path.join(self.media, self.sub.screenshot_path)))

    def test_bytes_that_are_not_the_type_they_claim_are_never_written(self):
        discovery.persist_screenshot_blobs(self.scan, [shot('a.png', b'<html></html>'), shot('a.jpg', PNG + b'x', 'image/jpeg')])
        self.sub.refresh_from_db()
        self.assertIsNone(self.sub.screenshot_path)
        self.assertFalse(os.path.isdir(os.path.join(self.media, f'example.test_{self.scan.id}', 'screenshots'))
                         and os.listdir(os.path.join(self.media, f'example.test_{self.scan.id}', 'screenshots')))


class ServingTests(Base):
    def test_a_stored_file_is_served_by_its_bytes_never_its_name(self):
        rel = f'example.test_{self.scan.id}/screenshots/sentinel-x.html'
        self.plant(rel, HOSTILE)
        Subdomain.objects.filter(pk=self.sub.pk).update(screenshot_path=rel)
        response = self.get()
        self.assertEqual((response.status_code, response['Content-Type']), (200, 'image/png'))  # not text/html, whatever the name says
        self.assertEqual(response['Content-Security-Policy'], "default-src 'none'; sandbox")
        self.plant(rel, b'<html><script>alert(1)</script></html>')
        self.assertEqual(self.get().status_code, 404)  # neither picture type: never served
        self.plant(rel, b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>')
        self.assertEqual(self.get().status_code, 404)

    def test_a_not_modified_answer_carries_the_same_headers(self):
        rel = f'example.test_{self.scan.id}/screenshots/a.png'
        self.plant(rel, PNG + b'x')
        Subdomain.objects.filter(pk=self.sub.pk).update(screenshot_path=rel)
        etag = self.get()['ETag']
        response = client_for(self.viewer).get(f'/cve/px/hosts/{self.sub.id}/screenshot/?row=1', HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

    def test_an_rdp_capture_is_served_the_same_way(self):
        rel = f'example.test_{self.scan.id}/rdp/192.0.2.1_3389.png'
        self.plant(rel, PNG + b'rdp')
        RdpScreenshot.objects.create(project=self.project, domain=self.domain, host='www.example.test', address='192.0.2.1', port=3389, image_path=rel)
        url = f'/cve/px/hosts/{self.sub.id}/rdp-screenshot/3389/'
        response = client_for(self.viewer).get(url)
        self.assertEqual((response.status_code, response['Content-Type']), (200, 'image/png'))
        for header, value in SAFE_HEADERS.items():
            self.assertEqual(response[header], value, header)
        self.plant(rel, b'<html></html>')
        self.assertEqual(client_for(self.viewer).get(url).status_code, 404)

    def test_the_image_type_is_read_from_the_magic_bytes(self):
        self.assertEqual(shots.image_type(PNG + b'x'), 'image/png')
        self.assertEqual(shots.image_type(JPEG), 'image/jpeg')
        for data in (b'', b'GIF89a', b'<svg/>', PNG[:7], b'RIFF....WEBP'):
            self.assertIsNone(shots.image_type(data), data)
        self.assertIsNone(shots.file_image_type(os.path.join(self.media, 'missing.png')))


class BackfillTests(Base):
    def stored(self, name, data, sub=None):
        rel = f'example.test_{self.scan.id}/screenshots/{name}'
        self.plant(rel, data)
        Subdomain.objects.filter(pk=(sub or self.sub).pk).update(screenshot_path=rel, screenshot_hash='abcd')
        return rel

    def run_backfill(self, apply=True):
        out = io.StringIO()
        call_command('neutralise_screenshots', *(['--apply'] if apply else []), stdout=out)
        return out.getvalue()

    def test_it_is_an_upgrade_backfill_that_runs_before_the_rescore(self):
        names = upgrade_backfills.BACKFILLS
        self.assertIn('neutralise_screenshots', names)
        self.assertLess(names.index('neutralise_screenshots'), names.index('rerate_findings'))

    def test_a_real_picture_with_a_page_name_is_renamed_and_anything_else_cleared(self):
        renamed = self.stored('sentinel-x.html', HOSTILE)
        other = Subdomain.objects.create(scan_history=self.scan, name='api.example.test', target_domain=self.domain)
        cleared = self.stored('sentinel-y.svg', b'<svg onload="alert(1)"/>', other)
        fine = Subdomain.objects.create(scan_history=self.scan, name='ok.example.test', target_domain=self.domain)
        kept = self.stored('sentinel-ok.png', PNG + b'ok', fine)
        dry = self.run_backfill(apply=False)
        self.assertIn('Dry run: 2 stored screenshot files (2 hosts)', dry)
        self.assertTrue(os.path.isfile(os.path.join(self.media, renamed)))  # a dry run changes nothing
        self.assertIn('1 renamed (real pictures), 1 cleared (not a picture)', self.run_backfill())
        self.sub.refresh_from_db()
        other.refresh_from_db()
        fine.refresh_from_db()
        self.assertRegex(self.sub.screenshot_path, r'/sentinel-[0-9a-f]{32}\.png$')
        self.assertEqual(self.get()['Content-Type'], 'image/png')
        self.assertFalse(os.path.exists(os.path.join(self.media, renamed)))
        self.assertEqual((other.screenshot_path, other.screenshot_hash), (None, ''))
        self.assertFalse(os.path.exists(os.path.join(self.media, cleared)))
        self.assertEqual(fine.screenshot_path, kept)  # a picture name is left alone
        self.assertIn('0 renamed', self.run_backfill())  # idempotent

    def test_a_row_that_points_outside_the_media_folder_is_cleared_and_nothing_outside_is_touched(self):
        outside = tempfile.NamedTemporaryFile(delete=False, suffix='.html')
        outside.write(PNG)
        outside.close()
        self.addCleanup(os.unlink, outside.name)
        Subdomain.objects.filter(pk=self.sub.pk).update(screenshot_path=os.path.relpath(outside.name, self.media))
        self.run_backfill()
        self.sub.refresh_from_db()
        self.assertIsNone(self.sub.screenshot_path)
        self.assertTrue(os.path.isfile(outside.name))
