import json
import os
import tempfile
from unittest import mock

from django.contrib.auth.models import User
from django.http import FileResponse, HttpResponse, JsonResponse, StreamingHttpResponse
from django.test import Client, SimpleTestCase, TestCase, override_settings

from cveFeed import updater
from reNgine.middleware import HtmlRevalidateMiddleware

A, B = 'a' * 40, 'b' * 40


class BuildIdTests(SimpleTestCase):
    """The build a process serves (updater.build_id): the short commit, re-read only when web/.commit changes."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        settings_override = override_settings(BASE_DIR=self.dir.name)
        settings_override.enable()
        self.addCleanup(settings_override.disable)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('CVENGINE_COMMIT', None)
        updater._build_seen = None

    def commit(self, sha):
        with open(os.path.join(self.dir.name, '.commit'), 'w') as f:
            f.write(sha + '\n')

    def test_it_is_the_short_commit_and_empty_when_unknown(self):
        self.assertEqual(updater.build_id(), '')
        updater._build_seen = None
        self.commit(A)
        self.assertEqual(updater.build_id(), A[:12])

    def test_it_is_read_once_so_a_process_never_announces_a_build_it_is_not_running(self):
        """The host writes web/.commit when a deploy starts and ./web is a bind mount: the old process must keep answering the old build."""
        self.commit(A)
        self.assertEqual(updater.build_id(), A[:12])
        self.commit(B)
        self.assertEqual(updater.build_id(), A[:12])

    def test_the_environment_names_the_build_when_there_is_no_file(self):
        os.environ['CVENGINE_COMMIT'] = B
        self.assertEqual(updater.build_id(), B[:12])


class HtmlRevalidateTests(SimpleTestCase):
    def run_it(self, response):
        return HtmlRevalidateMiddleware(lambda request: response)(None)

    def test_a_page_that_sets_nothing_must_be_revalidated(self):
        self.assertEqual(self.run_it(HttpResponse('<p>x</p>'))['Cache-Control'], 'private, no-cache')
        self.assertEqual(self.run_it(HttpResponse('<p>x</p>', content_type='text/html; charset=utf-8'))['Cache-Control'], 'private, no-cache')

    def test_a_response_with_its_own_header_is_left_alone(self):
        for value in ('no-store', 'public, max-age=60', 'private, max-age=5'):
            response = HttpResponse('<p>x</p>')
            response['Cache-Control'] = value
            self.assertEqual(self.run_it(response)['Cache-Control'], value)

    def test_json_files_and_streams_are_not_touched(self):
        self.assertNotIn('Cache-Control', self.run_it(JsonResponse({'ok': True})))
        self.assertNotIn('Cache-Control', self.run_it(HttpResponse('a{}', content_type='text/css')))
        self.assertNotIn('Cache-Control', self.run_it(StreamingHttpResponse(iter(['<p>x</p>']), content_type='text/html')))
        with tempfile.NamedTemporaryFile(suffix='.html') as f:
            response = FileResponse(open(f.name, 'rb'), content_type='text/html')
            self.assertNotIn('Cache-Control', self.run_it(response))
            response.close()


class PagesCarryTheBuildTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.client.force_login(User.objects.create_superuser('stale-root', password='x'))
        updater._build_seen = None
        self.addCleanup(setattr, updater, '_build_seen', None)

    def test_alive_names_the_build_and_stays_uncached(self):
        with mock.patch.object(updater, 'installed_sha', return_value=A):
            response = self.client.get('/cve/api/alive')
        self.assertEqual(response.json(), {'ok': True, 'build': A[:12]})
        self.assertEqual(response['Cache-Control'], 'no-store')

    def test_an_anonymous_caller_gets_no_build_from_alive_nor_from_any_page_before_sign_in(self):
        anonymous = Client()
        with mock.patch.object(updater, 'installed_sha', return_value=A):
            alive = anonymous.get('/cve/api/alive')
            login = anonymous.get('/login/')
        self.assertEqual((alive.status_code, alive['Location'].split('?')[0]), (302, '/login/'))  # the sign-in middleware answers first
        self.assertNotIn(A[:12], alive.content.decode())
        with mock.patch.object(updater, 'installed_sha', return_value=A):  # and were it to answer, the view itself tells no stranger the build
            from django.test import RequestFactory
            from django.contrib.auth.models import AnonymousUser
            from cveFeed import views
            request = RequestFactory().get('/cve/api/alive')
            request.user = AnonymousUser()
            self.assertEqual(json.loads(views.api_alive(request).content), {'ok': True})
        self.assertEqual(login.status_code, 200)
        self.assertNotIn('cvengine-build', login.content.decode())
        self.assertNotIn(A[:12], login.content.decode())

    def test_a_page_carries_the_build_it_was_rendered_by_and_is_revalidated(self):
        with mock.patch.object(updater, 'installed_sha', return_value=A):
            response = self.client.get('/cve/settings/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f'<meta name="cvengine-build" content="{A[:12]}">')
        self.assertEqual(response['Cache-Control'], 'private, no-cache')

    def test_a_server_that_does_not_know_its_build_stamps_an_empty_one(self):
        with mock.patch.object(updater, 'installed_sha', return_value=''):
            self.assertContains(self.client.get('/cve/settings/'), '<meta name="cvengine-build" content="">')

    def test_the_updates_state_names_the_build_so_the_settings_page_can_compare_it(self):
        with mock.patch.object(updater, 'installed_sha', return_value=A):
            self.assertEqual(self.client.get('/cve/api/settings/updates').json()['build'], A[:12])
