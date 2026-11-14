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
    """The build a process serves (updater.build_id): a fingerprint of the static cve/ files and the page templates, fixed when the process starts."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        root = self.dir.name
        for sub in ('static/cve', 'web/cveFeed/templates/cveFeed', 'web/templates'):
            os.makedirs(os.path.join(root, sub))
        self.write('static/cve/app.js', 'one')
        self.write('web/cveFeed/templates/cveFeed/base.html', '<p>base</p>')
        self.write('web/.commit', A)
        override = override_settings(BASE_DIR=os.path.join(root, 'web'), STATICFILES_DIRS=[os.path.join(root, 'static')])
        override.enable()
        self.addCleanup(override.disable)
        self.addCleanup(setattr, updater, '_build_seen', None)
        updater._build_seen = None

    def write(self, name, text):
        with open(os.path.join(self.dir.name, name), 'w') as f:
            f.write(text)

    def fresh(self):
        updater._build_seen = None
        return updater.build_id()

    def test_the_same_files_give_the_same_twelve_hex_characters(self):
        first = self.fresh()
        self.assertRegex(first, r'^[0-9a-f]{12}$')
        self.assertEqual(self.fresh(), first)

    def test_one_changed_script_or_template_changes_it(self):
        first = self.fresh()
        self.write('static/cve/app.js', 'two')
        second = self.fresh()
        self.assertNotEqual(second, first)
        self.write('web/cveFeed/templates/cveFeed/base.html', '<p>changed</p>')
        self.assertNotIn(self.fresh(), (first, second))

    def test_a_new_file_changes_it_and_the_commit_file_does_not(self):
        first = self.fresh()
        self.write('web/.commit', B)
        os.environ['CVENGINE_COMMIT'] = B
        self.addCleanup(os.environ.pop, 'CVENGINE_COMMIT', None)
        self.assertEqual(self.fresh(), first)
        self.write('static/cve/new.js', 'x')
        self.assertNotEqual(self.fresh(), first)

    def test_a_running_process_keeps_its_answer_when_files_change_under_it(self):
        """A deploy rewrites ./web (a bind mount) while the old process still serves: it must not announce the new build."""
        first = self.fresh()
        self.write('static/cve/app.js', 'rewritten by a deploy')
        self.assertEqual(updater.build_id(), first)

    def test_the_web_process_computes_it_when_it_starts(self):
        self.assertIsNone(updater._build_seen)
        HtmlRevalidateMiddleware(lambda request: None)
        self.assertRegex(updater._build_seen, r'^[0-9a-f]{12}$')


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
        response = self.client.get('/cve/api/alive')
        self.assertEqual(response.json(), {'ok': True, 'build': updater.build_id()})
        self.assertRegex(updater.build_id(), r'^[0-9a-f]{12}$')
        self.assertEqual(response['Cache-Control'], 'no-store')

    def test_an_anonymous_caller_gets_no_build_from_alive_nor_from_any_page_before_sign_in(self):
        anonymous = Client()
        alive = anonymous.get('/cve/api/alive')
        login = anonymous.get('/login/')
        self.assertEqual((alive.status_code, alive['Location'].split('?')[0]), (302, '/login/'))  # the sign-in middleware answers first
        if True:  # were it to answer, the view itself tells no stranger the build
            from django.test import RequestFactory
            from django.contrib.auth.models import AnonymousUser
            from cveFeed import views
            request = RequestFactory().get('/cve/api/alive')
            request.user = AnonymousUser()
            self.assertEqual(json.loads(views.api_alive(request).content), {'ok': True})
        self.assertEqual(login.status_code, 200)
        self.assertNotIn('cvengine-build', login.content.decode())
        self.assertNotIn(updater.build_id(), login.content.decode())

    def test_a_page_carries_the_build_it_was_rendered_by_and_is_revalidated(self):
        response = self.client.get('/cve/settings/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f'<meta name="cvengine-build" content="{updater.build_id()}">')
        self.assertEqual(response['Cache-Control'], 'private, no-cache')

    def test_the_updates_state_names_the_build_so_the_settings_page_can_compare_it(self):
        self.assertEqual(self.client.get('/cve/api/settings/updates').json()['build'], updater.build_id())
