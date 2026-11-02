from django.test import SimpleTestCase

from cveFeed import soft404


def answer(path='/admin', status=200, body='', **kw):
	return soft404.fingerprint({'status': status, 'body': body, 'content_type': kw.pop('content_type', 'text/html'), 'location': kw.pop('location', ''), **kw}, path)


SHELL = '<html><head><title>App</title></head><body><div id="root">Loading the application, please wait while it starts. ' + 'Welcome to the service portal. ' * 8 + '</div></body></html>'


class NormaliseTests(SimpleTestCase):
	def test_what_changes_between_two_requests_is_taken_out(self):
		a = soft404.normalise('id 3f2504e0-4f89-11d3-9a0c-0305e82c3301 at 2026-10-29T21:44:12Z nonce="abc123def456" n=1730238252 csrf-token: q1w2e3r4t5', '/x')
		b = soft404.normalise('id 9b2f1c88-0000-4a4a-8888-aaaaaaaaaaaa at 2026-10-30T01:02:03Z nonce="zzz999yyy888" n=1730300000 csrf-token: 0p9o8i7u6y', '/x')
		self.assertEqual(a, b)

	def test_the_requested_path_in_any_form_is_taken_out(self):
		text = 'Not found: /my page and /my%20page and /my page'
		self.assertNotIn('my page', soft404.normalise(text, '/my page'))
		self.assertEqual(soft404.normalise('See /a/b', '/a/b'), soft404.normalise('See /c/d', '/c/d'))

	def test_the_bare_slug_is_taken_out_with_and_without_the_slash_in_any_case_and_encoding(self):
		for text in ('The page "admin" could not be found', 'No such page: /admin', 'ADMIN is gone', 'Not found: admin/', 'Not found: %2Fadmin'):
			self.assertEqual(soft404.normalise(text, '/admin'), soft404.normalise(text.replace('admin', 'cvengine-ab12cd34ef56').replace('ADMIN', 'CVENGINE-AB12CD34EF56'), '/cvengine-ab12cd34ef56'), text)
		self.assertEqual(soft404.normalise('page "my page"', '/my page'), soft404.normalise('page "my%20page"', '/my page'))
		self.assertEqual(soft404.normalise('page "my+page"', '/my page'), soft404.normalise('page "my page"', '/my page'))

	def test_a_longer_word_that_holds_the_slug_is_left_alone(self):
		self.assertIn('administrator', soft404.normalise('the administrator panel is here', '/admin'))
		self.assertIn('padmin', soft404.normalise('padmin', '/admin'))

	def test_the_last_segment_and_the_whole_path_both_count_as_the_slug(self):
		self.assertEqual(soft404.normalise('Not found: "wp-login"', '/wp-login.php'), soft404.normalise('Not found: "cvengine-1"', '/cvengine-1.php'))
		self.assertEqual(soft404.normalise('Not found: "users"', '/api/users'), soft404.normalise('Not found: "cvengine-1"', '/api/cvengine-1'))
		self.assertEqual(soft404.normalise('Not found: "api/users"', '/api/users'), soft404.normalise('Not found: "api/cvengine-1"', '/api/cvengine-1'))


class SameTests(SimpleTestCase):
	def test_a_page_that_names_the_bare_slug_is_the_same_as_the_missing_page(self):
		def page(name):
			return f'<html><head><title>Not found - Example</title></head><body><h1>Oops</h1><p>The page "{name}" could not be found.</p><p>Try the search box.</p></body></html>'
		self.assertTrue(soft404.same(answer('/admin', body=page('admin')), answer('/cvengine-ab12cd34ef56', body=page('cvengine-ab12cd34ef56'))))

	def test_a_title_that_names_the_slug_is_the_same_as_the_missing_pages_title(self):
		chrome = 'Portal navigation menu footer copyright 2026 ' * 20

		def page(name):
			return {'body': f'<html><head><title>{name} - Portal</title></head><body>{chrome}<h2>{name}</h2></body></html>', 'title': f'{name} - Portal'}
		self.assertTrue(soft404.same(answer('/admin', **page('admin')), answer('/cvengine-ab12cd34ef56', **page('cvengine-ab12cd34ef56'))))
		self.assertTrue(soft404.same(answer('/Admin', **page('ADMIN')), answer('/cvengine-ab12cd34ef56', **page('cvengine-ab12cd34ef56'))))

	def test_a_real_page_that_uses_the_word_is_still_another_page(self):
		def missing(name):
			return f'<html><head><title>Portal</title></head><body>{"Portal menu footer " * 20}<p>The page "{name}" could not be found.</p></body></html>'
		real = '<html><head><title>Portal</title></head><body>' + 'Portal menu footer ' * 20 + '<p>Admin console: ' + ' '.join(f'user{n} role{n}' for n in range(40)) + '</p></body></html>'
		self.assertFalse(soft404.same(answer('/admin', body=real), answer('/cvengine-ab12cd34ef56', body=missing('cvengine-ab12cd34ef56'))))

	def test_the_same_page_is_the_same(self):
		self.assertTrue(soft404.same(answer(body=SHELL), answer('/cvengine-1', body=SHELL)))

	def test_a_reflected_path_does_not_make_two_pages_different(self):
		self.assertTrue(soft404.same(answer('/admin', body='<h1>No such page: /admin</h1>' + 'x ' * 40), answer('/cvengine-ab12', body='<h1>No such page: /cvengine-ab12</h1>' + 'x ' * 40)))

	def test_a_page_with_a_moving_part_is_the_same_when_the_rest_is(self):
		words = ' '.join(f'word{n}' for n in range(120))
		a = answer(body=f'<p>{words}</p><p>visitors today: 18</p>')
		b = answer('/cvengine-1', body=f'<p>{words}</p><p>visitors today: 21 and counting</p>')
		self.assertTrue(soft404.same(a, b))

	def test_another_status_or_type_is_another_page(self):
		self.assertFalse(soft404.same(answer(body=SHELL), answer(status=403, body=SHELL)))
		self.assertFalse(soft404.same(answer(body=SHELL), answer(body=SHELL, content_type='application/json')))

	def test_a_different_page_of_the_same_size_is_another_page(self):
		other = '<html><body>' + ' '.join(f'user{n} record{n} role{n}' for n in range(60)) + '</body></html>'
		self.assertFalse(soft404.same(answer(body=SHELL), answer(body=other)))

	def test_the_same_template_with_another_title_or_a_sign_in_form_is_another_page(self):
		chrome = ' '.join(f'nav{n} footer{n} link{n}' for n in range(80))
		missing = answer('/x', body=f'<title>Home</title>{chrome} not found', title='Home')
		self.assertTrue(soft404.same(answer(body=f'<title>Home</title>{chrome} not here', title='Home'), missing))
		self.assertFalse(soft404.same(answer(body=f'<title>Admin</title>{chrome} not here', title='Admin'), missing))
		self.assertFalse(soft404.same(answer(body=f'<title>Home</title>{chrome} <input type="password">', title='Home'), missing))

	def test_a_page_of_another_size_is_another_page(self):
		self.assertFalse(soft404.same(answer(body=SHELL), answer(body=SHELL + ' extra paragraph' * 400)))

	def test_redirects_are_the_same_when_they_lead_to_the_same_place(self):
		a = answer('/admin', 302, location='https://h.test/login?next=/admin')
		b = answer('/cvengine-ab12', 302, location='https://h.test/login?next=/cvengine-ab12')
		self.assertTrue(soft404.same(a, b))
		self.assertFalse(soft404.same(a, answer('/x', 302, location='https://h.test/other')))

	def test_a_short_body_must_be_identical(self):
		self.assertTrue(soft404.same(answer(body='Forbidden'), answer('/x', body='Forbidden')))
		self.assertFalse(soft404.same(answer(body='Forbidden'), answer('/x', body='Not allowed')))

	def test_nothing_to_compare_with_is_not_the_same(self):
		self.assertFalse(soft404.same(answer(body=SHELL), None))

	def test_what_may_be_stored_has_no_body_or_shingles(self):
		kept = soft404.public(answer(body=SHELL))
		self.assertEqual(set(kept), {'status', 'type', 'redirect', 'hash', 'length'})
