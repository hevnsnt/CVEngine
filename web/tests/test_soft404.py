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

	def test_a_word_of_the_page_that_is_also_in_the_path_is_left_alone(self):
		self.assertIn('admin panel', soft404.normalise('the admin panel is here', '/admin'))


class SameTests(SimpleTestCase):
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
