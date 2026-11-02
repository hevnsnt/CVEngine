from django.db import connection
from django.test import TestCase


class NoJitTests(TestCase):
	def test_the_app_connection_never_jit_compiles_a_query(self):
		# Postgres compiled the large one-row-per-host queries with LLVM before running them: 0.1 s of work took 2 s, and up to a
		# minute on a busy server (reNgine/settings.py, DATABASES)
		with connection.cursor() as cur:
			cur.execute('SHOW jit')
			self.assertEqual(cur.fetchone()[0], 'off')
