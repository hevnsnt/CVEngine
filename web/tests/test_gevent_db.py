"""A gevent worker keeps running while a task waits for Postgres (reNgine/gevent_db.py)."""
import os
import subprocess
import sys
import textwrap
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase

from reNgine import gevent_db

PROBE = textwrap.dedent('''
    import sys, time
    from gevent import monkey; monkey.patch_all()
    import gevent, psycopg2
    import importlib.util
    spec = importlib.util.spec_from_file_location('gevent_db', %(path)r)
    gevent_db = importlib.util.module_from_spec(spec); spec.loader.exec_module(gevent_db)
    if %(install)r:
        assert gevent_db.install()
    cfg = %(cfg)r
    ticks = []
    t0 = time.time()
    def ticker():
        last = time.time()
        while time.time() - t0 < 2.5:
            gevent.sleep(0.05); now = time.time(); ticks.append(now - last); last = now
    def query():
        c = psycopg2.connect(host=cfg['HOST'], port=cfg['PORT'], user=cfg['USER'], password=cfg['PASSWORD'], dbname='postgres')
        c.cursor().execute('select pg_sleep(1.5)'); c.close()
    gevent.joinall([gevent.spawn(ticker), gevent.spawn(query)])
    print('GAP %%.2f' %% max(ticks))
''')


class GeventDatabaseTests(SimpleTestCase):
    def gap(self, install):
        cfg = settings.DATABASES['default']
        code = PROBE % {'path': gevent_db.__file__, 'install': install, 'cfg': {k: cfg.get(k) for k in ('HOST', 'PORT', 'USER', 'PASSWORD', 'NAME')}}
        out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=60, env={**os.environ})
        self.assertIn('GAP', out.stdout, out.stderr[-500:])
        self.assertNotIn('Traceback', out.stderr, out.stderr[-800:])  # the query itself must have run
        return float(out.stdout.split('GAP')[1])

    def test_a_query_leaves_the_event_loop_running_when_the_callback_is_installed_and_freezes_it_when_not(self):
        try:
            import gevent  # noqa: F401
        except ImportError:
            self.skipTest('gevent is not installed')
        self.assertGreater(self.gap(False), 1.2)  # what psycopg2 does on its own: the whole worker waits
        self.assertLess(self.gap(True), 0.4)

    def test_it_is_installed_only_in_a_process_gevent_has_patched(self):
        with mock.patch.object(gevent_db, 'gevent_patched', return_value=False), mock.patch('psycopg2.extensions.set_wait_callback') as hook:
            self.assertFalse(gevent_db.install())
            hook.assert_not_called()
        with mock.patch.object(gevent_db, 'gevent_patched', return_value=True), mock.patch('psycopg2.extensions.set_wait_callback') as hook:
            self.assertTrue(gevent_db.install())
            hook.assert_called_once_with(gevent_db.wait_callback)
