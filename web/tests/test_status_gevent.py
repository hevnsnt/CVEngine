"""``system_status`` is also called inside a Celery lane (``reviewer.ops_checks``, half-hourly), which is a gevent worker: its probe "threads" are greenlets.
A deadline still holds there because a probe waits through gevent (Event waits, sockets, the database wait callback of ``reNgine.gevent_db``), and a thread
is not named there: Python 3.14 gives a thread's name to the operating system, and a greenlet runs on the main thread, so naming one renamed the whole
process in ``ps`` (``status-warm-row``, ``redis-claim``)."""
import os
import subprocess
import sys
import textwrap

from django.test import SimpleTestCase

SCRIPT = textwrap.dedent('''
    from gevent import monkey
    monkey.patch_all()
    import django, os, threading
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
    django.setup()
    import gevent
    from agentapi import status_probes
    from agentapi.status_probes import Probe
    names = []
    def watch(p, n, d):
        names.append(threading.current_thread().name)
        return 1
    run = status_probes.run([Probe('hangs', lambda p, n, d: gevent.sleep(30), limit=0.5, db=False), Probe('fine', watch, db=False)], budget=3)
    print('RESULT', run.results['hangs'].state, run.results['fine'].state, round(run.seconds, 1), names)
''')


class GeventDeadlineTests(SimpleTestCase):
    def test_a_probe_that_hangs_is_cut_off_in_a_gevent_worker_and_greenlets_are_not_named(self):
        out = subprocess.run([sys.executable, '-c', SCRIPT], capture_output=True, text=True, timeout=120, env={**os.environ, 'PYTHONPATH': os.pathsep.join(sys.path)},
                             cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        line = next((l for l in out.stdout.splitlines() if l.startswith('RESULT')), out.stderr[-800:])
        state_hangs, state_fine, seconds = line.split()[1:4]
        self.assertEqual((state_hangs, state_fine), ('timeout', 'ok'), line)
        self.assertLess(float(seconds), 2.5)
        self.assertNotIn('status-probe', line)  # the probe's greenlet carries no name of its own
