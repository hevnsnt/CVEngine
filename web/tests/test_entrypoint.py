import os
import re
import shlex
import subprocess
from pathlib import Path

from django.test import SimpleTestCase

SCRIPT = Path(__file__).resolve().parent.parent / 'celery-entrypoint.sh'


def worker_commands(autoreload=''):
    """Run just the worker-generation part of celery-entrypoint.sh and return the commands it would eval."""
    text = SCRIPT.read_text()
    start = text.index("loglevel='info'")
    end = text.index('eval "$commands"')
    body = text[start:end] + 'echo "$commands"\n'
    env = dict(os.environ, CELERY_AUTORELOAD=autoreload)
    out = subprocess.run(['bash', '-c', body], capture_output=True, text=True, env=env, check=True).stdout
    return [line for line in out.splitlines() if ' worker ' in line]


class EntrypointTests(SimpleTestCase):
    def test_few_gevent_workers(self):
        for autoreload in ('', '1'):
            cmds = worker_commands(autoreload)
            self.assertTrue(0 < len(cmds) <= 4)
            for cmd in cmds:
                self.assertIn('--pool=gevent', cmd)

    def test_no_queue_listed_twice(self):
        queues = []
        for cmd in worker_commands():
            queues += re.search(r'-Q (\S+)', cmd).group(1).split(',')
        self.assertEqual(len(queues), len(set(queues)))
        for required in ('discovery_queue', 'cve_feed_queue', 'send_notif_queue', 'api_queue'):
            self.assertIn(required, queues)

    def test_the_classic_worker_defaults_to_ten_slots(self):
        # certificate lookups may sleep up to 30 s in a slot waiting for crt.sh's pacing (ctmonitor.MAX_INLINE_WAIT), and every running task holds a
        # database connection: ten, not twenty, now that the autoscaler really fills them (reNgine/gevent_autoscale.py)
        saved = os.environ.pop('CLASSIC_CONCURRENCY', None)
        try:
            classic = [c for c in worker_commands() if 'classic_worker' in c]
            self.assertEqual(len(classic), 1)
            self.assertIn('--autoscale=10,1', classic[0])
            os.environ['CLASSIC_CONCURRENCY'] = '14'
            self.assertIn('--autoscale=14,1', [c for c in worker_commands() if 'classic_worker' in c][0])
        finally:
            os.environ.pop('CLASSIC_CONCURRENCY', None)
            if saved is not None:
                os.environ['CLASSIC_CONCURRENCY'] = saved

    def test_postgres_allows_enough_connections_for_the_workers_and_updates_apply_it(self):
        root = SCRIPT.parent.parent
        for name in ('docker-compose.yml', 'docker-compose.dev.yml'):
            self.assertIn('command: ["postgres", "-c", "max_connections=${POSTGRES_MAX_CONNECTIONS:-300}"]', (root / name).read_text(), name)
        # an existing install gets it on update: the db container is recreated when its definition changed, before the migration runs
        for name in ('update.sh', 'apply-update.sh', 'update-deploy.sh'):
            text = (root / 'scripts' / name).read_text()
            keep, recreate, ready = (text.index('up -d --no-recreate db redis'), text.index('up -d --no-deps db'),
                                     text.index('exec -T db pg_isready'))
            self.assertLess(keep, recreate, name)
            self.assertLess(recreate, ready, name)
            self.assertLess(ready, text.index('migrate --noinput', ready), name)

    def test_theharvester_is_gone(self):
        self.assertNotIn('theHarvester', ' '.join(worker_commands()))
        self.assertNotIn('theHarvester_queue', SCRIPT.read_text())


class WorkerSupervisionTests(SimpleTestCase):
    """The end of celery-entrypoint.sh (after the workers are started) over stand-in workers: it must pass a stop on to them, and a container
    whose worker died must not stay 'up' with that lane unconsumed."""

    def start(self, tmp, workers):
        text = SCRIPT.read_text()
        tail = text[text.index('eval "$commands"'):]
        commands = ''.join(f'sh -c \'echo $$ > "{tmp}/{name}.pid"; {body}\' &\n' for name, body in workers)
        return subprocess.Popen(['bash', '-c', f'commands={shlex.quote(commands)}\n{tail}'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def pid(self, tmp, name):
        import time
        path = Path(tmp) / f'{name}.pid'
        for _ in range(100):
            if path.exists() and path.read_text().strip():
                return int(path.read_text())
            time.sleep(0.05)
        self.fail(f'worker {name} did not start')

    def alive(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        try:  # a zombie that nobody has reaped yet is not running
            return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] != 'Z'
        except OSError:
            return False

    def test_one_worker_dying_stops_the_others_and_fails_the_container_so_it_restarts(self):
        import tempfile
        import time
        with tempfile.TemporaryDirectory() as tmp:
            process = self.start(tmp, [('lasting', 'exec sleep 60'), ('dying', 'sleep 0.5; exit 3')])
            lasting = self.pid(tmp, 'lasting')
            out, _ = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 3, out)
            self.assertIn('A Celery worker exited', out)
            time.sleep(0.2)
            self.assertFalse(self.alive(lasting), 'the surviving worker must be stopped, so the restart brings all of them back')

    def test_a_worker_that_exits_cleanly_still_fails_the_container(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            process = self.start(tmp, [('lasting', 'exec sleep 60'), ('quiet', 'sleep 0.3; exit 0')])
            out, _ = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 1, out)

    def test_a_stop_signal_is_passed_on_to_every_worker_and_the_container_exits(self):
        import signal
        import tempfile
        import time
        with tempfile.TemporaryDirectory() as tmp:
            process = self.start(tmp, [('one', 'exec sleep 60'), ('two', 'exec sleep 60')])
            pids = [self.pid(tmp, 'one'), self.pid(tmp, 'two')]
            time.sleep(0.3)  # the trap is installed once the workers are started
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=20)
            self.assertEqual(process.returncode, 143)
            time.sleep(0.2)
            self.assertFalse([pid for pid in pids if self.alive(pid)])

    def test_the_makemigrations_loop_and_the_clearing_collectstatic_are_gone(self):
        text = SCRIPT.read_text()
        self.assertNotIn('manage.py makemigrations', text)  # it wrote migration files into the host's checkout
        self.assertNotIn('collectstatic --no-input --clear', text)  # it emptied the volume the proxy serves
        self.assertNotIn('manage.py loaddata', text)  # it overwrote edited engines at every start; load_default_fixtures only adds what is missing
        self.assertIn('manage.py load_default_fixtures', text)


WEB_SCRIPT = Path(__file__).resolve().parent.parent / 'entrypoint.sh'
BEAT_SCRIPT = Path(__file__).resolve().parent.parent / 'beat-entrypoint.sh'


def web_command(**env):
    """Run entrypoint.sh with a stub python3 that prints its arguments; return the lines it printed."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        stub = Path(tmp) / 'python3'
        stub.write_text('#!/bin/sh\necho "$@"\n')
        stub.chmod(0o755)
        environ = {k: v for k, v in os.environ.items() if not k.startswith('GUNICORN_') and k != 'DEBUG'}
        environ.update(PATH=f'{tmp}:{os.environ["PATH"]}', **env)
        out = subprocess.run(['bash', str(WEB_SCRIPT)], capture_output=True, text=True, env=environ, check=True).stdout
    return out.splitlines()


class WebEntrypointTests(SimpleTestCase):
    def test_production_runs_gunicorn_after_migrating(self):
        lines = web_command(DEBUG='0')
        self.assertEqual(lines[0], 'manage.py migrate --noinput')
        self.assertIn('-m gunicorn reNgine.wsgi:application', lines[1])
        self.assertIn('--bind 0.0.0.0:8000', lines[1])  # the proxy's upstream is rengine:8000
        self.assertIn('--worker-class gthread', lines[1])
        self.assertNotIn('runserver', ' '.join(lines))

    def test_unset_debug_is_production(self):
        self.assertIn('gunicorn', ' '.join(web_command()))

    def test_timeout_covers_the_proxy_read_timeout_and_is_tunable(self):
        self.assertIn('--timeout 300', web_command(DEBUG='0')[1])
        self.assertIn('--timeout 600 ', web_command(DEBUG='0', GUNICORN_TIMEOUT='600')[1] + ' ')
        self.assertIn('--workers 2', web_command(DEBUG='0', GUNICORN_WORKERS='2')[1])

    def test_development_keeps_runserver(self):
        lines = web_command(DEBUG='1')
        self.assertEqual(lines[1], 'manage.py runserver 0.0.0.0:8000')
        self.assertNotIn('gunicorn', ' '.join(lines))

    def test_proxy_upstream_port_matches(self):
        conf = Path(__file__).resolve().parents[2] / 'config' / 'nginx' / 'rengine.conf'
        if conf.is_file():  # the config directory is not mounted inside the web container
            self.assertIn('http://rengine:8000/', conf.read_text())


class BeatEntrypointTests(SimpleTestCase):
    def test_wait_is_bounded_and_success_executes_beat(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            python = path / 'python3'
            sleep = path / 'sleep'
            python.write_text('#!/bin/sh\nexit "${MIGRATION_EXIT:-0}"\n')
            sleep.write_text('#!/bin/sh\nexit 0\n')
            python.chmod(0o755)
            sleep.chmod(0o755)
            env = {**os.environ, 'PATH': f'{temp}:{os.environ["PATH"]}', 'MIGRATION_EXIT': '1'}
            failed = subprocess.run(['bash', str(BEAT_SCRIPT), 'echo', 'beat-started'], capture_output=True, text=True, env=env)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn('attempt 60/60', failed.stdout)
            self.assertNotIn('beat-started', failed.stdout)
            env['MIGRATION_EXIT'] = '0'
            started = subprocess.run(['bash', str(BEAT_SCRIPT), 'echo', 'beat-started'], capture_output=True, text=True, env=env)
            self.assertEqual(started.returncode, 0)
            self.assertIn('beat-started', started.stdout)
