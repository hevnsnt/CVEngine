import os
import re
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
        for required in ('discovery_queue', 'cve_feed_queue', 'main_scan_queue', 'api_queue'):
            self.assertIn(required, queues)

    def test_theharvester_is_gone(self):
        self.assertNotIn('theHarvester', ' '.join(worker_commands()))
        self.assertNotIn('theHarvester_queue', SCRIPT.read_text())

    def test_api_tasks_are_loaded(self):
        classic = [c for c in worker_commands() if 'api_queue' in c]
        self.assertEqual(len(classic), 1)
        self.assertIn('api.shared_api_tasks', classic[0])


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
