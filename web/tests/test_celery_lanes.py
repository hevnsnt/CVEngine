"""A container must never stay up with a Celery lane missing.

The incident these pin (1.4.0, after the Update button): three of the four workers were gone, the entrypoint was still running, the container was
"up", and nothing consumed the cve_feed, validation and classic queues. The entrypoint had noticed the first worker die and sent the others SIGTERM
(a warm shutdown), then waited WITHOUT A LIMIT for them: the discovery worker held host assessments that wait on a Sentinel for hours, so the wait never
ended and `restart: always` was never reached. See ``celery-entrypoint.sh`` (``stop_lanes``, ``supervise``) and ``celery_healthcheck.py``.
"""
import os
import re
import shlex
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from unittest import mock

from django.test import SimpleTestCase, TestCase

WEB = Path(__file__).resolve().parent.parent
SCRIPT = WEB / 'celery-entrypoint.sh'
SCRIPTS = WEB.parent / 'scripts'


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] != 'Z'
    except OSError:
        return False


class Entrypoint:
    """The real end of celery-entrypoint.sh (from ``start_lanes``) over stand-in workers, one shell line each, in the shape the real lines have."""

    def __init__(self, tmp, workers, **env):
        self.tmp = Path(tmp)
        text = SCRIPT.read_text()
        tail = text[text.index('# --- start_lanes'):]
        commands = ''.join(f'sh -c \'echo $$ > "{tmp}/{name}.pid"; {body}\' -n {name} &\n' for name, body in workers)
        script = f'commands={shlex.quote(commands)}\n' + tail
        # the log goes to a file, not a pipe: a stand-in that is killed leaves its `sleep` child behind holding a pipe open, and reading would never end
        self.log = self.tmp / 'entrypoint.log'
        self.process = subprocess.Popen(['bash', '-c', script], stdout=(logfile := open(self.log, 'w')), stderr=subprocess.STDOUT, text=True,
                                        env={**os.environ, 'CELERY_SUPERVISE_INTERVAL': '0.2', **env}, start_new_session=True)
        logfile.close()  # the child has its own copy

    def cleanup(self):
        # whatever a test left behind (stand-ins that forked away) dies with the process group, by group id, never by a name pattern
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def pid(self, name):
        path = self.tmp / f'{name}.pid'
        for _ in range(100):
            if path.exists() and path.read_text().strip():
                return int(path.read_text())
            time.sleep(0.05)
        raise AssertionError(f'worker {name} did not start')

    def finish(self, timeout):
        try:
            self.process.wait(timeout=timeout)
        finally:
            self.cleanup()
        return self.process.returncode, self.log.read_text()


# a stand-in for a discovery worker that is busy: SIGTERM starts a "warm shutdown" that waits for the task it holds (here, a long sleep)
BUSY = 'trap "sleep 300" TERM; sleep 300 & wait'


class LaneSupervisionTests(SimpleTestCase):
    def test_a_lane_that_dies_while_discovery_is_busy_still_ends_the_container(self):
        # the incident: kill one lane, the others get SIGTERM, discovery will not stop for minutes. The container must still exit (bounded stop), non-zero.
        with tempfile.TemporaryDirectory() as tmp:
            ep = Entrypoint(tmp, [('discovery_worker', BUSY), ('cve_feed_worker', 'exec sleep 300'), ('validation_priority_worker', 'exec sleep 300'),
                                  ('classic_worker', 'exec sleep 300')], CELERY_STOP_GRACE='2')
            pids = {n: ep.pid(n) for n in ('discovery_worker', 'cve_feed_worker', 'validation_priority_worker', 'classic_worker')}
            time.sleep(0.4)
            os.kill(pids['cve_feed_worker'], signal.SIGKILL)  # an out-of-memory kill, say
            code, out = ep.finish(timeout=30)
            self.assertEqual(code, 137, out)  # the status of the lane that died: not 0, so restart: always acts
            self.assertIn("'cve_feed_worker'", out)  # the log says which lane
            self.assertIn('did not stop within 2s; killing it', out)
            time.sleep(0.3)
            ep.cleanup()
            self.assertFalse([n for n, pid in pids.items() if alive(pid)], 'no worker may outlive the container')

    def test_three_lanes_killed_at_once_leave_no_container_with_one_lane(self):
        with tempfile.TemporaryDirectory() as tmp:
            ep = Entrypoint(tmp, [('discovery_worker', BUSY), ('cve_feed_worker', 'exec sleep 300'), ('validation_priority_worker', 'exec sleep 300'),
                                  ('classic_worker', 'exec sleep 300')], CELERY_STOP_GRACE='2')
            pids = {n: ep.pid(n) for n in ('discovery_worker', 'cve_feed_worker', 'validation_priority_worker', 'classic_worker')}
            time.sleep(0.4)
            for name in ('cve_feed_worker', 'validation_priority_worker', 'classic_worker'):
                os.kill(pids[name], signal.SIGKILL)
            code, out = ep.finish(timeout=30)
            self.assertNotEqual(code, 0, out)
            time.sleep(0.3)
            self.assertFalse(alive(pids['discovery_worker']), 'the surviving lane must not be left running alone')

    def test_a_worker_that_fails_at_start_ends_the_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            ep = Entrypoint(tmp, [('discovery_worker', BUSY), ('cve_feed_worker', 'exit 1'), ('classic_worker', 'exec sleep 300')], CELERY_STOP_GRACE='2')
            code, out = ep.finish(timeout=30)
            self.assertEqual(code, 1, out)
            self.assertIn("'cve_feed_worker'", out)

    def test_a_worker_that_forks_away_and_exits_is_a_missing_lane(self):
        # a launcher that daemonises: its pid is gone while "its" process lives on elsewhere; the lane is not the process the supervisor started, so it is gone
        with tempfile.TemporaryDirectory() as tmp:
            ep = Entrypoint(tmp, [('discovery_worker', 'exec sleep 300'), ('classic_worker', '(sleep 300 &) ; exit 0')], CELERY_STOP_GRACE='2')
            code, out = ep.finish(timeout=30)
            self.assertEqual(code, 1, out)
            self.assertIn("'classic_worker'", out)
            ep.cleanup()

    def test_the_supervisor_checks_each_lane_not_a_wait_n(self):
        text = SCRIPT.read_text()
        self.assertFalse([line for line in text.splitlines() if 'wait -n' in line and not line.lstrip().startswith('#')])
        self.assertIn('lane_alive', text)
        # every wait after a stop is bounded, and a kill follows
        self.assertIn('CELERY_STOP_GRACE', text)
        self.assertIn('kill -KILL', text)

    def test_a_stop_is_still_a_warm_shutdown_then_exit_143(self):
        with tempfile.TemporaryDirectory() as tmp:
            ep = Entrypoint(tmp, [('one', 'exec sleep 300'), ('two', 'exec sleep 300')], CELERY_STOP_GRACE='5')
            pids = [ep.pid('one'), ep.pid('two')]
            time.sleep(0.4)
            ep.process.send_signal(signal.SIGTERM)
            code, out = ep.finish(timeout=30)
            self.assertEqual(code, 143, out)
            time.sleep(0.3)
            self.assertFalse([p for p in pids if alive(p)])

    def test_every_lane_line_names_its_node_so_the_log_and_the_check_can(self):
        text = SCRIPT.read_text()
        start, end = text.index("loglevel='info'"), text.index('# --- start_lanes')
        out = subprocess.run(['bash', '-c', text[start:end] + 'echo "$commands"\n'], capture_output=True, text=True, check=True).stdout
        names = re.findall(r' -n ([a-z_]+)', out)
        self.assertEqual(names, ['discovery_worker', 'cve_feed_worker', 'validation_priority_worker', 'classic_worker'])


class HealthcheckTests(SimpleTestCase):
    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('celery_healthcheck', WEB / 'celery_healthcheck.py')
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def app(self, replies):
        class Inspector:
            def active_queues(inner):
                return replies

        class Control:
            def inspect(inner, timeout=None):
                return Inspector()

        class App:
            control = Control()
        return App()

    ALL = {'discovery_worker@h': [{'name': 'discovery_queue'}], 'cve_feed_worker@h': [{'name': 'cve_feed_queue'}],
           'validation_priority_worker@h': [{'name': 'validation_priority_queue'}], 'classic_worker@h': [{'name': 'api_queue'}, {'name': 'report_queue'}]}

    def test_it_matches_the_workers_the_status_page_expects_and_the_entrypoints_node_names(self):
        from cveFeed import admin_api
        self.assertEqual(self.mod.LANES, admin_api.WORKERS)
        text = SCRIPT.read_text()
        for lane in self.mod.LANES:
            self.assertIn(f'"{lane}"', text)

    def test_healthy_when_all_four_answer_with_their_queue(self):
        self.assertEqual(self.mod.main([], self.app(self.ALL)), 0)

    def test_three_missing_lanes_fail_and_are_named(self):
        import io
        from contextlib import redirect_stdout
        only_discovery = {'discovery_worker@h': self.ALL['discovery_worker@h']}
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = self.mod.main([], self.app(only_discovery))
        self.assertEqual(code, 1)
        for lane in ('cve_feed_worker', 'validation_priority_worker', 'classic_worker'):
            self.assertIn(f'{lane} does not answer', buffer.getvalue())
        self.assertNotIn('discovery_worker', buffer.getvalue())

    def test_nothing_answering_at_all_fails(self):
        self.assertEqual(self.mod.main(['--json'], self.app({})), 1)

    def test_a_lane_that_answers_without_its_queue_fails(self):
        replies = dict(self.ALL, **{'cve_feed_worker@h': [{'name': 'something_else'}]})
        self.assertEqual(self.mod.lane_state(replies)['cve_feed_worker'], 'no_queue')
        self.assertEqual(self.mod.main([], self.app(replies)), 1)

    def test_the_celery_at_node_naming_also_counts(self):
        replies = {'celery@' + lane: self.ALL[lane + '@h'] for lane in self.mod.LANES}
        self.assertEqual(self.mod.main([], self.app(replies)), 0)

    def test_an_unreachable_broker_is_unhealthy_not_a_crash(self):
        class Boom:
            class control:
                @staticmethod
                def inspect(timeout=None):
                    raise ConnectionError('refused')
        self.assertEqual(self.mod.main(['--json'], Boom()), 1)

    def test_a_lane_that_missed_one_ping_is_asked_again(self):
        answers = [{'discovery_worker@h': self.ALL['discovery_worker@h']}, self.ALL]

        class Inspector:
            def active_queues(inner):
                return answers.pop(0)

        class Control:
            def inspect(inner, timeout=None):
                return Inspector()

        class App:
            control = Control()
        self.assertEqual(self.mod.main([], App()), 0)

    def test_the_celery_service_has_the_check_and_it_is_bounded(self):
        for name in ('docker-compose.yml', 'docker-compose.dev.yml'):
            text = (WEB.parent / name).read_text()
            celery = text[text.index('\n  celery:\n'):text.index('\n  celery-beat:\n')]
            self.assertIn('celery_healthcheck.py', celery, name)
            self.assertIn('timeout:', celery, name)
            self.assertIn('start_period:', celery, name)


class UpdateWarningTests(SimpleTestCase):
    """The updater says so when DISCOVERY_CONCURRENCY starves the Sentinels, and never edits the owner's env file."""

    def run_warn(self, env_text, live='0', builtin=None):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / 'scripts').mkdir()
            for name in ('host-fit.sh', 'redis-password.sh', 'update-deploy.sh'):
                (tmp / 'scripts' / name).write_text((SCRIPTS / name).read_text())
            (tmp / '.env').write_text(env_text + (f'CVENGINE_BUILTIN_SCANNER={builtin}\n' if builtin is not None else ''))
            stub = tmp / 'bin'
            stub.mkdir()
            (stub / 'docker').write_text('#!/usr/bin/env bash\ncase " $* " in\n  *" ps -q --status running db "*) echo dbid;;\n'
                                         f'  *external_sentinels*) echo "EXTERNAL_SENTINELS_LIVE {live}";;\nesac\n')
            (stub / 'docker').chmod(0o755)
            before = (tmp / '.env').read_text()
            env = {k: v for k, v in os.environ.items() if k not in ('DISCOVERY_CONCURRENCY', 'CVENGINE_BUILTIN_SCANNER')}
            out = subprocess.run(['bash', '-c', 'log() { echo "LOG: $*"; }; . scripts/host-fit.sh; . scripts/update-deploy.sh; warn_discovery_pin docker compose'],
                                 cwd=tmp, env={**env, 'PATH': f'{stub}:{env["PATH"]}'}, capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual((tmp / '.env').read_text(), before, 'the owner\'s env file is never edited')
            return out.stdout

    WARNING = ('Hosts assessed at once is held at 1 by DISCOVERY_CONCURRENCY in .env, so only 1 host is assessed at a time and your Sentinels wait for work. '
               'Remove that line from .env and run docker compose up -d celery; the server then sizes it itself.')

    def test_a_pin_of_one_with_a_sentinel_is_warned_about(self):
        self.assertIn(self.WARNING, self.run_warn('DISCOVERY_CONCURRENCY=1\n', live='2'))

    def test_the_built_in_scanner_alone_is_reason_enough(self):
        self.assertIn(self.WARNING, self.run_warn('DISCOVERY_CONCURRENCY=1\n', live='0'))

    def test_a_pin_of_three_says_three_hosts(self):
        out = self.run_warn('DISCOVERY_CONCURRENCY=3\n', live='1')
        self.assertIn('held at 3 by DISCOVERY_CONCURRENCY in .env, so only 3 hosts are assessed at a time', out)

    def test_four_or_more_and_no_line_say_nothing(self):
        self.assertEqual(self.run_warn('DISCOVERY_CONCURRENCY=4\n', live='2'), '')
        self.assertEqual(self.run_warn('DISCOVERY_CONCURRENCY=8\n', live='2'), '')
        self.assertEqual(self.run_warn('OTHER=1\n', live='2'), '')

    def test_no_scanner_at_all_says_nothing(self):
        self.assertEqual(self.run_warn('DISCOVERY_CONCURRENCY=1\n', live='0', builtin='0'), '')

    def test_the_warning_is_part_of_the_deploy_steps(self):
        text = (SCRIPTS / 'update-deploy.sh').read_text()
        self.assertIn('warn_discovery_pin "${compose[@]}"', text)


class DiscoveryPinTests(TestCase):
    """A DISCOVERY_CONCURRENCY below 4 in the environment (a 1.3 leftover) is said out loud: status, the Scanners page, Settings and the capacity error."""

    def pin(self, value):
        from cveFeed import autotune
        env = {k: v for k, v in os.environ.items() if k != 'DISCOVERY_CONCURRENCY'}
        if value is not None:
            env['DISCOVERY_CONCURRENCY'] = value
        with mock.patch.dict(os.environ, env, clear=True):
            return autotune.discovery_pin()

    def test_one_is_a_pin_and_names_the_variable_and_the_way_out(self):
        pin = self.pin('1')
        self.assertEqual(pin['value'], 1)
        self.assertEqual(pin['env'], 'DISCOVERY_CONCURRENCY=1')
        self.assertIn('Remove the line', pin['text'])

    def test_four_or_more_unset_and_the_default_are_not_a_pin(self):
        for value in (None, '8', '4', '16'):
            self.assertIsNone(self.pin(value), value)

    def test_the_status_the_scanners_page_and_settings_carry_it(self):
        from agentapi.system_status import _autotune
        from cveFeed import scanner_plan, settings_api
        with mock.patch.dict(os.environ, {'DISCOVERY_CONCURRENCY': '2'}):
            self.assertEqual(_autotune()['discovery_pin']['value'], 2)
            self.assertIn('held at 2', scanner_plan.state()['discovery_pin_notice'])
            self.assertIn('held at 2', settings_api._updates_state(settings_api._update_row())['discovery_pin_notice'])
        with mock.patch.dict(os.environ, {'DISCOVERY_CONCURRENCY': '8'}):
            self.assertIsNone(scanner_plan.state()['discovery_pin_notice'])

    def test_the_capacity_error_says_which_limit_and_what_pins_it(self):
        from cveFeed import host_assessment
        plain = host_assessment.capacity_message(20, 20, 1, 5, 3)
        self.assertTrue(plain.startswith('host assessment queue is at capacity'))
        self.assertIn('20 host assessments are queued or running across the installation (limit 20)', plain)
        self.assertNotIn('DISCOVERY_CONCURRENCY', plain)
        self.assertIn('of this project', host_assessment.capacity_message(1, 20, 5, 5, 3))
        self.assertIn('scans are running', host_assessment.capacity_message(1, 20, 1, 5, 25))
        with mock.patch.dict(os.environ, {'DISCOVERY_CONCURRENCY': '1'}):
            pinned = host_assessment.capacity_message(20, 20, 1, 5, 3)
        self.assertIn('DISCOVERY_CONCURRENCY=1 is set in the environment', pinned)
        self.assertIn('even when the Sentinels are idle', pinned)


class WorkersDownNoticeTests(TestCase):
    """The admin notices strip (alerts) carries a workers-down alert, named by lane, and clears it when they answer."""

    def checks(self, workers):
        from django.contrib.auth.models import User
        from cveFeed import reviewer
        User.objects.create_superuser('opsadmin', 'a@example.com', 'x')
        with mock.patch('agentapi.system_status.system_status', return_value={'problems': [], 'system': {'workers': workers, 'sentinels': {}}}):
            return {c['code']: c for c in reviewer.ops_checks()}

    LANES = ['discovery_worker', 'cve_feed_worker', 'validation_priority_worker', 'classic_worker']

    def consumers(self, up):
        return [{'worker': w, 'consuming': w in up} for w in self.LANES]

    def test_three_of_four_lanes_gone_is_a_problem_naming_them(self):
        got = self.checks({'state': 'degraded', 'consumers': self.consumers({'discovery_worker'})})['workers_down']
        self.assertEqual(got['state'], 'problem')
        self.assertIn('cve_feed_worker, validation_priority_worker, classic_worker', got['detail'])
        self.assertIn('docker compose restart celery', got['detail'])
        self.assertEqual(got['facts']['lanes_down'], ['cve_feed_worker', 'validation_priority_worker', 'classic_worker'])

    def test_no_worker_answering_at_all_is_a_problem(self):
        got = self.checks({'state': 'unknown', 'consumers': self.consumers(set())})['workers_down']
        self.assertEqual(got['state'], 'problem')
        self.assertIn('every worker lane', got['detail'])

    def test_all_four_answering_is_ok(self):
        self.assertEqual(self.checks({'state': 'responding', 'consumers': self.consumers(set(self.LANES))})['workers_down']['state'], 'ok')

    def test_the_alert_reaches_the_strip_and_resolves(self):
        from cveFeed import reviewer
        from cveFeed.models import AdminAlert
        self.checks({'state': 'degraded', 'consumers': self.consumers({'discovery_worker'})})
        with mock.patch('agentapi.system_status.system_status', return_value={'problems': [], 'system': {'workers': {'state': 'degraded', 'consumers': self.consumers({'discovery_worker'})}, 'sentinels': {}}}):
            reviewer.run_ops_checks()
        self.assertTrue(AdminAlert.objects.filter(code='workers_down', resolved_at__isnull=True).exists())
        with mock.patch('agentapi.system_status.system_status', return_value={'problems': [], 'system': {'workers': {'state': 'responding', 'consumers': self.consumers(set(self.LANES))}, 'sentinels': {}}}):
            reviewer.run_ops_checks()
        self.assertFalse(AdminAlert.objects.filter(code='workers_down', resolved_at__isnull=True).exists())


class FaultHandlerTests(SimpleTestCase):
    def test_a_native_crash_of_a_worker_prints_the_python_traceback(self):
        text = SCRIPT.read_text()
        self.assertIn('export PYTHONFAULTHANDLER="${PYTHONFAULTHANDLER:-1}"', text)
        # before the first worker command, so every lane inherits it, and an administrator's own value is kept
        self.assertLess(text.index('PYTHONFAULTHANDLER'), text.index('manage.py migrate --check'))
        out = subprocess.run(['bash', '-c', 'unset PYTHONFAULTHANDLER; eval "$(grep ^export.PYTHONFAULTHANDLER %s)"; echo "$PYTHONFAULTHANDLER"' % shlex.quote(str(SCRIPT))],
                             capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(out, '1')
        kept = subprocess.run(['bash', '-c', 'PYTHONFAULTHANDLER=0; eval "$(grep ^export.PYTHONFAULTHANDLER %s)"; echo "$PYTHONFAULTHANDLER"' % shlex.quote(str(SCRIPT))],
                              capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(kept, '0')
