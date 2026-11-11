"""scripts/watchdog.sh, the host side of the outer watchdog, with a stub `docker` so the real script runs without Docker: the tick through the
installation's own Compose layout, one tick at a time, the kill switch, the request file (only three actions, never through a link), STANDING DOWN
for every marker of an update (and both locks), the update lock held while it acts, the host's own limits, the answer file, and that
scripts/update-watch.sh drives it and still heartbeats. Run it on the host: ``cd web && python3 -m unittest tests.test_watchdog_script``."""
import fcntl
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'

DOCKER_STUB = """#!/usr/bin/env bash
echo "docker $*" >> "$STUB_DIR/calls.log"
case " $* " in
  *" watchdog_tick "*)
    if [ -f "$STUB_DIR/tick_fails" ]; then echo "Traceback: boom"; exit 1; fi
    if [ -f "$STUB_DIR/tick_slow" ]; then sleep 4; fi
    if [ -f "$STUB_DIR/tick_acts" ]; then echo '{"ok": true, "acted": ["R1"]}'; else echo '{"ok": true, "acted": [], "seconds": 0.1}'; fi
    exit 0;;
  *" ps -a --filter "*) exit 0;;
  *" ps -a --services "*) cat "$STUB_DIR/services" 2>/dev/null; exit 0;;
  *" up -d --no-deps --force-recreate "*)
    # the update lock must be held by the watchdog's own shell while it recreates a container
    if ( exec 9>>"$STUB_STATE/update.lock"; flock -n 9 ); then echo "NOLOCK" >> "$STUB_DIR/calls.log"; else echo "LOCKED" >> "$STUB_DIR/calls.log"; fi
    if [ -f "$STUB_DIR/recreate_fails" ]; then exit 1; fi
    exit 0;;
esac
exit 0
"""


@unittest.skipUnless(SCRIPTS.joinpath('watchdog.sh').is_file() and shutil.which('git') and shutil.which('flock'), 'needs the repository scripts directory, git and flock')
class WatchdogScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        (self.stub / 'docker').write_text(DOCKER_STUB)
        (self.stub / 'docker').chmod(0o755)
        self.work = self.tmp / 'work'
        (self.work / 'scripts').mkdir(parents=True)
        (self.work / 'web').mkdir()
        for name in ('watchdog.sh', 'update-state.py', 'compose-layout.sh', 'update-watch.sh'):
            shutil.copy(SCRIPTS / name, self.work / 'scripts' / name)
        (self.work / 'docker-compose.yml').write_text('services: {}\n')
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub), 'GIT_CONFIG_GLOBAL': os.devnull,
                    'GIT_CONFIG_SYSTEM': os.devnull, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t', 'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@t'}
        for name in ('CVENGINE_WATCHDOG', 'CVENGINE_COMPOSE_FILES', 'CVENGINE_COMPOSE_FILE', 'CVENGINE_COMPOSE_ENV_FILE', 'CVENGINE_COMPOSE_PROJECT'):
            self.env.pop(name, None)
        subprocess.run(['git', 'init', '-q', str(self.work)], check=True, env=self.env)
        self.state = Path(subprocess.run(['python3', 'scripts/update-state.py', 'directory'], cwd=self.work, env=self.env, check=True, capture_output=True, text=True).stdout.strip())
        self.env['STUB_STATE'] = str(self.state)

    def run_script(self, mode, **extra):
        return subprocess.run(['bash', 'scripts/watchdog.sh', mode], cwd=self.work, env={**self.env, **extra}, capture_output=True, text=True, timeout=60)

    def calls(self):
        log = self.stub / 'calls.log'
        return log.read_text().splitlines() if log.exists() else []

    def docker_calls(self):
        return [c for c in self.calls() if c.startswith('docker ') and ' compose version' not in c]

    def request(self, action='restart-celery', rule='R1', rid='0123456789ab'):
        (self.work / 'web' / '.watchdog-action').write_text(json.dumps({'id': rid, 'action': action, 'rule': rule, 'at': int(time.time())}))
        return rid

    def result(self):
        path = self.work / 'web' / '.watchdog-result'
        return json.loads(path.read_text()) if path.exists() else None

    def log_text(self):
        log = self.state / 'watchdog.log'
        return log.read_text() if log.exists() else ''

    def hold(self, path):
        fd = os.open(path, os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, fd)

    # ---- the tick ----

    def test_the_tick_runs_the_command_in_the_web_container_through_the_installations_layout(self):
        (self.work / 'docker-compose.over.yml').write_text('services: {}\n')
        result = self.run_script('tick', CVENGINE_COMPOSE_FILES='docker-compose.yml,docker-compose.over.yml', CVENGINE_COMPOSE_PROJECT='mystack')
        self.assertEqual(result.returncode, 0, result.stderr)
        call = [c for c in self.docker_calls() if 'watchdog_tick' in c]
        self.assertEqual(len(call), 1)
        self.assertIn('-p mystack -f docker-compose.yml -f docker-compose.over.yml exec -T web timeout', call[0])
        self.assertIn('python3 manage.py watchdog_tick', call[0])
        self.assertEqual(self.log_text(), '')  # a tick that did nothing leaves no line

    def test_the_layout_comes_from_dotenv_too(self):
        (self.work / 'docker-compose.over.yml').write_text('services: {}\n')
        (self.work / '.env').write_text('CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.over.yml\n')
        self.run_script('tick')
        self.assertIn('-f docker-compose.over.yml', [c for c in self.docker_calls() if 'watchdog_tick' in c][0])

    def test_a_tick_that_failed_or_acted_is_logged_and_the_script_still_succeeds(self):
        (self.stub / 'tick_fails').write_text('x')
        self.assertEqual(self.run_script('tick').returncode, 0)
        self.assertIn('tick failed (exit 1)', self.log_text())
        (self.stub / 'tick_fails').unlink()
        (self.stub / 'tick_acts').write_text('x')
        self.run_script('tick')
        self.assertIn('"acted": ["R1"]', self.log_text())

    def test_two_ticks_never_overlap(self):
        self.hold(self.state / 'watchdog.lock')
        self.assertEqual(self.run_script('tick').returncode, 0)
        self.assertEqual(self.docker_calls(), [])

    def test_the_kill_switch_in_the_environment_or_dotenv_stops_the_host_side(self):
        for env, dotenv in (({'CVENGINE_WATCHDOG': '0'}, ''), ({}, 'CVENGINE_WATCHDOG=off\n'), ({}, 'CVENGINE_WATCHDOG="false"\n')):
            (self.work / '.env').write_text(dotenv)
            self.run_script('tick', **env)
            self.assertEqual([c for c in self.docker_calls() if 'watchdog_tick' in c], [], (env, dotenv))
        (self.work / '.env').write_text('CVENGINE_WATCHDOG=1\n')
        self.run_script('tick')
        self.assertEqual(len([c for c in self.docker_calls() if 'watchdog_tick' in c]), 1)

    def test_a_tick_is_bounded_by_timeout_in_the_container(self):
        self.run_script('tick')
        self.assertRegex([c for c in self.docker_calls() if 'watchdog_tick' in c][0], r'exec -T web timeout -k 3 55 python3')

    # ---- the request file ----

    def test_restart_celery_recreates_celery_with_the_update_lock_held_and_answers(self):
        rid = self.request()
        self.assertEqual(self.run_script('act').returncode, 0)
        calls = self.docker_calls()
        self.assertEqual(len([c for c in calls if '--force-recreate celery' in c]), 1)
        self.assertIn('LOCKED', self.calls())
        self.assertFalse((self.work / 'web' / '.watchdog-action').exists())
        answer = self.result()
        self.assertEqual((answer['id'], answer['action'], answer['ok'], answer['standdown']), (rid, 'restart-celery', True, False))
        self.assertIn('restart-celery done', self.log_text())
        # the update lock is free again afterwards
        fd = os.open(self.state / 'update.lock', os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def test_the_scanner_and_the_tailscale_sidecar_follow_celery_when_they_exist(self):
        (self.stub / 'services').write_text('web\ncelery\nscanner\ntailscale\n')
        self.request()
        self.run_script('act')
        recreated = [c.split('--force-recreate ')[1].strip() for c in self.docker_calls() if '--force-recreate' in c]
        self.assertEqual(recreated, ['celery', 'scanner', 'tailscale'])

    def test_restart_celery_beat_and_the_prune(self):
        self.request('restart-celery-beat', 'R6')
        self.run_script('act')
        self.assertEqual([c for c in self.docker_calls() if '--force-recreate' in c][0].split('--force-recreate ')[1].strip(), 'celery-beat')
        self.request('prune-docker', 'R7', 'aaaaaaaaaaaa')
        self.run_script('act')
        calls = self.docker_calls()
        self.assertTrue(any(c == 'docker image prune -f' for c in calls))
        self.assertTrue(any(c == 'docker builder prune -f' for c in calls))
        self.assertFalse(any('volume' in c or 'system prune' in c or ' -a' in c.split('prune')[-1] for c in calls if 'prune' in c))

    def test_a_failed_recreate_is_answered_failed(self):
        (self.stub / 'recreate_fails').write_text('x')
        self.request()
        self.run_script('act')
        self.assertFalse(self.result()['ok'])
        self.assertIn('failed', self.result()['detail'])

    def test_an_unknown_action_a_bad_id_or_an_oversized_request_is_ignored(self):
        for body in ('{"id": "0123456789ab", "action": "rm -rf /", "rule": "R1"}', '{"id": "../../etc", "action": "restart-celery", "rule": "R1"}',
                     '{"id": "0123456789ab", "action": "restart-celery", "rule": "R1; reboot"}', 'not json', '{"id": "0123456789ab", "pad": "' + 'x' * 2000 + '"}'):
            (self.work / 'web' / '.watchdog-action').write_text(body)
            self.run_script('act')
            self.assertEqual(self.docker_calls(), [], body[:40])
            self.assertIsNone(self.result())
            self.assertFalse((self.work / 'web' / '.watchdog-action').exists())  # consumed, so it is not read again

    def test_a_request_that_is_a_link_is_never_followed(self):
        victim = self.tmp / 'victim'
        victim.write_text(json.dumps({'id': '0123456789ab', 'action': 'restart-celery', 'rule': 'R1'}))
        (self.work / 'web' / '.watchdog-action').symlink_to(victim)
        self.run_script('act')
        self.assertEqual(self.docker_calls(), [])
        self.assertTrue(victim.exists())

    def test_the_answer_is_never_written_through_a_link_the_web_container_planted(self):
        victim = self.tmp / 'host-only'
        victim.write_text('keep me')
        (self.work / 'web' / '.watchdog-result').symlink_to(victim)
        self.request()
        self.run_script('act')
        self.assertEqual(victim.read_text(), 'keep me')
        self.assertFalse((self.work / 'web' / '.watchdog-result').is_symlink())

    # ---- standing down ----

    def assert_stood_down(self, why):
        self.request()
        self.run_script('act')
        self.assertEqual([c for c in self.docker_calls() if '--force-recreate' in c], [], why)
        answer = self.result()
        self.assertTrue(answer['standdown'], why)
        self.assertFalse(answer['ok'])
        self.assertFalse((self.work / 'web' / '.watchdog-action').exists())

    def test_it_stands_down_while_an_update_is_approved(self):
        (self.work / 'web' / '.update-approved').write_text('a' * 40)
        self.assert_stood_down('approved')
        self.assertIn('approved', self.result()['detail'])

    def test_it_stands_down_while_an_update_drains_or_applies(self):
        for phase in ('draining', 'applying'):
            (self.work / 'web' / '.update-phase.json').write_text(json.dumps({'phase': phase, 'detail': '', 'scans_running': 0, 'changed_at': time.time()}))
            self.assert_stood_down(phase)

    def test_a_finished_or_long_dead_update_phase_does_not_block_it(self):
        (self.work / 'web' / '.update-phase.json').write_text(json.dumps({'phase': 'done', 'detail': '', 'scans_running': 0, 'changed_at': time.time()}))
        self.request()
        self.run_script('act')
        self.assertEqual(len([c for c in self.docker_calls() if '--force-recreate' in c]), 1)
        shutil.rmtree(self.state / 'x', ignore_errors=True)
        phase = self.work / 'web' / '.update-phase.json'
        phase.write_text(json.dumps({'phase': 'applying', 'detail': '', 'scans_running': 0, 'changed_at': 1}))
        old = time.time() - 4 * 3600
        os.utime(phase, (old, old))
        (self.state / 'watchdog-actions.log').unlink()
        (self.stub / 'calls.log').unlink()
        self.request(rid='bbbbbbbbbbbb')
        self.run_script('act')
        self.assertEqual(len([c for c in self.docker_calls() if '--force-recreate' in c]), 1)  # a script that died hours ago is not an update in progress

    def test_it_stands_down_while_the_update_script_holds_its_lock(self):
        self.hold(self.state / 'update.lock')
        self.assert_stood_down('update.lock')
        self.assertIn('update script', self.result()['detail'])

    def test_it_stands_down_while_the_web_side_holds_its_update_lock(self):
        self.hold(self.work / 'web' / '.update-lock')
        self.assert_stood_down('web/.update-lock')
        self.assertIn('web side', self.result()['detail'])

    def test_it_stands_down_while_the_maintenance_page_is_on(self):
        (self.work / 'config' / 'nginx' / 'state').mkdir(parents=True)
        (self.work / 'config' / 'nginx' / 'state' / 'maintenance').write_text('')
        self.assert_stood_down('maintenance')

    def test_an_approval_that_is_a_link_still_counts(self):
        (self.work / 'web' / '.update-approved').symlink_to(self.tmp / 'nowhere')
        self.assert_stood_down('approved link')

    def test_when_the_update_ends_the_next_request_is_carried_out(self):
        (self.work / 'web' / '.update-approved').write_text('a' * 40)
        self.assert_stood_down('approved')
        (self.work / 'web' / '.update-approved').unlink()
        (self.stub / 'calls.log').unlink(missing_ok=True)
        self.request(rid='cccccccccccc')
        self.run_script('act')
        self.assertTrue(self.result()['ok'])

    def test_the_switch_off_on_the_host_refuses_a_request_and_says_so(self):
        self.request()
        self.run_script('act', CVENGINE_WATCHDOG='0')
        self.assertEqual(self.docker_calls(), [])
        self.assertFalse(self.result()['ok'])
        self.assertIn('switched off', self.result()['detail'])

    # ---- the host's own limits ----

    def test_a_second_restart_within_ten_minutes_is_refused_by_the_host(self):
        self.request()
        self.run_script('act')
        self.request(rid='dddddddddddd')
        self.run_script('act')
        self.assertEqual(len([c for c in self.docker_calls() if '--force-recreate celery' in c]), 1)
        self.assertFalse(self.result()['ok'])
        self.assertIn('refused by the host', self.result()['detail'])

    def test_a_different_action_is_not_held_back_by_the_gap_of_another(self):
        self.request()
        self.run_script('act')
        self.request('restart-celery-beat', 'R6', 'eeeeeeeeeeee')
        self.run_script('act')
        self.assertTrue(self.result()['ok'])

    def test_twenty_four_restarts_in_a_day_is_the_hosts_limit(self):
        now = int(time.time())
        (self.state / 'watchdog-actions.log').write_text(''.join(f'{now - 3000 - i * 100} restart-celery R1\n' for i in range(24)))
        self.request('restart-celery-beat', 'R6', 'ffffffffffff')
        self.run_script('act')
        self.assertEqual([c for c in self.docker_calls() if '--force-recreate' in c], [])
        self.assertIn('limit 24', self.result()['detail'])

    def test_one_action_at_a_time(self):
        self.hold(self.state / 'watchdog-act.lock')
        self.request()
        self.assertEqual(self.run_script('act').returncode, 0)
        self.assertEqual(self.docker_calls(), [])
        self.assertTrue((self.work / 'web' / '.watchdog-action').exists())  # it stays until the running action ends

    def test_no_request_no_work(self):
        self.assertEqual(self.run_script('act').returncode, 0)
        self.assertEqual(self.docker_calls(), [])

    # ---- the watcher drives it ----

    def watch(self, seconds=5, **extra):
        return subprocess.run(['bash', 'scripts/update-watch.sh', str(seconds)], cwd=self.work,
                              env={**self.env, 'CVENGINE_HEARTBEAT_SECONDS': '1', 'CVENGINE_WATCHDOG_SECONDS': '2', **extra}, capture_output=True, text=True, timeout=60)

    def wait_for(self, predicate, seconds=15):
        end = time.time() + seconds
        while time.time() < end:
            if predicate():
                return True
            time.sleep(0.1)
        return False

    def test_the_watcher_ticks_every_few_seconds_and_keeps_its_heartbeat(self):
        self.watch(5)
        self.assertTrue(self.wait_for(lambda: len([c for c in self.docker_calls() if 'watchdog_tick' in c]) >= 2))
        self.assertTrue((self.work / 'web' / '.updater-heartbeat').exists())

    def test_the_watcher_carries_out_a_request_the_watchdog_left(self):
        self.request()
        self.watch(4)
        self.assertTrue(self.wait_for(lambda: self.result() is not None))
        self.assertTrue(self.result()['ok'])
        self.assertEqual(len([c for c in self.docker_calls() if '--force-recreate celery' in c]), 1)

    def test_the_watcher_without_the_watchdog_script_is_unchanged(self):
        (self.work / 'scripts' / 'watchdog.sh').unlink()
        result = self.watch(3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.docker_calls(), [])
        self.assertTrue((self.work / 'web' / '.updater-heartbeat').exists())

    def test_a_stuck_tick_never_delays_the_heartbeat(self):
        (self.stub / 'tick_slow').write_text('x')
        started = time.time()
        self.watch(4)
        self.assertLess(time.time() - started, 10)
        self.assertTrue((self.work / 'web' / '.updater-heartbeat').exists())

    def test_the_update_state_helper_accepts_only_known_answers(self):
        def run(*args):
            return subprocess.run(['python3', 'scripts/update-state.py', *args], cwd=self.work, env=self.env, capture_output=True, text=True)
        self.assertEqual(run('watchdog-result', '0123456789ab', 'restart-celery', 'ok', 'fine').returncode, 0)
        self.assertEqual(json.loads((self.work / 'web' / '.watchdog-result').read_text())['detail'], 'fine')
        self.assertNotEqual(run('watchdog-result', '0123456789ab', 'format-disk', 'ok').returncode, 0)
        self.assertNotEqual(run('watchdog-result', 'xyz', 'restart-celery', 'ok').returncode, 0)
        self.assertNotEqual(run('watchdog-result', '0123456789ab', 'restart-celery', 'maybe').returncode, 0)
        self.assertNotEqual(run('watchdog-result', '0123456789ab', 'restart-celery', 'ok', 'x' * 400).returncode, 0)


if __name__ == '__main__':
    unittest.main()
