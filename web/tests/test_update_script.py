"""Exercise the manual updater against a throwaway Git remote and stub service commands."""
import os
import signal
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'update.sh'
DOCKER = '''#!/usr/bin/env bash
echo "docker $*" >> "$STUB_DIR/calls"
case " $* " in
  *" ps -a --filter "*) if [ -f "$STUB_DIR/running_config_files" ]; then echo abc123; fi; exit 0;;
  *" inspect -f "*) case "$*" in
      *config_files*) cat "$STUB_DIR/running_config_files" 2>/dev/null;;
      *environment_file*) cat "$STUB_DIR/running_env_file" 2>/dev/null;;
      *'.compose.project"'*) cat "$STUB_DIR/running_project" 2>/dev/null;;
    esac; echo; exit 0;;
  *" ps -q --status running web "*) if [ -e "$STUB_DIR/web_up" ]; then echo web-container; fi; exit 0;;
  *" web python3 manage.py shell "*) case "$*" in
      *_abort_scan*) cat "$STUB_DIR/stop_json" 2>/dev/null;;
      *start_discoveries*) prev=''; for a in "$@"; do [ "$prev" = -e ] && echo "$a" >> "$STUB_DIR/requeue_env"; prev=$a; done
        echo "REQUEUED 1";;
      *'print("SCANS"'*) echo "SCANS 1 2";;
    esac; exit 0;;
  *" ps -q --status running celery "*) if [ -f "$STUB_DIR/container_down" ]; then exit 0; fi
    echo local-celery-container; exit 0;;
  *" ps -q --status running celery-beat "*) if [ ! -e "$STUB_DIR/beat_originally_down" ]; then
    echo local-beat-container; fi; exit 0;;
  *" exec -T celery python3 -c "*) if [ -e "$STUB_DIR/unresponsive_process" ]; then
      cat "$STUB_DIR/unresponsive_process"; else
      python3 -c 'import json,os; print("\\n".join(n.split("@",1)[0] for n in json.load(open(os.environ["STUB_DIR"]+"/queues"))))';
    fi; exit 0;;
  *" config --format json "*) if [ -f "$STUB_DIR/config.json" ]; then cat "$STUB_DIR/config.json"; else
    printf '{"name":"cvengine","volumes":{"postgres18_data":{"name":"cvengine_postgres18_data"}}}\n'; fi; exit 0;;
  *" volume inspect "*) if [[ "$*" == *"cvengine_postgres_data"* && -e "$STUB_DIR/old_volume" ]]; then exit 0; fi
    if [[ "$*" == *"cvengine_postgres18_data"* && -e "$STUB_DIR/new_volume" ]]; then exit 0; fi
    exit 1;;
  *" config --services "*) if [[ "$*" == *"docker-compose.dev.yml"* ]]; then
      printf 'db\\nredis\\nweb\\ncelery\\ncelery-beat\\n';
    else printf 'db\\nredis\\nweb\\ncelery\\ncelery-beat\\nproxy\\n'; fi; exit 0;;
  *" cancel_consumer "*) touch "$STUB_DIR/paused";
    if [ -e "$STUB_DIR/warn_on_control" ]; then echo 'SyntaxWarning: old scanner regex' >&2; fi
    echo '{}'; exit 0;;
  *" add_consumer "*) echo '{}'; exit 0;;
  *" active_queues "*) if [ -f "$STUB_DIR/inspect_fail" ]; then exit 1; fi
    if [ -f "$STUB_DIR/paused" ] && [ -f "$STUB_DIR/resume_once" ]; then rm "$STUB_DIR/resume_once"; cat "$STUB_DIR/queues"; exit 0; fi
    if [ -f "$STUB_DIR/paused" ]; then cat "$STUB_DIR/empty_queues";
    else cat "$STUB_DIR/queues"; fi; exit 0;;
  *" reserved "*) cat "$STUB_DIR/empty_queues"; exit 0;;
  *" scheduled "*) if [ -e "$STUB_DIR/persistent_scheduled" ]; then cat "$STUB_DIR/active";
    else cat "$STUB_DIR/empty_queues"; fi; exit 0;;
  *" active "*) if [ -f "$STUB_DIR/worker_lost" ]; then echo '{}'; exit 0; fi
    if [ -f "$STUB_DIR/worker_slow_once" ]; then rm "$STUB_DIR/worker_slow_once"; echo '{}'; exit 0; fi
    if [ -f "$STUB_DIR/active" ]; then
      if [ -f "$STUB_DIR/finish_after_one" ]; then rm "$STUB_DIR/finish_after_one";
        cat "$STUB_DIR/active"; exit 0; fi
      if [ -f "$STUB_DIR/persistent_active" ]; then cat "$STUB_DIR/active"; exit 0; fi
    fi
    cat "$STUB_DIR/empty_queues"; exit 0;;
  *" exec -T celery-beat "*) test ! -e "$STUB_DIR/beat_down"; exit $?;;
  *" build "*) test ! -e "$STUB_DIR/build_fail"; exit $?;;
  *" migrate --noinput "*) test ! -e "$STUB_DIR/migrate_fail"; exit $?;;
  *" collectstatic --noinput "*) test ! -e "$STUB_DIR/collectstatic_fail"; exit $?;;
  *" up -d --no-deps --force-recreate "*) rm -f "$STUB_DIR/paused" "$STUB_DIR/container_down" "$STUB_DIR/inspect_fail";
    if [ ! -e "$STUB_DIR/post_missing" ]; then cp "$STUB_DIR/healthy_queues" "$STUB_DIR/queues"; fi; exit 0;;
esac
exit 0
'''
QUEUES = ('{"discovery_worker@local":[{"name":"discovery_queue"}],'
          '"cve_feed_worker@local":[{"name":"cve_feed_queue"}],'
          '"validation_priority_worker@local":[{"name":"validation_priority_queue"}],'
          '"classic_worker@local":[{"name":"api_queue"}]}')


class UpdateScriptCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        for name, body in [('docker', DOCKER), ('curl', '#!/bin/sh\nprintf 200\n'),
                           ('systemctl', '#!/bin/sh\nexit 1\n')]:
            path = self.stub / name
            path.write_text(body)
            path.chmod(0o755)
        (self.stub / 'queues').write_text(QUEUES)
        (self.stub / 'healthy_queues').write_text(QUEUES)
        (self.stub / 'empty_queues').write_text('{' + ','.join(f'"{name}@local":[]' for name in
            ('discovery_worker', 'cve_feed_worker', 'validation_priority_worker', 'classic_worker')) + '}')
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub),
                    'CVENGINE_UPDATE_READY_SECONDS': '1', 'CVENGINE_UPDATE_DRAIN_SECONDS': '1',
                    'CVENGINE_UPDATE_POLL_SECONDS': '0.2',  # the script's real pause is 5 seconds per check; the stubs answer at once
                    'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t',
                    'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@t',
                    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull}
        self.env.pop('CVENGINE_COMPOSE_FILE', None)
        self.origin, self.work, self.other = self.tmp / 'origin.git', self.tmp / 'work', self.tmp / 'other'
        self.git('init', '--bare', '-b', 'master', str(self.origin), cwd=self.tmp)
        self.git('clone', str(self.origin), str(self.work), cwd=self.tmp)
        self.git('checkout', '-b', 'master', cwd=self.work)
        (self.work / 'scripts').mkdir()
        shutil.copy(SCRIPT, self.work / 'scripts' / 'update.sh')
        shutil.copy(SCRIPT.with_name('update-state.py'), self.work / 'scripts' / 'update-state.py')
        (self.work / 'web').mkdir()
        (self.work / 'web' / 'README').write_text('v1\n')
        (self.work / 'docker-compose.yml').write_text('services: {}\n')
        (self.work / 'docker-compose.dev.yml').write_text('services: {}\n')
        self.git('add', '-A', cwd=self.work)
        self.git('commit', '-m', 'old', cwd=self.work)
        self.git('push', 'origin', 'master', cwd=self.work)
        self.git('clone', str(self.origin), str(self.other), cwd=self.tmp)
        (self.other / 'web' / 'README').write_text('v2\n')
        self.git('commit', '-am', 'new', cwd=self.other)
        self.git('push', 'origin', 'master', cwd=self.other)
        (self.work / '.env').write_text('local-only=true\n')

    def git(self, *args, cwd):
        return subprocess.run(['git', *args], cwd=cwd, env=self.env, check=True, capture_output=True, text=True).stdout.strip()

    def run_update(self, *args, **env):
        return subprocess.run(['bash', 'scripts/update.sh', *args], cwd=self.work, env={**self.env, **env},
                              capture_output=True, text=True, timeout=45)

    def calls(self):
        path = self.stub / 'calls'
        return path.read_text().splitlines() if path.exists() else []


@unittest.skipUnless(SCRIPT.is_file() and shutil.which('git') and shutil.which('flock'), 'needs git and flock')
class ManualUpdateTests(UpdateScriptCase):
    def test_shared_web_state_symlinks_never_write_host_targets(self):
        victim = self.tmp / 'host-only'
        victim.write_text('unchanged')
        for name in ('.update-lock', '.commit'):
            (self.work / 'web' / name).symlink_to(victim)
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(victim.read_text(), 'unchanged')
        self.assertFalse((self.work / 'web' / '.commit').is_symlink())
        self.assertTrue((self.work / '.git' / 'cvengine-update' / 'update.lock').is_file())

    def test_legacy_scan_plan_is_imported_and_requeued_once(self):
        (self.stub / 'web_up').touch()
        legacy = self.work / 'web' / '.update-requeue.json'
        legacy.write_text('[{"scan": 5, "domain": 2, "mode": "passive"}]')
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertFalse(legacy.exists())
        self.assertIn('"mode": "passive"', (self.stub / 'requeue_env').read_text())
        self.assertFalse((self.work / '.git' / 'cvengine-update' / 'requeue.json').exists())

    def test_legacy_symlink_plan_is_rejected_without_reading_or_writing_it(self):
        victim = self.tmp / 'host-only'
        victim.write_text('[{"scan": 5, "domain": 2, "mode": "deep"}]')
        (self.work / 'web' / '.update-requeue.json').symlink_to(victim)
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(victim.read_text(), '[{"scan": 5, "domain": 2, "mode": "deep"}]')
        self.assertFalse(any(' build ' in c or 'cancel_consumer' in c for c in self.calls()))

    def test_migrates_then_recreates_apps_and_requires_all_worker_queues(self):
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        calls = self.calls()
        self.assertLess(next(i for i, c in enumerate(calls) if ' migrate --noinput' in c),
                        next(i for i, c in enumerate(calls) if '--force-recreate web' in c))
        self.assertLess(next(i for i, c in enumerate(calls) if ' collectstatic --noinput' in c),
                        next(i for i, c in enumerate(calls) if '--force-recreate web' in c))
        self.assertIn('docker compose -f docker-compose.yml up -d --no-deps --force-recreate web celery celery-beat proxy', calls)
        self.assertFalse(any('--force-recreate db' in c or '--force-recreate redis' in c for c in calls))
        self.assertIn('active_queues', '\n'.join(calls))

    def test_active_work_finishes_after_dispatch_pauses_and_update_continues(self):
        (self.stub / 'active').write_text('{' + ','.join(f'"{name}@local":[{{"id":"work"}}]' for name in
            ('discovery_worker', 'cve_feed_worker', 'validation_priority_worker', 'classic_worker')) + '}')
        (self.stub / 'finish_after_one').touch()
        # The script compares whole seconds (bash SECONDS) with the deadline after its first poll, so a one second deadline fails
        # whenever the first poll lands across a second boundary on a loaded runner. Five is far from that edge, and the work
        # still finishes after one poll (the next one runs after the poll pause).
        result = self.run_update(CVENGINE_UPDATE_DRAIN_SECONDS='5')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        calls = self.calls()
        self.assertLess(next(i for i, c in enumerate(calls) if ' stop -t 30 celery-beat' in c),
                        next(i for i, c in enumerate(calls) if ' cancel_consumer ' in c))
        self.assertLess(next(i for i, c in enumerate(calls) if ' stop -t 60 celery' in c),
                        next(i for i, c in enumerate(calls) if ' migrate --noinput' in c))
        self.assertLess(next(i for i, c in enumerate(calls) if ' build ' in c),
                        next(i for i, c in enumerate(calls) if ' stop -t 30 celery-beat' in c))

    def test_drain_timeout_restores_consumers_and_beat_without_killing_work(self):
        (self.stub / 'active').write_text('{' + ','.join(f'"{name}@local":[{{"id":"work"}}]' for name in
            ('discovery_worker', 'cve_feed_worker', 'validation_priority_worker', 'classic_worker')) + '}')
        (self.stub / 'persistent_active').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bounded drain', result.stderr)
        self.assertTrue(any(' add_consumer ' in c for c in self.calls()))
        self.assertIn('docker compose -f docker-compose.yml start celery-beat', self.calls())
        self.assertFalse(any(' stop -t 60 celery' in c for c in self.calls()))

    def test_lost_worker_aborts_and_resumes_dispatch(self):
        (self.stub / 'worker_lost').touch()
        result = self.run_update(CVENGINE_UPDATE_MISSING_POLLS='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('A worker disappeared: classic_worker@local', result.stderr)
        self.assertTrue(any(' add_consumer ' in c for c in self.calls()))

    def test_a_worker_that_misses_one_reply_is_waited_for(self):
        (self.stub / 'worker_slow_once').touch()
        result = self.run_update(CVENGINE_UPDATE_DRAIN_SECONDS='60')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('waiting for', result.stdout)
        self.assertTrue(any(' stop -t 60 celery' in c for c in self.calls()))

    def test_a_queue_that_resumes_after_the_pause_is_paused_again(self):
        (self.stub / 'resume_once').touch()
        result = self.run_update(CVENGINE_UPDATE_DRAIN_SECONDS='60')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        cancels = [c for c in self.calls() if ' cancel_consumer ' in c]
        self.assertEqual(len(cancels), 8)  # four queues, then the same four once more

    def test_force_stops_the_workers_without_a_drain_and_requeues_scans(self):
        (self.stub / 'web_up').touch()
        (self.stub / 'active').write_text((self.stub / 'queues').read_text().replace('"name":"', '"id":"t","name":"x'))
        (self.stub / 'persistent_active').touch()
        (self.stub / 'stop_json').write_text('REQUEUE_JSON [{"scan": 5, "domain": 2, "mode": "deep"}]\n')
        result = self.run_update('--force')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn('Letting active work finish', result.stdout)
        self.assertIn('Force: stopping the workers now', result.stdout)
        calls = self.calls()
        self.assertTrue(any(' stop -t 10 celery' in c for c in calls))
        self.assertTrue(any(' migrate --noinput' in c for c in calls))
        self.assertIn('"mode": "deep"', (self.stub / 'requeue_env').read_text())

    def test_force_proceeds_when_the_workers_cannot_be_inspected(self):
        (self.stub / 'inspect_fail').touch()
        result = self.run_update('--force')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('worker state is unknown', result.stderr)
        self.assertTrue(any(' migrate --noinput' in c for c in self.calls()))

    def test_interrupt_restores_dispatch_without_stopping_active_work(self):
        (self.stub / 'active').write_text('{' + ','.join(f'"{name}@local":[{{"id":"work"}}]' for name in
            ('discovery_worker', 'cve_feed_worker', 'validation_priority_worker', 'classic_worker')) + '}')
        (self.stub / 'persistent_active').touch()
        env = {**self.env, 'CVENGINE_UPDATE_DRAIN_SECONDS': '30'}
        process = subprocess.Popen(['bash', 'scripts/update.sh'], cwd=self.work, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not (self.stub / 'paused').exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue((self.stub / 'paused').exists(), 'updater did not pause consumers')
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=12)
            self.assertNotEqual(process.returncode, 0)
            self.assertTrue(any(' add_consumer ' in c for c in self.calls()))
            self.assertIn('docker compose -f docker-compose.yml start celery-beat', self.calls())
            self.assertFalse(any(' stop -t 60 celery' in c for c in self.calls()))
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_migration_failure_does_not_restart_apps(self):
        (self.stub / 'migrate_fail').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('--force-recreate web' in c for c in self.calls()))
        self.assertTrue(any(' add_consumer ' in c for c in self.calls()))

    def test_static_publish_failure_does_not_serve_new_app(self):
        (self.stub / 'collectstatic_fail').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('--force-recreate web' in c for c in self.calls()))

    def test_build_failure_does_not_restart_apps(self):
        (self.stub / 'build_fail').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('--force-recreate web' in c for c in self.calls()))
        self.assertFalse(any(' stop -t 30 celery-beat' in c for c in self.calls()))

    def readme(self):
        return (self.work / 'web' / 'README').read_text()

    def test_a_failure_before_the_migration_returns_the_checkout_to_the_previous_commit(self):
        # ./web is bind-mounted into the workers and Beat: restarting them on unmigrated new code would break them
        for flag in ('build_fail', 'migrate_fail'):
            with self.subTest(flag=flag):
                (self.stub / flag).touch()
                result = self.run_update()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.readme(), 'v1\n')
                self.assertIn('Returned the checkout', result.stderr)
                (self.stub / flag).unlink()

    def test_a_drain_timeout_returns_the_checkout_before_beat_restarts(self):
        (self.stub / 'active').write_text('{' + ','.join(f'"{name}@local":[{{"id":"work"}}]' for name in
            ('discovery_worker', 'cve_feed_worker', 'validation_priority_worker', 'classic_worker')) + '}')
        (self.stub / 'persistent_active').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.readme(), 'v1\n')
        self.assertIn('docker compose -f docker-compose.yml start celery-beat', self.calls())

    def test_a_failure_after_the_migration_keeps_the_new_code(self):
        (self.stub / 'collectstatic_fail').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.readme(), 'v2\n')  # the schema is new: the old code must not come back
        self.assertNotIn('Returned the checkout', result.stderr)

    def test_a_bad_ready_seconds_value_stops_before_anything_is_paused(self):
        result = self.run_update(CVENGINE_UPDATE_READY_SECONDS='15m')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CVENGINE_UPDATE_READY_SECONDS must be from 1 to 900', result.stderr)
        self.assertFalse(any(' stop -t 30 celery-beat' in c or ' migrate --noinput' in c for c in self.calls()))
        self.assertEqual(self.readme(), 'v1\n')

    def test_a_bad_poll_seconds_value_stops_before_anything_is_paused(self):
        for bad in ('soon', '-1', '1s', ''.join(['1', '.'])):
            result = self.run_update(CVENGINE_UPDATE_POLL_SECONDS=bad)
            self.assertNotEqual(result.returncode, 0, bad)
            self.assertIn('CVENGINE_UPDATE_POLL_SECONDS must be a number of seconds', result.stderr)
            self.assertFalse(any(' stop -t 30 celery-beat' in c or ' migrate --noinput' in c for c in self.calls()))
        self.assertEqual(self.readme(), 'v1\n')

    def test_a_zero_poll_pause_falls_back_to_five_seconds_instead_of_busy_looping(self):
        text = SCRIPT.read_text()
        self.assertIn('sleep "$poll_seconds"', text)
        self.assertNotIn('sleep 5', text)  # every pause goes through the setting
        self.assertIn('poll_seconds=${CVENGINE_UPDATE_POLL_SECONDS:-5}', text)
        result = self.run_update(CVENGINE_UPDATE_POLL_SECONDS='0')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_beat_is_ready_only_once_celery_beat_runs_not_while_its_entrypoint_waits(self):
        import re
        code = re.search(r'beat_ready\(\) \{\n.*?python3 -c \\\n\s+"(.*?)" \\', SCRIPT.read_text(), re.S).group(1)
        code = code.replace('\\\\0', '\\0')
        for argv, ready in ((['/bin/bash', '/usr/src/app/beat-entrypoint.sh', 'celery', '-A', 'reNgine', 'beat'], False),
                            (['/usr/local/bin/python3', '/usr/local/bin/celery', '-A', 'reNgine', 'beat', '-l', 'INFO'], True),
                            (['/usr/local/bin/python3', '/usr/local/bin/celery', '-A', 'reNgine', 'worker'], False)):
            fake = self.tmp / 'cmdline'
            fake.write_bytes(b'\0'.join(a.encode() for a in argv) + b'\0')
            status = subprocess.run(['python3', '-c', code.replace('/proc/1/cmdline', str(fake))]).returncode
            self.assertEqual(status == 0, ready, argv)

    def test_old_database_volume_requires_explicit_migration(self):
        (self.stub / 'old_volume').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('upgrade-postgres.sh', result.stderr)
        self.assertFalse(any(' build ' in c for c in self.calls()))

    def test_existing_old_and_new_database_volumes_allow_update(self):
        (self.stub / 'old_volume').touch()
        (self.stub / 'new_volume').touch()
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_originally_stopped_beat_is_not_started_after_drain_abort(self):
        (self.stub / 'beat_originally_down').touch()
        (self.stub / 'active').write_text(('{"discovery_worker@local":[{"id":"work"}]}'))
        (self.stub / 'persistent_active').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(' start celery-beat' in c for c in self.calls()))

    def test_scheduled_worker_tasks_are_drained_before_stop(self):
        (self.stub / 'active').write_text('{' + ','.join(
            f'"{name}@local":[{{"id":"eta"}}]' for name in
            ('discovery_worker', 'cve_feed_worker', 'validation_priority_worker', 'classic_worker')) + '}')
        (self.stub / 'persistent_scheduled').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bounded drain', result.stderr)
        self.assertFalse(any(' stop -t 60 celery' in c for c in self.calls()))

    def test_fetched_updater_is_reexecuted_before_build(self):
        path = self.other / 'scripts' / 'update.sh'
        path.write_text(path.read_text().replace('set -Eeuo pipefail', 'set -Eeuo pipefail\necho fetched-updater-ran', 1))
        self.git('commit', '-am', 'new updater', cwd=self.other)
        self.git('push', 'origin', 'master', cwd=self.other)
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('fetched-updater-ran', result.stdout)

    def test_missing_priority_consumer_is_repaired(self):
        (self.stub / 'queues').write_text(QUEUES.replace('"validation_priority_worker@local":[{"name":"validation_priority_queue"}],', ''))
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('repair missing workers', result.stderr)

    def test_post_restart_celery_prefixed_worker_names_are_accepted(self):
        (self.stub / 'healthy_queues').write_text(QUEUES
            .replace('discovery_worker@local', 'celery@discovery_worker')
            .replace('cve_feed_worker@local', 'celery@cve_feed_worker')
            .replace('validation_priority_worker@local', 'celery@validation_priority_worker')
            .replace('classic_worker@local', 'celery@classic_worker'))
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_all_workers_absent_is_repaired(self):
        (self.stub / 'queues').write_text('{}')
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('No managed Celery workers are reachable', result.stdout)

    def test_stopped_celery_container_is_repaired(self):
        (self.stub / 'container_down').touch()
        (self.stub / 'inspect_fail').touch()
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_uninspectable_running_container_aborts_before_stopping_beat(self):
        (self.stub / 'inspect_fail').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('worker state is unknown', result.stderr)
        self.assertFalse(any(' stop -t 30 celery-beat' in c for c in self.calls()))

    def test_unresponsive_named_worker_process_aborts_before_stop(self):
        (self.stub / 'queues').write_text('{}')
        (self.stub / 'unresponsive_process').write_text('discovery_worker\n')
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('does not answer inspection', result.stderr)
        self.assertFalse(any(' stop -t 30 celery-beat' in c for c in self.calls()))

    def test_control_warnings_are_not_replayed_and_drain_progress_is_visible(self):
        (self.stub / 'warn_on_control').touch()
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn('SyntaxWarning', result.stdout + result.stderr)
        self.assertIn('Drain: 0 active, 0 reserved, 0 scheduled', result.stdout)

    def test_missing_priority_consumer_after_restart_fails_readiness(self):
        (self.stub / 'queues').write_text('{}')
        (self.stub / 'post_missing').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Readiness failed', result.stderr)
        self.assertFalse(any(' up -d --no-deps celery-beat' in c for c in self.calls()))

    def test_http_readiness_failure_restores_beat_when_new_workers_are_healthy(self):
        (self.stub / 'curl').write_text('#!/bin/sh\nprintf 503\n')
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Readiness failed', result.stderr)
        self.assertIn('Celery Beat is running', result.stderr)
        self.assertIn('docker compose -f docker-compose.yml up -d --no-deps celery-beat', self.calls())
        self.assertFalse(any(' stop celery-beat' in c for c in self.calls()))

    def test_beat_waiting_for_migrations_fails_readiness(self):
        (self.stub / 'beat_down').touch()
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Readiness failed', result.stderr)

    def test_dev_compose_uses_web_port_and_does_not_require_proxy(self):
        result = self.run_update(CVENGINE_COMPOSE_FILE='docker-compose.dev.yml')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('docker compose -f docker-compose.dev.yml up -d --no-deps --force-recreate web celery celery-beat', self.calls())
        self.assertFalse(any('--force-recreate web celery celery-beat proxy' in c for c in self.calls()))


PROXY_CONFIG = ('{"name":"cvengine","volumes":{"postgres18_data":{"name":"cvengine_postgres18_data"}},'
                '"services":{"proxy":{"ports":[{"target":443,"published":"%s","host_ip":"%s","protocol":"tcp"}]},'
                '"web":{"ports":[{"target":8000,"published":"8000","host_ip":"127.0.0.1","protocol":"tcp"}]}}}')


@unittest.skipUnless(SCRIPT.is_file() and shutil.which('git') and shutil.which('flock'), 'needs git and flock')
class UpdateLayoutAndScanTests(UpdateScriptCase):
    """Overlay Compose layouts, port ownership, preflight and stopping scans for a quick drain."""

    def setUp(self):
        super().setUp()
        for name in ('docker-compose.host.yml',):
            (self.work / name).write_text('services: {}\n')
        (self.work / '.env.production').write_text('POSTGRES_PASSWORD=x\n')
        self.git('add', 'docker-compose.host.yml', '.env.production', cwd=self.work)
        self.git('commit', '-m', 'overlay', cwd=self.work)
        self.git('pull', '--no-rebase', '--no-edit', 'origin', 'master', cwd=self.work)
        self.git('push', 'origin', 'master', cwd=self.work)
        self.git('pull', '--no-rebase', '--no-edit', 'origin', 'master', cwd=self.other)
        (self.other / 'web' / 'README').write_text('v3\n')
        self.git('commit', '-am', 'newer', cwd=self.other)
        self.git('push', 'origin', 'master', cwd=self.other)
        self.write_stub('ss', '#!/bin/sh\n[ -f "$STUB_DIR/ss_out" ] && cat "$STUB_DIR/ss_out"; exit 0\n')
        self.write_stub('curl', '#!/bin/sh\nfor a; do last=$a; done; echo "$last" >> "$STUB_DIR/curl_urls"; printf 200\n')

    def write_stub(self, name, body):
        path = self.stub / name
        path.write_text(body)
        path.chmod(0o755)

    def test_overlay_layout_from_env_file_is_used_for_every_compose_call(self):
        (self.work / '.env').write_text('CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.host.yml\n'
                                        'CVENGINE_COMPOSE_ENV_FILE=.env.production\nCVENGINE_COMPOSE_PROJECT=cvengine\n')
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        prefix = 'docker compose --env-file .env.production -p cvengine -f docker-compose.yml -f docker-compose.host.yml'
        self.assertIn(prefix + ' up -d --no-deps --force-recreate web celery celery-beat proxy', self.calls())
        self.assertFalse(any(c.startswith('docker compose -f docker-compose.yml ') for c in self.calls()))

    def test_with_no_layout_named_the_running_stacks_files_env_file_and_project_are_used(self):
        (self.stub / 'running_config_files').write_text(f'{self.work}/docker-compose.yml,{self.work}/docker-compose.host.yml\n')
        (self.stub / 'running_env_file').write_text(f'{self.work}/.env.production\n')
        (self.stub / 'running_project').write_text('cvengine\n')
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Using the Compose layout the running stack was started with', result.stdout)
        prefix = 'docker compose --env-file .env.production -p cvengine -f docker-compose.yml -f docker-compose.host.yml'
        self.assertIn(prefix + ' up -d --no-deps --force-recreate web celery celery-beat proxy', self.calls())
        self.assertFalse(any(c.startswith('docker compose -f docker-compose.yml ') for c in self.calls()))

    def test_a_layout_named_in_env_wins_over_the_running_stack(self):
        (self.stub / 'running_config_files').write_text(f'{self.work}/docker-compose.yml,{self.work}/docker-compose.host.yml\n')
        (self.work / '.env').write_text('CVENGINE_COMPOSE_FILES=docker-compose.yml\n')
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn('Using the Compose layout the running stack', result.stdout)
        self.assertIn('docker compose -f docker-compose.yml up -d --no-deps --force-recreate web celery celery-beat proxy', self.calls())

    def test_a_running_stack_started_from_files_elsewhere_stops_the_update_before_anything_changes(self):
        (self.stub / 'running_config_files').write_text('/srv/elsewhere/docker-compose.yml\n')
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CVENGINE_COMPOSE_FILES', result.stderr)
        self.assertFalse(any(' build ' in c for c in self.calls()))

    def test_unknown_compose_file_is_refused_before_anything_changes(self):
        result = self.run_update(CVENGINE_COMPOSE_FILES='docker-compose.yml,../etc/x.yml')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CVENGINE_COMPOSE_FILES', result.stderr)
        self.assertFalse(any(' build ' in c for c in self.calls()))

    def test_published_port_held_by_host_service_stops_before_build(self):
        (self.stub / 'config.json').write_text(PROXY_CONFIG % ('443', ''))
        (self.stub / 'ss_out').write_text('LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=6))\n')
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('nginx (pid 812) already holds it', result.stderr)
        self.assertFalse(any(' build ' in c for c in self.calls()))

    def test_ports_held_by_docker_or_on_other_addresses_are_fine(self):
        (self.stub / 'config.json').write_text(PROXY_CONFIG % ('18443', '127.0.0.1'))
        (self.stub / 'ss_out').write_text('LISTEN 0 511 127.0.0.1:18443 0.0.0.0:* users:(("docker-proxy",pid=9,fd=4))\n'
                                          'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=6))\n')
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('https://127.0.0.1:18443/', (self.stub / 'curl_urls').read_text())

    def test_check_reports_and_changes_nothing(self):
        (self.stub / 'web_up').touch()
        before = self.git('rev-parse', 'HEAD', cwd=self.work)
        result = subprocess.run(['bash', 'scripts/update.sh', '--check'], cwd=self.work, env=self.env,
                                capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('is available', result.stdout)
        self.assertIn('Scans:     1 running, 2 queued', result.stdout)
        self.assertIn('Result: ready', result.stdout)
        self.assertEqual(before, self.git('rev-parse', 'HEAD', cwd=self.work))
        self.assertFalse(any(' build ' in c or ' stop ' in c or 'cancel_consumer' in c for c in self.calls()))

    def test_check_fails_on_port_conflict(self):
        (self.stub / 'config.json').write_text(PROXY_CONFIG % ('443', ''))
        (self.stub / 'ss_out').write_text('LISTEN 0 511 *:443 *:* users:(("nginx",pid=812,fd=6))\n')
        result = subprocess.run(['bash', 'scripts/update.sh', '--check'], cwd=self.work, env=self.env,
                                capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 1)
        self.assertIn('proxy publishes 0.0.0.0:443, which nginx (pid 812) already holds', result.stdout)

    def test_stop_scans_stops_before_pause_and_requeues_after_readiness(self):
        (self.stub / 'web_up').touch()
        (self.stub / 'stop_json').write_text('REQUEUE_JSON [{"scan": 5, "domain": 2, "mode": "deep"}]\n')
        result = subprocess.run(['bash', 'scripts/update.sh', '--stop-scans'], cwd=self.work, env=self.env,
                                capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        calls = '\n'.join(self.calls())
        self.assertLess(calls.index('_abort_scan'), calls.index('cancel_consumer'))
        self.assertLess(calls.index('--force-recreate web'), calls.index('start_discoveries'))
        self.assertIn('"mode": "deep"', (self.stub / 'requeue_env').read_text())
        self.assertIn('Queued 1 stopped scan(s) again', result.stdout)
        self.assertFalse((self.work / '.git' / 'cvengine-update' / 'requeue.json').exists())

    def test_stopped_scans_survive_a_failed_update_for_the_next_run(self):
        (self.stub / 'web_up').touch()
        (self.stub / 'stop_json').write_text('REQUEUE_JSON [{"scan": 5, "domain": 2, "mode": null}]\n')
        (self.stub / 'migrate_fail').touch()
        result = subprocess.run(['bash', 'scripts/update.sh', '--stop-scans'], cwd=self.work, env=self.env,
                                capture_output=True, text=True, timeout=45)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Stopped scans are saved', result.stderr)
        saved = self.work / '.git' / 'cvengine-update' / 'requeue.json'
        self.assertTrue(saved.exists())
        self.assertEqual(oct(saved.stat().st_mode & 0o777), '0o600')
        (self.stub / 'migrate_fail').unlink()
        (self.stub / 'stop_json').write_text('REQUEUE_JSON []\n')
        again = self.run_update()
        self.assertEqual(again.returncode, 0, again.stderr + again.stdout)
        self.assertIn('"domain": 2', (self.stub / 'requeue_env').read_text())
        self.assertFalse(saved.exists())

    def test_unused_untracked_overlay_is_pointed_out(self):
        (self.work / 'docker-compose.local.yml').write_text('services: {}\n')
        result = subprocess.run(['bash', 'scripts/update.sh', '--check'], cwd=self.work, env=self.env,
                                capture_output=True, text=True, timeout=45)
        self.assertIn('docker-compose.local.yml is not part of this update', result.stdout)
        self.assertNotIn('docker-compose.dev.yml is not part', result.stdout)

    def test_help_prints_usage(self):
        result = subprocess.run(['bash', 'scripts/update.sh', '--help'], cwd=self.work, env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn('--stop-scans', result.stdout)
        self.assertIn('CVENGINE_COMPOSE_FILES', result.stdout)
