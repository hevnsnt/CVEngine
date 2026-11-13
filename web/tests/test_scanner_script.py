"""scripts/scanner.sh, scripts/scanner-update.sh and scripts/scanner_lock.py: the built-in scanner FOLLOWS the newest published Sentinel image (the moving
tag ``main``), scanner.lock.json is the known-good floor it was tested with, and every way the image changes (the server's update scripts, the scheduled
Scanner update) pulls it, starts it, keeps it only once it is healthy AND has checked in with a contract version the server accepts, otherwise puts the
previous image back, and never fails the update. The docker those scripts call is web/tests/fake_docker.py."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'scripts'
FAKE_DOCKER = Path(__file__).resolve().parent / 'fake_docker.py'
MOVING = 'ghcr.io/hevnsnt/cvengine-sentinel:main'
ROLLBACK = 'cvengine-sentinel-rollback:previous'
OLD, NEW = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64
FLOOR = json.loads((ROOT / 'scanner.lock.json').read_text())['floor']['contract_version']  # the contract the floor commit speaks: the tests follow it, they do not repeat it


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class ScannerScriptBase(unittest.TestCase):
    """A work directory with the scripts, the lock and the compose file, and the fake docker first on the PATH."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        shutil.copy(FAKE_DOCKER, self.stub / 'docker')
        (self.stub / 'docker').chmod(0o755)
        self.work = self.tmp / 'work'
        (self.work / 'scripts').mkdir(parents=True)
        for name in ('scanner.sh', 'scanner_lock.py'):
            shutil.copy(SCRIPTS / name, self.work / 'scripts' / name)
        shutil.copy(ROOT / 'docker-compose.yml', self.work / 'docker-compose.yml')
        shutil.copy(ROOT / 'scanner.lock.json', self.work / 'scanner.lock.json')
        self.lock = json.loads((ROOT / 'scanner.lock.json').read_text())
        (self.work / '.env').write_text('POSTGRES_DB=x\n')
        self.env = {**{k: v for k, v in os.environ.items() if not k.startswith('CVENGINE_')}, 'PATH': f'{self.stub}:{os.environ["PATH"]}',
                    'STUB_DIR': str(self.stub), 'CVENGINE_SCANNER_READY_SECONDS': '1', 'CVENGINE_SCANNER_POLL': '0'}
        self.state = {'images': {}, 'registry': {MOVING: NEW}, 'container': None, 'contract': {OLD: str(FLOOR), NEW: str(FLOOR)},
                      'release': {OLD: 'oldrelease0001', NEW: 'newrelease0002'}, 'healthy': {OLD: True, NEW: True}, 'server': f'{FLOOR} 1', 'default_ref': MOVING}
        self.save()

    def save(self):
        (self.stub / 'state.json').write_text(json.dumps(self.state))

    def reload(self):
        self.state = json.loads((self.stub / 'state.json').read_text())
        return self.state

    def running_old(self):
        """The scanner container runs the old image, which is also on this host under the name the moving tag had."""
        self.state['images'][MOVING] = OLD
        self.state['container'] = {'id': 'scannerid', 'image_id': OLD, 'ref': MOVING}
        self.save()

    def run_fn(self, *calls):
        script = '. scripts/scanner.sh\n' + '\n'.join(f'{c} docker compose -f docker-compose.yml' for c in calls)
        return subprocess.run(['bash', '-c', script], cwd=self.work, env=self.env, capture_output=True, text=True, timeout=60)

    def calls(self):
        path = self.stub / 'calls.log'
        return path.read_text().splitlines() if path.exists() else []

    def env_file(self):
        return (self.work / '.env').read_text()

    def running_image(self):
        container = self.reload()['container']
        return container['image_id'] if container else None


class ScannerCapabilityTests(ScannerScriptBase):
    """The scanner service drops every capability but NET_RAW and SYS_CHROOT; an image from before that (nmap and naabu with cap_net_admin as a file
    capability cannot start without NET_ADMIN) gets NET_ADMIN back for itself only, and loses it again when a newer image replaces it."""

    def extra(self):
        return [l for l in self.env_file().splitlines() if l.startswith('CVENGINE_SCANNER_EXTRA_CAP=')]

    def test_a_current_image_runs_with_the_reduced_set_and_nothing_is_written(self):
        self.running_old()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(self.running_image(), NEW, result.stderr)
        self.assertEqual(self.extra(), [])
        self.assertEqual(len([c for c in self.calls() if ' up -d ' in c]), 1)  # no second recreate

    def test_an_image_from_before_the_reduction_gets_net_admin_for_itself_and_the_scanner_is_recreated(self):
        self.state['net_admin_images'] = [NEW]
        self.running_old()
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.running_image(), NEW)
        self.assertEqual(self.extra(), ['CVENGINE_SCANNER_EXTRA_CAP=NET_ADMIN'])
        self.assertIn('NET_ADMIN', result.stderr)
        self.assertEqual(len([c for c in self.calls() if ' up -d ' in c]), 2)  # started, then recreated with the capability

    def test_a_held_old_image_gets_it_too_and_a_second_run_changes_nothing(self):
        self.state['net_admin_images'] = [OLD]
        self.state['images']['my/own:1'] = OLD
        self.save()
        (self.work / '.env').write_text('POSTGRES_DB=x\nCVENGINE_SCANNER_IMAGE=my/own:1\n')
        self.assertEqual(self.run_fn('cvengine_scanner_start').returncode, 0)
        self.assertEqual(self.extra(), ['CVENGINE_SCANNER_EXTRA_CAP=NET_ADMIN'])
        ups = len([c for c in self.calls() if ' up -d ' in c])
        self.assertEqual(self.run_fn('cvengine_scanner_start').returncode, 0)
        self.assertEqual(self.extra(), ['CVENGINE_SCANNER_EXTRA_CAP=NET_ADMIN'])
        self.assertEqual(len([c for c in self.calls() if ' up -d ' in c]), ups + 1)  # the restart itself, not another recreate

    def test_a_newer_image_takes_the_capability_away_again(self):
        (self.work / '.env').write_text('POSTGRES_DB=x\nCVENGINE_SCANNER_EXTRA_CAP=NET_ADMIN\n')
        self.running_old()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(self.running_image(), NEW, result.stderr)
        self.assertEqual(self.extra(), [])
        self.assertIn('POSTGRES_DB=x', self.env_file())

    def test_a_scanner_that_cannot_be_reached_is_left_as_it_is(self):
        self.state['container'] = None
        self.state['up_fails'] = True
        self.save()
        result = self.run_fn('cvengine_scanner_start --no-wait')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.extra(), [])


class ScannerUpdateTests(ScannerScriptBase):
    def test_a_newer_image_is_pulled_started_and_kept_when_it_is_healthy_and_checked_in(self):
        self.running_old()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'docker pull -q {MOVING}', self.calls())
        self.assertIn('docker compose -f docker-compose.yml up -d --no-deps --force-recreate scanner', self.calls())
        self.assertEqual(self.running_image(), NEW)
        self.assertIn('is healthy and has checked in', result.stderr)
        self.assertNotIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())
        self.assertEqual(self.reload()['images'][ROLLBACK], OLD, 'the image that worked is kept under a name of its own')
        self.assertTrue(any('report done' in r and 'oldrelease0001' in r and 'newrelease0002' in r for r in self.state['reports']))
        # the scanner was asked to finish its work first
        self.assertTrue([c for c in self.calls() if 'client.control drain' in c])

    def test_a_rebuilt_image_of_the_same_commit_clears_the_failure_an_earlier_rollback_reported(self):
        self.running_old()
        self.state['release'][NEW] = self.state['release'][OLD]  # the fix is a new image of the same commit
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(self.running_image(), NEW, result.stderr)
        self.assertTrue(any('report done' in r for r in self.reload()['reports']))

    def test_a_new_image_that_fails_its_health_wait_is_replaced_by_the_previous_one_and_says_why(self):
        self.running_old()
        self.state['healthy'][NEW] = False
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.running_image(), OLD)
        self.assertIn('was not kept', result.stderr)
        self.assertIn('sent no heartbeat', result.stderr)
        self.assertIn(f'CVENGINE_SCANNER_ROLLBACK_IMAGE={ROLLBACK}', self.env_file())
        self.assertTrue([c for c in self.calls() if '--force-recreate --pull never scanner' in c], 'the old image comes back from this host, never from the registry')
        report = [r for r in self.state['reports'] if 'report failed' in r]
        self.assertTrue(report and 'kept the previous image: it sent no heartbeat' in report[0])

    def test_a_new_image_that_checks_in_with_a_contract_below_the_floor_is_rolled_back(self):
        self.running_old()
        self.state['contract'][NEW] = str(FLOOR - 1)  # healthy, and speaking an older contract than the floor this release was tested with
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.running_image(), OLD)
        self.assertIn(f'contract version {FLOOR - 1} is below the floor {FLOOR}', result.stderr)
        self.assertIn(f'CVENGINE_SCANNER_ROLLBACK_IMAGE={ROLLBACK}', self.env_file())
        self.assertTrue(any('report failed' in r and f'below the floor {FLOOR}' in r for r in self.state['reports']))

    def test_a_contract_the_server_no_longer_speaks_is_refused_too(self):
        self.running_old()
        data = dict(self.lock)
        data['floor'] = {**self.lock['floor'], 'contract_version': 1}  # a low floor: the server's own line (min_supported FLOOR here) is what refuses it
        (self.work / 'scanner.lock.json').write_text(json.dumps(data))
        self.state['contract'][NEW] = str(FLOOR - 1)
        self.state['server'] = f'{FLOOR + 1} {FLOOR}'
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertIn(f'older than the {FLOOR} this server still speaks', result.stderr)
        self.assertEqual(self.running_image(), OLD)

    def test_a_scanner_on_a_newer_contract_than_the_server_is_kept(self):
        self.running_old()
        self.state['contract'][NEW] = str(FLOOR + 6)  # newer than the server's: it is offered what this server knows, so it is fine
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(self.running_image(), NEW)
        self.assertNotIn('was not kept', result.stderr)
        self.assertNotIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())

    def test_a_pull_that_fails_keeps_the_running_scanner_untouched(self):
        self.running_old()
        self.state['pull_fails'] = True
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('could not pull', result.stderr)
        self.assertIn('make scanner-build', result.stderr)
        self.assertEqual(self.running_image(), OLD)
        self.assertFalse([c for c in self.calls() if 'force-recreate' in c or 'drain' in c], 'a failed pull restarts nothing')
        self.assertNotIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())

    def test_the_newest_image_already_running_restarts_nothing(self):
        self.running_old()
        self.state['registry'][MOVING] = OLD
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('already runs the newest', result.stderr)
        self.assertFalse([c for c in self.calls() if 'force-recreate' in c or 'drain' in c])

    def test_a_busy_scanner_finishes_its_work_first_and_is_updated_at_the_next_run(self):
        self.running_old()
        self.state['busy'] = True
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('still busy', result.stderr)
        self.assertEqual(self.running_image(), OLD)
        self.assertTrue([c for c in self.calls() if 'client.control undrain' in c], 'the scanner takes work again')
        self.assertFalse([c for c in self.calls() if 'force-recreate' in c])

    def test_the_next_update_after_a_rollback_tries_the_newest_image_again(self):
        self.running_old()
        self.state['healthy'][NEW] = False
        self.save()
        self.run_fn('cvengine_scanner_update')
        self.assertIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())
        self.reload()
        self.state['healthy'][NEW] = True  # fixed upstream
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())
        self.assertEqual(self.running_image(), NEW)

    def test_the_moving_tag_is_pulled_every_time_even_when_a_copy_is_on_the_host(self):
        self.running_old()
        self.run_fn('cvengine_scanner_fetch')
        self.assertIn(f'docker pull -q {MOVING}', self.calls())

    def test_a_first_start_with_no_previous_image_is_never_rolled_back_and_never_fails(self):
        self.state['healthy'][NEW] = False
        self.save()
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('is not accepted yet', result.stderr)
        self.assertNotIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())
        self.assertEqual(self.running_image(), NEW)

    def test_a_fresh_install_pulls_the_newest_image_and_needs_no_digest(self):
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.running_image(), NEW)
        self.assertFalse([c for c in self.calls() if '@sha256' in c])

    def test_the_update_scripts_path_checks_a_changed_image_even_for_make_up(self):
        self.running_old()
        self.state['healthy'][NEW] = False
        self.save()
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start --no-wait')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.running_image(), OLD, 'make up never leaves a scanner that did not check in')

    def test_make_up_on_a_first_start_does_not_wait(self):
        self.state['healthy'][NEW] = False
        self.save()
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start --no-wait')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse([c for c in self.calls() if 'exec -T scanner' in c and 'client.control' in c])  # no heartbeat wait (the capability look at the image is not one)

    def test_when_the_new_image_is_not_on_the_host_the_scanner_keeps_the_one_that_ran(self):
        self.running_old()
        self.state['pull_fails'] = True
        self.state['images'].pop(MOVING)  # the tag is gone from this host (pruned), the container still runs its image
        self.save()
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('keeping the one that ran', result.stderr)
        self.assertEqual(self.running_image(), OLD)

    def test_turned_off_it_is_removed_and_nothing_is_fetched(self):
        (self.work / '.env').write_text('CVENGINE_BUILTIN_SCANNER=0\n')
        self.running_old()
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start', 'cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('docker compose -f docker-compose.yml rm -sf scanner', self.calls())
        self.assertFalse([c for c in self.calls() if c.startswith('docker pull') or 'force-recreate' in c])

    def test_an_install_without_the_service_is_left_alone(self):
        self.state['no_scanner'] = True
        self.save()
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start', 'cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c for c in self.calls() if 'config --services' not in c], [])

    def test_the_from_source_fallback_builds_the_floor_commit(self):
        result = self.run_fn('cvengine_scanner_build')
        self.assertEqual(result.returncode, 0, result.stderr)
        build = [c for c in self.calls() if c.startswith('docker build')]
        self.assertEqual(len(build), 1)
        self.assertIn('BUILDKIT_CONTEXT_KEEP_GIT_DIR=1', build[0])
        self.assertIn(f'cvengine-sentinel-local:{self.lock["floor"]["version"]}', build[0])
        self.assertTrue(build[0].endswith(f'https://github.com/hevnsnt/cvENGINE-sentinel.git#{self.lock["floor"]["commit"]}'))


class HeldScannerTests(ScannerScriptBase):
    """CVENGINE_SCANNER_IMAGE in .env holds the scanner at a version: it is honoured and never overridden."""

    def hold(self, image):
        (self.work / '.env').write_text(f'POSTGRES_DB=x\nCVENGINE_SCANNER_IMAGE={image}\n')

    def test_the_scheduled_update_leaves_a_held_scanner_alone(self):
        held = 'ghcr.io/hevnsnt/cvengine-sentinel@sha256:' + 'c' * 64
        self.hold(held)
        self.state['images'][held] = 'sha256:' + 'c' * 64
        self.state['container'] = {'id': 'scannerid', 'image_id': 'sha256:' + 'c' * 64, 'ref': held}
        self.save()
        result = self.run_fn('cvengine_scanner_update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('held at CVENGINE_SCANNER_IMAGE', result.stderr)
        self.assertFalse([c for c in self.calls() if c.startswith('docker pull') or 'force-recreate' in c or 'drain' in c])
        self.assertEqual(self.running_image(), 'sha256:' + 'c' * 64)

    def test_the_updater_starts_the_held_image_never_the_moving_tag_and_never_rolls_it_back(self):
        held = 'ghcr.io/hevnsnt/cvengine-sentinel:1.4'
        self.hold(held)
        self.state['images'][held] = 'sha256:' + 'd' * 64
        self.state['healthy']['sha256:' + 'd' * 64] = False  # even unhealthy: it is the administrator's choice
        self.running_old()
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse([c for c in self.calls() if c.startswith('docker pull') and MOVING in c], 'the moving tag is never pulled over a held image')
        self.assertEqual(self.running_image(), 'sha256:' + 'd' * 64)
        self.assertNotIn('CVENGINE_SCANNER_ROLLBACK_IMAGE', self.env_file())
        self.assertIn('CVENGINE_SCANNER_IMAGE=ghcr.io/hevnsnt/cvengine-sentinel:1.4', self.env_file())
        self.assertFalse([c for c in self.calls() if c.startswith('docker tag')], 'nothing is tagged for a rollback that will not happen')

    def test_a_held_image_that_is_not_on_the_host_is_pulled_by_its_own_name(self):
        held = 'ghcr.io/hevnsnt/cvengine-sentinel@sha256:' + 'e' * 64
        self.hold(held)
        self.state['registry'][held] = 'sha256:' + 'e' * 64
        self.save()
        result = self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'docker pull -q {held}', self.calls())
        self.assertEqual(self.running_image(), 'sha256:' + 'e' * 64)

    def test_a_held_image_in_the_environment_wins_over_the_file(self):
        self.env['CVENGINE_SCANNER_IMAGE'] = 'cvengine-sentinel-local:latest'
        self.state['images']['cvengine-sentinel-local:latest'] = 'sha256:' + 'f' * 64
        self.save()
        self.run_fn('cvengine_scanner_fetch', 'cvengine_scanner_start')
        self.assertFalse([c for c in self.calls() if c.startswith('docker pull')])
        self.assertEqual(self.running_image(), 'sha256:' + 'f' * 64)


class LockTests(unittest.TestCase):
    """scanner.lock.json is the known-good floor, not a pin: what it must hold, and what ``check`` proves."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location('scanner_lock', SCRIPTS / 'scanner_lock.py')
        cls.lock = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.lock)
        cls.data = json.loads((ROOT / 'scanner.lock.json').read_text())
        cls.compose = (ROOT / 'docker-compose.yml').read_text()

    def run_cli(self, *args):
        return subprocess.run(['python3', str(SCRIPTS / 'scanner_lock.py'), *args], capture_output=True, text=True)

    def test_the_lock_is_valid_and_check_passes_offline(self):
        result = self.run_cli('check')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_lock_names_the_moving_tag_and_a_floor_not_an_exact_pin(self):
        self.assertEqual(self.data['tag'], 'main')
        self.assertEqual(self.run_cli('ref').stdout.strip(), MOVING)
        self.assertNotIn('digest', self.data, 'no top-level digest: the lock does not choose the image')
        floor = self.data['floor']
        self.assertRegex(floor['commit'], r'^[0-9a-f]{40}$')
        self.assertTrue(floor['commit'].startswith(floor['version']))
        self.assertIsInstance(floor['contract_version'], int)
        if floor.get('digest') is not None:  # optional, kept for provenance
            self.assertRegex(floor['digest'], r'^sha256:[0-9a-f]{64}$')
        self.assertEqual(self.run_cli('floor').stdout.strip(), floor['commit'])
        self.assertEqual(self.run_cli('contract-floor').stdout.strip(), str(floor['contract_version']))

    def test_the_compose_default_is_the_moving_tag_and_never_a_digest(self):
        self.assertEqual(self.lock.compose_default(self.compose), MOVING)
        self.assertNotIn('@sha256', self.lock.compose_default(self.compose))

    def test_check_fails_when_the_compose_default_is_a_digest_or_another_tag(self):
        pinned = self.compose.replace(MOVING + '}}', 'ghcr.io/hevnsnt/cvengine-sentinel@' + OLD + '}}')
        problems = self.lock.check(self.data, pinned, server=(FLOOR, 1))
        self.assertTrue(any('not the moving tag' in p for p in problems) and any('not a digest' in p for p in problems), problems)
        other = self.compose.replace(MOVING + '}}', 'ghcr.io/hevnsnt/cvengine-sentinel:1.4}}')
        self.assertTrue(self.lock.check(self.data, other, server=(FLOOR, 1)))
        self.assertEqual(self.lock.check(self.data, self.compose, server=(FLOOR, 1)), [])

    def test_check_fails_when_the_floor_is_above_the_contract_the_server_reads(self):
        data = {**self.data, 'floor': {**self.data['floor'], 'contract_version': FLOOR + 1}}
        problems = self.lock.check(data, self.compose, server=(FLOOR, 1))
        self.assertTrue(any(f'above the contract version {FLOOR} this server reads' in p for p in problems), problems)

    def test_the_floor_is_not_above_what_the_installed_library_reads(self):
        pair = self.lock.server_contract()
        if pair is None:
            self.skipTest('the scanner library is not installed')
        self.assertLessEqual(self.data['floor']['contract_version'], pair[0])
        from agentapi import sentinel_contract  # the module the server itself reads it through
        self.assertEqual(pair, (sentinel_contract.version(), sentinel_contract.min_supported()))

    def test_check_fails_when_the_tag_is_not_the_one_the_publish_workflow_moves(self):
        data = {**self.data, 'tag': 'latest'}
        compose = self.compose.replace(MOVING + '}}', 'ghcr.io/hevnsnt/cvengine-sentinel:latest}}')
        self.assertTrue(any("moves 'main'" in p for p in self.lock.check(data, compose, server=(FLOOR, 1))))

    def test_the_floor_commit_is_checked_against_the_sentinel_main_branch(self):
        def reply(status):
            handle = mock.MagicMock()
            handle.__enter__.return_value = handle
            handle.read.return_value = json.dumps({'status': status}).encode()
            return handle
        for status, ok in (('ahead', True), ('identical', True), ('diverged', False), ('behind', False)):
            with mock.patch('urllib.request.urlopen', return_value=reply(status)):
                self.assertEqual(self.lock.remote_check(self.data)[0], ok, status)
        error = urllib.error.HTTPError('u', 404, 'Not Found', {}, None)
        with mock.patch('urllib.request.urlopen', side_effect=error):
            ok, why = self.lock.remote_check(self.data)
        self.assertFalse(ok)
        self.assertIn('is not in hevnsnt/cvENGINE-sentinel', why)
        with mock.patch('urllib.request.urlopen', return_value=reply('ahead')) as opened:
            self.lock.remote_check(self.data)
        self.assertIn(f'/compare/{self.data["floor"]["commit"]}...main', opened.call_args[0][0].full_url)

    def test_accepts_follows_the_floor_and_the_servers_own_line(self):
        accepts = self.lock.accepts
        self.assertEqual(accepts(self.data, FLOOR, FLOOR, 1), (True, ''))
        self.assertEqual(accepts(self.data, FLOOR + 6, FLOOR, 1), (True, ''), 'a newer contract is fine')
        self.assertFalse(accepts(self.data, FLOOR - 1, FLOOR, 1)[0])
        self.assertIn(f'below the floor {FLOOR}', accepts(self.data, FLOOR - 1, FLOOR, 1)[1])
        low = {**self.data, 'floor': {**self.data['floor'], 'contract_version': 1}}
        self.assertEqual(accepts(low, 1, FLOOR, 1), (True, ''))
        self.assertIn('older than the 2 this server still speaks', accepts(low, 1, FLOOR, 2)[1])
        for bad in (None, True, 0, 'x'):
            self.assertFalse(accepts(self.data, bad)[0], bad)

    def test_the_command_line_says_yes_and_no(self):
        self.assertEqual(self.run_cli('accepts', str(FLOOR), str(FLOOR), '1').returncode, 0)
        refused = self.run_cli('accepts', str(FLOOR - 1), str(FLOOR), '1')
        self.assertEqual(refused.returncode, 1)
        self.assertIn('below the floor', refused.stderr)
        self.assertEqual(self.run_cli('accepts', 'x').returncode, 2)

    def test_the_floor_only_moves_up_and_a_digest_is_optional(self):
        new = 'f' * 40
        raised = self.lock.raise_floor(self.data, new, self.data['floor']['contract_version'] + 1)
        self.assertEqual((raised['floor']['commit'], raised['floor']['version'], raised['floor']['digest']), (new, new[:12], None))
        with self.assertRaises(self.lock.LockError):
            self.lock.raise_floor(self.data, new, self.data['floor']['contract_version'] - 1)
        with self.assertRaises(self.lock.LockError):
            self.lock.raise_floor(self.data, 'short', FLOOR)
        with self.assertRaises(self.lock.LockError):
            self.lock.validate({**self.data, 'tag': 'sha256:' + 'a' * 64})
        self.lock.validate({**self.data, 'image': 'localhost:5055/cvengine-sentinel'})  # a registry with a port is a registry
        with self.assertRaises(self.lock.LockError):
            self.lock.validate({**self.data, 'image': 'localhost:5055'})

    def test_raise_floor_leaves_the_compose_default_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'scripts').mkdir()
            shutil.copy(SCRIPTS / 'scanner_lock.py', work / 'scripts')
            shutil.copy(ROOT / 'scanner.lock.json', work)
            shutil.copy(ROOT / 'docker-compose.yml', work)
            out = subprocess.run(['python3', 'scripts/scanner_lock.py', 'raise-floor', '--commit', 'a' * 40, '--contract', str(FLOOR)], cwd=work, capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual((work / 'docker-compose.yml').read_text(), self.compose)
            self.assertEqual(subprocess.run(['python3', 'scripts/scanner_lock.py', 'check'], cwd=work).returncode, 0)

    def test_the_floor_commit_is_the_one_the_servers_library_pin_comes_from(self):
        requirements = (ROOT / 'web' / 'requirements.txt').read_text()
        self.assertIn(f'cvENGINE-sentinel@{self.data["floor"]["commit"]}', requirements)


@unittest.skipUnless(shutil.which('docker') and subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode == 0, 'needs docker compose')
class ComposeRenderingTests(unittest.TestCase):
    """What `docker compose config` makes of the scanner service: the moving tag by default, an administrator's image or the rollback image when set."""

    def render(self, **env):
        base = {k: v for k, v in os.environ.items() if not k.startswith('CVENGINE_')}
        out = subprocess.run(['docker', 'compose', '-f', str(ROOT / 'docker-compose.yml'), '--env-file', os.devnull, 'config', '--format', 'json'],
                             capture_output=True, text=True, env={**base, **env}, cwd=ROOT)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)['services']['scanner']

    def test_the_default_image_is_the_moving_tag_and_pulls_only_a_missing_one(self):
        scanner = self.render()
        self.assertEqual(scanner['image'], MOVING)
        self.assertEqual(scanner['pull_policy'], 'missing')

    def test_the_pull_policy_can_be_switched_to_always(self):
        self.assertEqual(self.render(CVENGINE_SCANNER_PULL_POLICY='always')['pull_policy'], 'always')

    def test_an_administrators_image_wins_and_the_rollback_image_comes_next(self):
        digest = 'ghcr.io/hevnsnt/cvengine-sentinel@sha256:' + 'c' * 64
        self.assertEqual(self.render(CVENGINE_SCANNER_IMAGE=digest)['image'], digest)
        self.assertEqual(self.render(CVENGINE_SCANNER_ROLLBACK_IMAGE=ROLLBACK)['image'], ROLLBACK)
        self.assertEqual(self.render(CVENGINE_SCANNER_IMAGE=digest, CVENGINE_SCANNER_ROLLBACK_IMAGE=ROLLBACK)['image'], digest)


class UpdatePathTests(unittest.TestCase):
    """Every path that recreates celery also fetches the scanner's image first and starts the scanner after (it shares celery's network namespace)."""

    def text(self, name):
        return (ROOT / name).read_text()

    def test_each_update_path_fetches_before_and_starts_after(self):
        for name, after in (('scripts/update.sh', 'worker_queues_ready && beat_ready'), ('scripts/update-deploy.sh', 'verify_serving || return 1'),
                            ('scripts/apply-update.sh', 'verify_running "${services[@]}" || return 1'), ('Makefile', '--force-recreate tailscale')):
            with self.subTest(name=name):
                text = self.text(name)
                self.assertIn('cvengine_scanner_fetch', text)
                self.assertIn('cvengine_scanner_start', text)
                self.assertLess(text.index(after), text.index('cvengine_scanner_start'))

    def test_the_web_updater_never_fetches_before_the_page_when_it_runs_after_the_merge(self):
        text = self.text('scripts/update-deploy.sh')
        # deploy_current runs after the merge (./web is a bind mount: the old image already reads the new code), so the page is its first act and the fetch
        # is made from the deploy steps, under it. The early fetch belongs to apply-update.sh, before the merge (test_apply_update_script has the order).
        self.assertNotIn('deploy_scanner_fetch early', text)
        body = text[text.index('deploy_current() {'):text.index('deploy_steps() {')]
        before_the_page = body[:body.index('  maintenance_on\n')]
        self.assertNotIn('fetch', '\n'.join(l for l in before_the_page.splitlines() if not l.lstrip().startswith('#')))  # nothing slow comes before the page in the deploy of an older host
        self.assertLess(text.index('  maintenance_on\n'), text.index('  deploy_scanner_fetch once\n'))
        self.assertLess(text.index('cvengine_scanner_start'), text.index('  prune_old_images\n'))

    def test_make_up_waits_for_nothing_on_a_first_start(self):
        self.assertIn('cvengine_scanner_start --no-wait', self.text('Makefile'))

    def test_the_scheduled_scanner_update_exists_and_is_wired_in(self):
        self.assertTrue(os.access(ROOT / 'scripts' / 'scanner-update.sh', os.X_OK))
        self.assertIn('cvengine_scanner_update', self.text('scripts/scanner-update.sh'))
        self.assertIn('scripts/scanner-update.sh', self.text('scripts/auto-deploy.sh'))
        self.assertIn('CVENGINE_SCANNER_UPDATE_HOURS', self.text('scripts/auto-deploy.sh'))
        self.assertIn('scanner-update:', self.text('Makefile'))

    def test_the_scripts_parse(self):
        for name in ('scripts/scanner.sh', 'scripts/scanner-update.sh', 'scripts/auto-deploy.sh', 'scripts/update.sh', 'scripts/update-deploy.sh', 'scripts/apply-update.sh',
                     'install.sh', 'scripts/init-env.sh'):
            with self.subTest(name=name):
                subprocess.run(['bash', '-n', str(ROOT / name)], check=True)

    def test_the_compose_default_is_the_rollback_then_the_moving_tag(self):
        self.assertRegex(self.text('docker-compose.yml'),
                         re.escape('image: "${CVENGINE_SCANNER_IMAGE:-${CVENGINE_SCANNER_ROLLBACK_IMAGE:-') + r'[^}@]+\}\}"')

    def test_no_script_tells_a_person_to_pin_a_digest_for_the_scanner_to_update(self):
        for name in ('install.sh', 'scripts/scanner.sh', 'scripts/update.sh', 'Makefile'):
            with self.subTest(name=name):
                self.assertNotIn('scanner_lock.py pin', self.text(name))
                self.assertNotIn('scanner_lock.py published', self.text(name))
