"""The host-size rule and the choice of scanners in the updater (scripts/host-fit.sh, scripts/update.sh, scripts/update-deploy.sh, scripts/apply-scanner-plan.sh).

Run through the real scripts against a throwaway Git remote and stub commands: a fake `docker` (the same one tests/test_update_script.py uses, with the answers of
`manage.py external_sentinels` and the containers' memory limits added), a fake host memory (CVENGINE_HOST_MEM_MB, the override the tests and rehearsals use). The new
scripts arrive with the fetched commit, as they do on a real host, so the preflight runs from the script that was just fetched."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_update_script import SCRIPT, UpdateScriptCase

SCRIPTS = SCRIPT.parent
ROOT = SCRIPTS.parent

WRAPPER = '''#!/usr/bin/env bash
case " $* " in
  *" ps -q --status running db "*) if [ -e "$STUB_DIR/db_down" ]; then exit 0; fi; echo dbid; exit 0;;
  *" exec -T web python3 manage.py external_sentinels "*|*" run --rm --no-deps -T --entrypoint python3 web manage.py external_sentinels "*)
    echo "docker $*" >> "$STUB_DIR/calls"
    if [ -e "$STUB_DIR/externals_unavailable" ]; then echo "ModuleNotFoundError: No module named 'cvengine_scanner'" >&2; exit 1; fi
    echo "EXTERNAL_SENTINELS_LIVE $(cat "$STUB_DIR/externals" 2>/dev/null || echo 0)"; exit 0;;
  *" inspect -f {{.HostConfig.Memory}} "*)
    id=${@: -1}; grep "^$id " "$STUB_DIR/limits" 2>/dev/null | cut -d' ' -f2-; exit 0;;
esac
case "$*" in
  *" ps -q") [ -f "$STUB_DIR/limits" ] && cut -d' ' -f1 "$STUB_DIR/limits"; exit 0;;
  *" config --services"*) if [ -e "$STUB_DIR/has_scanner" ]; then "$STUB_DIR/docker-orig" "$@"; echo scanner; else "$STUB_DIR/docker-orig" "$@"; fi; exit 0;;
esac
exec "$STUB_DIR/docker-orig" "$@"
'''

GB = 1024 ** 3


class FitCase(UpdateScriptCase):
    def setUp(self):
        super().setUp()
        (self.stub / 'docker-orig').write_text((self.stub / 'docker').read_text())
        (self.stub / 'docker-orig').chmod(0o755)
        (self.stub / 'docker').write_text(WRAPPER)
        for name in ('host-fit.sh', 'init-env.sh', 'scanner.sh', 'scanner_lock.py'):
            shutil.copy(SCRIPTS / name, self.other / 'scripts' / name)
        shutil.copy(ROOT / 'scanner.lock.json', self.other / 'scanner.lock.json')
        shutil.copy(ROOT / '.env.example', self.other / '.env.example')
        self.git('add', '-A', cwd=self.other)
        self.git('commit', '-m', 'the fit scripts', cwd=self.other)
        self.git('push', 'origin', 'master', cwd=self.other)
        (self.work / '.env').write_text('DOMAIN_NAME=example.com\nPOSTGRES_PASSWORD=pw\nAUTHORITY_PASSWORD=pw\n')
        (self.stub / 'web_up').touch()
        self.env = {k: v for k, v in self.env.items() if k not in ('CVENGINE_HOST_MEM_MB', 'CVENGINE_INSTALL_SENTINELS', 'SCANNER_MEM_LIMIT')}

    def set_externals(self, n):
        (self.stub / 'externals').write_text(f'{n}\n')

    def env_text(self):
        return (self.work / '.env').read_text()

    def keys(self):
        return {line.split('=', 1)[0]: line.split('=', 1)[1] for line in self.env_text().splitlines() if '=' in line and not line.startswith('#')}

    def update(self, mem_mb=None, *args, **env):
        if mem_mb is not None:
            env['CVENGINE_HOST_MEM_MB'] = str(mem_mb)
        result = self.run_update(*args, **env)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return result


@unittest.skipUnless(SCRIPT.is_file() and shutil.which('git') and shutil.which('flock'), 'needs git and flock')
class HostSizeRuleTests(FitCase):
    def test_a_host_of_4_5_gb_with_no_keys_gets_1g_and_one_plain_line(self):
        result = self.update(4608)
        self.assertEqual(self.keys()['SCANNER_MEM_LIMIT'], '1g')
        self.assertIn('This host has 4.5 GB of memory, so SCANNER_MEM_LIMIT=1g was written to .env', result.stdout)
        self.assertEqual(result.stdout.count('SCANNER_MEM_LIMIT=1g was written'), 1)

    def test_it_is_written_before_anything_is_stopped(self):
        self.update(4608)
        calls = self.calls()
        self.assertTrue(self.env_text().count('SCANNER_MEM_LIMIT=1g') == 1)
        self.assertLess(next(i for i, c in enumerate(calls) if ' build ' in c), next(i for i, c in enumerate(calls) if 'cancel_consumer' in c))

    def test_a_host_of_16_gb_gets_nothing_written(self):
        before = self.env_text()
        result = self.update(16384)
        self.assertEqual(self.env_text(), before)
        self.assertNotIn('SCANNER_MEM_LIMIT', result.stdout)

    def test_the_line_is_7_gb(self):
        self.update(6834)  # 6834 MB is under 7000000 kB, 6836 MB is not
        self.assertEqual(self.keys().get('SCANNER_MEM_LIMIT'), '1g')

    def test_just_over_the_line_writes_nothing(self):
        self.update(6836)
        self.assertNotIn('SCANNER_MEM_LIMIT', self.keys())

    def test_an_owners_limit_is_never_changed(self):
        (self.work / '.env').write_text(self.env_text() + 'SCANNER_MEM_LIMIT=2g\n')
        result = self.update(4608)
        self.assertEqual(self.keys()['SCANNER_MEM_LIMIT'], '2g')
        self.assertIn('SCANNER_MEM_LIMIT=2g is already set, so it is left as it is', result.stdout)

    def test_an_owners_limit_in_the_environment_is_never_changed_either(self):
        self.update(4608, SCANNER_MEM_LIMIT='3g')
        self.assertNotIn('SCANNER_MEM_LIMIT', self.keys())

    def test_an_owners_scanner_switch_is_left_alone(self):
        for value in ('0', '1'):
            with self.subTest(value=value):
                (self.work / '.env').write_text(self.env_text().replace('CVENGINE_BUILTIN_SCANNER=0\n', '').replace('CVENGINE_BUILTIN_SCANNER=1\n', '') + f'CVENGINE_BUILTIN_SCANNER={value}\n')
                self.update(4608)
                self.assertNotIn('SCANNER_MEM_LIMIT', self.keys())
                self.assertEqual(self.keys()['CVENGINE_BUILTIN_SCANNER'], value)

    def test_it_is_idempotent(self):
        self.update(4608)
        once = self.env_text()
        again = self.update(4608)
        self.assertEqual(self.env_text(), once)
        self.assertEqual(once.count('SCANNER_MEM_LIMIT='), 1)
        self.assertNotIn('was written', again.stdout)

    def test_the_env_file_compose_reads_gets_it_too(self):
        (self.work / '.env.vps').write_text('X=1\n')
        (self.work / '.env').write_text(self.env_text() + 'CVENGINE_COMPOSE_ENV_FILE=.env.vps\n')
        self.update(4608)
        self.assertIn('SCANNER_MEM_LIMIT=1g', (self.work / '.env.vps').read_text())

    def test_check_says_what_the_update_would_do_and_changes_nothing(self):
        self.update(16384)  # brings the new scripts in: --check runs the script the checkout has
        before = self.env_text()
        result = self.run_update('--check', CVENGINE_HOST_MEM_MB='4608')
        self.assertEqual(self.env_text(), before)
        self.assertIn('will write SCANNER_MEM_LIMIT=1g', result.stdout)

    def test_the_rule_table_has_one_place(self):
        out = subprocess.run(['bash', '-c', f'. {SCRIPTS}/host-fit.sh; cvengine_fit_rule_table; cvengine_fit_scanner_limit 4718592; cvengine_fit_scanner_limit 16777216; cvengine_fit_scanner_limit 0'],
                             capture_output=True, text=True).stdout.splitlines()
        self.assertEqual(out[1:3], ['under 7 GB                1g', '7 GB or more              default (3g), nothing written'])
        self.assertEqual(out[3:], ['1g'])  # 4.5 GB gets 1g; 16 GB and an unreadable host get nothing
        self.assertIn('. scripts/host-fit.sh', (ROOT / 'install.sh').read_text())  # install.sh uses the same function


@unittest.skipUnless(SCRIPT.is_file() and shutil.which('git') and shutil.which('flock'), 'needs git and flock')
class ChoiceOfScannersTests(FitCase):
    def test_two_live_sentinels_and_no_answer_keep_the_scanner_at_1g_and_say_so(self):
        self.set_externals(2)
        result = self.update(4608)
        keys = self.keys()
        self.assertEqual(keys['SCANNER_MEM_LIMIT'], '1g')
        self.assertNotIn('CVENGINE_BUILTIN_SCANNER', keys)  # never removed without an answer
        self.assertIn('You have 2 Sentinels of your own that are live.', result.stdout)
        self.assertIn('It was kept, because a scanner is never removed without your answer.', result.stdout)
        self.assertIn('Settings > Sentinels', result.stdout)
        self.assertIn('scripts/update.sh --sentinels external', result.stdout)
        notice = (self.work / 'web' / '.update-notice.json').read_text()
        self.assertIn('"scanner_kept"', notice)
        self.assertIn('"externals": 2', notice)
        self.assertIn('"limit": "1g"', notice)

    def test_two_live_sentinels_on_a_big_host_keep_the_scanner_and_say_so(self):
        self.set_externals(2)
        result = self.update(16384)
        self.assertNotIn('SCANNER_MEM_LIMIT', self.keys())
        self.assertIn('It was kept', result.stdout)
        self.assertIn('"limit": "3g"', (self.work / 'web' / '.update-notice.json').read_text())

    def test_one_live_sentinel_is_not_enough_to_say_anything(self):
        self.set_externals(1)
        result = self.update(16384)
        self.assertNotIn('It was kept', result.stdout)
        self.assertFalse((self.work / 'web' / '.update-notice.json').exists())

    def test_the_answer_external_removes_the_scanner(self):
        self.set_externals(2)
        (self.stub / 'has_scanner').touch()
        result = self.update(4608, '--sentinels', 'external')
        keys = self.keys()
        self.assertEqual(keys['CVENGINE_BUILTIN_SCANNER'], '0')
        self.assertEqual(keys['CVENGINE_SENTINEL_PLAN'], 'external')
        self.assertIn('Which scanners run: Sentinels of your own only (the built-in scanner is removed).', result.stdout)
        self.assertTrue(any(' rm -sf scanner' in c for c in self.calls()), self.calls())
        self.assertFalse((self.work / 'web' / '.update-notice.json').exists())

    def test_the_environment_variable_is_the_same_answer(self):
        self.update(16384, CVENGINE_INSTALL_SENTINELS='external')
        self.assertEqual(self.keys()['CVENGINE_BUILTIN_SCANNER'], '0')

    def test_both_and_internal_turn_a_scanner_that_was_off_back_on(self):
        for plan in ('both', 'internal'):
            with self.subTest(plan=plan):
                (self.work / '.env').write_text(self.env_text().replace('CVENGINE_BUILTIN_SCANNER=0\n', '') + 'CVENGINE_BUILTIN_SCANNER=0\n')
                self.update(16384, '--sentinels', plan)
                self.assertEqual(self.keys()['CVENGINE_BUILTIN_SCANNER'], '1')
                self.assertEqual(self.keys()['CVENGINE_SENTINEL_PLAN'], plan)

    def test_a_choice_that_is_not_one_of_the_three_is_refused_before_anything_happens(self):
        result = self.run_update('--sentinels', 'everything')
        self.assertEqual(result.returncode, 2)
        self.assertIn('must be internal, both or external', result.stderr)
        self.assertEqual(self.calls(), [])

    def test_once_somebody_chose_nothing_is_asked_or_noted_again(self):
        self.update(16384, '--sentinels', 'both')
        self.set_externals(3)
        again = self.update(16384)
        self.assertNotIn('It was kept', again.stdout)
        self.assertEqual(self.keys()['CVENGINE_SENTINEL_PLAN'], 'both')

    def test_an_owners_scanner_switch_means_somebody_chose(self):
        (self.work / '.env').write_text(self.env_text() + 'CVENGINE_BUILTIN_SCANNER=1\n')
        self.set_externals(2)
        result = self.update(16384)
        self.assertNotIn('It was kept', result.stdout)
        self.assertEqual(self.keys()['CVENGINE_BUILTIN_SCANNER'], '1')

    def test_a_server_that_cannot_say_changes_nothing_and_says_so(self):
        (self.stub / 'externals_unavailable').touch()
        before = self.env_text()
        result = self.update(16384)
        self.assertEqual(self.env_text(), before)
        self.assertIn('Could not read how many Sentinels of your own are live', result.stdout)
        self.assertIn('which scanners run is not changed', result.stdout)

    def test_a_database_that_is_not_running_changes_nothing_and_says_so(self):
        (self.stub / 'db_down').touch()
        result = self.update(16384)
        self.assertIn('which scanners run is not changed', result.stdout)

    def test_the_count_is_read_by_a_one_off_container_of_the_new_image_after_the_build(self):
        # the running container is still on the old image and cannot start the new code, so it is not the one asked
        self.set_externals(2)
        self.update(16384)
        calls = self.calls()
        ask = next(i for i, c in enumerate(calls) if 'external_sentinels' in c)
        self.assertIn(' run --rm --no-deps -T --entrypoint python3 web manage.py external_sentinels', calls[ask])
        self.assertGreater(ask, next(i for i, c in enumerate(calls) if ' build ' in c))
        self.assertLess(ask, next(i for i, c in enumerate(calls) if 'cancel_consumer' in c))

    def test_the_updater_never_waits_for_an_answer(self):
        self.set_externals(2)
        for extra in ({'CVENGINE_UPDATE_NONINTERACTIVE': '1'}, {}):
            result = subprocess.run(['bash', 'scripts/update.sh'], cwd=self.work, env={**self.env, 'CVENGINE_HOST_MEM_MB': '4608', **extra},
                                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        # a pipe nobody writes to (a terminal that never answers) must not matter either
        proc = subprocess.Popen(['bash', 'scripts/update.sh'], cwd=self.work, env={**self.env, 'CVENGINE_HOST_MEM_MB': '4608'},
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out = proc.stdout.read()
        proc.wait(timeout=45)
        self.assertEqual(proc.returncode, 0, out)

    def test_it_is_idempotent_with_an_answer_and_without(self):
        self.set_externals(2)
        self.update(4608)
        first = self.env_text()
        self.update(4608)
        self.assertEqual(self.env_text(), first)
        self.update(4608, '--sentinels', 'external')
        second = self.env_text()
        self.update(4608, '--sentinels', 'external')
        self.assertEqual(self.env_text(), second)


@unittest.skipUnless(SCRIPT.is_file() and shutil.which('git') and shutil.which('flock'), 'needs git and flock')
class MemoryBudgetTests(FitCase):
    def test_limits_over_90_percent_of_the_host_warn_and_name_the_largest_and_its_setting(self):
        (self.stub / 'limits').write_text(f'c1 {4 * GB} celery\nc2 {GB} web\nc3 {GB} scanner\nc4 {GB // 2} celery-beat\n')
        result = self.update(4608)
        self.assertIn('Memory warning: the containers may use up to 6.5 GB together', result.stdout)
        self.assertIn('more than 90 percent of this host\'s 4.5 GB', result.stdout)
        self.assertIn('The largest is celery at 4 GB; lower it with CELERY_MEM_LIMIT in .env', result.stdout)

    def test_a_scanner_that_is_the_largest_names_its_own_setting(self):
        (self.stub / 'limits').write_text(f'c1 {GB} celery\nc2 {3 * GB} scanner\nc3 {GB} web\n')
        result = self.update(4608, CVENGINE_UPDATE_BACKUPS='0')
        self.assertIn('The largest is scanner at 3 GB; lower it with SCANNER_MEM_LIMIT', result.stdout)

    def test_limits_that_fit_say_so_in_one_line(self):
        (self.stub / 'limits').write_text(f'c1 {GB} celery\nc2 {GB} web\n')
        result = self.update(16384)
        self.assertIn('Memory budget: the container limits add up to 2 GB on a host with 16 GB (under 90 percent).', result.stdout)
        self.assertNotIn('Memory warning', result.stdout)

    def test_the_check_is_after_the_start_and_never_fails_the_update(self):
        (self.stub / 'limits').write_text(f'c1 {64 * GB} celery\n')
        result = self.update(4608)
        self.assertIn('Memory warning', result.stdout)
        self.assertLess(result.stdout.index('Starting the built-in scanner') if 'Starting the built-in scanner' in result.stdout else 0, result.stdout.index('Memory warning'))


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class InAppPathTests(unittest.TestCase):
    """The Update button's path: scripts/update-deploy.sh reads the answer the dialog collected (through the state helper) and applies it with the same function."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / 'scripts').mkdir()
        (self.tmp / 'web').mkdir()
        for name in ('host-fit.sh', 'init-env.sh', 'update-state.py'):
            shutil.copy(SCRIPTS / name, self.tmp / 'scripts' / name)
        (self.tmp / '.env').write_text('DOMAIN_NAME=example.com\nPOSTGRES_PASSWORD=pw\nAUTHORITY_PASSWORD=pw\n')
        subprocess.run(['git', 'init', '-q'], cwd=self.tmp, check=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        (self.stub / 'docker').write_text('#!/bin/sh\ncase "$*" in\n  *"ps -q --status running"*) echo web;;\n  *external_sentinels*) echo "EXTERNAL_SENTINELS_LIVE ${LIVE:-2}";;\nesac\nexit 0\n')
        (self.stub / 'docker').chmod(0o755)
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'CVENGINE_HOST_MEM_MB': '4608'}

    def fit(self, answer=None, live=2):
        if answer:
            (self.tmp / 'web' / '.update-sentinels').write_text(answer + '\n')
        code = ('log() { echo "LOG $*"; }; . scripts/host-fit.sh; '
                'plan=$(python3 scripts/update-state.py sentinels-choice 2>/dev/null) || plan=""; '
                'cvengine_fit_run "$plan" docker compose; echo "SHORT=$cv_fit_short"')
        return subprocess.run(['bash', '-c', code], cwd=self.tmp, env={**self.env, 'LIVE': str(live)}, capture_output=True, text=True)

    def keys(self):
        return dict(line.split('=', 1) for line in (self.tmp / '.env').read_text().splitlines() if '=' in line and not line.startswith('#'))

    def test_the_answer_from_the_dialog_is_applied_and_consumed(self):
        out = self.fit('external')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.keys()['CVENGINE_BUILTIN_SCANNER'], '0')
        self.assertEqual(self.keys()['CVENGINE_SENTINEL_PLAN'], 'external')
        self.assertIn('SHORT=scanners: Sentinels of your own only', out.stdout)
        self.assertFalse((self.tmp / 'web' / '.update-sentinels').exists())

    def test_with_no_answer_the_automatic_default_applies_and_records_the_notice(self):
        out = self.fit(None, live=2)
        self.assertEqual(self.keys()['SCANNER_MEM_LIMIT'], '1g')
        self.assertNotIn('CVENGINE_BUILTIN_SCANNER', self.keys())
        self.assertIn('It was kept', out.stdout)
        self.assertTrue((self.tmp / 'web' / '.update-notice.json').exists())
        self.assertIn('SHORT=the built-in scanner was kept', out.stdout)

    def test_an_answer_clears_an_earlier_notice(self):
        self.fit(None, live=2)
        self.fit('both')
        self.assertFalse((self.tmp / 'web' / '.update-notice.json').exists())

    def test_a_planted_link_is_not_an_answer(self):
        (self.tmp / 'secret').write_text('external\n')
        os.symlink(self.tmp / 'secret', self.tmp / 'web' / '.update-sentinels')
        self.fit(None, live=0)
        self.assertNotIn('CVENGINE_BUILTIN_SCANNER', self.keys())

    def test_the_deploy_script_calls_the_shared_function_before_the_scanner_is_fetched(self):
        text = (SCRIPTS / 'update-deploy.sh').read_text()
        self.assertLess(text.index('build web celery celery-beat'), text.index('cvengine_fit_run "$fit_plan"'))
        self.assertLess(text.index('cvengine_fit_run "$fit_plan"'), text.index('cvengine_scanner_fetch'))
        self.assertLess(text.index('cvengine_scanner_start'), text.index('cvengine_fit_budget'))
        self.assertIn('sentinels-choice', text)
        self.assertIn('cvengine_fit_run', (SCRIPTS / 'update.sh').read_text())
