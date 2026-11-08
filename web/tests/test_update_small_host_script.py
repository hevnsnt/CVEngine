"""The disk gate and the build-memory step of the in-app update (scripts/update-disk.sh, scripts/update-deploy.sh), run through the real scripts with fake
`docker`, `df` and a fake host size (CVENGINE_HOST_MEM_MB). Nothing here touches Docker or the disk of the machine it runs on."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'

SENTENCE_9 = 'This update needs about 14 GB of free disk; this server has 9 GB free. Free some space or add disk, then try again.'

DOCKER = r'''#!/usr/bin/env bash
echo "docker $*" >> "$STUB/calls"
case " $* " in
  *" info "*) echo "$STUB/dockerroot"; exit 0;;
  *" image inspect "*) [ -e "$STUB/has_image" ] && exit 0; exit 1;;
  *" image prune "*) [ -e "$STUB/prune_frees" ] && cat "$STUB/prune_frees" > "$STUB/free"; exit 0;;
  *" builder prune "*) [ -e "$STUB/builder_frees" ] && cat "$STUB/builder_frees" > "$STUB/free"; exit 0;;
  *" ps --status running --services "*) cat "$STUB/running" 2>/dev/null; exit 0;;
  *" config --services "*) printf 'web\ncelery\ncelery-beat\ndb\nredis\nproxy\nreviewer\nscanner\n'; exit 0;;
  *" build web celery celery-beat "*) [ -e "$STUB/build_fails" ] && exit 1; exit 0;;
  *" showmigrations "*) echo "[X]  app.0001_initial"; exit 0;;
esac
exit 0
'''
DF = r'''#!/usr/bin/env bash
echo "df $*" >> "$STUB/calls"
[ -e "$STUB/df_denied_for" ] && [ "${@: -1}" = "$(cat "$STUB/df_denied_for")" ] && { echo "df: permission denied" >&2; exit 1; }
printf 'Filesystem 1M-blocks Used Available Capacity Mounted on\n/dev/x 100000 1 %s 1%% /\n' "$(cat "$STUB/free")"
'''
HELPER = '#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n'


class SmallHostCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        (self.stub / 'dockerroot').mkdir()
        for name, body in (('docker', DOCKER), ('df', DF)):
            (self.stub / name).write_text(body)
            (self.stub / name).chmod(0o755)
        (self.stub / 'helper.py').write_text(HELPER)
        self.work = self.tmp / 'work'
        (self.work / 'scripts').mkdir(parents=True)
        (self.work / 'web').mkdir()
        for name in ('update-disk.sh', 'update-deploy.sh', 'host-fit.sh', 'update-state.py'):
            shutil.copy(SCRIPTS / name, self.work / 'scripts' / name)
        (self.work / 'scripts' / 'db-backup.sh').write_text('#!/usr/bin/env bash\nexit 0\n')
        (self.work / 'scripts' / 'db-backup.sh').chmod(0o755)
        env = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t', 'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@t',
               'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull, 'PATH': os.environ['PATH']}
        subprocess.run('git init -q . && git add -A && git commit -q -m x', shell=True, cwd=self.work, env=env, check=True)
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB': str(self.stub), 'GIT_CONFIG_GLOBAL': os.devnull,
                    'GIT_CONFIG_SYSTEM': os.devnull, 'TMPDIR': str(self.tmp)}
        for key in ('CVENGINE_UPDATE_MIN_FREE_MB', 'CVENGINE_FAKE_DISK_FREE_MB', 'CVENGINE_HOST_MEM_MB', 'CVENGINE_BUILTIN_SCANNER',
                    'CVENGINE_UPDATE_STOP_CELERY', 'CVENGINE_SCANNER_IMAGE'):
            self.env.pop(key, None)
        self.set_free(20000)

    def set_free(self, mb):
        (self.stub / 'free').write_text(f'{mb}\n')

    def calls(self):
        return (self.stub / 'calls').read_text().splitlines() if (self.stub / 'calls').exists() else []

    def bash(self, script, **env):
        return subprocess.run(['bash', '-c', script], cwd=self.work, env={**self.env, **env}, capture_output=True, text=True, timeout=120)


class DiskGateTests(SmallHostCase):
    def check(self, plan='', **env):
        out = self.bash(f'. scripts/update-disk.sh; cvengine_disk_check "{plan}"; echo "rc=$?"; echo "SENTENCE=$cv_disk_sentence"; echo "NEED=$(cvengine_disk_need_mb "{plan}")"', **env)
        self.assertEqual(out.returncode, 0, out.stderr)
        rc = int([line for line in out.stdout.splitlines() if line.startswith('rc=')][0][3:])
        sentence = [line for line in out.stdout.splitlines() if line.startswith('SENTENCE=')][0][9:]
        need = int([line for line in out.stdout.splitlines() if line.startswith('NEED=')][0][5:])
        return rc, sentence, need, out.stdout

    def test_room_enough_touches_nothing(self):
        self.set_free(14500)
        rc, sentence, need, _ = self.check()
        self.assertEqual((rc, sentence, need), (0, '', 14000))
        self.assertFalse([c for c in self.calls() if 'prune' in c])

    def test_the_first_14_update_needs_14_gb_a_host_with_the_scanner_image_needs_less(self):
        self.assertEqual(self.check()[2], 14000)  # scanner image not on this host
        (self.stub / 'has_image').touch()
        shutil.copy(SCRIPTS.parent / 'scanner.lock.json', self.work / 'scanner.lock.json')
        shutil.copy(SCRIPTS / 'scanner_lock.py', self.work / 'scripts' / 'scanner_lock.py')
        self.assertEqual(self.check()[2], 8900)  # already there
        (self.stub / 'has_image').unlink()
        self.assertEqual(self.check(CVENGINE_BUILTIN_SCANNER='0')[2], 8900)  # the scanner is off: nothing to pull
        self.assertEqual(self.check(plan='external')[2], 8900)  # the answer is Sentinels only
        self.assertEqual(self.check(CVENGINE_UPDATE_MIN_FREE_MB='6144')[2], 6144)  # an administrator's own figure replaces it
        self.assertEqual(self.check(CVENGINE_UPDATE_MIN_FREE_MB='0')[0], 0)  # the way back needs no new space

    def test_short_says_the_sentence_and_clears_only_what_is_safe(self):
        self.set_free(9500)
        rc, sentence, _, _ = self.check()
        self.assertEqual((rc, sentence), (1, SENTENCE_9))
        calls = self.calls()
        self.assertIn('docker image prune -f', calls)
        self.assertIn('docker builder prune -f', calls)
        # never a tagged image (no -a, no rmi) and never a volume
        for call in calls:
            self.assertNotRegex(call, r'prune .*(-a|--all)\b|rmi|volume|system prune|compose down')

    def test_below_the_floor_it_cleans_first_and_goes_on_when_that_is_enough(self):
        self.set_free(9500)
        (self.stub / 'prune_frees').write_text('3000\n')  # dangling images were few
        (self.stub / 'builder_frees').write_text('15200\n')  # the build cache was big
        rc, sentence, _, out = self.check()
        self.assertEqual((rc, sentence), (0, ''))
        self.assertIn('freed enough space', out)

    def test_the_gb_figures_round_the_honest_way(self):
        self.set_free(9999)
        self.assertIn('this server has 9 GB free', self.check()[1])  # 9.999 GB is said as 9, never as 10
        self.set_free(0)
        self.assertIn('this server has 0 GB free', self.check()[1])

    def test_an_unreadable_docker_directory_is_measured_through_its_parent(self):
        self.set_free(5000)
        (self.stub / 'df_denied_for').write_text(f'{self.stub}/dockerroot')
        rc, sentence, _, _ = self.check()
        self.assertEqual(rc, 1)
        self.assertIn('this server has 5 GB free', sentence)

    def test_a_disk_that_cannot_be_measured_says_nothing(self):
        (self.stub / 'df').write_text('#!/usr/bin/env bash\nexit 1\n')
        self.assertEqual(self.check()[0], 0)

    def test_the_fake_for_rehearsals(self):
        self.set_free(100000)
        rc, sentence, _, _ = self.check(CVENGINE_FAKE_DISK_FREE_MB='9500')
        self.assertEqual((rc, sentence), (1, SENTENCE_9))

    def test_the_report_the_update_screen_reads(self):
        self.set_free(9500)
        out = self.bash('. scripts/update-disk.sh; cvengine_disk_report; cat web/.update-disk.json')
        self.assertEqual(out.returncode, 0, out.stderr)
        import json
        data = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual((data['free_mb'], data['need_mb']), (9500, 14000))
        self.assertIn('at', data)


class BuildMemoryTests(SmallHostCase):
    def deploy(self, mem_mb, running='web\ncelery\ncelery-beat\ndb\nredis\nproxy\nscanner\n', **env):
        (self.stub / 'running').write_text(running)
        script = ('COMPOSE=(docker compose); log() { echo "LOG $*" >> "$STUB/log"; }; phase() { echo "PHASE $*" >> "$STUB/log"; }; '
                  'STATE_HELPER="$STUB/helper.py"; . scripts/update-deploy.sh; deploy_steps; echo "rc=$?"; echo "STAGE=$DEPLOY_STAGE"; echo "WHY=$DEPLOY_WHY"')
        out = self.bash(script, CVENGINE_HOST_MEM_MB=str(mem_mb), **env)
        rc = int([line for line in out.stdout.splitlines() if line.startswith('rc=')][0][3:])
        why = [line for line in out.stdout.splitlines() if line.startswith('WHY=')][0][4:]
        return rc, why

    def index(self, fragment, calls):
        return next(i for i, c in enumerate(calls) if fragment in c)

    def test_a_small_host_stops_celery_and_the_scanner_for_the_build_and_brings_them_back(self):
        rc, _ = self.deploy(4608)
        calls = self.calls()
        self.assertEqual(rc, 0, calls)
        stop = self.index('compose stop -t 30 scanner celery', calls)
        build = self.index('compose build web celery celery-beat', calls)
        start_celery = self.index('compose start celery', calls)
        start_scanner = self.index('compose start scanner', calls)
        self.assertLess(stop, build)
        self.assertLess(build, start_celery)
        self.assertLess(start_celery, start_scanner)  # the scanner joins celery's network: celery first
        self.assertLess(start_scanner, self.index('--force-recreate', calls))  # back before the migration and the recreate
        for forbidden in ('stop -t 30 web', ' stop web', ' stop db', ' stop redis', ' stop proxy', 'rm -sf'):
            self.assertFalse([c for c in calls if forbidden in c and 'celery' not in c.split(forbidden)[0]], forbidden)
        stopped = [c for c in calls if ' stop ' in c]
        self.assertEqual(len(stopped), 1)
        for never in ('web', 'db', 'redis', 'proxy', 'beat'):
            self.assertNotIn(f' {never}', stopped[0])

    def test_a_big_host_stops_nothing(self):
        rc, _ = self.deploy(16384)
        self.assertEqual(rc, 0)
        self.assertFalse([c for c in self.calls() if ' stop ' in c or ' start ' in c])

    def test_a_host_of_exactly_7_gb_is_not_small(self):
        self.deploy(7000000 // 1024 + 1)
        self.assertFalse([c for c in self.calls() if ' stop ' in c])

    def test_it_can_be_turned_off(self):
        self.deploy(4608, CVENGINE_UPDATE_STOP_CELERY='0')
        self.assertFalse([c for c in self.calls() if ' stop ' in c])

    def test_only_what_is_running_is_stopped_and_started(self):
        self.deploy(4608, running='web\ncelery\ncelery-beat\ndb\nredis\nproxy\n')  # no built-in scanner here
        calls = self.calls()
        self.assertIn('docker compose stop -t 30 celery', calls)
        self.assertFalse([c for c in calls if 'compose start scanner' in c])

    def test_a_failed_build_brings_celery_and_the_scanner_back_and_says_so(self):
        (self.stub / 'build_fails').touch()
        rc, why = self.deploy(4608)
        calls = self.calls()
        self.assertEqual(rc, 1)
        self.assertIn('Nothing was changed', why)
        self.assertLess(self.index('compose build web celery celery-beat', calls), self.index('compose start celery', calls))
        self.assertIn('docker compose start scanner', calls)
        # no half-state: nothing after the build ran (no database backup, migration, recreate), nothing is left stopped
        for later in ('migrate --noinput', '--force-recreate', 'collectstatic'):
            self.assertFalse([c for c in calls if later in c], later)
        self.assertTrue((self.work / 'config' / 'nginx' / 'state' / 'maintenance').exists() is False)
        log = (self.stub / 'log').read_text()
        self.assertIn('could not be built', log)

    def test_the_disk_gate_stops_the_deploy_before_anything_is_stopped(self):
        self.set_free(9500)
        rc, why = self.deploy(4608)
        calls = self.calls()
        self.assertEqual(rc, 1)
        self.assertEqual(why, SENTENCE_9)
        self.assertFalse([c for c in calls if ' stop ' in c or ' build ' in c or ' up ' in c or 'pull' in c], calls)
        self.assertIn('(nothing was stopped or changed)', (self.stub / 'log').read_text())


if __name__ == '__main__':
    unittest.main()
