"""scripts/openvas-disk-check.sh: the OpenVAS add-on is not started on a Docker disk that cannot hold it (issue #394: about 59 GB on a first start,
and the first feed load filled a Docker Desktop disk to 98 % with no warning). docker and df are stubs; the script itself runs unmodified."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GB = 1024 * 1024  # df -Pk counts 1 KiB blocks
DOCKER = '''#!/usr/bin/env bash
echo "docker $*" >> "$STUB_DIR/calls"
case "$1" in
  info) cat "$STUB_DIR/root" 2>/dev/null; exit 0;;
  volume) cat "$STUB_DIR/volumes" 2>/dev/null; exit 0;;
  ps) cat "$STUB_DIR/celery_id" 2>/dev/null; exit 0;;
  exec) [ -f "$STUB_DIR/vm_free_kb" ] || exit 1; printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\noverlay 1 1 %s 1%% /\\n' "$(cat "$STUB_DIR/vm_free_kb")"; exit 0;;
esac
exit 0
'''
DF = '''#!/usr/bin/env bash
[ -f "$STUB_DIR/host_free_kb" ] || exit 1
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 1 1 %s 1%% /\\n' "$(cat "$STUB_DIR/host_free_kb")"
'''


@unittest.skipUnless((ROOT / 'scripts' / 'openvas-disk-check.sh').is_file() and shutil.which('bash'), 'needs the repository scripts directory')
class OpenvasDiskCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        self.stub.mkdir()
        for name, body in (('docker', DOCKER), ('df', DF)):
            (self.stub / name).write_text(body)
            (self.stub / name).chmod(0o755)
        self.work = self.tmp / 'my install'
        (self.work / 'scripts').mkdir(parents=True)
        shutil.copy(ROOT / 'scripts' / 'openvas-disk-check.sh', self.work / 'scripts' / 'openvas-disk-check.sh')
        self.data_root = self.tmp / 'docker-data'
        self.data_root.mkdir()
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub)}
        self.env.pop('CVENGINE_OPENVAS_MIN_FREE_GB', None)

    def put(self, name, value):
        (self.stub / name).write_text(f'{value}\n')

    def run_check(self, **env):
        return subprocess.run(['bash', 'scripts/openvas-disk-check.sh'], cwd=self.work, env={**self.env, **env}, capture_output=True, text=True, timeout=60)

    def test_a_linux_host_with_too_little_room_is_refused_with_the_reason_and_the_override(self):
        self.put('root', self.data_root)
        self.put('host_free_kb', 40 * GB)
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('has 40 GB free; OpenVAS needs about 60 GB', result.stdout)
        self.assertIn('CVENGINE_OPENVAS_MIN_FREE_GB', result.stdout)

    def test_enough_room_passes(self):
        self.put('root', self.data_root)
        self.put('host_free_kb', 75 * GB)
        self.assertEqual(self.run_check().returncode, 0)

    def test_once_the_database_volume_exists_less_is_needed(self):
        self.put('root', self.data_root)
        self.put('host_free_kb', 20 * GB)
        self.put('volumes', 'cvengine_openvas_psql_data_vol')
        self.assertEqual(self.run_check().returncode, 0)
        self.put('host_free_kb', 10 * GB)
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn('needs about 15 GB', result.stdout)

    def test_docker_desktop_is_measured_inside_its_vm(self):
        self.put('root', '/var/lib/docker-is-inside-the-vm')  # not a directory on this machine
        self.put('celery_id', 'abc123')
        self.put('vm_free_kb', 30 * GB)
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('has 30 GB free', result.stdout)
        calls = (self.stub / 'calls').read_text()
        self.assertIn(f'label=com.docker.compose.project.working_dir={self.work}', calls)  # a path with a space is passed whole
        self.assertIn('docker exec abc123 df -Pk /', calls)

    def test_the_floor_can_be_set_or_the_check_skipped(self):
        self.put('root', self.data_root)
        self.put('host_free_kb', 40 * GB)
        self.assertEqual(self.run_check(CVENGINE_OPENVAS_MIN_FREE_GB='30').returncode, 0)
        self.assertEqual(self.run_check(CVENGINE_OPENVAS_MIN_FREE_GB='0').returncode, 0)
        (self.work / '.env').write_text('CVENGINE_OPENVAS_MIN_FREE_GB="35"\n')
        self.assertEqual(self.run_check().returncode, 0)
        bad = self.run_check(CVENGINE_OPENVAS_MIN_FREE_GB='lots')
        self.assertEqual(bad.returncode, 1)
        self.assertIn('whole number', bad.stdout)

    def test_a_disk_it_cannot_measure_does_not_block_but_says_so(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0)
        self.assertIn('Could not read the free space', result.stdout)

    def test_make_and_the_switch_check_before_anything_starts(self):
        makefile = (ROOT / 'Makefile').read_text()
        target = re.search(r'^openvas-up:.*?\n((?:\t.*\n)+)', makefile, re.M).group(1)
        self.assertLess(target.index('openvas-disk-check.sh'), target.index('up -d'))
        sync = (ROOT / 'scripts' / 'openvas-sync.sh').read_text()
        self.assertLess(sync.index('scripts/openvas-disk-check.sh'), sync.index('--profile openvas up -d'))
