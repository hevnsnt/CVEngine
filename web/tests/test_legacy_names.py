"""scripts/legacy_names.py: an install made before 1.5.0 keeps working under the new names, and the old names leave only after the update worked.

This module and the script are the only code that spells the old name (tests/test_no_legacy_name.py): they test the move away from it.
"""
import importlib.util
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('legacy_names', ROOT / 'scripts' / 'legacy_names.py')
names = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(names)

SECRET = 'Zq7' + 'x' * 45  # the length of a generated secret


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)

    def run_script(self, action, *argv):
        out = StringIO()
        with redirect_stdout(out):
            code = names.main([action, '--root', str(self.dir), '--', *argv])
        return code, out.getvalue()


class EnvTests(Base):
    def write_env(self, text, name='.env', mode=0o640):
        path = self.dir / name
        path.write_text(text)
        os.chmod(path, mode)
        return path

    def test_each_old_variable_gets_its_new_name_with_the_value_and_no_value_is_printed(self):
        env = self.write_env(f'COMPOSE_PROJECT_NAME=rengine\nPOSTGRES_DB=rengine\nRENGINE_SECRET_KEY={SECRET}\nexport RENGINE_HOME=/srv/x\n# RENGINE_RESULTS=/r\n')
        code, out = self.run_script('migrate')
        self.assertEqual(code, 0)
        text = env.read_text()
        self.assertIn(f'RENGINE_SECRET_KEY={SECRET}\nCVENGINE_SECRET_KEY={SECRET}\n', text)
        self.assertIn('export RENGINE_HOME=/srv/x\nexport CVENGINE_HOME=/srv/x\n', text)
        self.assertIn('COMPOSE_PROJECT_NAME=rengine\nPOSTGRES_DB=rengine\n', text)  # values: the install keeps its project, database and role
        self.assertIn('# RENGINE_RESULTS=/r\n', text)  # a comment is not a setting
        self.assertNotIn(SECRET, out)
        self.assertNotIn('/srv/x', out)
        self.assertIn('CVENGINE_SECRET_KEY', out)
        self.assertEqual(stat.S_IMODE(env.stat().st_mode), 0o640)
        backup = self.dir / '.env.pre-cvengine-rename'
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertNotIn('CVENGINE_HOME', backup.read_text())

    def test_migrate_twice_changes_nothing_the_second_time(self):
        env = self.write_env(f'RENGINE_SECRET_KEY={SECRET}\n')
        self.run_script('migrate')
        first = env.read_text()
        code, out = self.run_script('migrate')
        self.assertEqual((code, out), (0, ''))
        self.assertEqual(env.read_text(), first)

    def test_a_new_name_already_there_yields_to_the_old_value_that_was_in_effect(self):
        env = self.write_env('CVENGINE_HOME=/ignored\nRENGINE_HOME=/in-effect\n')
        self.run_script('migrate')
        lines = env.read_text().splitlines()
        self.assertIn('CVENGINE_HOME=/in-effect', lines)
        self.assertNotIn('CVENGINE_HOME=/ignored', lines)
        self.assertTrue(any(x.startswith('# CVENGINE_HOME=/ignored') for x in lines))
        self.run_script('migrate')
        self.assertEqual(env.read_text().count('CVENGINE_HOME=/in-effect'), 1)

    def test_cleanup_removes_the_old_lines_once_the_new_ones_exist(self):
        env = self.write_env(f'A=1\nRENGINE_SECRET_KEY={SECRET}\nRENGINE_ONLY_OLD=2\n')
        self.run_script('migrate')
        code, out = self.run_script('cleanup')
        self.assertEqual(code, 0)
        self.assertEqual(env.read_text(), f'A=1\nCVENGINE_SECRET_KEY={SECRET}\nCVENGINE_ONLY_OLD=2\n')
        self.assertNotIn(SECRET, out)
        self.assertEqual(self.run_script('cleanup')[1].count('removed'), 0)

    def test_the_env_file_the_layout_names_is_migrated_too(self):
        self.write_env('A=1\n')
        other = self.write_env('RENGINE_HOME=/h\n', name='.env.vps')
        self.run_script('migrate', 'docker', 'compose', '--env-file', '.env.vps', '-p', 'cvengine', '-f', 'docker-compose.yml')
        self.assertIn('CVENGINE_HOME=/h', other.read_text())
        self.assertEqual((self.dir / '.env').read_text(), 'A=1\n')

    def test_an_install_without_old_names_is_left_alone(self):
        env = self.write_env('COMPOSE_PROJECT_NAME=cvengine\nCVENGINE_FIELD_KEY=k\n')
        self.assertEqual(self.run_script('migrate'), (0, ''))
        self.assertEqual(self.run_script('cleanup')[1], '')
        self.assertEqual(env.read_text(), 'COMPOSE_PROJECT_NAME=cvengine\nCVENGINE_FIELD_KEY=k\n')
        self.assertFalse((self.dir / '.env.pre-cvengine-rename').exists())


@unittest.skipUnless(shutil.which('git'), 'git is not installed')
class OverlayTests(Base):
    def test_an_overlay_of_the_install_names_the_new_network_and_files_and_a_tracked_file_is_never_edited(self):
        overlay = textwrap.dedent('''\
            services:
              cloudflared:
                networks: [rengine_network]
              proxy:
                volumes:
                  - ./config/nginx/rengine.conf:/etc/nginx/conf.d/rengine.conf:ro
            networks:
              rengine_network_extra: {}
            ''')
        (self.dir / 'docker-compose.vps.yml').write_text(overlay)
        (self.dir / 'docker-compose.yml').write_text('networks:\n  rengine_network:\n')
        subprocess.run(['git', 'init', '-q', str(self.dir)], check=True)
        subprocess.run(['git', '-C', str(self.dir), 'add', 'docker-compose.yml'], check=True)
        code, out = self.run_script('migrate', 'docker', 'compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.vps.yml')
        self.assertEqual(code, 0)
        text = (self.dir / 'docker-compose.vps.yml').read_text()
        self.assertIn('networks: [cvengine_network]', text)
        self.assertIn('./config/nginx/cvengine.conf:/etc/nginx/conf.d/cvengine.conf:ro', text)
        self.assertIn('rengine_network_extra', text)  # only whole names
        self.assertEqual((self.dir / 'docker-compose.vps.yml.pre-cvengine-rename').read_text(), overlay)
        self.assertEqual((self.dir / 'docker-compose.yml').read_text(), 'networks:\n  rengine_network:\n')
        self.assertEqual(self.run_script('migrate', 'docker', 'compose', '-f', 'docker-compose.vps.yml')[1], '')


class CertificateTests(Base):
    def certs(self):
        folder = self.dir / 'secrets' / 'certs'
        folder.mkdir(parents=True)
        for name in ('rengine.pem', 'rengine_rsa.key', 'rengine_chain.pem'):
            (folder / name).write_text(f'-----{name}-----\n')
            os.chmod(folder / name, 0o600)
        return folder

    def test_the_certificate_files_get_their_new_names_and_lose_the_old_ones_only_at_cleanup(self):
        folder = self.certs()
        self.run_script('migrate')
        for old, new in (('rengine.pem', 'cvengine.pem'), ('rengine_rsa.key', 'cvengine_rsa.key'), ('rengine_chain.pem', 'cvengine_chain.pem')):
            self.assertTrue(os.path.samefile(folder / old, folder / new))  # one file, two names: a rollback still finds the old one
        self.assertEqual(stat.S_IMODE((folder / 'cvengine_rsa.key').stat().st_mode), 0o600)
        self.run_script('cleanup')
        self.assertEqual(sorted(os.listdir(folder)), ['cvengine.pem', 'cvengine_chain.pem', 'cvengine_rsa.key'])
        self.assertEqual((folder / 'cvengine.pem').read_text(), '-----rengine.pem-----\n')

    def test_a_certificate_folder_of_root_is_changed_by_a_throwaway_root_container(self):
        # scripts/update.sh run by a member of the docker group: make certs wrote the folder as root, so the link is made in a container
        from unittest import mock
        self.certs()
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            out = 'cvengine/web:latest\nnginx:alpine@sha256:abc\n' if argv[:2] == ['docker', 'ps'] else ''
            return subprocess.CompletedProcess(argv, 0, out, '')
        with mock.patch.object(names.os, 'link', side_effect=PermissionError(13, 'denied')), mock.patch.object(names, 'run', fake_run):
            code, out = self.run_script('migrate')
        self.assertEqual(code, 0)
        docker_run = [c for c in calls if c[:2] == ['docker', 'run']]
        self.assertEqual(len(docker_run), 1)
        self.assertIn('nginx:alpine@sha256:abc', docker_run[0])
        self.assertIn('--network', docker_run[0])
        self.assertEqual(docker_run[0][-1], 'ln /c/rengine.pem /c/cvengine.pem && ln /c/rengine_rsa.key /c/cvengine_rsa.key && ln /c/rengine_chain.pem /c/cvengine_chain.pem')
        self.assertIn('cvengine.pem, cvengine_rsa.key, cvengine_chain.pem', out)

    def test_without_an_image_to_do_it_as_root_migrate_stops_the_update_before_anything_changes(self):
        from unittest import mock
        self.certs()
        with mock.patch.object(names.os, 'link', side_effect=PermissionError(13, 'denied')), \
                mock.patch.object(names, 'run', lambda argv, **kw: subprocess.CompletedProcess(argv, 0, '', '')):
            code, _ = self.run_script('migrate')
        self.assertEqual(code, 1)

    def test_an_old_name_that_differs_from_the_new_file_is_kept(self):
        folder = self.certs()
        (folder / 'cvengine.pem').write_text('a newer certificate\n')
        self.run_script('migrate')
        self.assertEqual((folder / 'cvengine.pem').read_text(), 'a newer certificate\n')
        code, out = self.run_script('cleanup')
        self.assertTrue((folder / 'rengine.pem').exists())
        self.assertIn('kept rengine.pem', out)


class NetworkAndPackageTests(Base):
    def fake_docker(self, attached):
        state = self.dir / 'calls'
        bin_dir = self.dir / 'bin'
        bin_dir.mkdir()
        (bin_dir / 'docker').write_text(textwrap.dedent(f'''\
            #!/bin/sh
            echo "$*" >> {state}
            case "$*" in
              "network inspect cvengine_rengine_network") [ -e {self.dir}/gone ] && exit 1; exit 0;;
              "network rm cvengine_rengine_network") touch {self.dir}/gone; exit 0;;
              *"config --services"*) printf 'web\\nproxy\\ncloudflared\\n';;
              "ps -a --filter network=cvengine_rengine_network"*) printf '{attached}';;
            esac
            exit 0
            '''))
        os.chmod(bin_dir / 'docker', 0o755)
        path = os.environ['PATH']
        os.environ['PATH'] = f'{bin_dir}:{path}'
        self.addCleanup(os.environ.__setitem__, 'PATH', path)
        return state

    def test_containers_of_the_install_left_on_the_old_network_move_and_the_network_is_removed(self):
        calls = self.fake_docker('cvengine-cloudflared-1\\trunning\\tcvengine\\tcloudflared\\tFalse\\n')
        code, out = self.run_script('cleanup', 'docker', 'compose', '-p', 'cvengine', '-f', 'docker-compose.yml')
        self.assertEqual(code, 0)
        lines = calls.read_text().splitlines()
        self.assertIn('compose -p cvengine -f docker-compose.yml up -d --no-deps cloudflared', lines)
        self.assertEqual(lines[-1], 'network rm cvengine_rengine_network')
        self.assertIn('removed the old network cvengine_rengine_network (moved to the new one first: cloudflared)', out)
        self.assertEqual(self.run_script('cleanup', 'docker', 'compose', '-p', 'cvengine')[1], '')  # gone: nothing more to do

    def test_a_container_of_another_project_keeps_the_old_network(self):
        calls = self.fake_docker('someone-else\\trunning\\tother\\tapp\\tFalse\\n')
        code, out = self.run_script('cleanup', 'docker', 'compose', '-p', 'cvengine')
        self.assertEqual(code, 0)
        self.assertNotIn('network rm cvengine_rengine_network', calls.read_text())
        self.assertIn('is kept: someone-else still use it', out)

    def test_a_leftover_package_folder_with_only_byte_code_is_removed_and_one_with_files_is_kept(self):
        self.fake_docker('')
        cache = self.dir / 'web' / 'reNgine' / '__pycache__'
        cache.mkdir(parents=True)
        (cache / 'settings.cpython-314.pyc').write_bytes(b'\0')
        self.run_script('cleanup', 'docker', 'compose', '-p', 'x')
        self.assertFalse((self.dir / 'web' / 'reNgine').exists())
        cache.mkdir(parents=True)
        (self.dir / 'web' / 'reNgine' / 'local_notes.txt').write_text('mine')
        self.run_script('cleanup', 'docker', 'compose', '-p', 'x')
        self.assertTrue((self.dir / 'web' / 'reNgine' / 'local_notes.txt').exists())


class ProxyConfTests(Base):
    def test_a_copy_of_the_old_proxy_configuration_left_on_the_host_is_kept_under_a_backup_name(self):
        nginx = self.dir / 'config' / 'nginx'
        nginx.mkdir(parents=True)
        (nginx / 'rengine.conf').write_text('map_hash_bucket_size 128;  # added by hand\n')
        code, out = self.run_script('cleanup')
        self.assertEqual(code, 0)
        self.assertFalse((nginx / 'rengine.conf').exists())
        self.assertEqual((nginx / 'rengine.conf.pre-cvengine-rename').read_text(), 'map_hash_bucket_size 128;  # added by hand\n')
        self.assertEqual(self.run_script('cleanup')[1], '')

    def test_the_empty_folder_docker_leaves_at_the_old_mount_path_is_removed(self):
        folder = self.dir / 'config' / 'nginx' / 'rengine.conf'
        folder.mkdir(parents=True)
        self.assertIn('removed the empty folder', self.run_script('cleanup')[1])
        self.assertFalse(folder.exists())


class ScriptsCallItTests(unittest.TestCase):
    """Every path that starts the stack moves the names first, and every update path removes the old ones after it is verified."""

    def test_the_update_paths_and_make_up_run_it(self):
        deploy = (ROOT / 'scripts' / 'update-deploy.sh').read_text()
        self.assertLess(deploy.index('legacy_names.py migrate'), deploy.index('config --services', deploy.index('deploy_steps() {')))
        self.assertLess(deploy.index('verify_serving || return 1'), deploy.index('legacy_names.py cleanup'))
        update = (ROOT / 'scripts' / 'update.sh').read_text()
        self.assertLess(update.index('legacy_names.py migrate'), update.index('\n"${compose[@]}" config --quiet\n'))
        self.assertIn('legacy_names.py cleanup', update)
        self.assertIn('legacy_names.py migrate', (ROOT / 'Makefile').read_text())
        self.assertIn('legacy_names.py migrate', (ROOT / 'scripts' / 'init-env.sh').read_text())


if __name__ == '__main__':
    unittest.main()
