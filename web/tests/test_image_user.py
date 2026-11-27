"""The server image runs as an unprivileged account, from its own copy of the source (security review S4).

web, celery, celery-beat and the one-off migrate service run as uid 10002 with every capability dropped and no-new-privileges; ./web is not mounted
over the source; the static volume is written by celery alone; the one-off ownership service hands the paths the application writes to that account
before anything of a new image runs, in every update path and in `make up`. These checks read the files (the CI tests run outside the image); the
image itself was built and run as the account when this was written (see the pull request)."""
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from django.test import SimpleTestCase, override_settings

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / 'web'
APP = ('web', 'celery', 'celery-beat', 'migrate')
HOST = '/var/lib/cvengine/web'


def compose(name='docker-compose.yml'):
    return yaml.safe_load((ROOT / name).read_text())['services']


def volumes(service):
    """``{target: (source, read_only)}`` of a service's short-syntax volumes."""
    out = {}
    for entry in service.get('volumes', []):
        parts = entry.split(':')
        out[parts[1].rstrip('/')] = (parts[0], len(parts) > 2 and 'ro' in parts[2].split(','))
    return out


def env(service):
    return dict(item.split('=', 1) for item in service.get('environment', []) if '=' in item)


class DockerfileUserTests(SimpleTestCase):
    def setUp(self):
        self.text = (WEB / 'Dockerfile').read_text()

    def test_the_image_ends_as_the_fixed_unprivileged_account(self):
        users = re.findall(r'(?m)^USER\s+(\S+)$', self.text)
        self.assertEqual(users[-1], '10002:10002')
        self.assertGreater(self.text.index('USER 10002:10002'), self.text.index('COPY . /usr/src/app/'))
        self.assertIn('useradd --uid 10002 --gid 10002 --groups cvengine-proxy', self.text)
        self.assertIn('groupadd --gid 101 cvengine-proxy', self.text)  # the proxy's nginx group: the scan results folder is 0750 for the two of them
        self.assertIn('ENV HOME=/home/cvengine', self.text)

    def test_only_the_writable_paths_are_the_accounts(self):
        line = next(l for l in self.text.splitlines() if 'chown cvengine:cvengine ' in l)
        self.assertEqual(set(line.split('chown cvengine:cvengine ')[1].split('\\')[0].split()),
                         {'/home/cvengine/.config', '/home/cvengine/logs', '/root/cvengine-generated-templates', '/usr/src/app/staticfiles'})
        self.assertIn('CVENGINE_LOG_DIR=/home/cvengine/logs', self.text)  # the log files are not written beside the source any more
        self.assertIn('chown cvengine:cvengine-proxy /usr/src/scan_results && chmod 0750 /usr/src/scan_results', self.text)
        self.assertNotRegex(self.text, r'chown\s+(-R\s+)?cvengine\S*\s+/usr/src/app(\s|/?$)')  # the source stays root's
        self.assertNotRegex(self.text, r'chown\s+(-R\s+)?cvengine\S*\s+/opt/')  # and the interpreter and packages

    def test_nothing_is_patched_at_run_time_in_the_installed_packages(self):
        self.assertIn("sed -i 's/purge()/truncate()/g'", self.text)  # whatportis, at build time
        self.assertNotIn('sed -i', (WEB / 'celery-entrypoint.sh').read_text())

    def test_the_build_context_is_an_allow_list_of_the_tracked_entries(self):
        lines = [l.strip() for l in (WEB / '.dockerignore').read_text().splitlines() if l.strip() and not l.startswith('#')]
        self.assertEqual(lines[0], '*', 'everything is left out unless listed')
        allowed = {l[1:] for l in lines if l.startswith('!')}
        out = subprocess.run(['git', 'ls-files', 'web'], cwd=ROOT, capture_output=True, text=True)
        if out.returncode != 0 or not out.stdout.strip():
            self.skipTest('not a git checkout')
        tracked = {path.split('/')[1] for path in out.stdout.split()} - {'.dockerignore', '.gitignore'}
        self.assertEqual(tracked - allowed, set(), 'a tracked top-level entry of web/ is missing from web/.dockerignore')
        for never in ('secret', '.commit', '.update-approved', 'staticfiles', 'cve-seed.jsonl.gz'):
            self.assertNotIn(never, allowed)


class ComposeLayoutTests(SimpleTestCase):
    def setUp(self):
        self.services = compose()

    def test_the_application_services_are_unprivileged(self):
        for name in APP:
            with self.subTest(name=name):
                service = self.services[name]
                self.assertEqual(service.get('user'), '10002:10002')
                self.assertEqual(service.get('cap_drop'), ['ALL'])
                self.assertNotIn('cap_add', service, 'the server needs no capability: port 8000, no scan tool')
                self.assertEqual(service.get('security_opt'), ['no-new-privileges:true'])
                self.assertNotIn('privileged', service)

    def test_no_application_service_mounts_the_source_and_web_is_read_only_where_nothing_is_written(self):
        for name in APP:
            with self.subTest(name=name):
                mounts = volumes(self.services[name])
                self.assertNotIn('/usr/src/app', mounts, 'the image runs its own copy of the source')
                self.assertFalse([t for t, (s, _) in mounts.items() if s == './web' and t != HOST], 'web/ is mounted at one path only')
                self.assertEqual(env(self.services[name]).get('CVENGINE_HOST_DIR'), HOST)
                self.assertEqual(env(self.services[name]).get('CVENGINE_HOME'), HOST)
        self.assertEqual(volumes(self.services['migrate'])[HOST], ('./web', True))
        self.assertEqual(volumes(self.services['celery-beat'])[HOST], ('./web', True))
        # web and celery write their update requests there (Settings > Updates, the watchdog, the scanner plan); the folder's sticky bit keeps
        # every file they do not own out of reach (web/ownership.sh)
        self.assertEqual(volumes(self.services['web'])[HOST], ('./web', False))
        self.assertEqual(volumes(self.services['celery'])[HOST], ('./web', False))

    def test_only_celery_writes_the_static_files(self):
        writers = [name for name, service in self.services.items()
                   if volumes(service).get('/usr/src/app/staticfiles', (None, True)) == ('static_volume', False)]
        self.assertEqual(sorted(writers), ['celery', 'ownership'])
        for name in ('web', 'proxy'):
            self.assertEqual(volumes(self.services[name])['/usr/src/app/staticfiles'], ('static_volume', True), name)

    def test_beat_writes_no_volume(self):
        self.assertTrue(all(ro for _, ro in volumes(self.services['celery-beat']).values()), volumes(self.services['celery-beat']))

    def test_home_is_the_accounts_and_the_generated_templates_keep_their_recorded_path(self):
        for name in ('web', 'celery', 'celery-beat'):
            mounts = volumes(self.services[name])
            self.assertEqual(mounts['/home/cvengine/.config'][0], 'tool_config', name)
            self.assertEqual(mounts['/root/cvengine-generated-templates'][0], 'generated_templates', name)

    def test_the_ownership_service_is_root_with_three_capabilities_and_nothing_else(self):
        service = self.services['ownership']
        self.assertEqual(service['user'], '0:0')
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertEqual(sorted(service['cap_add']), ['CHOWN', 'DAC_OVERRIDE', 'FOWNER'])
        self.assertEqual(service['security_opt'], ['no-new-privileges:true'])
        self.assertEqual(service['network_mode'], 'none')
        self.assertEqual(service['restart'], 'no')
        self.assertNotIn('env_file', service)
        self.assertNotIn('POSTGRES_PASSWORD', json.dumps(service))
        self.assertEqual(service['entrypoint'], '/usr/src/app/ownership.sh')
        handed = {target for target, _ in volumes(service).items()}
        for name in APP:
            for target, (source, read_only) in volumes(self.services[name]).items():
                if not read_only and source not in ('./web',) and target != '/var/run/tailscale-status':
                    self.assertIn(target, handed, f'{name} writes {target}, which the ownership service does not hand over')
        self.assertEqual(self.services['migrate']['depends_on']['ownership'], {'condition': 'service_completed_successfully'})

    def test_the_development_file_keeps_the_writable_source_mount(self):
        dev = compose('docker-compose.dev.yml')
        for name in APP:
            with self.subTest(name=name):
                self.assertEqual(volumes(dev[name])['/usr/src/app'], ('./web', False))
                self.assertEqual(dev[name]['user'], '0:0', 'the bind-mounted files are the developer\'s, not uid 10002\'s')


class _ComposeLoader(yaml.SafeLoader):
    """Reads Compose's own tags (``!reset``, ``!override``) as their plain value."""


_ComposeLoader.add_multi_constructor('!', lambda loader, suffix, node: loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode)
                                     else loader.construct_mapping(node) if isinstance(node, yaml.MappingNode) else loader.construct_scalar(node))


class ScannerGroupTests(SimpleTestCase):
    """The built-in scanner keeps its image's own user and is given group 10002, the server's, to read the 0640 enrollment blob."""

    OVERLAYS = ('docker-compose.hostnet.yml', 'docker-compose.macvlan.yml', 'docker-compose.apparmor.yml')

    def overlay(self, name):
        return yaml.load((ROOT / name).read_text(), Loader=_ComposeLoader)['services'].get('scanner', {})

    def test_the_default_compose_gives_the_scanner_group_10002_and_keeps_its_own_user(self):
        scanner = compose()['scanner']
        self.assertEqual([str(g) for g in scanner.get('group_add', [])], ['10002'])
        self.assertNotIn('user', scanner, "the Sentinel image's own user (uid 10001) runs it")
        self.assertEqual(volumes(scanner)['/bootstrap'], ('scanner_bootstrap', True))

    def test_every_scanner_overlay_keeps_the_group(self):
        # Compose merges an overlay's group_add into the base list, and none of them sets a user or replaces the list
        for name in self.OVERLAYS:
            with self.subTest(overlay=name):
                scanner = self.overlay(name)
                self.assertNotIn('user', scanner)
                self.assertNotIn('group_add', scanner)

    def test_docker_compose_config_has_the_group_in_the_default_stack_and_with_the_hostnet_overlay(self):
        if shutil.which('docker') is None:
            self.skipTest('docker is not installed here; the file checks above still run')
        for files in (['docker-compose.yml'], ['docker-compose.yml', 'docker-compose.hostnet.yml']):
            with self.subTest(files=files):
                args = ['docker', 'compose', '--project-directory', str(ROOT)]
                for name in files:
                    args += ['-f', str(ROOT / name)]
                out = subprocess.run(args + ['config', '--format', 'json', 'scanner'], capture_output=True, text=True, timeout=120,
                                     env={**os.environ, 'COMPOSE_PROFILES': ''})
                if out.returncode != 0 and 'unknown flag' in out.stderr:
                    self.skipTest(f'this docker compose cannot print one service as JSON: {out.stderr.strip()}')
                self.assertEqual(out.returncode, 0, out.stderr)
                scanner = json.loads(out.stdout)['services']['scanner']
                self.assertEqual([str(g) for g in scanner.get('group_add', [])], ['10002'])
                self.assertNotIn('user', scanner)
                if 'docker-compose.hostnet.yml' in files:
                    self.assertEqual(scanner.get('network_mode'), 'host')


class UpdateOrderTests(SimpleTestCase):
    """The ownership service runs after the image is built and before anything of the new image runs, on every path; collectstatic runs in celery."""

    def text(self, name):
        return (ROOT / name).read_text()

    def test_the_web_updater(self):
        text = self.text('scripts/update-deploy.sh')
        body = text[text.index('deploy_steps() {'):text.index('\n}\n', text.index('deploy_steps() {'))]
        first = body.index('  app_ownership || return 1\n')
        self.assertLess(body.index('build web celery celery-beat'), first)
        self.assertLess(first, body.index('cvengine_fit_run'))  # the host-fit count runs the new image
        self.assertLess(first, body.index('check_db_roles'))
        self.assertLess(first, body.index('run_migrations'))
        second = body.index('  app_ownership || return 1\n', first + 1)
        self.assertLess(body.index('run_migrations'), second)
        self.assertLess(second, body.index('up -d --no-deps --force-recreate "${services[@]}"'))
        self.assertIn('run --rm --no-deps --entrypoint python3 celery manage.py collectstatic', body)
        self.assertIn('DEPLOY_WHY=', text[text.index('app_ownership() {'):])

    def test_the_command_line_update(self):
        text = self.text('scripts/update.sh')
        first = text.index('cvengine_app_ownership "${compose[@]}"')
        self.assertLess(text.index('"${compose[@]}" build web celery celery-beat'), first)
        self.assertLess(first, text.index('owner_run manage.py migrate --noinput'))
        second = text.index('cvengine_app_ownership "${compose[@]}"', first + 1)
        self.assertLess(second, text.index('"${compose[@]}" up -d --no-deps --force-recreate "${services[@]}"'))

    def test_the_fallback_deploy_of_the_host_script(self):
        text = self.text('scripts/apply-update.sh')
        body = text[text.index('deploy_builtin() {'):]
        self.assertLess(body.index('build web celery celery-beat'), body.index('cvengine_app_ownership'))
        self.assertLess(body.index('cvengine_app_ownership'), body.index('manage.py migrate --noinput'))

    def test_make_up(self):
        text = self.text('Makefile')
        up = text[text.index('\nup: '):text.index('\nbuild: ')]
        first = up.index('cvengine_app_ownership')
        self.assertLess(up.index('build web\n'), first)
        self.assertLess(first, up.index('run --rm -e CVENGINE_DB_ALLOW_OWNER_FALLBACK'))
        self.assertLess(up.index('cvengine_app_ownership', first + 1), up.index('up -d --build --no-deps ${SERVICES}'))

    def test_no_script_writes_the_static_volume_through_web(self):
        for name in ('scripts/update.sh', 'scripts/update-deploy.sh', 'scripts/apply-update.sh', 'Makefile'):
            self.assertNotRegex(self.text(name), r'--entrypoint python3 web manage\.py collectstatic', name)

    def test_the_scripts_parse(self):
        for name in ('scripts/app-ownership.sh', 'scripts/update-deploy.sh', 'scripts/apply-update.sh', 'scripts/update.sh'):
            subprocess.run(['bash', '-n', str(ROOT / name)], check=True)
        subprocess.run(['sh', '-n', str(WEB / 'ownership.sh')], check=True)


FAKE = '''#!/usr/bin/env bash
echo "docker $*" >> "$STUB_DIR/calls"
case " $* " in
  *" config --services "*) cat "$STUB_DIR/services"; exit 0;;
  *" run --rm --no-deps -T ownership "*) cat "$STUB_DIR/out" 2>/dev/null; exit "$(cat "$STUB_DIR/status" 2>/dev/null || echo 0)";;
esac
exit 0
'''


class AppOwnershipScriptTests(unittest.TestCase):
    """scripts/app-ownership.sh: one line, the failure is a failure, a layout without the service is left alone."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / 'docker').write_text(FAKE)
        (self.tmp / 'docker').chmod(0o755)
        (self.tmp / 'services').write_text('db\nredis\nownership\nmigrate\nweb\n')

    def run_it(self):
        env = {**os.environ, 'PATH': f'{self.tmp}:{os.environ["PATH"]}', 'STUB_DIR': str(self.tmp)}
        return subprocess.run(['bash', '-c', f'. {ROOT}/scripts/app-ownership.sh && cvengine_app_ownership docker compose -f x.yml'],
                              env=env, capture_output=True, text=True, timeout=30)

    def test_the_services_last_line_is_said(self):
        (self.tmp / 'out').write_text('ownership: created the Django secret (web/secret)\nownership: handed 3 path(s) to the application account (uid 10002): web/secret\n')
        out = self.run_it()
        self.assertEqual(out.returncode, 0)
        self.assertEqual(out.stdout.strip(), 'ownership: handed 3 path(s) to the application account (uid 10002): web/secret')
        self.assertIn('docker compose -f x.yml run --rm --no-deps -T ownership', (self.tmp / 'calls').read_text())

    def test_a_failure_fails(self):
        (self.tmp / 'out').write_text('chown: changing ownership: Operation not permitted\n')
        (self.tmp / 'status').write_text('3')
        out = self.run_it()
        self.assertEqual(out.returncode, 1)
        self.assertIn('failed (status 3)', out.stdout)
        self.assertIn('Operation not permitted', out.stdout)

    def test_a_layout_without_the_service_is_left_alone(self):
        (self.tmp / 'services').write_text('db\nweb\n')
        out = self.run_it()
        self.assertEqual(out.returncode, 0)
        self.assertNotIn(' run ', (self.tmp / 'calls').read_text())


@unittest.skipUnless(shutil.which('sh') and shutil.which('find') and shutil.which('stat'), 'needs a POSIX shell')
class OwnershipScriptTests(unittest.TestCase):
    """web/ownership.sh on a scratch tree, as this account (it can only give files to itself here, which is enough to see what it changes)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        for path in ('usr/src/scan_results/scan1', 'usr/src/app/staticfiles', 'root/cvengine-generated-templates', 'home/cvengine/.config/cvengine/seed',
                     'var/lib/cvengine-db-owner', 'var/lib/cvengine-reviewer', 'var/lib/cvengine-scanner', 'var/lib/cvengine/web'):
            (self.root / path).mkdir(parents=True)
        self.web = self.root / 'var/lib/cvengine/web'
        (self.web / '.update-mode').write_text('manual\n')
        (self.web / 'outside').write_text('x')
        os.symlink('/etc/passwd', self.web / '.update-approved')  # a link a container planted is never followed
        self.uid, self.gid = os.getuid(), os.getgid()
        self.env = {**os.environ, 'CVENGINE_OWNERSHIP_ROOT': str(self.root), 'CVENGINE_APP_UID': str(self.uid), 'CVENGINE_APP_GID': str(self.gid),
                    'CVENGINE_PROXY_GID': str(self.gid)}
        self.env.pop('CVENGINE_HOST_DIR', None)

    def run_it(self):
        out = subprocess.run(['sh', str(WEB / 'ownership.sh')], env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def test_a_first_run_creates_the_secret_and_sets_the_folder_modes_and_a_second_changes_nothing(self):
        first = self.run_it()
        self.assertIn('ownership: created the Django secret (web/secret)', first)
        secret = self.web / 'secret'
        self.assertEqual(len(secret.read_text().strip()), 64)
        self.assertEqual(self.mode(secret), 0o600)
        self.assertEqual(self.mode(self.web), 0o1775, 'the sticky bit: the application cannot replace a file it does not own')
        self.assertEqual(self.mode(self.root / 'usr/src/scan_results'), 0o750)
        self.assertEqual(self.mode(self.root / 'var/lib/cvengine-scanner'), 0o2751, 'setgid: the blob takes group 10002, which the scanner is given')
        self.assertTrue((self.web / '.update-approved').is_symlink())
        self.assertEqual(self.run_it().strip(), f'ownership: every application path already belongs to uid {self.uid}; nothing changed')

    def test_the_update_lock_belongs_to_the_folders_owner_group_app_and_0660(self):
        # opened in place with O_CREAT by the application, the host and a rolled back root release: fs.protected_regular lets each of them open it
        # only while it belongs to the folder's owner (it refused root on a 10002-owned lock, so the watchdog read the lock as free)
        lock = self.web / '.update-lock'
        self.assertIn('web/.update-lock', self.run_it())
        info = os.stat(lock)
        self.assertEqual((info.st_uid, info.st_gid, self.mode(lock)), (os.stat(self.web).st_uid, self.gid, 0o660))
        os.chmod(lock, 0o600)  # as the application creates it when it is missing
        self.assertIn('web/.update-lock', self.run_it())
        self.assertEqual(self.mode(lock), 0o660)
        self.assertNotIn('.update-lock', self.run_it())

    def test_a_planted_update_lock_link_is_left_alone(self):
        victim = self.root / 'victim'
        victim.write_text('keep')
        os.chmod(victim, 0o600)
        os.symlink(victim, self.web / '.update-lock')
        self.run_it()
        self.assertTrue((self.web / '.update-lock').is_symlink())
        self.assertEqual(self.mode(victim), 0o600)

    def test_a_scanner_blob_readable_by_others_is_closed_to_the_group(self):
        blob = self.root / 'var/lib/cvengine-scanner/blob'
        blob.write_text('enrol')
        os.chmod(blob, 0o644)
        self.assertIn('cvengine-scanner/blob', self.run_it())
        self.assertEqual(self.mode(blob), 0o640)
        self.assertEqual(os.stat(blob).st_gid, self.gid)
        self.assertEqual(blob.read_text(), 'enrol')
        self.assertNotIn('cvengine-scanner/blob', self.run_it())

    def test_an_existing_secret_is_kept_and_its_mode_tightened(self):
        (self.web / 'secret').write_text('k' * 64 + '\n')
        os.chmod(self.web / 'secret', 0o644)
        self.assertNotIn('created the Django secret', self.run_it())
        self.assertEqual((self.web / 'secret').read_text(), 'k' * 64 + '\n')
        self.assertEqual(self.mode(self.web / 'secret'), 0o600)


class HostDirTests(SimpleTestCase):
    """The update channel's files live in the host's web/ folder, which production mounts beside the source, not over it."""

    def test_the_channel_follows_the_host_dir_and_falls_back_to_the_source_folder(self):
        from cveFeed import scanner_plan, updater, watchdog
        with override_settings(CVENGINE_HOST_DIR=HOST):
            self.assertEqual(updater._file('.update-approved'), f'{HOST}/.update-approved')
            self.assertEqual(scanner_plan._file('.scanner-plan-wanted'), f'{HOST}/.scanner-plan-wanted')
            self.assertEqual(watchdog._home(), HOST)
        with override_settings(CVENGINE_HOST_DIR='', BASE_DIR='/src/web'):
            self.assertEqual(updater._file('.commit'), '/src/web/.commit')
            self.assertEqual(watchdog._home(), '/src/web')

    def test_the_scanner_blob_is_0640_with_the_group_the_scanner_is_given(self):
        # celery is uid 10002 with no capability: it cannot give the file away, but it can give its own file its own group (10002)
        from agentapi import builtin_scanner
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {'CVENGINE_SCANNER_BOOTSTRAP_DIR': tmp,
                                                                                 'CVENGINE_APP_GID': str(os.getgid())}):
            builtin_scanner._write_blob('enrol')
            info = os.stat(os.path.join(tmp, 'blob'))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o640)
            self.assertEqual(info.st_gid, os.getgid())

    def test_the_scanner_blob_is_never_written_readable_by_others(self):
        # a writer that cannot give the file the scanner's group (as the old fallback to 0644 did) writes nothing at all
        from agentapi import builtin_scanner
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {'CVENGINE_SCANNER_BOOTSTRAP_DIR': tmp, 'CVENGINE_APP_GID': '10002'}), \
                mock.patch('os.fchown', side_effect=PermissionError(1, 'Operation not permitted')), \
                self.assertLogs('agentapi.builtin_scanner', 'ERROR'):
            with self.assertRaises(builtin_scanner.BlobPermissionError):
                builtin_scanner._write_blob('enrol')
            self.assertEqual(os.listdir(tmp), [], 'neither the blob nor its temporary file is left')
