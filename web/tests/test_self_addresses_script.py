"""This server's own public addresses written by the install and every update (scripts/self-addresses.sh, CVENGINE_SELF_ADDRESSES).

The script runs for real in bash against stub `ip` and `curl` commands on PATH: `ip` prints the interfaces a test gives it, `curl` answers an echo
service only when the test wrote that service's answer, and records every call. The update is the real scripts/update.sh against a throwaway Git
remote (tests/test_update_script.py), with the new script arriving in the fetched commit as it does on a real host.
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_update_script import SCRIPT, UpdateScriptCase

ROOT = Path(__file__).resolve().parents[2]
SELF = ROOT / 'scripts' / 'self-addresses.sh'

IP_STUB = '''#!/bin/sh
echo "ip $*" >> "$STUB_DIR/ip_calls"
case "$*" in *"addr show scope global"*) cat "$STUB_DIR/interfaces" 2>/dev/null;; esac
exit 0
'''
CURL_STUB = '''#!/bin/sh
echo "curl $*" >> "$STUB_DIR/curl_calls"
for last in "$@"; do :; done
host=$(printf '%s' "$last" | sed -e 's|^https://||' -e 's|/.*||')
if [ -f "$STUB_DIR/echo/$host" ]; then cat "$STUB_DIR/echo/$host"; exit 0; fi
exit 7
'''


def iface(n, name, family, addr, extra=''):
    word = 'inet' if family == 4 else 'inet6'
    return f'{n}: {name}    {word} {addr} scope global {extra}{name}\\       valid_lft forever preferred_lft forever\n'


PUBLIC_V4 = iface(2, 'eth0', 4, '8.8.4.4/24 brd 8.8.4.255')
PUBLIC_V6 = iface(2, 'eth0', 6, '2001:4860:4860::8844/64', 'dynamic mngtmpaddr noprefixroute ')
PRIVATE = (iface(3, 'eth1', 4, '10.0.0.5/24 brd 10.0.0.255') + iface(4, 'docker0', 4, '172.17.0.1/16 brd 172.17.255.255')
           + iface(5, 'tailscale0', 4, '100.109.175.43/32') + iface(5, 'tailscale0', 6, 'fd7a:115c:a1e0::9e35:af2c/128'))


class StubCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stub = self.tmp / 'stub'
        (self.stub / 'echo').mkdir(parents=True)
        for name, body in (('ip', IP_STUB), ('curl', CURL_STUB)):
            (self.stub / name).write_text(body)
            (self.stub / name).chmod(0o755)
        self.dir = self.tmp / 'site'
        (self.dir / 'scripts').mkdir(parents=True)
        shutil.copy(SELF, self.dir / 'scripts' / 'self-addresses.sh')
        self.env = {**os.environ, 'PATH': f'{self.stub}:{os.environ["PATH"]}', 'STUB_DIR': str(self.stub)}
        self.env.pop('CVENGINE_SELF_ADDRESSES_DETECT', None)

    def interfaces(self, text):
        (self.stub / 'interfaces').write_text(text)

    def echo(self, host, answer):
        (self.stub / 'echo' / host).write_text(answer)

    def curl_calls(self):
        path = self.stub / 'curl_calls'
        return path.read_text().splitlines() if path.exists() else []

    def ip_calls(self):
        path = self.stub / 'ip_calls'
        return path.read_text().splitlines() if path.exists() else []

    def write_env(self, text):
        (self.dir / '.env').write_text(text)

    def env_text(self):
        return (self.dir / '.env').read_text()

    def keys(self):
        return [line for line in self.env_text().splitlines() if line.startswith('CVENGINE_SELF_ADDRESSES')]

    def ensure(self, **env):
        return subprocess.run(['bash', '-c', 'set -euo pipefail; . scripts/self-addresses.sh; cvengine_ensure_self_addresses'], cwd=self.dir,
                              env={**self.env, **env}, capture_output=True, text=True, timeout=60)


@unittest.skipUnless(shutil.which('bash') and shutil.which('python3'), 'needs bash and python3')
class DetectionTests(StubCase):
    def test_the_public_addresses_of_the_interfaces_are_written_and_no_echo_service_is_asked(self):
        self.interfaces(PUBLIC_V4 + PUBLIC_V6 + PRIVATE)
        self.write_env('DOMAIN_NAME=example.com\n')
        result = self.ensure()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.keys(), ['CVENGINE_SELF_ADDRESSES=8.8.4.4,2001:4860:4860::8844',
                                       'CVENGINE_SELF_ADDRESSES_DETECTED=8.8.4.4,2001:4860:4860::8844'])
        self.assertEqual(self.curl_calls(), [])
        self.assertIn('CVENGINE_SELF_ADDRESSES=8.8.4.4,2001:4860:4860::8844 was written to .env', result.stdout)
        self.assertTrue(self.env_text().startswith('DOMAIN_NAME=example.com\n'))
        self.assertIn("# managed by the updater: this host's own public addresses", self.env_text())

    def test_private_shared_ula_and_docker_addresses_are_never_taken(self):
        self.interfaces(PRIVATE)
        self.write_env('DOMAIN_NAME=example.com\n')
        result = self.ensure()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.keys(), [])
        self.assertIn('Could not find this server\'s own public address', result.stdout)

    def test_temporary_and_deprecated_ipv6_addresses_are_left_out_because_they_rotate(self):
        self.interfaces(PUBLIC_V4 + iface(2, 'eth0', 6, '2001:4860:4860::1/64', 'temporary dynamic ')
                        + iface(2, 'eth0', 6, '2001:4860:4860::2/64', 'deprecated dynamic ') + PUBLIC_V6)
        self.write_env('')
        self.assertEqual(self.ensure().returncode, 0)
        self.assertEqual(self.keys()[0], 'CVENGINE_SELF_ADDRESSES=8.8.4.4,2001:4860:4860::8844')

    def test_behind_nat_the_echo_services_answer_one_at_a_time_with_a_timeout(self):
        self.interfaces(PRIVATE)
        self.echo('ipv4.icanhazip.com', '9.9.9.9\n')  # the first service in the list does not answer
        self.write_env('DOMAIN_NAME=example.com\n')
        result = self.ensure()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.keys()[0], 'CVENGINE_SELF_ADDRESSES=9.9.9.9')
        calls = self.curl_calls()
        v4 = [c for c in calls if c.startswith('curl -4 ')]
        self.assertEqual([c.split()[-1] for c in v4], ['https://api.ipify.org', 'https://ipv4.icanhazip.com'])
        for call in calls:
            self.assertIn('--connect-timeout 3 --max-time 5', call)
        self.assertTrue(all(c.split()[-1].startswith('https://') for c in calls))

    def test_the_echo_is_asked_only_for_the_family_the_interfaces_lack(self):
        self.interfaces(PUBLIC_V4 + PRIVATE)
        self.echo('api6.ipify.org', '2001:4860:4860::8888\n')
        self.write_env('')
        self.assertEqual(self.ensure().returncode, 0)
        self.assertEqual(self.keys()[0], 'CVENGINE_SELF_ADDRESSES=8.8.4.4,2001:4860:4860::8888')
        self.assertFalse(any(c.startswith('curl -4 ') for c in self.curl_calls()))

    def test_an_echo_answer_that_is_not_a_public_address_of_its_family_is_ignored(self):
        self.interfaces(PRIVATE)
        self.echo('api.ipify.org', '<html>blocked</html>')
        self.echo('ipv4.icanhazip.com', '192.168.1.10\n')
        self.echo('checkip.amazonaws.com', '2001:4860:4860::8888\n')
        self.echo('api6.ipify.org', '100.64.0.1\n')
        self.write_env('')
        self.assertEqual(self.ensure().returncode, 1)
        self.assertEqual(self.keys(), [])

    def test_offline_the_update_goes_on_and_a_managed_value_is_kept(self):
        self.interfaces(PRIVATE)
        self.write_env('CVENGINE_SELF_ADDRESSES=8.8.4.4\nCVENGINE_SELF_ADDRESSES_DETECTED=8.8.4.4\n')
        before = self.env_text()
        result = self.ensure()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.env_text(), before)
        self.assertNotIn('Could not find', result.stdout)  # a value is set, so there is nothing to tell

    def test_ip_and_curl_that_fail_fail_nothing(self):
        for name in ('ip', 'curl'):
            (self.stub / name).write_text('#!/bin/sh\necho broken >&2\nexit 1\n')
        self.write_env('')
        result = self.ensure()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.keys(), [])

    def test_without_ip_or_curl_nothing_fails(self):
        (self.stub / 'ip').unlink()
        (self.stub / 'curl').unlink()
        self.write_env('')
        path = f'{self.stub}:/usr/bin:/bin'
        for tool in ('ip', 'curl'):  # the host's own copies are hidden too
            if shutil.which(tool, path=path):
                self.skipTest(f'{tool} is in /usr/bin or /bin on this machine')
        result = self.ensure(PATH=path)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.keys(), [])


@unittest.skipUnless(shutil.which('bash') and shutil.which('python3'), 'needs bash and python3')
class ManagedValueTests(StubCase):
    def test_an_operators_own_value_is_never_changed_and_nothing_is_asked(self):
        self.interfaces(PUBLIC_V4)
        self.write_env('CVENGINE_SELF_ADDRESSES=203.0.113.7\n')
        before = self.env_text()
        self.assertEqual(self.ensure().returncode, 1)
        self.assertEqual(self.env_text(), before)
        self.assertEqual((self.ip_calls(), self.curl_calls()), ([], []))

    def test_an_operator_who_changed_a_managed_value_keeps_the_change(self):
        self.interfaces(PUBLIC_V4)
        self.write_env('CVENGINE_SELF_ADDRESSES=9.9.9.9\nCVENGINE_SELF_ADDRESSES_DETECTED=8.8.4.4\n')
        before = self.env_text()
        self.assertEqual(self.ensure().returncode, 1)
        self.assertEqual(self.env_text(), before)

    def test_the_older_name_set_by_an_operator_is_respected(self):
        self.interfaces(PUBLIC_V4)
        self.write_env('CVENGINE_OWN_ADDRESSES=203.0.113.7\n')
        self.assertEqual(self.ensure().returncode, 1)
        self.assertEqual(self.keys(), [])

    def test_a_stale_managed_value_is_replaced_once_with_one_copy_of_each_line(self):
        self.interfaces(PUBLIC_V4)
        self.write_env("A=1\n# managed by the updater: this host's own public addresses (old text)\nCVENGINE_SELF_ADDRESSES=9.9.9.9\n"
                       'B=2\nCVENGINE_SELF_ADDRESSES_DETECTED=9.9.9.9\n')
        result = self.ensure()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('changed: CVENGINE_SELF_ADDRESSES=8.8.4.4 was written to .env (it was 9.9.9.9)', result.stdout)
        text = self.env_text()
        self.assertEqual(self.keys(), ['CVENGINE_SELF_ADDRESSES=8.8.4.4', 'CVENGINE_SELF_ADDRESSES_DETECTED=8.8.4.4'])
        self.assertEqual(text.count('# managed by the updater'), 1)
        self.assertIn('A=1\n', text)
        self.assertIn('B=2\n', text)

    def test_a_second_run_changes_nothing_and_says_nothing(self):
        self.interfaces(PUBLIC_V6 + PUBLIC_V4)
        self.write_env('')
        self.assertEqual(self.ensure().returncode, 0)
        first = self.env_text()
        result = self.ensure()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertEqual(self.env_text(), first)

    def test_the_order_of_a_managed_value_does_not_count_as_a_change(self):
        self.interfaces(PUBLIC_V4 + PUBLIC_V6)
        self.write_env('CVENGINE_SELF_ADDRESSES=2001:4860:4860::8844, 8.8.4.4\n'
                       'CVENGINE_SELF_ADDRESSES_DETECTED=8.8.4.4,2001:4860:4860::8844\n')
        before = self.env_text()
        self.assertEqual(self.ensure().returncode, 1)
        self.assertEqual(self.env_text(), before)

    def test_a_managed_value_the_operator_emptied_is_detected_again(self):
        self.interfaces(PUBLIC_V4)
        self.write_env('CVENGINE_SELF_ADDRESSES=\nCVENGINE_SELF_ADDRESSES_DETECTED=9.9.9.9\n')
        self.assertEqual(self.ensure().returncode, 0)
        self.assertEqual(self.keys(), ['CVENGINE_SELF_ADDRESSES=8.8.4.4', 'CVENGINE_SELF_ADDRESSES_DETECTED=8.8.4.4'])

    def test_the_switch_turns_detection_off_from_env_or_the_environment(self):
        self.interfaces(PUBLIC_V4)
        self.write_env('CVENGINE_SELF_ADDRESSES_DETECT=0\n')
        self.assertEqual(self.ensure().returncode, 1)
        self.write_env('')
        self.assertEqual(self.ensure(CVENGINE_SELF_ADDRESSES_DETECT='off').returncode, 1)
        self.assertEqual(self.keys(), [])
        self.assertEqual((self.ip_calls(), self.curl_calls()), ([], []))

    def test_the_file_keeps_its_mode(self):
        self.interfaces(PUBLIC_V4)
        self.write_env('A=1')  # no newline at the end
        os.chmod(self.dir / '.env', 0o600)
        self.assertEqual(self.ensure().returncode, 0)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir / '.env').st_mode), 0o600)
        self.assertTrue(self.env_text().startswith('A=1\n#'))

    def test_without_env_nothing_is_created(self):
        self.interfaces(PUBLIC_V4)
        self.assertEqual(self.ensure().returncode, 1)
        self.assertFalse((self.dir / '.env').exists())


class WiringTests(unittest.TestCase):
    def test_both_update_paths_write_it_before_the_application_is_recreated(self):
        recreate = 'up -d --no-deps --force-recreate "${services[@]}"'  # web, celery, celery-beat and the proxy
        for name in ('update.sh', 'update-deploy.sh'):
            src = (ROOT / 'scripts' / name).read_text()
            call = src.index('cvengine_ensure_self_addresses')
            self.assertIn('-f scripts/self-addresses.sh', src[call - 200:call], name)  # tests copy only some scripts into their checkout
            self.assertLess(call, src.index(recreate), name)

    def test_the_installer_writes_it_after_the_env_file_is_made(self):
        src = (ROOT / 'install.sh').read_text()
        self.assertLess(src.index('./scripts/init-env.sh'), src.index('cvengine_ensure_self_addresses'))

    def test_the_application_containers_read_env(self):
        compose = (ROOT / 'docker-compose.yml').read_text()
        for service in ('web', 'celery', 'celery-beat'):
            found = re.search(rf'^  {re.escape(service)}:\n(.*?)(?=^  \S)', compose, re.S | re.M)
            assert found is not None, service
            block = found.group(1)
            self.assertRegex(block, r'env_file:\n\s+- path: \.env', service)
            self.assertNotIn('CVENGINE_SELF_ADDRESSES', block, service)  # an explicit entry would hide the value in .env


@unittest.skipUnless(SCRIPT.is_file() and shutil.which('git') and shutil.which('flock') and shutil.which('python3'), 'needs git, flock, python3')
class UpdateWritesItTests(UpdateScriptCase):
    def setUp(self):
        super().setUp()
        (self.stub / 'ip').write_text(IP_STUB)  # the update's own curl stub stays: it answers 200, which is no address
        (self.stub / 'ip').chmod(0o755)
        (self.stub / 'interfaces').write_text(PUBLIC_V4 + PRIVATE)
        shutil.copy(SELF, self.other / 'scripts' / 'self-addresses.sh')
        self.git('add', '-A', cwd=self.other)
        self.git('commit', '-m', 'the self addresses script', cwd=self.other)
        self.git('push', 'origin', 'master', cwd=self.other)
        self.env.pop('CVENGINE_SELF_ADDRESSES_DETECT', None)

    def test_the_update_writes_the_managed_line_before_it_recreates_the_application(self):
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        env = (self.work / '.env').read_text()
        self.assertIn('local-only=true\n', env)
        self.assertIn('CVENGINE_SELF_ADDRESSES=8.8.4.4\nCVENGINE_SELF_ADDRESSES_DETECTED=8.8.4.4\n', env)
        self.assertIn('CVENGINE_SELF_ADDRESSES=8.8.4.4 was written to .env', result.stdout)
        self.assertTrue(any('--force-recreate web' in c for c in self.calls()))

    def test_an_update_with_no_address_found_still_succeeds(self):
        (self.stub / 'interfaces').write_text(PRIVATE)
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn('CVENGINE_SELF_ADDRESSES=', (self.work / '.env').read_text())
        self.assertIn('CVENGINE_SELF_ADDRESSES is not set', result.stdout)

    def test_an_operators_value_survives_the_update(self):
        (self.work / '.env').write_text('local-only=true\nCVENGINE_SELF_ADDRESSES=203.0.113.7\n')
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual((self.work / '.env').read_text(), 'local-only=true\nCVENGINE_SELF_ADDRESSES=203.0.113.7\n')
