"""The host inventory reporter scripts (scripts/inventory): run against fixture command output, the same report from the shell and the
Python script, what they refuse, that the token never reaches a command line, and a real HTTPS round trip to a local server. The
PowerShell script cannot run here (no pwsh in CI), so it is checked by reading it: see PowerShellScriptTests."""
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from django.test import SimpleTestCase

from cveFeed import inventory_schema as schema

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / 'scripts' / 'inventory'
SERVED = REPO / 'web' / 'static' / 'cve' / 'inventory'
SH, PY, PS1 = SCRIPTS / 'cvengine-inventory.sh', SCRIPTS / 'cvengine-inventory.py', SCRIPTS / 'cvengine-inventory.ps1'
TOKEN = 'cve_' + 'x' * 43
TOOLS = ('sh', 'sed', 'awk', 'tr', 'cut', 'grep', 'head', 'tail', 'sort', 'uniq', 'wc', 'date', 'stat', 'cat', 'mktemp', 'rm', 'uname', 'id',
		'basename', 'cksum', 'iconv', 'sleep', 'curl', 'mkdir', 'sha256sum', 'env', 'true', 'false', 'dirname')

OS_RELEASE = '''PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
'''
DPKG = 'bash\t5.1-6ubuntu1.1\tamd64\tbash\tii \nlibssl3\t3.0.2-0ubuntu1.10\tamd64\topenssl\tii \nopenssl\t3.0.2-0ubuntu1.10\tamd64\topenssl\tii \n' \
	'oldpkg\t1.0\tamd64\toldpkg\trc \nattr\t1:2.5.1-1build1\tamd64\tattr\tii \n'
RPM = 'curl\t(none)\t7.76.1-26.el9\tx86_64\tcurl-7.76.1-26.el9.src.rpm\t1700000500\nkernel-core\t0\t5.14.0-362.el9\tx86_64\tkernel-5.14.0-362.el9.src.rpm\t1700000900\n' \
	'gpg-pubkey\t(none)\t5a6340b3-6229229e\t(none)\t(none)\t1600000000\nbind\t32\t9.16.23-1.el9\tx86_64\tbind-9.16.23-1.el9.src.rpm\t1700000100\n'
APK = 'openssl-3.1.4-r0 x86_64 {openssl} (Apache-2.0) [installed]\nlibssl3-3.1.4-r0 x86_64 {openssl} (Apache-2.0) [installed]\nbusybox-1.36.1-r15 x86_64 {busybox} (GPL-2.0-only) [installed]\n'
SS = '''Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*     users:(("systemd-resolve",pid=612,fd=13))
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*     users:(("sshd",pid=801,fd=3))
tcp   LISTEN 0      128             [::]:22           [::]:*     users:(("sshd",pid=801,fd=4))
tcp   LISTEN 0      511       192.0.2.10:443       0.0.0.0:*     users:(("nginx",pid=900,fd=6),("nginx",pid=901,fd=6))
tcp   ESTAB  0      0         192.0.2.10:22  198.51.100.1:5555
'''
IP = '1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\n2: eth0    inet6 2001:db8::10/64 scope global\n2: eth0    inet6 fe80::1/64 scope link\n'


def script_text(body):
	return '#!/bin/sh\n' + body


class Fixture:
	"""A directory standing in for / (CVENGINE_ROOT) and a PATH holding only the basic tools and the commands the test stubs."""

	def __init__(self, stubs, test):
		self.dir = Path(tempfile.mkdtemp(prefix='inventory-test-'))
		test.addCleanup(shutil.rmtree, str(self.dir), True)
		self.root, self.bin, self.base = self.dir / 'root', self.dir / 'bin', self.dir / 'base'
		for folder in (self.bin, self.base):
			folder.mkdir()
		for name in TOOLS:
			found = shutil.which(name)
			if found:
				(self.base / name).symlink_to(found)
		(self.root / 'etc').mkdir(parents=True)
		(self.root / 'proc').mkdir()
		(self.root / 'var/lib/dpkg').mkdir(parents=True)
		(self.root / 'etc/os-release').write_text(OS_RELEASE)
		(self.root / 'etc/machine-id').write_text('0123456789abcdef0123456789abcdef\n')
		(self.root / 'proc/stat').write_text('cpu  1 2 3\nbtime 1700000000\n')
		status = self.root / 'var/lib/dpkg/status'
		status.write_text('')
		os.utime(str(status), (1700001000, 1700001000))
		for name, body in stubs.items():
			self.stub(name, body)

	def stub(self, name, body):
		path = self.bin / name
		path.write_text(script_text(body))
		path.chmod(0o755)

	def env(self, **extra):
		env = {'PATH': f'{self.bin}:{self.base}', 'CVENGINE_ROOT': str(self.root), 'HOME': str(self.dir), 'TMPDIR': str(self.dir), 'LC_ALL': 'C.UTF-8'}
		env.update(extra)
		return env

	def run(self, script, *args, **env):
		command = ['/bin/sh', str(script)] if script.suffix == '.sh' else [sys.executable, '-I', str(script)]
		# -I would drop CVENGINE_ROOT? no: it only isolates sys.path and ignores PYTHON* variables, so the test hook still works
		return subprocess.run(command + list(args), env=self.env(**env), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)


def stubs_linux():
	return {
		'dpkg-query': 'case "$*" in *linux-image*) printf "linux-image-5.15.0-91-generic\\tii \\nlinux-image-5.15.0-88-generic\\tii \\n";; *) printf %s ' + shell_quote(DPKG) + ';; esac',
		'ss': 'printf %s ' + shell_quote(SS),
		'ip': 'case "$*" in *addr*) printf %s ' + shell_quote(IP) + ';; esac',
		'hostname': 'case "$1" in -f) echo web01.example.test;; *) echo web01;; esac',
		'docker': 'printf "nginx:1.25\\nregistry.example.test/app:2.1\\nnginx:1.25\\n"',
		'systemctl': 'case "$1" in list-units) printf "ssh.service loaded active running OpenBSD Secure Shell server\\ncron.service loaded active running Regular\\n";; is-active) [ "$2" = ufw ] && echo active || echo inactive;; is-enabled) exit 1;; esac',
		'getenforce': 'echo Enforcing',
	}


def shell_quote(text):
	return "'" + text.replace("'", "'\\''") + "'"


class ReportTests(SimpleTestCase):
	def report(self, script, stubs=None, **kw):
		fixture = Fixture(stubs if stubs is not None else stubs_linux(), self)
		(fixture.root / 'run/systemd/system').mkdir(parents=True)
		done = fixture.run(script, '--dry-run', *kw.get('args', ()))
		self.assertEqual(done.returncode, 0, done.stderr)
		return json.loads(done.stdout), done, fixture

	def check_linux_report(self, data, script_name):
		clean = schema.validate(data)  # what the server would accept of it
		self.assertEqual(clean['dropped'], {'services': 2})  # a loopback-only listener and the IPv6 twin of port 22
		self.assertEqual(data['script'], {'name': script_name, 'version': '1.0.0'})
		os_block = data['os']
		self.assertEqual((os_block['family'], os_block['id'], os_block['name'], os_block['version'], os_block['codename'], os_block['id_like']),
			('linux', 'ubuntu', 'Ubuntu', '22.04', 'jammy', ['debian']))
		self.assertEqual(os_block['pretty'], 'Ubuntu 22.04.3 LTS')
		self.assertEqual(os_block['last_boot'], '2023-11-14T22:13:20Z')
		self.assertEqual(os_block['last_update'], '2023-11-14T22:30:00Z')
		self.assertEqual(data['host']['machine_id'], hashlib.sha256(b'cvengine-inventory-v1:0123456789abcdef0123456789abcdef').hexdigest())
		self.assertNotIn('0123456789abcdef0123456789abcdef', json.dumps(data))  # only ever the hash
		names = {(p['n'], p['v'], p['e']) for p in data['packages']}
		self.assertEqual(names, {('bash', '5.1-6ubuntu1.1', 'dpkg'), ('libssl3', '3.0.2-0ubuntu1.10', 'dpkg'), ('openssl', '3.0.2-0ubuntu1.10', 'dpkg'),
			('attr', '1:2.5.1-1build1', 'dpkg')})  # the removed "rc" package is not installed
		libssl = next(p for p in data['packages'] if p['n'] == 'libssl3')
		self.assertEqual((libssl['a'], libssl['s']), ('amd64', 'openssl'))
		self.assertNotIn('s', next(p for p in data['packages'] if p['n'] == 'bash'))
		return clean

	def test_the_shell_script_reports_a_linux_host(self):
		data, done, _ = self.report(SH)
		clean = self.check_linux_report(data, 'cvengine-inventory.sh')
		self.assertEqual(data['host']['hostname'], 'web01')
		self.assertEqual(data['host']['fqdn'], 'web01.example.test')
		self.assertEqual(data['host']['ips'], ['192.0.2.10', '2001:db8::10'])
		self.assertEqual([(s['n'], s['p'], s.get('x')) for s in clean['services']], [(22, 'tcp', 'sshd'), (443, 'tcp', 'nginx')])
		self.assertEqual(data['runtime']['containers'], [{'rt': 'docker', 'image': 'nginx:1.25'}, {'rt': 'docker', 'image': 'registry.example.test/app:2.1'}])
		self.assertEqual(data['runtime']['units'], ['ssh.service', 'cron.service'])
		self.assertEqual(data['runtime']['kernels_installed'], ['5.15.0-91-generic', '5.15.0-88-generic'])
		self.assertEqual(data['security'], {'firewall': 'ufw active', 'selinux': 'enforcing'})
		self.assertIn('dry run: nothing was sent', done.stderr)

	def test_the_python_script_reports_the_same_host(self):
		data, done, _ = self.report(PY)
		clean = self.check_linux_report(data, 'cvengine-inventory.py')
		self.assertEqual(data['host']['ips'], ['192.0.2.10', '2001:db8::10'])
		self.assertEqual([(s['n'], s['p'], s.get('x')) for s in clean['services']], [(22, 'tcp', 'sshd'), (443, 'tcp', 'nginx')])
		self.assertEqual(data['runtime']['containers'], [{'rt': 'docker', 'image': 'nginx:1.25'}, {'rt': 'docker', 'image': 'registry.example.test/app:2.1'}])
		self.assertEqual(data['runtime']['units'], ['ssh.service', 'cron.service'])
		self.assertEqual(data['security'], {'firewall': 'ufw active', 'selinux': 'enforcing'})

	def test_both_scripts_say_the_same_thing_about_the_same_machine(self):
		sh, _, _ = self.report(SH)
		py, _, _ = self.report(PY)
		for key in ('os', 'packages', 'services', 'runtime', 'security', 'patches'):
			left, right = sh[key], py[key]
			if key == 'packages':
				left, right = sorted(left, key=lambda p: p['n']), sorted(right, key=lambda p: p['n'])
			self.assertEqual(left, right, key)

	def test_rpm_and_apk_systems(self):
		for script in (SH, PY):
			stubs = {'rpm': 'case "$1" in -qa) printf %s ' + shell_quote(RPM) + ';; esac', 'ip': 'true', 'hostname': 'echo box'}
			data, _, fixture = self.report(script, stubs)
			rpm = {(p['n'], p['v']): p for p in data['packages']}
			self.assertEqual(set(rpm), {('curl', '7.76.1-26.el9'), ('kernel-core', '5.14.0-362.el9'), ('bind', '32:9.16.23-1.el9')}, script.name)
			self.assertEqual(rpm[('kernel-core', '5.14.0-362.el9')]['s'], 'kernel')
			self.assertEqual(data['os']['last_update'], '2023-11-14T22:28:20Z')  # the newest install time, not the database's modified time
			apk, _, _ = self.report(script, {'apk': 'case "$1" in list) printf %s ' + shell_quote(APK) + ';; esac'})
			found = {(p['n'], p['v'], p['e']) for p in apk['packages']}
			self.assertEqual(found, {('openssl', '3.1.4-r0', 'apk'), ('libssl3', '3.1.4-r0', 'apk'), ('busybox', '1.36.1-r15', 'apk')}, script.name)
			self.assertEqual(next(p for p in apk['packages'] if p['n'] == 'libssl3')['s'], 'openssl')

	def test_hostile_package_names_cannot_break_the_json(self):
		lines = [b'ok\t1.0\tamd64\tok\tii ', b'he said "hi" \\ back\t1"2\tall\tsrc\tii ', b'bad\xff\xfe\x01name\t1\tall\tbad\tii ',
			'caf\u00e9 \u202e\U0001F600\t2\tall\tcaf\tii '.encode(), b'{{7*7}}$(id)`id`\t3\tall\tx\tii ']
		for script in (SH, PY):
			fixture = Fixture({'dpkg-query': 'case "$*" in *linux-image*) ;; *) cat "$CVENGINE_ROOT/dpkg.out";; esac', 'ip': 'true', 'hostname': 'echo box'}, self)
			(fixture.root / 'dpkg.out').write_bytes(b'\n'.join(lines) + b'\n')
			done = fixture.run(script, '--dry-run')
			self.assertEqual(done.returncode, 0, done.stderr)
			data = json.loads(done.stdout)  # valid JSON, valid UTF-8
			by_name = {p['n']: p for p in data['packages']}
			self.assertEqual(by_name['he said "hi" \\ back']['v'], '1"2', script.name)
			self.assertIn('{{7*7}}$(id)`id`', by_name, script.name)  # data, never run
			self.assertTrue(any(n.startswith('caf') for n in by_name), script.name)
			clean = schema.validate(data)
			self.assertEqual(len(clean['packages']), 5, script.name)

	def test_the_macs_are_only_sent_when_asked_for(self):
		stubs = {**stubs_linux(), 'ip': 'case "$*" in *link*) echo "2: eth0: <BROADCAST> mtu 1500 state UP\\    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff";; *addr*) printf %s ' + shell_quote(IP) + ';; esac'}
		for script in (SH, PY):
			without, _, _ = self.report(script, stubs)
			self.assertFalse(without['host'].get('macs'), script.name)
			with_macs, _, _ = self.report(script, stubs, args=['--macs'])
			self.assertEqual(with_macs['host']['macs'], ['aa:bb:cc:dd:ee:ff'], script.name)

	def test_nothing_secret_is_in_the_report(self):
		env = {'AWS_SECRET_ACCESS_KEY': 'topsecretvalue', 'MY_PASSWORD': 'hunter2hunter2', 'CVENGINE_TOKEN': TOKEN}
		for script in (SH, PY):
			fixture = Fixture(stubs_linux(), self)
			(fixture.root / '.bash_history').write_text('mysql -phistorysecret\n')
			(fixture.root / 'etc/shadow').write_text('root:$6$saltsalt$hash:19000:0:99999:7:::\n')
			done = fixture.run(script, '--dry-run', **env)
			for secret in ('topsecretvalue', 'hunter2hunter2', TOKEN, 'historysecret', '$6$saltsalt'):
				self.assertNotIn(secret, done.stdout, script.name)
				self.assertNotIn(secret, done.stderr, script.name)

	def test_a_machine_without_a_hasher_or_an_id_still_reports(self):
		for script in (SH, PY):
			fixture = Fixture(stubs_linux(), self)
			(fixture.root / 'etc/machine-id').unlink()
			done = fixture.run(script, '--dry-run')
			self.assertEqual(done.returncode, 0, done.stderr)
			self.assertNotIn('machine_id', json.loads(done.stdout)['host'])


class OptionTests(SimpleTestCase):
	def run_script(self, script, *args, **env):
		fixture = Fixture(stubs_linux(), self)
		return fixture.run(script, *args, **env)

	def test_the_token_is_never_a_command_line_argument(self):
		for script in (SH, PY):
			for args in (['--token', TOKEN], [f'--token={TOKEN}']):
				done = self.run_script(script, '--server', 'https://cvengine.example.test', '--project', 'p', *args)
				self.assertEqual(done.returncode, 1, script.name)
				self.assertIn('never a command-line argument', done.stderr)
				self.assertNotIn(TOKEN, done.stderr)

	def test_configuration_errors_exit_1(self):
		cases = (
			(['--project', 'p'], 'required'), (['--server', 'http://cvengine.example.test', '--project', 'p'], 'https'),
			(['--server', 'https://cvengine.example.test'], 'project'), (['--server', 'https://cvengine.example.test', '--project', 'a b'], 'project'),
			(['--server', 'https://cvengine.example.test', '--project', 'p'], 'token'), (['--server', 'https://u:p@cvengine.example.test', '--project', 'p'], 'https'),
			(['--timeout', '0'], 'timeout'), (['--timeout', 'abc'], 'timeout'), (['--retries', '99'], 'retries'), (['--bogus'], ''),
			(['--server', 'https://cvengine.example.test', '--project', 'p', '--token-file', '/nonexistent/token'], 'token'))
		for script in (SH, PY):
			for args, word in cases:
				done = self.run_script(script, *args)
				self.assertEqual(done.returncode, 1, (script.name, args, done.stderr))
				self.assertIn(word, done.stderr.lower(), (script.name, args))

	def test_a_dry_run_needs_neither_server_nor_token(self):
		for script in (SH, PY):
			self.assertEqual(self.run_script(script, '--dry-run').returncode, 0)

	def test_the_token_file_is_read_and_a_loose_one_is_warned_about(self):
		for script in (SH, PY):
			fixture = Fixture(stubs_linux(), self)
			token_file = fixture.dir / 'token'
			token_file.write_text('not a token\n')
			token_file.chmod(0o644)
			done = fixture.run(script, '--server', 'https://127.0.0.1:9', '--project', 'p', '--token-file', str(token_file), '--retries', '0')
			self.assertEqual(done.returncode, 1, script.name)
			token_file.write_text(TOKEN + '\n')
			done = fixture.run(script, '--server', 'https://127.0.0.1:9', '--project', 'p', '--token-file', str(token_file), '--retries', '0')
			self.assertIn('readable by other users', done.stderr, script.name)
			self.assertEqual(done.returncode, 3, script.name)  # got as far as trying the network: nothing listens on port 9

	def test_install_cron_prints_and_installs_nothing(self):
		for script in (SH, PY):
			fixture = Fixture(stubs_linux(), self)
			done = fixture.run(script, '--install-cron', '--server', 'https://cvengine.example.test', '--project', 'proj-a')
			self.assertEqual(done.returncode, 0, done.stderr)
			self.assertIn('Nothing has been installed', done.stdout)
			self.assertIn('/etc/cron.d/cvengine-inventory', done.stdout)
			self.assertIn('OnCalendar=daily', done.stdout)
			self.assertIn('RandomizedDelaySec', done.stdout)
			self.assertIn('--server https://cvengine.example.test --project proj-a --token-file /etc/cvengine-inventory.token', done.stdout)
			self.assertNotIn('cve_', done.stdout)
			self.assertEqual(sorted(p.name for p in fixture.dir.iterdir()), ['base', 'bin', 'root'])  # not even a temporary file left behind

	def test_version_and_help(self):
		for script in (SH, PY):
			self.assertEqual(self.run_script(script, '--version').stdout.strip(), f'{script.name} 1.0.0')
			helped = self.run_script(script, '--help')
			self.assertEqual(helped.returncode, 0)
			self.assertIn('--ca-file', helped.stdout)
			self.assertIn('--insecure', helped.stdout)

	def test_an_insecure_run_says_so_loudly(self):
		for script in (SH, PY):
			done = self.run_script(script, '--server', 'https://127.0.0.1:9', '--project', 'p', '--insecure', '--retries', '0', CVENGINE_TOKEN=TOKEN)
			self.assertIn('NOT being checked', done.stderr, script.name)
			self.assertIn('--insecure', done.stderr)

	def test_a_system_that_is_not_linux_or_macos_is_refused_by_the_shell_script(self):
		fixture = Fixture({**stubs_linux(), 'uname': 'echo FreeBSD'}, self)
		done = fixture.run(SH, '--dry-run')
		self.assertEqual(done.returncode, 2)
		self.assertIn('.ps1', done.stderr)


class RecordingHandler(BaseHTTPRequestHandler):
	def do_POST(self):
		body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
		self.server.seen.append({'path': self.path, 'auth': self.headers.get('Authorization'), 'type': self.headers.get('Content-Type'), 'body': body})
		status, text = self.server.answers.pop(0) if len(self.server.answers) > 1 else self.server.answers[0]
		self.send_response(status)
		self.send_header('Content-Type', 'application/json')
		self.end_headers()
		self.wfile.write(text.encode())

	def log_message(self, *args):
		pass


class RoundTripTests(SimpleTestCase):
	"""A real HTTPS server with a throwaway certificate: what goes on the wire and how each answer is handled."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.certs = Path(tempfile.mkdtemp(prefix='inventory-certs-'))
		subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(cls.certs / 'key.pem'), '-out', str(cls.certs / 'ca.pem'),
			'-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-days', '2'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		cls.server = HTTPServer(('127.0.0.1', 0), RecordingHandler)
		context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		context.load_cert_chain(str(cls.certs / 'ca.pem'), str(cls.certs / 'key.pem'))
		cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
		cls.server.seen, cls.server.answers = [], [(201, '{"accepted": true}')]
		cls.port = cls.server.server_address[1]
		threading.Thread(target=cls.server.serve_forever, daemon=True).start()

	@classmethod
	def tearDownClass(cls):
		cls.server.shutdown()
		cls.server.server_close()
		shutil.rmtree(str(cls.certs), True)
		super().tearDownClass()

	def setUp(self):
		self.server.seen.clear()
		self.server.answers[:] = [(201, '{"accepted": true}')]

	def send(self, script, *extra, token=TOKEN):
		fixture = Fixture(stubs_linux(), self)
		args = ['--server', f'https://127.0.0.1:{self.port}', '--project', 'proj-a', *extra]
		return fixture.run(script, *args, CVENGINE_TOKEN=token)

	def test_a_report_reaches_the_server_with_the_token_in_a_header_only(self):
		for script in (SH, PY):
			self.server.seen.clear()
			done = self.send(script, '--ca-file', str(self.certs / 'ca.pem'), '--retries', '0')
			self.assertEqual(done.returncode, 0, (script.name, done.stderr))
			request = self.server.seen[0]
			self.assertEqual((request['path'], request['auth'], request['type']), ('/api/v1/projects/proj-a/inventory', f'Bearer {TOKEN}', 'application/json'))
			schema.validate(json.loads(request['body']))
			self.assertNotIn(TOKEN, request['body'].decode())
			self.assertIn('sent:', done.stderr)

	def test_the_certificate_is_verified_by_default(self):
		for script in (SH, PY):
			done = self.send(script, '--retries', '0')
			self.assertEqual(done.returncode, 3, (script.name, done.stderr))
			self.assertIn('certificate is not trusted', done.stderr)
			self.assertIn('--ca-file', done.stderr)
			self.assertEqual(self.server.seen, [])  # the token was never sent to a server that could not prove who it was

	def test_insecure_skips_the_check(self):
		for script in (SH, PY):
			done = self.send(script, '--insecure', '--retries', '0')
			self.assertEqual(done.returncode, 0, (script.name, done.stderr))
			self.assertIn('NOT being checked', done.stderr)

	def test_a_refusal_is_not_retried_and_says_why(self):
		for script in (SH, PY):
			self.server.seen.clear()
			self.server.answers[:] = [(400, '{"error": "schema must be cvengine-inventory/1"}')]
			done = self.send(script, '--ca-file', str(self.certs / 'ca.pem'), '--retries', '3')
			self.assertEqual(done.returncode, 4, (script.name, done.stderr))
			self.assertIn('schema must be', done.stderr)
			self.assertEqual(len(self.server.seen), 1, script.name)

	def test_a_server_error_is_retried_with_a_delay_then_given_up(self):
		for script in (SH, PY):
			self.server.seen.clear()
			self.server.answers[:] = [(503, '{"error": "busy"}')]
			started = time.time()
			done = self.send(script, '--ca-file', str(self.certs / 'ca.pem'), '--retries', '1')
			self.assertEqual(done.returncode, 5, (script.name, done.stderr))
			self.assertEqual(len(self.server.seen), 2, script.name)
			self.assertGreaterEqual(time.time() - started, 2)
			self.assertIn('retrying in', done.stderr)
			self.assertIn('giving up', done.stderr)

	def test_a_server_that_recovers_is_reported_to_once(self):
		for script in (SH, PY):
			self.server.seen.clear()
			self.server.answers[:] = [(429, '{"error": "slow down"}'), (200, '{"accepted": true}')]
			done = self.send(script, '--ca-file', str(self.certs / 'ca.pem'), '--retries', '2')
			self.assertEqual(done.returncode, 0, (script.name, done.stderr))
			self.assertEqual(len(self.server.seen), 2)

	def test_a_server_that_is_not_there_exits_3(self):
		for script in (SH, PY):
			fixture = Fixture(stubs_linux(), self)
			done = fixture.run(script, '--server', 'https://127.0.0.1:9', '--project', 'p', '--retries', '0', '--timeout', '3', CVENGINE_TOKEN=TOKEN)
			self.assertEqual(done.returncode, 3, (script.name, done.stderr))

	def test_the_shell_script_never_puts_the_token_on_a_command_line(self):
		fixture = Fixture(stubs_linux(), self)
		fixture.stub('curl', 'cat > "$CAPTURE.stdin"; printf "%s\\n" "$@" > "$CAPTURE.args"; for a in "$@"; do [ "$prev" = -o ] && printf \'{"accepted": true}\' > "$a"; prev=$a; done; printf 201')
		capture = fixture.dir / 'curl'
		done = fixture.run(SH, '--server', 'https://cvengine.example.test', '--project', 'proj-a', '--ca-file', str(fixture.root / 'etc/os-release'), CVENGINE_TOKEN=TOKEN, CAPTURE=str(capture))
		self.assertEqual(done.returncode, 0, done.stderr)
		args = (fixture.dir / 'curl.args').read_text()
		self.assertNotIn(TOKEN, args)
		self.assertNotIn('cve_', args)
		self.assertIn(TOKEN, (fixture.dir / 'curl.stdin').read_text())  # given to curl on its standard input
		for wanted in ('--proto', '=https', '--tlsv1.2', '--cacert', '--max-time'):
			self.assertIn(wanted, args)
		for forbidden in ('-L', '--location', '--insecure', '-k'):
			self.assertNotIn(forbidden, args.split('\n'))


class SourceTests(SimpleTestCase):
	def test_the_scripts_compile_and_the_shell_script_is_posix_clean(self):
		subprocess.run([sys.executable, '-m', 'py_compile', str(PY)], check=True)
		for shell in ('sh', 'dash', 'bash'):
			if shutil.which(shell):
				subprocess.run([shell, '-n', str(SH)], check=True)
		shellcheck = shutil.which('shellcheck') or os.environ.get('SHELLCHECK')
		if not shellcheck:
			self.skipTest('shellcheck is not installed')
		done = subprocess.run([shellcheck, '-s', 'sh', str(SH)], stdout=subprocess.PIPE, universal_newlines=True)
		self.assertEqual(done.returncode, 0, done.stdout)

	def test_the_python_script_is_python_3_6_compatible_by_syntax(self):
		source = PY.read_text()
		for newer in (':=', 'capture_output', 'text=True', 'fromisoformat', 'removeprefix'):
			self.assertNotIn(newer, source, newer)
		import ast
		ast.parse(source, feature_version=(3, 6))

	def test_the_copies_the_server_hands_out_are_the_scripts(self):
		for script in (SH, PY, PS1):
			self.assertEqual((SERVED / script.name).read_bytes(), script.read_bytes(), f'{script.name} differs: run make inventory-sync')
		self.assertTrue(os.stat(SH).st_mode & stat.S_IXUSR and os.stat(PY).st_mode & stat.S_IXUSR)

	def test_no_script_has_an_em_dash_and_the_token_option_only_refuses(self):
		for script in (SH, PY, PS1):
			self.assertNotIn('\u2014', script.read_text())
		self.assertIn("add_argument('--token', help=argparse.SUPPRESS)", PY.read_text())  # accepted only to refuse it with the reason


class PowerShellScriptTests(SimpleTestCase):
	"""pwsh is not available where these tests run, so the script is checked by reading it: balanced, read-only, no token parameter."""

	@property
	def source(self):
		return PS1.read_text()

	def code(self):
		text = re.sub(r"@'.*?'@", '', self.source, flags=re.S)
		text = re.sub(r'@".*?"@', '', text, flags=re.S)
		return re.sub(r'<#.*?#>', '', text, flags=re.S)

	def test_braces_parentheses_and_brackets_balance(self):
		code = self.code()
		for opening, closing in ('{}', '()', '[]'):
			self.assertEqual(code.count(opening), code.count(closing), opening)

	def test_it_only_reads(self):
		changing = re.findall(r'\b(?:Remove|Set|New|Add|Clear|Install|Uninstall|Enable|Disable|Start|Stop|Restart|Register|Unregister|Invoke|Out|Copy|Move|Rename|Import|Export|Update)-(\w+)', self.code())
		self.assertEqual(sorted(set(changing)), ['Object', 'Report', 'Sleep', 'StrictMode', 'Type'])
		for banned in ('Invoke-Expression', 'iex ', 'Set-Content', 'Add-Content', 'Out-File', 'Get-Package', 'Find-Package', 'Install-', 'Get-Credential', 'Get-EventLog', 'Get-WinEvent', 'Get-History'):
			self.assertNotIn(banned, self.code())

	def test_the_token_is_not_a_parameter(self):
		param = self.source[self.source.index('param('):self.source.index(')\n\nSet-StrictMode')]
		self.assertNotRegex(param, r'(?i)token\b(?!File)')
		self.assertIn('$env:CVENGINE_TOKEN', self.source)
		self.assertIn('[ValidateRange(1, 300)][int]$TimeoutSec', param)

	def test_it_has_the_documented_options_and_guards(self):
		for wanted in ('[switch]$Insecure', '[switch]$DryRun', '[switch]$Schedule', '[string]$CaFile', 'AllowAutoRedirect = $false', "'^https://", 'cvengine-inventory-v1:',
				'NOT being checked', 'Get-HotFix', 'Microsoft.Update.Session', 'QueryHistory', 'WOW6432Node', 'Get-NetTCPConnection', 'Get-MpComputerStatus', 'Get-BitLockerVolume',
				'Component Based Servicing', 'RebootRequired'):
			self.assertIn(wanted, self.source)


def load_python_script():
	import importlib.util
	spec = importlib.util.spec_from_file_location('cvengine_inventory_script', str(PY))
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


class ParserTests(SimpleTestCase):
	"""What the Python script makes of the output of the commands it runs, including the macOS ones no test machine can run."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.script = load_python_script()

	def test_os_release_is_read_as_data_never_run(self):
		parsed = self.script.parse_os_release('ID=ubuntu\nNAME="Ubuntu"\nPRETTY_NAME=\'Ubuntu 22.04\'\nVERSION_ID="22.04"\nHOME_URL=$(touch /tmp/pwned)\n# comment\nbad line\n')
		self.assertEqual((parsed['ID'], parsed['NAME'], parsed['PRETTY_NAME'], parsed['VERSION_ID']), ('ubuntu', 'Ubuntu', 'Ubuntu 22.04', '22.04'))
		self.assertEqual(parsed['HOME_URL'], '$(touch /tmp/pwned)')
		self.assertNotIn('comment', parsed)

	def test_package_listings(self):
		self.assertEqual([p['n'] for p in self.script.parse_dpkg(DPKG)], ['bash', 'libssl3', 'openssl', 'attr'])
		rpms, newest = self.script.parse_rpm(RPM)
		self.assertEqual((sorted(p['n'] for p in rpms), newest), (['bind', 'curl', 'kernel-core'], 1700000900))
		self.assertEqual({p['n']: p['v'] for p in rpms}['bind'], '32:9.16.23-1.el9')
		self.assertEqual({p['n']: p['s'] for p in rpms}['curl'], 'curl')
		apk = list(self.script.parse_apk(APK))
		self.assertEqual((apk[1]['n'], apk[1]['v'], apk[1]['s'], apk[1]['a']), ('libssl3', '3.1.4-r0', 'openssl', 'x86_64'))
		self.assertEqual(list(self.script.parse_pairs('openssl 3.2.0-1\nlinux 6.6.1.arch1-1\njunk\n', 'pacman'))[1], {'n': 'linux', 'v': '6.6.1.arch1-1', 'e': 'pacman'})
		self.assertEqual(list(self.script.parse_pairs('wget 1.21.3 1.21.4\n', 'brew', take_last=True)), [{'n': 'wget', 'v': '1.21.4', 'e': 'brew'}])

	def test_listening_sockets_from_ss_netstat_and_lsof(self):
		sockets = [self.script.service(*row) for row in self.script.parse_ss(SS)]
		self.assertEqual(sockets[1], {'p': 'tcp', 'a': '*', 'n': 22, 'x': 'sshd'})
		self.assertEqual(sockets[3], {'p': 'tcp', 'a': '192.0.2.10', 'n': 443, 'x': 'nginx'})
		self.assertEqual(len(sockets), 4)  # the established connection is not a listener
		netstat = 'Active Internet connections\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp6       0      0 :::80    :::*   LISTEN\nudp        0      0 0.0.0.0:68   0.0.0.0:*\ntcp 0 0 10.0.0.1:22 10.0.0.2:5 ESTABLISHED\n'
		self.assertEqual([self.script.service(*r)['n'] for r in self.script.parse_netstat(netstat)], [22, 80, 68])
		lsof = 'p100\ncsshd\nPTCP\nn*:22\nPTCP\nn[::1]:631\np200\ncmDNSResponder\nPUDP\nn*:5353\nPTCP\nn192.0.2.5:8080 (LISTEN)\n'
		found = [self.script.service(*r) for r in self.script.parse_lsof(lsof)]
		self.assertEqual([(s['p'], s['a'], s['n'], s['x']) for s in found],
			[('tcp', '*', 22, 'sshd'), ('tcp', '::1', 631, 'sshd'), ('udp', '*', 5353, 'mDNSResponder'), ('tcp', '192.0.2.5', 8080, 'mDNSResponder')])
		self.assertIsNone(self.script.service('tcp', 'garbage', ''))

	def test_a_mac_reports_its_version_and_build(self):
		answers = {('sw_vers', '-productName'): 'macOS\n', ('sw_vers', '-productVersion'): '14.2.1\n', ('sw_vers', '-buildVersion'): '23C71\n',
			('sysctl', '-n', 'kern.boottime'): '{ sec = 1700000000, usec = 0 } Tue Nov 14 22:13:20 2023\n'}
		original = self.script.run
		self.script.run = lambda argv, timeout=60: answers.get(tuple(argv), '')
		try:
			block = self.script.os_block('macos', 0)
		finally:
			self.script.run = original
		self.assertEqual((block['name'], block['version'], block['build'], block['id'], block['pretty'], block['last_boot']),
			('macOS', '14.2.1', '23C71', 'macos', 'macOS 14.2.1', '2023-11-14T22:13:20Z'))
		self.assertEqual(schema.validate({'schema': 'cvengine-inventory/1', 'host': {'hostname': 'mac'}, 'os': block})['os']['family'], 'macos')

	def test_macos_applications_are_read_from_their_plists(self):
		import plistlib
		with tempfile.TemporaryDirectory() as folder:
			app = Path(folder) / 'Pages.app' / 'Contents'
			app.mkdir(parents=True)
			(app / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleShortVersionString': '13.2', 'CFBundleName': 'Pages'}))
			(Path(folder) / 'Broken.app' / 'Contents').mkdir(parents=True)
			(Path(folder) / 'Broken.app' / 'Contents' / 'Info.plist').write_bytes(b'not a plist')
			(Path(folder) / 'notes.txt').write_text('not an app')
			self.assertEqual(self.script.macos_apps([folder, '/nonexistent']), [{'n': 'Pages', 'v': '13.2', 'e': 'macapp'}])
