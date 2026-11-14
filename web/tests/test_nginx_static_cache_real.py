"""A real nginx (throwaway container) serving config/nginx/rengine.conf's /staticfiles/ rules: a hashed URL that exists is immutable for a year, a
hashed URL that does not exist (404) carries no Cache-Control at all, and nosniff stays on both. Opt in with CVENGINE_NGINX_DOCKER_TEST=1 (needs
docker and the nginx:alpine image); it is skipped otherwise, so CI without docker is unaffected."""
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
HASH = 'abcdef0123'
PORT = 18099


@unittest.skipUnless(os.environ.get('CVENGINE_NGINX_DOCKER_TEST') == '1' and shutil.which('docker'), 'set CVENGINE_NGINX_DOCKER_TEST=1 (needs docker)')
class RealNginxStaticCacheTests(unittest.TestCase):
    def fetch(self, path):
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{PORT}{path}', timeout=5) as r:
                return r.status, r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.headers

    def test_200_is_immutable_and_404_is_not(self):
        conf = open(os.path.join(REPO, 'config', 'nginx', 'rengine.conf'), encoding='utf-8').read()
        head = conf[:conf.index('server {')]
        loc = conf[conf.index('    location /staticfiles/'):]
        loc = loc[:loc.index('\n    }') + 6].replace('/usr/src/app/staticfiles/', '/srv/static/')
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o755)
            os.makedirs(f'{tmp}/static')
            with open(f'{tmp}/static/a.css', 'w') as f:
                f.write('a{}')
            os.chmod(f'{tmp}/static', 0o755)
            os.chmod(f'{tmp}/static/a.css', 0o644)
            with open(f'{tmp}/nginx.conf', 'w') as f:
                os.fchmod(f.fileno(), 0o644)
                f.write('events {}\nhttp {\n' + head + 'server { listen 8099;\n' + loc + '\n}\n}\n')
            name = f'cvengine-nginxtest-{os.getpid()}'
            subprocess.run(['docker', 'run', '-d', '--rm', '--name', name, '-p', f'127.0.0.1:{PORT}:8099', '-v', f'{tmp}/nginx.conf:/etc/nginx/nginx.conf:ro',
                            '-v', f'{tmp}/static:/srv/static:ro', 'nginx:alpine'], check=True, capture_output=True)
            self.addCleanup(lambda: subprocess.run(['docker', 'rm', '-f', name], capture_output=True))
            time.sleep(2)
            status, headers = self.fetch(f'/staticfiles/a.css?v={HASH}')
            self.assertEqual((status, headers['Cache-Control']), (200, 'public, max-age=31536000, immutable'))
            self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
            status, headers = self.fetch(f'/staticfiles/gone.css?v={HASH}')
            self.assertEqual(status, 404)
            self.assertIsNone(headers['Cache-Control'])
            self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
            status, headers = self.fetch('/staticfiles/a.css')
            self.assertEqual((status, headers['Cache-Control']), (200, 'no-cache'))
