"""The reviewer's only line to cvENGINE: ``/api/v1/reviewer/*`` on the compose network, with the token the server left on the shared volume.
Standard library only. The token is read from its file when needed and again after a 401 (the server replaces it before it expires)."""
import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

MAX_BYTES = 8_000_000
_REF = re.compile(r'^t\d{1,12}$')
_JOB = re.compile(r'^\d{1,12}$')


class ServerError(RuntimeError):
    def __init__(self, message, status=0):
        super().__init__(message)
        self.status = status


class Server:
    def __init__(self, base=None, token_file=None, timeout=60):
        self.base = (base or os.environ.get('CVENGINE_REVIEWER_SERVER', 'http://web:8000')).rstrip('/')
        self.token_file = token_file or os.environ.get('CVENGINE_REVIEWER_TOKEN_FILE', '/bootstrap/token')
        self.timeout = timeout
        self._token = None

    def token(self, reload=False):
        if self._token is None or reload:
            try:
                with open(self.token_file, encoding='utf-8') as handle:
                    value = handle.read().strip()
            except OSError:
                value = ''
            self._token = value if re.fullmatch(r'cve_[A-Za-z0-9_-]{20,80}', value or '') else None
        return self._token

    def _request(self, method, path, body=None, query=None, retry=True):
        token = self.token()
        if not token:
            raise ServerError('no token yet: the server has not written one (is CVENGINE_REVIEWER on and an App Admin set up?)')
        url = f'{self.base}/api/v1/reviewer/{path}'
        if query:
            url += '?' + urllib.parse.urlencode(query)
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method, headers={
            'Authorization': f'Bearer {token}', 'Accept': 'application/json',
            **({'Content-Type': 'application/json'} if data is not None else {})})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - the server's own compose address
                raw = response.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 401 and retry and self.token(reload=True) not in (None, token):
                return self._request(method, path, body, query, retry=False)  # the server replaced the token
            try:
                message = json.loads(exc.read(20_000) or b'{}').get('error') or ''
            except (ValueError, AttributeError):
                message = ''
            raise ServerError(f'{method} {path}: HTTP {exc.code} {str(message)[:200]}', exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ServerError(f'{method} {path}: the server is unreachable ({type(exc).__name__})') from None
        if len(raw) > MAX_BYTES:
            raise ServerError(f'{method} {path}: oversized answer')
        try:
            return json.loads(raw or b'{}')
        except ValueError:
            raise ServerError(f'{method} {path}: the answer is not JSON') from None

    def config(self):
        return self._request('GET', 'config')

    def next_findings(self, limit):
        return self._request('GET', 'findings/next', query={'limit': int(limit)}).get('packets') or []

    def verdict(self, ref, body):
        if not _REF.match(str(ref)):
            raise ServerError('a packet with a malformed reference')
        return self._request('POST', f'findings/{ref}/verdict', body=body)

    def refusal(self, ref, body):
        """Tell the server the model gave no usable answer for this packet, so it is not handed out again at once."""
        if not _REF.match(str(ref)):
            raise ServerError('a packet with a malformed reference')
        return self._request('POST', f'findings/{ref}/refusal', body=body)

    def next_jobs(self, limit):
        return self._request('GET', 'jobs/next', query={'limit': int(limit)}).get('jobs') or []

    def job_result(self, job_id, body):
        if not _JOB.match(str(job_id)):
            raise ServerError('a job with a malformed id')
        return self._request('POST', f'jobs/{job_id}/result', body=body)

    def usage(self, body):
        return self._request('POST', 'usage', body=body)

    def ops_snapshot(self, release=None):
        query = {'templates_release': release['tag'], 'templates_published_at': release.get('published_at', '')} if release else None
        return self._request('GET', 'ops/snapshot', query=query)

    def ops_report(self, body):
        return self._request('POST', 'ops/report', body=body)


def latest_templates_release(timeout=10):
    """The newest nuclei-templates release, ``{tag, published_at}``, from GitHub's API at a fixed URL, or None. The model plays no part
    in this request."""
    request = urllib.request.Request('https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest',
                                     headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'cvengine-reviewer'})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - a fixed https URL
            data = json.loads(response.read(500_000))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    tag = str(data.get('tag_name') or '') if isinstance(data, dict) else ''
    if not re.fullmatch(r'v?\d+(?:\.\d+){1,3}', tag):
        return None
    published = str(data.get('published_at') or '')
    return {'tag': tag, 'published_at': published if re.fullmatch(r'[0-9T:.Z+-]{10,40}', published) else ''}
