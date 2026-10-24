"""Shareable worker failure metadata without prompts, customer data, or secrets."""
import hashlib
import re
import traceback

from django.utils import timezone


def _failure_code(error):
    """Classify known framework errors without copying exception text or scan data."""
    message = str(error).lower()
    for needle, code in (
        ('invalid literal for int', 'invalid_integer'),
        ('port could not be cast', 'invalid_url_port'),
        ('port out of range', 'invalid_url_port'),
        ('invalid ipv6 url', 'invalid_url'),
        ('cannot be both deferred and traversed', 'invalid_query'),
        ('expected a number', 'invalid_record_reference'),
        ('is not a valid uuid', 'invalid_record_reference'),
    ):
        if needle in message:
            return code
    return 'unexpected_value' if isinstance(error, ValueError) else 'unexpected_error'


def worker_failure(error, *, stage, job_id, finding_id, finding_kind=None):
    frames = traceback.extract_tb(error.__traceback__)[-8:]
    # Traceback source lines and exception messages can contain scanned URLs,
    # payloads or credentials. Only static frame identities are retained.
    stack = []
    for frame in frames:
        path = frame.filename.replace('\\', '/')
        if '/web/' in path:
            path = path.rsplit('/web/', 1)[-1]
        else:
            path = path.rsplit('/', 1)[-1]
        path = re.sub(r'[^A-Za-z0-9_./-]', '', path)[:100]
        function = re.sub(r'[^A-Za-z0-9_]', '', frame.name)[:80]
        stack.append(f'{path}:{int(frame.lineno)} {function}')
    category = re.sub(r'[^A-Za-z0-9_]', '', type(error).__name__)[:40] or 'Exception'
    now = timezone.now()
    digest = hashlib.sha256(f'{stage}:{category}:{job_id}:{now.isoformat()}'.encode()).hexdigest()[:12]
    kind = finding_kind if finding_kind in ('cve_match', 'nuclei', 'db_exposure', 'route_auth', 'hygiene', 'bbot') else 'unknown'
    return {'id': digest, 'time': now.isoformat(), 'stage': stage[:40], 'category': category,
            'failure_code': _failure_code(error), 'finding_kind': kind,
            'job_id': job_id, 'finding_id': finding_id, 'stack': '\n'.join(stack)[:1200],
            'outcome': 'failed', 'action': 'Share this diagnostic ID and finding kind with an administrator.'}
