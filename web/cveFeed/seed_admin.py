"""The CVE catalog seed from the Settings page: create one, download it, load one from another install. App Admin only.

Everything that touches the files lives here so the page, the API and the worker agree:

* The files sit in a private folder (``CVENGINE_SEED_DIR``, default ``~/.config/cvengine/seed`` inside the web and worker containers, which is
  the ``tool_config`` volume: shared by both, never served by the proxy, not part of the source tree). One seed at most: a new export replaces
  the old one, and a seed older than 24 hours is removed.
* One job at a time, export or import (a Redis lock). Its progress is a small record in the cache (``JOB``) that the page polls.
* An export is the same file ``manage.py export_cve_seed`` writes, including the scrub that withholds anything of this instance
  (cveFeed.seed_scrub); the manifest says how many records the scrub dropped and why.
* An import checks the upload against its manifest first (size, sha256, count) when one is given, then runs ``seed.import_seed``: the same
  validation as the command line and the first-run load.
"""
import os
import secrets
import time

from django.core.cache import cache

SEED_NAME = 'cve-seed.jsonl.gz'
LOCK = 'cvengine:cve-seed-building'  # one export or import at a time (the name predates imports)
JOB = 'cvengine:cve-seed-job'
KEEP_SECONDS = 24 * 3600
LOCK_SECONDS = 3600
MAX_UPLOAD = 256 * 1024 * 1024  # a whole catalog is about 14 MB today


def seed_dir():
    path = os.environ.get('CVENGINE_SEED_DIR', '').strip() or os.path.join(os.path.expanduser('~'), '.config', 'cvengine', 'seed')
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def seed_path():
    return os.path.join(seed_dir(), SEED_NAME)


def manifest_path():
    return seed_path() + '.manifest.json'


def _remove(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def prune(force=False):
    """Remove the exported seed once it is 24 hours old (``force``: now), and any upload a stopped import left behind."""
    directory = seed_dir()
    now = time.time()
    for name in os.listdir(directory):
        full = os.path.join(directory, name)
        try:
            age = now - os.path.getmtime(full)
        except OSError:
            continue
        if name.startswith('incoming-') and age > LOCK_SECONDS * 2:
            _remove(full)
        elif name.startswith(('.cve-seed-',)) and age > LOCK_SECONDS * 2:
            _remove(full)
        elif name in (SEED_NAME, SEED_NAME + '.manifest.json') and (force or age > KEEP_SECONDS):
            _remove(full)


def built():
    """The manifest of the seed on disk, and when it will be removed; ``(None, None)`` when there is none."""
    import json
    prune()
    try:
        with open(manifest_path(), encoding='utf-8') as f:
            manifest = json.load(f)
        modified = os.path.getmtime(manifest_path())
    except (OSError, ValueError):
        return None, None
    if not os.path.isfile(seed_path()) or not isinstance(manifest, dict):
        return None, None
    from datetime import datetime, timezone as tz
    return manifest, datetime.fromtimestamp(modified + KEEP_SECONDS, tz=tz.utc).isoformat()


def status():
    manifest, expires = built()
    job = cache.get(JOB)
    busy = bool(cache.get(LOCK))
    if job and job.get('state') == 'running' and not busy:  # the worker died: the lock ran out
        job = dict(job, state='failed', error='the job stopped before it finished')
    return {'built': manifest, 'building': busy, 'file': SEED_NAME if manifest else None, 'expires_at': expires, 'job': job}


def begin(kind, user):
    """Take the one-job lock and write the first progress record; False when another job holds it."""
    if not cache.add(LOCK, kind, LOCK_SECONDS):
        return False
    cache.set(JOB, {'kind': kind, 'state': 'running', 'stage': 'Queued', 'count': 0, 'by': user.username, 'started_at': time.time(),
                    'finished_at': None, 'error': '', 'result': None}, LOCK_SECONDS * 2)
    return True


def progress(**changes):
    job = cache.get(JOB) or {}
    job.update(changes)
    cache.set(JOB, job, LOCK_SECONDS * 2)


def finish(result=None, error=''):
    progress(state='failed' if error else 'done', error=error, result=result, finished_at=time.time(), stage='')
    cache.delete(LOCK)


def run_export(user_id):
    """The worker's side of 'Create seed file'. Returns the manifest numbers."""
    from django.contrib.auth.models import User
    from cveFeed import activity, detection_author, seed
    from cveFeed.admin_api import audit
    user = User.objects.filter(pk=user_id).first()
    handle = activity.log('inventory', 'Creating the CVE seed file', status='running')
    try:
        progress(stage='Writing any missing detection records')
        while detection_author.author_rules(batch=5000):
            pass
        detection_author.refresh_rules(batch=5000)
        detection_author.refresh_client_library_records(seconds=600)  # an exported seed carries the corrected library records
        prune(force=True)  # the next export replaces the last one
        manifest = seed.export_seed(seed_path(), progress=lambda n: progress(count=n), stage=lambda text: progress(stage=text))
    except Exception as exc:
        activity.settle(handle, 'failed', message='Creating the CVE seed file failed; see the worker log')
        finish(error='the export failed (%s)' % type(exc).__name__)
        raise
    dropped = manifest['dropped']
    activity.settle(handle, 'done', message=f"Created the CVE seed file: {manifest['count']} CVEs, {manifest['with_detection']} with a detection record"
                    + (f", {dropped['records'] + dropped['detections']} withheld by the scrub" if dropped['records'] + dropped['detections'] else ''))
    if user:
        audit(user, 'cve_seed.created', SEED_NAME, count=manifest['count'], bytes=manifest['bytes'], sha256=manifest['sha256'],
              dropped_records=dropped['records'], dropped_detections=dropped['detections'])
    finish(result={k: manifest[k] for k in ('count', 'tiers', 'with_detection', 'bytes', 'sha256')})
    return manifest['count']


def run_import(path, user_id, verified):
    """The worker's side of 'Import a seed file'; removes the upload when done."""
    from django.contrib.auth.models import User
    from cveFeed import activity, seed
    from cveFeed.admin_api import audit
    user = User.objects.filter(pk=user_id).first()
    handle = activity.log('feed', 'Importing a CVE seed file', status='running')
    try:
        progress(stage='Importing')
        counts = seed.import_seed(path, progress=lambda c: progress(count=c['seen'], stage=f"Importing: {c['created']} new so far"))
    except (OSError, ValueError) as exc:
        activity.settle(handle, 'failed', message='Importing the CVE seed file failed: %s' % str(exc)[:200])
        finish(error=str(exc)[:300])
        return None
    except Exception as exc:
        activity.settle(handle, 'failed', message='Importing the CVE seed file failed; see the worker log')
        finish(error='the import failed (%s)' % type(exc).__name__)
        raise
    finally:
        _remove(path)
    counts.pop('manifest', None)
    activity.settle(handle, 'done', message=f"Imported {counts['created']} CVEs and {counts['detections']} detection records from a seed file")
    if counts['created']:
        from startScan.models import Subdomain
        if Subdomain.objects.exists():  # an instance with hosts needs the new CVEs checked against them
            from cveFeed.tasks import correlate_cves
            correlate_cves.delay()
    if user:
        audit(user, 'cve_seed.imported', SEED_NAME, verified=verified, **{k: counts[k] for k in ('seen', 'created', 'skipped', 'detections', 'invalid')})
    finish(result=dict(counts, verified=verified))
    return counts['created']


def save_stream(request, limit, prefix):
    """Stream a request body into the private folder (mode 0600), never past ``limit`` bytes; returns the path. ValueError when it is too big
    or ends early."""
    path = os.path.join(seed_dir(), f'{prefix}-{secrets.token_hex(8)}')
    declared, size = int(request.META.get('CONTENT_LENGTH') or 0), 0
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as out:
            while True:
                chunk = request.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ValueError('the file is larger than the %d MB limit' % (limit >> 20))
                out.write(chunk)
        if size != declared:
            raise ValueError('the upload ended early; try again')
    except BaseException:
        _remove(path)
        raise
    return path
