"""The approved Nuclei template set as one downloadable tarball, for Sentinels.

The server runs nuclei on a snapshot directory of the installed templates that passed the template policy
(``cveFeed.nuclei_scan.approved_templates``). A Sentinel cannot rebuild that set from the policy's name alone, so the same snapshot is
packed here as a ``.tar.gz`` it can fetch (``GET /api/v1/sentinel/template-policy/bundle``) and run nuclei on, and the task target carries the
archive's sha256 so the Sentinel knows when its copy is stale.

The archive is built once per snapshot and kept on disk next to it (same directory, same lifetime), never per request, under the snapshot's own
lock, and served from disk by the caller. It is reproducible: files in sorted order, regular files only (a symlink is read through, and only
when it points inside the snapshot), relative paths, no directory entries, fixed owner, mode and times, and a gzip header with no name or time,
so identical content gives an identical sha256 on every server and every rebuild.
"""
import gzip
import hashlib
import logging
import os
import tarfile
import tempfile
import time
from collections import namedtuple

logger = logging.getLogger(__name__)

SUFFIX = '.bundle.tar.gz'
PART_SUFFIX = '.part'
MAX_FILES = 100_000  # the whole community library is about 10,000 templates
MAX_BYTES = 512 * 1024 * 1024  # of template text before compression
MAX_PACKED_BYTES = 256 * 1024 * 1024  # of archive
STALE_PART_SECONDS = 3600
TEMPLATE_SUFFIXES = ('.yaml', '.yml')

Bundle = namedtuple('Bundle', 'path sha256 bytes templates rev revision')
_BUILT = {}  # snapshot directory -> its Bundle; only touched under the snapshot lock
_TOO_BIG = {}  # snapshot directory -> (revision, why) of a snapshot over the caps, so a request never repeats the attempt


class BundleError(Exception):
    """The bundle cannot be offered (no snapshot, or it is over the size caps); the message is safe to show a Sentinel."""


class TooBig(BundleError):
    """The approved set is over a size cap: a property of the snapshot, so it is not retried until the snapshot changes."""


class _Sink:
    """Writes to a file while hashing and counting what goes through it, so the sha256 needs no second read and the size cap holds while packing."""

    def __init__(self, raw):
        self.raw, self.digest, self.size = raw, hashlib.sha256(), 0

    def write(self, data):
        self.size += len(data)
        if self.size > MAX_PACKED_BYTES:
            raise TooBig(f'the approved template bundle is larger than {MAX_PACKED_BYTES // (1024 * 1024)} MiB')
        self.digest.update(data)
        return self.raw.write(data)

    def flush(self):
        self.raw.flush()


def _safe_name(relative):
    """The archive name for a path relative to the snapshot, or ``None`` for one that is not a plain relative path."""
    name = relative.replace(os.sep, '/')
    parts = name.split('/')
    if name.startswith('/') or '\x00' in name or '\\' in name or any(part in ('', '.', '..') for part in parts):
        return None
    return name


def _collect(root):
    """``[(archive name, path, size)]`` of the regular files under ``root``, sorted by name. A symlink counts when it points at a regular file inside
    ``root`` (the snapshot holds copies, so this is belt and braces); anything else that is not a regular template file is left out."""
    real_root = os.path.realpath(root)
    found, total = [], 0
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(base, d)))
        for filename in files:
            if not filename.endswith(TEMPLATE_SUFFIXES):
                continue
            path = os.path.join(base, filename)
            name = _safe_name(os.path.relpath(path, root))
            if name is None:
                continue
            if os.path.islink(path):
                target = os.path.realpath(path)
                if os.path.commonpath([real_root, target]) != real_root:
                    continue
            try:
                info = os.stat(path)
            except OSError:
                continue
            if not os.path.isfile(path):
                continue
            found.append((name, path, info.st_size))
            total += info.st_size
            if len(found) > MAX_FILES:
                raise TooBig(f'the approved template set has more than {MAX_FILES} files')
            if total > MAX_BYTES:
                raise TooBig(f'the approved template set is larger than {MAX_BYTES // (1024 * 1024)} MiB')
    if not found:
        raise BundleError('the approved template set is empty')
    found.sort(key=lambda item: item[0])
    return found


def _sweep(keep):
    """Delete bundle files whose snapshot directory is gone, and part files a crashed build left behind (``keep`` is never touched)."""
    directory = tempfile.gettempdir()
    try:
        names = os.listdir(directory)
    except OSError:
        return
    now = time.time()
    for name in names:
        path = os.path.join(directory, name)
        if path == keep or not name.startswith('cvengine-approved-nuclei-'):
            continue
        try:
            if name.endswith(SUFFIX) and not os.path.isdir(path[:-len(SUFFIX)]):
                os.unlink(path)
            elif name.endswith(PART_SUFFIX) and now - os.path.getmtime(path) > STALE_PART_SECONDS:
                os.unlink(path)
        except OSError:
            continue


def _pack(root, final, rev, revision):
    files = _collect(root)
    handle, part = tempfile.mkstemp(prefix=os.path.basename(final) + '.', suffix=PART_SUFFIX, dir=os.path.dirname(final))
    try:
        with os.fdopen(handle, 'wb') as raw:
            sink = _Sink(raw)
            with gzip.GzipFile(filename='', mode='wb', compresslevel=6, fileobj=sink, mtime=0) as packed:
                with tarfile.open(fileobj=packed, mode='w', format=tarfile.GNU_FORMAT) as tar:
                    for name, path, size in files:
                        member = tarfile.TarInfo(name)
                        member.size, member.mode, member.mtime = size, 0o644, 0
                        member.uid = member.gid = 0
                        member.uname = member.gname = ''
                        with open(path, 'rb') as source:
                            tar.addfile(member, source)
        os.replace(part, final)
    except BundleError:
        _discard(part)
        raise
    except (OSError, tarfile.TarError) as error:
        _discard(part)
        logger.error('Could not pack the approved Nuclei templates: %s', error)
        raise BundleError('the approved template bundle could not be built') from error
    return Bundle(final, sink.digest.hexdigest(), sink.size, len(files), rev, revision)


def _discard(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _for_snapshot(directory, revision, count, rev):
    """The bundle of this snapshot: the one built before when its file is still there, else a new one (called under the snapshot lock)."""
    final = directory.rstrip('/') + SUFFIX
    known = _BUILT.get(directory)
    if known and known.revision == revision and known.rev == rev and os.path.isfile(known.path) and os.path.getsize(known.path) == known.bytes:
        return known
    refused = _TOO_BIG.get(directory)
    if refused and refused[0] == revision:
        raise TooBig(refused[1])
    try:
        bundle = _pack(directory, final, rev, revision)
    except TooBig as error:
        _TOO_BIG.clear()
        _TOO_BIG[directory] = (revision, str(error))
        raise
    for old_directory, old in list(_BUILT.items()):
        if old_directory != directory:
            _discard(old.path)
            del _BUILT[old_directory]
    _BUILT[directory] = bundle
    _sweep(final)
    logger.info('Built the approved Nuclei template bundle: %d templates, %d bytes, sha256 %s', bundle.templates, bundle.bytes, bundle.sha256)
    return bundle


def current():
    """The bundle of the approved snapshot in force now, built on first use. Raises ``BundleError`` when there is none or it is over the caps."""
    from cveFeed import nuclei_scan
    try:
        return nuclei_scan.with_approved_snapshot(_for_snapshot)
    except RuntimeError as error:  # no template library installed, or no template passed the policy
        raise BundleError(str(error)) from error


def policy(bundle, path):
    """The body of ``GET /api/v1/sentinel/template-policy``."""
    from cveFeed import nuclei_scan
    return {'rev': bundle.rev, 'read_only': bundle.rev == nuclei_scan.TEMPLATE_POLICY_REV,
            'bundle': {'sha256': bundle.sha256, 'bytes': bundle.bytes, 'templates': bundle.templates, 'path': path}}


def response(bundle, if_none_match=None):
    """The bundle as an HTTP response: 304 when the caller already has it, else the archive streamed from disk (never read into memory). The
    ``ETag`` is the sha256 in double quotes, as HTTP wants."""
    from django.http import FileResponse, HttpResponseNotModified
    etag = f'"{bundle.sha256}"'
    if matches(if_none_match, bundle.sha256):
        answer = HttpResponseNotModified()
    else:
        try:
            answer = FileResponse(open(bundle.path, 'rb'), content_type='application/gzip', as_attachment=True,
                                  filename=f'nuclei-templates-{bundle.sha256[:12]}.tar.gz')
        except OSError as error:  # the file went away between the lookup and the open (a rebuild swept it): the caller may simply ask again
            raise BundleError('the approved template bundle was just replaced; try again') from error
        answer['Content-Length'] = str(bundle.bytes)
    answer['ETag'] = etag
    answer['Cache-Control'] = 'private, no-cache'
    return answer


def sha256_if_ready():
    """The current bundle's sha256 for a task target, or ``None`` when it is not cheap to know: only an already cached snapshot is packed (once), a
    cold one is left for the first policy request. Never raises, so a dispatch never fails over a bundle."""
    from cveFeed import nuclei_scan
    try:
        if nuclei_scan.approved_snapshot_cached() is None:
            return None
        return current().sha256
    except Exception:  # noqa: BLE001 - the target simply carries no sha yet
        return None


def matches(header, sha256):
    """Whether an ``If-None-Match`` value names this bundle (a list, ``*``, weak and quoted forms all accepted)."""
    for item in (header or '').split(','):
        item = item.strip()
        if item == '*' or item.removeprefix('W/').strip('"') == sha256:
            return True
    return False
