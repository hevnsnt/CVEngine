"""The CVE catalog as a file: export it from one instance, import it into another.

Hydrating the catalog from cve.now takes one request per CVE (tens of thousands), so every new install used to spend hours rebuilding
what another instance already had. A seed is that catalog, pre-processed, as one gzip of JSON lines: every CVE with its scores, exploitation
signals, affected ranges and references, and its shared detection record (remote steps, host commands, validation profile; see
cveFeed.detection). A fresh install imports the published seed on first start and the incremental feed takes over from there.

Format 1: line 1 is the manifest ``{"format": 1, ...}``, every other line one CVE. ``<seed>.manifest.json`` beside the file carries the
count, size and sha256 so a download can be verified.

The seed is data from outside, so nothing in it is trusted: every field is typed and clipped on the way in, and each detection strategy
is re-validated against the allowlist and its commands and profile are rendered again here, whatever the file says."""
import gzip
import hashlib
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone as dt_timezone

from django.utils import timezone

from cveFeed import detection
from cveFeed.models import CVEDetection, CVEEntry

logger = logging.getLogger(__name__)

FORMAT = 1
DEFAULT_URL = 'https://github.com/hevnsnt/CVEngine/releases/download/cve-seed/cve-seed.jsonl.gz'
MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 6 * 1024 * 1024 * 1024  # a full catalogue is well under 1 GB of JSON
MAX_MANIFEST_BYTES = 64 * 1024
CVE_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]{3,63}$')
TEXT_LIMITS = {'title': 2000, 'summary': 8000, 'summary_model': 128, 'original_description': 8000, 'cvss_vector': 128,
               'severity_source': 128, 'stated_severity': 128, 'status': 128}


def seed_url():
    return os.environ.get('CVENGINE_CVE_SEED_URL', DEFAULT_URL).strip()


def seed_enabled():
    return os.environ.get('CVENGINE_CVE_SEED', '1').strip().lower() not in ('0', 'off', 'false', 'no')


# --- export -----------------------------------------------------------------------------------------------------------------

def _iso(value):
    return value.isoformat() if value else None


def record_for(cve, detection_row=None):
    """One catalog line for a CVE. The feed's full entry is not stored, so none is shipped."""
    from cveFeed.threat import classify_threat_tier
    record = {'cve_id': cve.cve_id, 'tier': classify_threat_tier(cve.kev, cve.epss_reached, cve.exploit_db, cve.cvss),
              'cvss': cve.cvss, 'kev': cve.kev, 'epss_reached': cve.epss_reached, 'exploit_db': cve.exploit_db,
              'affected': cve.affected, 'references': cve.references, 'sources': cve.sources, 'intel': cve.intel,
              'published_at': _iso(cve.published_at), 'first_seen_at': _iso(cve.first_seen_at)}
    for field in TEXT_LIMITS:
        record[field] = getattr(cve, field)
    if detection_row is not None and detection_row.strategy:
        record['detection'] = {'source': detection_row.source, 'schema_version': detection_row.schema_version,
                               'strategy': detection_row.strategy}
    return record


def export_seed(path, progress=None):
    """Write the whole catalog to ``path`` (and ``path`` + ``.manifest.json`` beside it). Returns the manifest."""
    from django.db.models import Max
    detections = {d.cve_entry_id: d for d in CVEDetection.objects.exclude(strategy={}).iterator(chunk_size=2000)}
    tiers, count = {'fire': 0, 'smoke': 0, 'ice': 0}, 0
    # the newest publication time the snapshot holds: what a consumer may assume the feed is complete through (the export time says when
    # it was written, not what the catalog had read by then)
    covers_through = _iso(CVEEntry.objects.aggregate(newest=Max('published_at'))['newest'])
    directory = os.path.dirname(os.path.abspath(path))
    handle, tmp = tempfile.mkstemp(prefix='.cve-seed-', dir=directory)
    os.close(handle)
    try:
        with gzip.open(tmp, 'wt', encoding='utf-8', compresslevel=9) as out:
            out.write(json.dumps({'format': FORMAT, 'generated_at': timezone.now().isoformat(), 'covers_through': covers_through,
                                  'detection_schema': detection.SCHEMA_VERSION}) + '\n')
            for cve in CVEEntry.objects.order_by('id').iterator(chunk_size=2000):
                record = record_for(cve, detections.get(cve.id))
                tiers[record['tier']] += 1
                out.write(json.dumps(record, separators=(',', ':'), default=str) + '\n')
                count += 1
                if progress and count % 5000 == 0:
                    progress(count)
        digest = hashlib.sha256()
        with open(tmp, 'rb') as f:
            for block in iter(lambda: f.read(1 << 20), b''):
                digest.update(block)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    manifest = {'format': FORMAT, 'generated_at': timezone.now().isoformat(), 'covers_through': covers_through, 'count': count, 'tiers': tiers,
                'with_detection': sum(1 for d in detections.values()), 'bytes': os.path.getsize(path), 'sha256': digest.hexdigest()}
    with open(path + '.manifest.json', 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=1)
    return manifest


# --- import -----------------------------------------------------------------------------------------------------------------

def _time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt_timezone.utc)


def _flag(value):
    return value if isinstance(value, bool) else None


def _list(value, limit=500):
    return value[:limit] if isinstance(value, list) else []


def clean_record(raw):
    """The CVEEntry field values for one catalog line, or None when the line is not a usable CVE."""
    from cveFeed.correlation import clean_affected
    if not isinstance(raw, dict) or not isinstance(raw.get('cve_id'), str) or not CVE_ID.match(raw['cve_id']):
        return None
    cvss = raw.get('cvss')
    fields = {'cve_id': raw['cve_id'][:64], 'cvss': float(cvss) if isinstance(cvss, (int, float)) and not isinstance(cvss, bool) and 0 <= cvss <= 10 else None,
              'kev': _flag(raw.get('kev')), 'epss_reached': _flag(raw.get('epss_reached')), 'exploit_db': _flag(raw.get('exploit_db')),
              'affected': clean_affected(raw.get('affected')), 'references': _list(raw.get('references')), 'sources': _list(raw.get('sources')),
              'intel': raw.get('intel') if isinstance(raw.get('intel'), dict) else {},
              'published_at': _time(raw.get('published_at')), 'first_seen_at': _time(raw.get('first_seen_at'))}
    for field, limit in TEXT_LIMITS.items():
        value = raw.get(field)
        fields[field] = value[:limit] if isinstance(value, str) else ''
    return fields


def detection_for(raw, cvss_vector):
    """The detection record fields for a catalog line: the strategy re-validated and re-rendered here, or None."""
    block = raw.get('detection')
    if not isinstance(block, dict) or block.get('source') not in ('rules', 'ai'):  # a manual record is local to the instance that wrote it
        return None
    strategy, _ = detection.validate_strategy(block.get('strategy'))
    if strategy is None:
        return None
    return {'source': block['source'], 'strategy': detection.finalize(strategy, cvss_vector), 'schema_version': detection.SCHEMA_VERSION}


def iter_lines(path):
    """The manifest and then the catalog lines of a seed file, each a decoded object. Over-long or undecodable lines are skipped.
    Each line is read with a length limit (a line with no newline never fills memory) and the decompressed total is capped, so a
    crafted file cannot exhaust a worker; a file that expands past the cap is refused."""
    consumed = 0

    def check(chunk):
        nonlocal consumed
        consumed += len(chunk)
        if consumed > MAX_DECOMPRESSED_BYTES:
            raise ValueError('the seed expands to more than the allowed %d MB' % (MAX_DECOMPRESSED_BYTES >> 20))

    with gzip.open(path, 'rb') as handle:
        first = handle.readline(MAX_LINE_BYTES + 1)
        check(first)
        manifest = json.loads(first.decode('utf-8', errors='replace')) if len(first) <= MAX_LINE_BYTES and first.strip() else {}
        if not isinstance(manifest, dict) or manifest.get('format') != FORMAT:
            raise ValueError('not a CVEngine CVE seed (format %r)' % (manifest.get('format') if isinstance(manifest, dict) else None))
        yield manifest
        while True:
            line = handle.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            check(line)
            if len(line) > MAX_LINE_BYTES and not line.endswith(b'\n'):  # over-long: read past the rest of it without keeping it
                while True:
                    chunk = handle.readline(MAX_LINE_BYTES + 1)
                    check(chunk)
                    if not chunk or chunk.endswith(b'\n'):
                        break
                continue
            if not line.strip() or len(line) > MAX_LINE_BYTES:
                continue
            try:
                yield json.loads(line.decode('utf-8', errors='replace'))
            except ValueError:
                continue


def import_seed(path, batch=1000, progress=None):
    """Add the catalog's CVEs this instance lacks, and its detection records where a CVE has none. A CVE already here is never
    overwritten (the incremental feed keeps it current). Safe to run again. Returns the counts."""
    stream = iter_lines(path)
    manifest = next(stream)
    counts = {'seen': 0, 'created': 0, 'skipped': 0, 'invalid': 0, 'detections': 0, 'manifest': manifest}
    pending = []

    def flush():
        if not pending:
            return
        ids = [p[0]['cve_id'] for p in pending]
        known = set(CVEEntry.objects.filter(cve_id__in=ids).values_list('cve_id', flat=True))
        fresh = [p for p in pending if p[0]['cve_id'] not in known]
        CVEEntry.objects.bulk_create([CVEEntry(**p[0]) for p in fresh], ignore_conflicts=True, batch_size=500)
        counts['created'] += len(fresh)
        counts['skipped'] += len(pending) - len(fresh)
        by_id = dict(CVEEntry.objects.filter(cve_id__in=ids).values_list('cve_id', 'id'))
        have = set(CVEDetection.objects.filter(cve_entry_id__in=by_id.values()).values_list('cve_entry_id', flat=True))
        rows = [CVEDetection(cve_entry_id=by_id[p[0]['cve_id']], rules_at=timezone.now(), **p[1]) for p in pending
                if p[1] and p[0]['cve_id'] in by_id and by_id[p[0]['cve_id']] not in have]
        CVEDetection.objects.bulk_create(rows, ignore_conflicts=True, batch_size=500)
        counts['detections'] += len(rows)
        pending.clear()

    for raw in stream:
        counts['seen'] += 1
        fields = clean_record(raw)
        if fields is None:
            counts['invalid'] += 1
            continue
        pending.append((fields, detection_for(raw, fields['cvss_vector'])))
        if len(pending) >= batch:
            flush()
            if progress:
                progress(counts)
    flush()
    # the feed is complete through what the snapshot holds (older seeds only say when they were written, which is later than that:
    # the walk's margin and the coverage window absorb the difference)
    from cveFeed import feed_watermark
    feed_watermark.note_snapshot(_time(manifest.get('covers_through')) or _time(manifest.get('generated_at')))
    return counts


# --- download ---------------------------------------------------------------------------------------------------------------

def _fetch_manifest(session, url):
    """The manifest object at ``url``: an HTTP error is an error, and the body is read with a size cap."""
    with session.get(url, stream=True, timeout=30) as response:
        response.raise_for_status()
        body, size = [], 0
        for block in response.iter_content(8192):
            size += len(block)
            if size > MAX_MANIFEST_BYTES:
                raise ValueError('the seed manifest is larger than expected')
            body.append(block)
    try:
        return json.loads(b''.join(body).decode('utf-8'))
    except ValueError:
        raise ValueError('the seed manifest is missing or not understood') from None


def download_seed(url=None, directory=None, session=None):
    """Fetch the seed and verify it against its manifest; returns the local path. Raises when the manifest or the checksum is missing or wrong."""
    import requests
    url = url or seed_url()
    if not url.startswith('https://'):
        raise ValueError('the seed URL must be https')
    session = session or requests.Session()
    manifest = _fetch_manifest(session, url + '.manifest.json')
    if not isinstance(manifest, dict) or manifest.get('format') != FORMAT or not re.fullmatch(r'[0-9a-f]{64}', str(manifest.get('sha256', ''))):
        raise ValueError('the seed manifest is missing or not understood')
    if int(manifest.get('bytes') or 0) > MAX_DOWNLOAD_BYTES:
        raise ValueError('the seed is larger than the download limit')
    directory = directory or tempfile.gettempdir()
    handle, path = tempfile.mkstemp(prefix='cve-seed-', suffix='.jsonl.gz', dir=directory)
    digest, size = hashlib.sha256(), 0
    try:
        with os.fdopen(handle, 'wb') as out, session.get(url, stream=True, timeout=60) as response:
            response.raise_for_status()
            for block in response.iter_content(1 << 20):
                size += len(block)
                if size > MAX_DOWNLOAD_BYTES:
                    raise ValueError('the seed is larger than the download limit')
                digest.update(block)
                out.write(block)
        if digest.hexdigest() != manifest['sha256']:
            raise ValueError('the seed does not match the checksum in its manifest')
    except BaseException:
        os.unlink(path)
        raise
    return path


def load_published_seed(url=None, session=None):
    """Download and import the published seed. Returns the import counts; raises on a network or verification failure."""
    path = download_seed(url, session=session)
    try:
        return import_seed(path)
    finally:
        os.unlink(path)
