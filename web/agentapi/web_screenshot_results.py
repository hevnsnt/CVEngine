"""The server's reading of a ``web_screenshot`` result (contract version 3): the pictures a Sentinel's browser took of the pages of one task.

Every byte of it is untrusted. ``clean`` keeps the contract's shape, clips every string, and checks every picture before anything opens it: valid
base64, at most ``MAX_IMAGE_BYTES``, a PNG signature, an ``IHDR`` chunk whose checksum holds and whose sides are at most ``MAX_IMAGE_SIDE``, and the
closing ``IEND`` chunk, so a hostile page or Sentinel cannot hand the server's image library a decompression bomb or a file that only says it is an
image. A picture that fails is not stored: its page is reported as an error with the reason. ``bind`` then cuts the result down to the pages the task
asked about (an id the task did not name is dropped, and counted), so a Sentinel can only ever answer for its own task's pages, and holds each
picture to the size cap the task carried. Names a Sentinel reports are never used as file names: ``cveFeed.web_shot`` writes every picture to a path
of its own making.
"""
import base64
import binascii
import struct
import zlib

from agentapi.services import ApiError

MAX_PAGES = 6                      # pages in one task (the contract's bound): six pictures of at most 2 MiB stay under the 24 MiB a result body may be
MAX_IMAGE_BYTES = 2 * 1024 * 1024  # the contract's bound; a task may ask for less (``max_bytes``)
MAX_IMAGE_SIDE = 4096              # a capture is 1280x800; a PNG that claims more is not one, and is never handed to an image library
OUTCOMES = ('ok', 'timeout', 'unreachable', 'tls_error', 'error', 'blank', 'blocked', 'too_big', 'unavailable')
MAX_HOSTS = 2000
_PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
_PNG_END = b'\x00\x00\x00\x00IEND\xaeB`\x82'
TOO_BIG = 'The picture is larger than the size allowed.'


def _text(value, limit):
    from agentapi.sentinel_broker import _text as clip
    return clip(value, limit)


def _hosts(values):
    if not isinstance(values, list):
        return []
    out = []
    for value in values[:MAX_HOSTS]:
        host = _text(value, 260).strip().lower().rstrip('.')
        if host and not any(c.isspace() for c in host) and host not in out:
            out.append(host)
    return out


def png_problem(data):
    """Why ``data`` is not a PNG this server will open (``''`` when it is): the signature, an ``IHDR`` chunk of length 13 with a good checksum, sides
    from 1 to ``MAX_IMAGE_SIDE``, and the ``IEND`` chunk that closes every PNG."""
    if len(data) < 45 or not data.startswith(_PNG_SIGNATURE):
        return 'not a PNG'
    length, kind = struct.unpack('>I4s', data[8:16])
    if length != 13 or kind != b'IHDR':
        return 'no IHDR chunk'
    header, crc = data[16:29], struct.unpack('>I', data[29:33])[0]
    if zlib.crc32(b'IHDR' + header) & 0xFFFFFFFF != crc:
        return 'IHDR checksum'
    width, height = struct.unpack('>II', header[:8])
    if not (0 < width <= MAX_IMAGE_SIDE and 0 < height <= MAX_IMAGE_SIDE):
        return f'sides above {MAX_IMAGE_SIDE} pixels'
    if not data.endswith(_PNG_END):
        return 'no IEND chunk'
    return ''


def _picture(raw):
    """``(base64 text, reason)``: the picture when it passes every check above, else ``''`` and why it was refused."""
    if not isinstance(raw, str) or not raw:
        return '', 'The scanner reported a picture that was not sent.'
    if len(raw) > (MAX_IMAGE_BYTES + 2) // 3 * 4:
        return '', TOO_BIG
    try:
        data = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return '', 'The picture was not valid base64.'
    if len(data) > MAX_IMAGE_BYTES:
        return '', TOO_BIG
    problem = png_problem(data)
    return ('', f'The picture was not a usable PNG ({problem}).') if problem else (raw, '')


def _page(item):
    if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'].strip() or len(item['id']) > 40:
        return None
    outcome = item.get('outcome')
    if outcome not in OUTCOMES:
        return None
    status = item.get('status')
    page = {'id': item['id'], 'outcome': outcome, 'reason': _text(item.get('reason'), 300), 'final_url': _text(item.get('final_url'), 2000),
            'status': status if isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 999 else None,
            'title': _text(item.get('title'), 300)}
    if outcome == 'ok':
        image, why = _picture(item.get('image'))
        if why:
            page.update(outcome='error', reason=why)
        else:
            page['image'] = image
    return page


def clean(body):
    pages = body.get('pages')
    if not isinstance(pages, list) or len(pages) > MAX_PAGES:
        raise ApiError(400, 'a web_screenshot result lists its pages (at most %d)' % MAX_PAGES)
    sandbox = body.get('sandbox')
    if not isinstance(sandbox, dict) or not isinstance(sandbox.get('engaged'), bool):
        raise ApiError(400, 'a web_screenshot result says whether the browser sandbox engaged')
    out = {'sandbox': {'engaged': sandbox['engaged'], 'reason': _text(sandbox.get('reason'), 400), 'version': _text(sandbox.get('version'), 60)},
           'pages': [p for p in map(_page, pages) if p is not None], 'touched': _hosts(body.get('touched')), 'refused': _hosts(body.get('refused'))}
    dropped = body.get('dropped_requests')
    out['dropped_requests'] = dropped if isinstance(dropped, int) and not isinstance(dropped, bool) and dropped >= 0 else 0
    if not out['sandbox']['engaged']:
        out['pages'] = []  # a browser that was not proven sandboxed opened nothing, whatever it says it did
    return out


def bind(result, task):
    """``result`` cut down to the pages ``task`` asked about, each once, and each picture held to the size the task allowed."""
    target = task.target if isinstance(task.target, dict) else {}
    asked = {p.get('id') for p in target.get('pages') or [] if isinstance(p, dict)}
    limit = target.get('max_bytes')
    limit = limit if isinstance(limit, int) and not isinstance(limit, bool) and 0 < limit <= MAX_IMAGE_BYTES else MAX_IMAGE_BYTES
    kept, seen = [], set()
    for page in result['pages']:
        if page['id'] not in asked or page['id'] in seen:
            continue
        seen.add(page['id'])
        if page.get('image') and len(base64.b64decode(page['image'])) > limit:
            page = {k: v for k, v in page.items() if k != 'image'}
            page.update(outcome='error', reason=TOO_BIG)
        kept.append(page)
    dropped = len(result['pages']) - len(kept)
    result = {**result, 'pages': kept}
    return {**result, 'dropped': dropped} if dropped else result
