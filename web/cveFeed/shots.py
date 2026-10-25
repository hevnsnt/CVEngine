"""Screenshot diffing: did the front page of a host change visibly between two scans?

Each screenshot gowitness takes is reduced to a 64-bit difference hash (dhash): the image is scaled to 9 by 8 grey pixels and
every pixel is compared with its right neighbour. Two screenshots of the same page differ in a few bits; a page that was
replaced differs in many. The hamming distance between two hashes is compared with a threshold. Pillow is optional at run
time: without it ``dhash_file`` returns an empty hash and nothing is compared.
"""
import logging
import os
import warnings

try:
    from PIL import Image
except ImportError:  # pragma: no cover - exercised by patching Image to None
    Image = None

logger = logging.getLogger(__name__)

CROP_TOP_RATIO = 0.0  # gowitness captures the page only; kept for tuning (a browser bar would be cropped here)
MAX_HASH_PER_FLUSH = 100  # screenshots hashed per persist_screenshots call (bbot delivers them in small batches anyway)
MAX_SHOT_DIFFS_PER_SCAN = 1000
DEFAULT_THRESHOLD = 12  # bits of 64 (CVENGINE_SHOT_THRESHOLD)
HASH_BITS = 64
_warned = []  # scan ids already told that Pillow is missing (bounded)


def threshold():
    try:
        return max(1, min(HASH_BITS, int(os.environ.get('CVENGINE_SHOT_THRESHOLD', DEFAULT_THRESHOLD))))
    except ValueError:
        return DEFAULT_THRESHOLD


def available():
    return Image is not None


MAX_SHOT_BYTES = 8 * 1024 * 1024  # a screenshot is a few hundred KB; a bigger file is not one gowitness made
MAX_SHOT_PIXELS = 50_000_000


def dhash_file(path, size=8):
    """The difference hash of an image file as 16 hex characters, or an empty string when the file cannot be read as an
    image (missing, corrupt, over MAX_SHOT_BYTES or MAX_SHOT_PIXELS, a decompression bomb) or Pillow is not installed. Never
    raises. The file is a page capture of a target's content, so it is size-checked before it is opened and Pillow's own
    decompression-bomb warning is treated as an error."""
    if Image is None:
        return ''
    try:
        if os.stat(path).st_size > MAX_SHOT_BYTES:
            logger.warning('screenshot %s is larger than %s bytes: not hashed', path, MAX_SHOT_BYTES)
            return ''
        with warnings.catch_warnings():
            # Pillow only warns between its pixel limit and twice the limit (and raises above): make both an error, and set the
            # filter before opening, because the check runs inside Image.open
            warnings.simplefilter('error', getattr(Image, 'DecompressionBombWarning', Warning))
            with Image.open(path) as image:
                if image.width * image.height > MAX_SHOT_PIXELS:
                    logger.warning('screenshot %s has too many pixels: not hashed', path)
                    return ''
                if hasattr(image, 'draft'):
                    image.draft('L', (size * 16, size * 16))  # JPEGs decode at a fraction of the size
                grey = image.convert('L')
                if CROP_TOP_RATIO:
                    grey = grey.crop((0, int(grey.height * CROP_TOP_RATIO), grey.width, grey.height))
                small = grey.resize((size + 1, size), getattr(Image, 'Resampling', Image).LANCZOS)
                pixels = small.tobytes()
    except Exception as exc:  # noqa: BLE001 - a bad screenshot must never interrupt discovery
        logger.warning('could not hash screenshot %s: %s', path, exc)
        return ''
    bits = 0
    for row in range(size):
        for col in range(size):
            bits = (bits << 1) | (pixels[row * (size + 1) + col] > pixels[row * (size + 1) + col + 1])
    return f'{bits:0{size * size // 4}x}'


THUMB_WIDTH = 320


def thumbnail_path(path, width=THUMB_WIDTH):
    """The path of a ``width``-pixel-wide JPEG thumbnail of the screenshot at ``path``, written beside it the first time and
    whenever the original is newer, or ``None`` when one cannot be made (Pillow missing, over MAX_SHOT_BYTES or MAX_SHOT_PIXELS,
    corrupt, a decompression bomb), in which case the caller serves the full image. Never raises. Guarded exactly like
    ``dhash_file``: the file is a page capture of a target's content."""
    if Image is None:
        return None
    thumb = f'{path}.thumb-{width}.jpg'
    try:
        info = os.stat(path)
        if os.path.isfile(thumb) and os.stat(thumb).st_mtime >= info.st_mtime:
            return thumb
        if info.st_size > MAX_SHOT_BYTES:
            logger.warning('screenshot %s is larger than %s bytes: not thumbnailed', path, MAX_SHOT_BYTES)
            return None
        with warnings.catch_warnings():
            warnings.simplefilter('error', getattr(Image, 'DecompressionBombWarning', Warning))
            with Image.open(path) as image:
                if image.width * image.height > MAX_SHOT_PIXELS:
                    logger.warning('screenshot %s has too many pixels: not thumbnailed', path)
                    return None
                if hasattr(image, 'draft'):
                    image.draft('RGB', (width * 2, width * 2))  # JPEGs decode at a fraction of the size
                rgb = image.convert('RGB')
                height = max(1, round(rgb.height * width / rgb.width)) if rgb.width > width else rgb.height
                small = rgb.resize((min(width, rgb.width), height), getattr(Image, 'Resampling', Image).LANCZOS)
                partial = f'{thumb}.{os.getpid()}.tmp'
                small.save(partial, 'JPEG', quality=80, optimize=True)
        os.replace(partial, thumb)  # atomic: a concurrent request never serves half a file
        return thumb
    except Exception as exc:  # noqa: BLE001 - a bad screenshot must never fail the page that shows it
        logger.warning('could not thumbnail screenshot %s: %s', path, exc)
        return None


def hamming(a, b):
    """Bits that differ between two hashes (0 to 64)."""
    return bin(int(a, 16) ^ int(b, 16)).count('1')


def warn_unavailable(scan):
    """One activity line per scan saying comparison is off because Pillow is not installed."""
    if Image is not None or scan.id in _warned:
        return
    _warned.append(scan.id)
    del _warned[:-1000]
    from cveFeed import activity
    activity.log('scan', 'screenshot comparison skipped: Pillow is not installed', project=scan.domain.project_id, scan_id=scan.id)
