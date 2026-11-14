"""Text from a scanned host is untrusted, and Postgres refuses two things a host can send: a NUL character (U+0000) in text or JSON, and a lone
surrogate (U+D800 to U+DFFF), which JSON allows and UTF-8 does not. One such character in a banner, a header or a certificate field used to make the
write of a Sentinel's whole result fail (``DataError``), so the task could never be stored: the Sentinel sent it again until its lease ran out and
the host stayed unchecked. ``clean`` runs over everything a Sentinel or agent reports before it is stored. It changes nothing else."""
import re

_BAD = re.compile('[\x00\ud800-\udfff]')
MAX_DEPTH = 24
REPLACEMENT = '\ufffd'


def text(value):
    """``value`` without NUL and with each lone surrogate replaced by U+FFFD, so it is valid UTF-8 and valid JSON text for Postgres."""
    if not _BAD.search(value):
        return value
    return _BAD.sub(lambda m: '' if m.group() == '\x00' else REPLACEMENT, value)


def clean(value, _depth=0):
    """``value`` (strings, lists, dicts, numbers, None) with every string and every dict key made safe for Postgres. Anything nested deeper than
    ``MAX_DEPTH`` is dropped: a JSON document that deep is not a scan result."""
    if isinstance(value, str):
        return text(value)
    if _depth >= MAX_DEPTH:
        return None
    if isinstance(value, dict):
        return {(text(k) if isinstance(k, str) else k): clean(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v, _depth + 1) for v in value]
    return value
