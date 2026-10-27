"""Decode (and, for completeness, encode) the Sentinel provisioning blob.

The blob is standard base64 (RFC 4648, with padding) of compact JSON, nothing more: no custom framing, no new key
material, no signing. It is exactly the payload ``POST /api/v1/projects/{slug}/sentinels/enroll`` already returns
(``{enrollment_token, server_url, expires_at, project}``), packaged as one copy-pasteable string for a Sentinel's
``CVENGINE_SENTINEL_BLOB`` environment variable. This module is the client-side half of the format the server
documents and produces in ``agentapi.sentinel_broker.encode_enrollment_blob``/``decode_enrollment_blob``; the two are
not a shared import (this client has no Django dependency and ships separately from the server), so both sides
implement the same few lines independently, documented identically in both places.
"""
import base64
import binascii
import json

REQUIRED_FIELDS = ('enrollment_token', 'server_url')


class BlobError(ValueError):
    """CVENGINE_SENTINEL_BLOB was not a valid provisioning blob. The message says why, never the raw value: it may be
    (or contain) a live enrollment secret, so callers must not log it."""


def decode_blob(raw):
    """``CVENGINE_SENTINEL_BLOB`` -> ``{enrollment_token, server_url, expires_at, project}``. Raises ``BlobError`` (never
    anything else) on anything that is not valid base64-encoded JSON, or that is missing a field the client needs."""
    if not isinstance(raw, str) or not raw.strip():
        raise BlobError('CVENGINE_SENTINEL_BLOB is empty')
    try:
        data = json.loads(base64.b64decode(raw.strip(), validate=True).decode('utf-8'))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise BlobError('CVENGINE_SENTINEL_BLOB is not a valid base64 JSON provisioning blob') from exc
    if not isinstance(data, dict):
        raise BlobError('CVENGINE_SENTINEL_BLOB is not a valid base64 JSON provisioning blob')
    missing = [key for key in REQUIRED_FIELDS if not isinstance(data.get(key), str) or not data[key]]
    if missing:
        raise BlobError(f'CVENGINE_SENTINEL_BLOB is missing: {", ".join(missing)}')
    return data


def encode_blob(payload):
    """The inverse of ``decode_blob``; not needed by the client in normal operation (the server builds the blob a
    person copies in), but kept here, tested, as the one place both sides of the format are written down."""
    return base64.b64encode(json.dumps(payload, separators=(',', ':')).encode('utf-8')).decode('ascii')
