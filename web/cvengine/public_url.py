"""The address agents, Sentinels and message links use to reach this server.

``CVENGINE_PUBLIC_API_URL`` (optional, for example ``https://scanner.example.com``) names a public address in front of this server that is not
``DOMAIN_NAME``: a hosted server sits behind one shared host, and its own ``DOMAIN_NAME`` is an origin name that clients are not meant to use.
When it is set, the Sentinel enrollment ``server_url``, the default link base of server emails, the MCP address on the MCP page and the host
shown on the API keys and Sentinels pages all use it. When it is unset or not a usable URL, each place keeps its own behaviour (``DOMAIN_NAME``,
or the request's host on the pages).

A usable value is an ``http`` or ``https`` URL with a host, an optional port and no path, query, fragment or user name; a trailing slash is
dropped. Anything else is ignored, so a typo falls back to the working address instead of handing out a broken one.
"""
import os
from urllib.parse import urlsplit

ENV_NAME = 'CVENGINE_PUBLIC_API_URL'


def _parse(raw):
    value = str(raw or '').strip().rstrip('/')
    if not value:
        return None
    try:
        parts = urlsplit(value)
        port = parts.port  # raises ValueError for a port that is not a number in range
    except ValueError:
        return None
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.path or parts.query or parts.fragment:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    host = parts.hostname.lower()
    if ':' in host:
        host = f'[{host}]'
    netloc = f'{host}:{port}' if port else host
    return f'{parts.scheme}://{netloc}', netloc


def configured():
    """``(base_url, host)`` from ``CVENGINE_PUBLIC_API_URL``, or ``None`` when it is unset or not a usable URL."""
    from django.conf import settings
    raw = getattr(settings, 'CVENGINE_PUBLIC_API_URL', None)
    if raw is None:
        raw = os.environ.get(ENV_NAME, '')
    return _parse(raw)


def base_url():
    """``CVENGINE_PUBLIC_API_URL`` (no trailing slash), or ``None`` when it is not set."""
    found = configured()
    return found[0] if found else None


def host():
    """The host (and port, when one is given) of ``CVENGINE_PUBLIC_API_URL``, or ``None`` when it is not set."""
    found = configured()
    return found[1] if found else None


def domain_base_url():
    """The address built from ``DOMAIN_NAME`` alone: ``https://<DOMAIN_NAME>``, ``http`` for a loopback name."""
    domain = os.environ.get('DOMAIN_NAME', 'localhost').strip() or 'localhost'
    scheme = 'http' if domain in ('localhost', '127.0.0.1') else 'https'
    return f'{scheme}://{domain}'
