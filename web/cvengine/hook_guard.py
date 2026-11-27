"""Notification webhook addresses must reach a public server (N3b review, SSRF).

The server POSTs scan messages to the Slack, Lark and Discord webhook addresses. An address that resolves to loopback, link local, a
cloud metadata service (169.254.169.254, fd00:ec2::254), a private range or any other address that is not public would have the server
send its messages, and the request it builds, inside its own network. The rule fails closed: a name that does not resolve, or that
resolves to any address that is not public, is refused.

``hook_refusal`` is checked when the setting is saved (an answer of 400) and again right before every send, on the name resolved at
that moment, so a value saved before this rule, or a name whose DNS answer changed later, is skipped instead of called.
"""
import ipaddress
import logging
import socket
import threading
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

METADATA_NAMES = frozenset({'metadata.google.internal', 'metadata', 'instance-data', 'instance-data.ec2.internal'})

_logged = set()
_logged_lock = threading.Lock()


def _public(ip):
    if getattr(ip, 'ipv4_mapped', None):
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def hook_host(url):
    try:
        return (urlsplit(str(url or '').strip()).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


def hook_refusal(url):
    """Return why the webhook address may not be called, or None when every address it resolves to now is public."""
    url = str(url or '').strip()
    try:
        parts = urlsplit(url)
    except ValueError:
        return 'is not a valid address'
    if parts.scheme.lower() not in ('http', 'https') or not parts.netloc:
        return 'must be an http or https address'
    host = hook_host(url)
    if not host:
        return 'must be an http or https address'
    if host in METADATA_NAMES:
        return 'points at a cloud metadata service'
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return None if _public(literal) else 'points at an address that is not public (loopback, link local, metadata or private)'
    try:
        found = {str(info[4][0]).split('%')[0] for info in socket.getaddrinfo(host, None)}
    except (OSError, UnicodeError):
        return 'has a host name that does not resolve'
    if not found:
        return 'has a host name that does not resolve'
    try:
        if all(_public(ipaddress.ip_address(a)) for a in found):
            return None
    except ValueError:
        pass
    return 'resolves to an address that is not public (loopback, link local, metadata or private)'


def hook_allowed(url, channel):
    """Send time check. A refused address is not called; it is logged once per channel and host for the life of the process."""
    reason = hook_refusal(url)
    if reason is None:
        return True
    key = (channel, hook_host(url))
    with _logged_lock:
        first = key not in _logged
        _logged.add(key)
    if first:
        logger.warning('%s webhook not called: host %s %s. Replace it in Settings > Notifications.', channel, key[1] or '(none)', reason)
    return False
