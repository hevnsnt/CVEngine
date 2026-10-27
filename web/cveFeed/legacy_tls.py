"""The one place cvENGINE speaks TLS 1.0 / 1.1 on purpose.

The hygiene check has to find servers that still accept the old protocols, and a modern client cannot even read the certificate of one
that speaks nothing newer. So this client is built to talk only 1.0 / 1.1. It sends no credential and verifies nothing: it reads the
certificate and reports the protocol version the server chose. The deliberately weak protocol range lives in exactly this module, apart
from every other TLS use, and the code scanner is told about this file in .github/codeql/codeql-config.yml.
"""
import socket
import ssl

from cveFeed import pinned_transport


def _context():
    """A client that will talk TLS 1.0 / 1.1 only, to find servers that still accept the old protocols."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version, ctx.maximum_version = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
    ctx.set_ciphers('ALL:@SECLEVEL=0')
    return ctx


def handshake(host, port, timeout, addresses=None, project=None):
    """``(der_certificate, protocol, cipher)`` from a TLS 1.0 / 1.1 handshake, or None when this build cannot speak the old protocols or the
    server refuses them. ``project`` may authorise a tailnet device of its own (see pinned_transport)."""
    kw = {} if project is None else {'project': project}
    try:
        ctx = _context()
    except (ValueError, ssl.SSLError):
        return None
    try:
        with pinned_transport.open_socket(addresses if addresses is not None else pinned_transport.resolve(host, port, **kw), timeout, **kw) as raw, \
                ctx.wrap_socket(raw, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version(), (tls.cipher() or ('',))[0]
    except (OSError, ssl.SSLError, socket.timeout, ValueError):
        return None


def accepts(host, port, timeout, addresses=None, project=None):
    """True only if the server actually negotiated TLS 1.0 or 1.1 (a successful handshake alone proves nothing)."""
    got = handshake(host, port, timeout, addresses=addresses, project=project)
    return bool(got) and got[1] in ('TLSv1', 'TLSv1.1')
