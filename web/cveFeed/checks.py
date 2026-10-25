"""Django system checks (``manage.py check``; also printed when the web container runs its migrations at start)."""
from django.conf import settings
from django.core import checks

PLACEHOLDER_DOMAINS = ('example.com', 'example.org', 'example.net', 'example', 'test', 'invalid', 'localhost')  # RFC 2606
LOOPBACK = ('', 'localhost', '127.0.0.1', '[::1]', '::1')


@checks.register(checks.Tags.security)
def allowed_hosts_check(app_configs=None, **kwargs):
    """Only DOMAIN_NAME's host, loopback and CVENGINE_ALLOWED_HOSTS are accepted (any other Host header gets 400 Bad Request). A
    DOMAIN_NAME that is unset, loopback or still the example placeholder means the site answers 400 to everyone but loopback."""
    from urllib.parse import urlsplit
    try:
        host = (urlsplit('//' + (getattr(settings, 'DOMAIN_NAME', '') or '')).hostname or '').lower()
    except ValueError:
        host = ''
    extra = [h for h in settings.ALLOWED_HOSTS if h.lower() not in LOOPBACK and h.lower() != host]
    placeholder = any(host == d or host.endswith('.' + d) for d in PLACEHOLDER_DOMAINS)
    if (host in LOOPBACK or placeholder) and not extra:
        return [checks.Warning(
            f'DOMAIN_NAME is {host or "unset"!r}, so only loopback requests are accepted; a browser reaching this server by its '
            'real name or IP address gets "400 Bad Request".',
            hint='Set DOMAIN_NAME in .env to the public name of this server, and list any other name or IP address users type '
                 'in CVENGINE_ALLOWED_HOSTS (comma separated). See docs/UPGRADE.md.',
            id='cvengine.W001')]
    return []
