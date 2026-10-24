"""The page shown when Django rejects a form POST for CSRF reasons, with the reason logged for the operator."""
import logging

from django.shortcuts import render

logger = logging.getLogger(__name__)


def csrf_failure(request, reason=''):
    logger.warning('CSRF check failed for %s %s (host %s, origin %s): %s', request.method, request.path,
                   request.get_host(), request.META.get('HTTP_ORIGIN', '-'), reason)
    return render(request, 'error.html', {
        'code': 403, 'title': 'Could not verify this request',
        'message': 'The page you submitted has expired, or the address you used does not match this server. '
                   'Reload the page and try again. If it keeps happening, open CVEngine at the address it was installed with, '
                   'or ask an administrator to add your address to CVENGINE_CSRF_TRUSTED_ORIGINS.'}, status=403)
