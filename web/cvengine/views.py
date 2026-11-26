"""Protected media view: checks access, then hands the file to nginx."""

import mimetypes
import os
from urllib.parse import quote

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse

NOT_FOUND = 'File not found'


def _owns_scan(folder):
    """Return True when the folder name '<domain>_<scan id>' is a visible scan."""
    from startScan.models import ScanHistory

    name, sep, number = folder.rpartition('_')
    if not sep or not name or not number or not number.isdecimal():
        return False
    return ScanHistory.objects.filter(pk=int(number), domain__name=name).exists()


@login_required
def serve_protected_media(request, path):
    """Answer with an X-Accel-Redirect header when the caller may read the file."""
    try:
        root = os.path.realpath(settings.MEDIA_ROOT)
        target = os.path.realpath(os.path.join(root, path))
    except ValueError:
        raise Http404(NOT_FOUND)

    if not target.startswith(root + os.sep):
        raise Http404(NOT_FOUND)

    relative = os.path.relpath(target, root)
    if not request.user.is_superuser:
        first = relative.split(os.sep, 1)[0]
        if not _owns_scan(first):
            raise Http404(NOT_FOUND)

    if os.path.isdir(target) or not os.path.exists(target):
        raise Http404(NOT_FOUND)

    content_type = mimetypes.guess_type(target)[0] or 'application/octet-stream'
    response = HttpResponse(status=200)
    response['Content-Type'] = content_type
    response['X-Accel-Redirect'] = '/protected_media/' + quote(relative)
    return response
