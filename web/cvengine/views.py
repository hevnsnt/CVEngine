import os
import mimetypes
from urllib.parse import quote
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from django.conf import settings

def _media_owner_visible(first_segment):
    """Scan artifacts live under ``<domain>_<scan id>/``. Only serve them if that scan, of that domain, is in a project the caller can see:
    the scoped default managers do the filtering. A bare ``<domain>/`` folder (the layout of the upstream project) is not served to anyone
    but an App Admin: it is not tied to a scan, so it cannot be attributed to a project, and CVEngine never writes that layout."""
    import re

    from startScan.models import ScanHistory
    m = re.match(r'^(.+)_(\d+)$', first_segment)
    return bool(m and ScanHistory.objects.filter(pk=int(m.group(2)), domain__name=m.group(1)).exists())


@login_required
def serve_protected_media(request, path):
    root = os.path.realpath(settings.MEDIA_ROOT)
    file_path = os.path.realpath(os.path.join(root, path))
    if not file_path.startswith(root + os.sep):  # ../ and absolute paths
        raise Http404("File not found")
    first = os.path.relpath(file_path, root).split(os.sep)[0]
    # Same answer for "does not exist" and "belongs to someone else", so this is not a file-existence oracle.
    if not request.user.is_superuser and not _media_owner_visible(first):
        raise Http404("File not found")
    if os.path.isdir(file_path) or not os.path.exists(file_path):
        raise Http404("File not found")
    content_type, _ = mimetypes.guess_type(file_path)
    response = HttpResponse()
    response['Content-Type'] = content_type or 'application/octet-stream'
    response['X-Accel-Redirect'] = '/protected_media/' + quote(os.path.relpath(file_path, root))  # a URI for nginx: a literal % ? # must not be read as syntax
    return response

