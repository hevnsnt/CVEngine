"""Database sessions that do not store the session key.

Django's database backend keeps the cookie value itself as the row's primary key, so a copy of the ``django_session`` table (a backup, a
read-only SQL injection) is a list of working logins. Here the row is keyed by a keyed hash of the cookie value (HMAC with the Django
secret, 160 bits), so the table identifies sessions without being able to impersonate them. The cookie, its lifetime and everything the
application does with ``request.session`` are unchanged."""
import hashlib
import hmac
import logging

from django.conf import settings
from django.contrib.sessions.backends import db
from django.core.exceptions import SuspiciousOperation
from django.utils import timezone

logger = logging.getLogger(__name__)


def db_key(session_key):
    """The value stored in ``django_session.session_key`` for a cookie value (40 hex characters; a cookie value is 32 characters)."""
    return hmac.new(settings.SECRET_KEY.encode(), b'cvengine/session/v1:' + session_key.encode(), hashlib.sha256).hexdigest()[:40]


class SessionStore(db.SessionStore):
    def _get_session_from_db(self):
        try:
            return self.model.objects.get(session_key=db_key(self.session_key), expire_date__gt=timezone.now())
        except (self.model.DoesNotExist, SuspiciousOperation) as exc:
            if isinstance(exc, SuspiciousOperation):
                logging.getLogger('django.security.%s' % exc.__class__.__name__).warning(str(exc))
            self._session_key = None

    def exists(self, session_key):
        return self.model.objects.filter(session_key=db_key(session_key)).exists()

    def create_model_instance(self, data):
        return self.model(session_key=db_key(self._get_or_create_session_key()), session_data=self.encode(data),
                          expire_date=self.get_expiry_date())

    def delete(self, session_key=None):
        session_key = session_key or self.session_key
        if session_key is None:
            return
        self.model.objects.filter(session_key=db_key(session_key)).delete()
