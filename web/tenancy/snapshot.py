"""One request's view of the signed-in user's memberships, read once and reused by the tenancy checks of that same request.

Before the view runs, a signed-in request asks the same membership questions several times: the project ids the user may see
(``roles.allowed_project_ids``), whether an organization requires MFA (``roles.requires_mfa``) and the user's role for the project in the
URL (``roles.effective_role`` or ``roles.user_best_role``). Each asked the database again. While a request runs, ``activate`` publishes a
``Snapshot`` of the user's project memberships and organization memberships; those functions answer from it when they are asked about
that same user, and run their own queries otherwise. The answers are the same; only the number of round trips changes.

What keeps it from showing anyone more than before:

* **It lives for one request only.** Nothing is kept between requests (no cache, no TTL): the next request reads everything again, so a
  membership removed, a role changed or an organization's MFA policy switched on counts from the very next request.
* **It only ever answers for its own user.** A question about any other user (an admin screen asking about someone else, a test that
  switches users) is answered by the original queries. A bearer token and a session are both just ``request.user``; each request builds its
  own snapshot for whoever that is.
* **Any write to what it was read from turns it off for the rest of the request.** A save or delete of an organization, a project or a
  membership (the ``tenancy.signals`` receivers) and any other statement that changes those tables on this request's connection (a bulk
  ``update``, ``bulk_create``, raw SQL: the ``execute_wrapper`` below) switch the snapshot off: every later question in the request is
  asked of the database again, exactly as before, which also covers a write that is rolled back later. Every other request of this process
  drops what it read as well (``_generation``), so a change made by one request is not answered from another's earlier read.
* **No snapshot, no change.** Outside a request (Celery, management commands, tests calling ``roles`` directly) nothing is active and every
  function runs its original queries.
"""
import contextlib
import contextvars
import re
import threading

from django.db import connection

_active = contextvars.ContextVar('tenancy_snapshot', default=None)
_lock = threading.Lock()
_generation = 0  # bumped by every write to a watched table anywhere in this process; a snapshot read under an older one is read again
_WATCHED = None  # matches the table names of Org, Project, OrgMembership and ProjectMembership, quoted or not (compiled on first use)


def _watched():
    global _WATCHED
    if _WATCHED is None:
        from dashboard.models import Org, OrgMembership, Project, ProjectMembership
        tables = (m._meta.db_table for m in (Org, Project, OrgMembership, ProjectMembership))
        _WATCHED = re.compile(r'\b(?:%s)\b' % '|'.join(re.escape(t) for t in tables), re.I)
    return _WATCHED


def changed():
    """What a user may see changed (a membership, a project or an organization): no snapshot is believed from now on.

    The snapshot of the running request is switched off for the rest of it, and every other snapshot in this process is read again."""
    global _generation
    with _lock:
        _generation += 1
    snap = _active.get()
    while snap is not None:
        snap.disabled = True
        snap = snap.parent


def _watch_writes(execute, sql, params, many, context):
    """``connection.execute_wrapper`` hook: a statement that may change a watched table switches the snapshot off (see ``changed``)."""
    try:
        return execute(sql, params, many, context)
    finally:
        text = sql if isinstance(sql, str) else str(sql)
        if not text.lstrip()[:6].upper().startswith('SELECT') and _watched().search(text):
            changed()


class Snapshot:
    """The memberships of one user, read at most once per request (and read again only after another request's write)."""

    def __init__(self, user, parent=None):
        self.user_pk = user.pk
        self.parent = parent
        self.disabled = False
        self._reset()

    def _reset(self):
        self._generation = _generation
        self._memberships = None
        self._org_projects = None  # ids of every project of the user's organizations, read without the request scope

    def usable(self):
        if self.disabled:
            return False
        if self._generation != _generation:
            self._reset()
        return True

    def matches(self, user):
        """Whether ``user`` is the user this snapshot was read for (whether or not it may still be used)."""
        return (user is not None and getattr(user, 'is_authenticated', False) is True
                and user.pk is not None and user.pk == self.user_pk)

    def memberships(self):
        """``(project rows, org rows)``: (project_id, role, its org requires MFA) and (org_id, role, org requires MFA), in id order."""
        if self._memberships is None:
            from dashboard.models import OrgMembership, ProjectMembership
            pm = list(ProjectMembership.objects.filter(user_id=self.user_pk).order_by('pk')
                      .values_list('project_id', 'role', 'project__org__require_mfa'))
            om = list(OrgMembership.objects.filter(user_id=self.user_pk).order_by('pk')
                      .values_list('org_id', 'role', 'org__require_mfa'))
            self._memberships = (pm, om)
        return self._memberships

    def project_role(self, project_id):
        return next((role for pid, role, _ in self.memberships()[0] if pid == project_id), None)

    def org_role(self, org_id):
        return next((role for oid, role, _ in self.memberships()[1] if oid == org_id), None)

    def roles(self):
        """Every role the user holds: the project memberships' first, then the organization memberships' (as ``user_best_role`` lists them)."""
        pm, om = self.memberships()
        return [role for _, role, _ in pm] + [role for _, role, _ in om]

    def requires_mfa(self):
        pm, om = self.memberships()
        return any(req is True for _, _, req in om) or any(req is True for _, _, req in pm)

    def allowed_project_ids(self):
        """The same set ``roles.allowed_project_ids`` computes, as a new set every call (callers add to it: ``scope.allow``)."""
        from dashboard.models import Project
        from tenancy import scope
        pm, om = self.memberships()
        ids = {pid for pid, _, _ in pm}
        org_ids = [oid for oid, _, _ in om]
        if org_ids:
            if self._org_projects is None:
                self._org_projects = frozenset(Project._base_manager.filter(org_id__in=org_ids).values_list('id', flat=True))
            org_projects = self._org_projects
            active = scope.current_allowed()
            if active is not None:
                # roles.allowed_project_ids reads these through the scoped Project.objects, which adds id IN (the active scope): the same cut
                org_projects = org_projects & set(active)
            ids |= org_projects
        return ids


def for_user(user):
    """The active snapshot when it belongs to ``user`` and nothing it was read from has changed since, else None (ask the database)."""
    snap = _active.get()
    if snap is None or not snap.matches(user) or not snap.usable():
        return None
    return snap


@contextlib.contextmanager
def activate(user):
    """Publish a snapshot for ``user`` for the duration of the block (one request). Reuses the one already active for the same user, so
    AgentTokenMiddleware and TenancyMiddleware of one request share it (and one switched off stays off)."""
    current = _active.get()
    if current is not None and current.matches(user):
        yield current
        return
    snap = Snapshot(user, parent=current)
    token = _active.set(snap)
    try:
        with connection.execute_wrapper(_watch_writes):
            yield snap
    finally:
        _active.reset(token)
