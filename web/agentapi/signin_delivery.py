"""THE one gate for a stored sign-in (``cveFeed.models.AuthCredential``) on its way to a Sentinel that is not the built-in scanner.

A signed-in task names its sign-in by reference (``SentinelTask.secret_ref`` ``authcred:<id>``), never by value, and the scanner that holds the task reads
the value once through ``POST sentinel/tasks/<id>/secret`` (``sentinel_broker.read_secret``). The built-in scanner, which runs next to this server, may
always do so when its image reads secrets. An external Sentinel may do so only when every one of these holds (``decision``), checked wherever such a task
is offered, claimed, counted or read:

* the task is a kind an external client runs signed in (``KINDS``: the nuclei web passes and the signed-in route check);
* the Sentinel has no problem (active, unrevoked, a sentinel scope token that is not read only);
* its client says it handles a sign-in safely: ``info.features`` names ``FEATURE`` (``secret_read_external``). An older client never says so and is never
  sent one. ``secret_read`` is not reused: it is the built-in image's word, and a client that reports it outside the built-in scanner says nothing about
  how it keeps the value on a machine this server does not run;
* the credential exists, belongs to the task's project and has not expired;
* its owner switched ``allow_external_sentinels`` on for this one sign-in (off by default, set on the Targets page or over REST, audited);
* the Sentinel was enrolled by someone who may manage that sign-in themselves: an App Admin, or an admin of the project's organization (the same people
  ``agentapi.authcheck`` lets store one). A Sentinel a project member enrolled is never sent one, as it is never sent keys it could not set
  (``sentinel_stream.key_levels``). An instance wide fleet Sentinel an App Admin enrolled qualifies, the owner's switch still decides;
* and, checked first by ``SentinelEff.refusal``, the project and the target are in the Sentinel's scope.

Nothing here reads or decrypts a value: only the credential's plain columns.
"""
from django.db.models import CharField, Q, Subquery, Value
from django.db.models.functions import Cast, Concat

FEATURE = 'secret_read_external'  # ``info.features`` entry of a Sentinel client that reads a stored sign-in safely (sentinel_settings.FEATURES)
REF_PREFIX = 'authcred:'  # mirrors sentinel_broker.SECRET_REF_PREFIX
KINDS = ('nuclei_light', 'nuclei_targeted', 'nuclei_deep', 'route_probe_signed')  # what an external client runs signed in
BUILTIN_ONLY_UNLESS_GATED = ('route_probe_signed',)  # a built-in only kind (sentinel_broker.builtin_only_kind) that this gate may open to an external Sentinel

# Why an external Sentinel is not given a stored sign-in, with the plain sentence for it. The order is the order a reader should act on it.
REASONS = {
    'signin_external_off': 'the stored sign-in is not allowed on external Sentinels (Targets, Sign-in: "Also send it to my external Sentinels" is off)',
    'signin_not_owner': 'the Sentinel was enrolled by someone who may not manage this project\'s stored sign-ins (an App Admin or the organization admin must enroll it)',
    'signin_client_outdated': 'the Sentinel is too old to receive a stored sign-in safely (update it: it must report the secret_read_external feature)',
    'signin_expired': 'the stored sign-in has expired',
    'signin_gone': 'the stored sign-in no longer exists',
    'signin_wrong_project': 'the stored sign-in belongs to another project',
    'signin_wrong_kind': 'this kind of work never carries a stored sign-in to an external Sentinel',
    'signin_sentinel_unusable': 'the Sentinel cannot be given work now',
}
NONE_ORDER = ('signin_external_off', 'signin_not_owner', 'signin_client_outdated', 'signin_expired', 'signin_gone')


def is_ref(ref):
    return isinstance(ref, str) and ref.startswith(REF_PREFIX)


def credential_id(ref):
    tail = ref[len(REF_PREFIX):] if is_ref(ref) else ''
    return int(tail) if tail.isdigit() and len(tail) <= 18 else None


def _row(cred_id):
    from cveFeed.models import AuthCredential
    return (AuthCredential.objects.filter(pk=cred_id).values('project_id', 'project__org_id', 'expires_at', 'allow_external_sentinels').first()
            if cred_id is not None else None)


def may_manage(user, org_id):
    """Whether ``user`` may set or replace a stored sign-in of a project of organization ``org_id`` (``agentapi.authcheck._admin``)."""
    from tenancy import roles
    return bool(user is not None and (user.is_superuser or (org_id and roles.can_manage_org(user, org_id))))


def sentinel_ready(eff):
    """``(True, '')`` when ``eff`` (``sentinel_broker.SentinelEff`` of a Sentinel that is not the built-in scanner) may as such be sent a sign-in, not yet
    for a given task: the part of ``decision`` that does not depend on the credential."""
    if eff.problem:
        return False, 'signin_sentinel_unusable'
    if FEATURE not in ((eff.agent.info or {}).get('features') or []):
        return False, 'signin_client_outdated'
    token = eff.agent.token
    if token.revoked or token.read_only or token.scope != 'sentinel':
        return False, 'signin_sentinel_unusable'
    return True, ''


def decision(eff, kind, ref, project_id, now=None):
    """``(True, '')`` when ``eff`` may be sent the stored sign-in ``ref`` names for a task of ``kind`` in project ``project_id``, else ``(False, reason)``
    (``REASONS``). The built-in scanner: when its image reads secrets (``SentinelEff.reads_secrets``), as always."""
    from django.utils import timezone
    if not is_ref(ref):
        return False, 'signin_wrong_kind'
    if eff.builtin:
        if eff.problem:
            return False, 'signin_sentinel_unusable'
        return (True, '') if eff.reads_secrets else (False, 'signin_client_outdated')
    if kind not in KINDS:
        return False, 'signin_wrong_kind'
    ready = sentinel_ready(eff)
    if not ready[0]:
        return ready
    row = _row(credential_id(ref))
    if row is None:
        return False, 'signin_gone'
    if row['project_id'] != project_id:
        return False, 'signin_wrong_project'
    if row['expires_at'] is not None and row['expires_at'] <= (now or timezone.now()):
        return False, 'signin_expired'
    if not row['allow_external_sentinels']:
        return False, 'signin_external_off'
    if not may_manage(eff.agent.token.user, row['project__org_id']):
        return False, 'signin_not_owner'
    return True, ''


def offer_q(eff):
    """The ``SentinelTask`` filter of the signed-in tasks an external Sentinel may be offered at all (``SentinelEff.secret_filter``), in SQL, so a queue of
    sign-ins it may never read does not fill its candidate list: a kind of ``KINDS`` naming a sign-in whose owner allowed external Sentinels, of an
    organization its enrolling user manages. ``decision`` still checks every task where it is taken. ``None`` when it may be sent none."""
    from cveFeed.models import AuthCredential
    if eff.builtin or not sentinel_ready(eff)[0]:
        return None
    creds = AuthCredential.objects.filter(allow_external_sentinels=True)
    user = eff.agent.token.user
    if not user.is_superuser:  # the organizations it is an admin of, as a subquery: no extra statement on every poll (``tenancy.roles.managed_org_ids``)
        from dashboard.models import OrgMembership
        from tenancy import roles
        creds = creds.filter(project__org_id__in=OrgMembership.objects.filter(user=user, role=roles.ADMIN).values('org_id'))
    refs = creds.annotate(ref=Concat(Value(REF_PREFIX), Cast('pk', CharField()))).values('ref')
    return Q(kind__in=KINDS, secret_ref__in=Subquery(refs))


def none_answer(reasons):
    """``{'reason', 'message'}`` for signed-in work when every Sentinel live for it is refused the sign-in (``reasons``: codes of ``decision``), or ``None``
    when none of them is a reason a reader can act on here."""
    codes = set(reasons)
    for code in NONE_ORDER:
        if code in codes:
            return {'reason': code, 'message': REASONS[code]}
    return None
