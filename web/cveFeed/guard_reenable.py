"""Accounts the old abuse guard disabled, enabled again by the update (``reenable_guard_disabled_users``, an update step in
cveFeed.upgrade_backfills; docs/UPGRADE.md).

Before 1.5.0 the input guard (reNgine.input_guard) disabled an account at its strike threshold, revoked every API token the account held, and
wrote ``abuse.account_disabled`` to the audit log with that account as actor and its username as target. A link opened from a mail or chat app
was enough to trip it, and the guard no longer disables anyone, so the update enables those accounts again. Only those: an account is enabled
again when all of these hold (``review``):

* the audit log has the guard's own ``abuse.account_disabled`` row for it (actor: the account itself). An account without that row is never
  touched, whatever else says about it;
* it is still disabled;
* nothing after that row could have disabled it another way: no ``user.update`` audit row naming it that set ``is_active`` (the Administration
  page), no Django admin change to it, and no sign-in after it (an account that signed in was enabled in between, so whatever disabled it later
  was not the guard);
* this step has not already enabled it for that row (an ``abuse.account_reenabled`` row naming the guard row): an account an administrator
  disabled again afterwards stays disabled.

Nothing else is restored. The API tokens the guard revoked stay revoked: it recorded no token ids and a token row keeps no revocation time, so
a token the guard revoked cannot be told from one its owner or an administrator revoked before. The audit entry and the output list the
account's revoked tokens created before the guard acted (name and the hint the screens show, never more) as the ones the guard may have
revoked, for an administrator to reissue.
"""
from django.db import transaction

GUARD_ACTION = 'abuse.account_disabled'
DONE_ACTION = 'abuse.account_reenabled'
ACTOR_NAME = 'cvENGINE update'
TOKENS_NOTE = ('API tokens are not restored: the old guard revoked every token of the account and recorded no token ids, so a token it '
               'revoked cannot be told from one revoked by its owner or an administrator. The revoked tokens listed here were made before '
               'the guard acted; reissue the ones still needed on the API keys page.')

# why an account the guard disabled is left as it is (``review``), in words for the output
LEFT_WHY = {
    'admin': 'an administrator changed whether it is active after the guard acted',
    'signed_in': 'it signed in after the guard acted, so something else disabled it later',
    'done_earlier': 'this update step enabled it once already; it was disabled again since',
}


def _guard_rows():
    """The newest guard row of each account: ``{user id: AuditLog}``. A row whose account was deleted has no actor and is left out."""
    from dashboard.models import AuditLog
    newest = {}
    for row in AuditLog.objects.filter(action=GUARD_ACTION, actor__isnull=False).order_by('id').only('id', 'actor_id', 'target', 'created_at'):
        newest[row.actor_id] = row
    return newest


def _changed_by_admin(user, row):
    """Whether anything after the guard row could have set ``is_active``: the Administration page's ``user.update`` with ``is_active`` among its
    fields (target: the username then, so the guard's target and the current name are both looked for) or a Django admin change of the account."""
    from django.contrib.admin.models import LogEntry
    from django.contrib.contenttypes.models import ContentType

    from dashboard.models import AuditLog
    names = {row.target, user.username} - {''}
    if AuditLog.objects.filter(id__gt=row.id, action='user.update', target__in=names, detail__fields__contains=['is_active']).exists():
        return True
    return LogEntry.objects.filter(content_type=ContentType.objects.get_for_model(type(user)), object_id=str(user.pk),
                                   action_time__gt=row.created_at).exists()


def _done_earlier(row):
    from dashboard.models import AuditLog
    return AuditLog.objects.filter(action=DONE_ACTION, detail__guard_audit_id=row.id).exists()


def revoked_tokens(user, before):
    """The account's revoked API tokens made before ``before`` (the guard's moment): the ones the guard may have revoked. Name and hint only."""
    from dashboard.models import ApiToken
    return [{'id': t.pk, 'name': t.name, 'hint': t.hint, 'scope': t.scope}
            for t in ApiToken.objects.filter(user=user, revoked=True, created_at__lte=before).order_by('id')]


def review():
    """``(enable, left)``: the accounts to enable again as ``[(user, guard row)]``, and the ones the guard disabled that stay as they are as
    ``[(user, guard row, why)]`` (``why`` a key of LEFT_WHY). An account the guard disabled that is active now is in neither."""
    from django.contrib.auth import get_user_model
    rows = _guard_rows()
    users = {u.pk: u for u in get_user_model().objects.filter(pk__in=list(rows))}
    enable, left = [], []
    for pk, row in sorted(rows.items()):
        user = users.get(pk)
        if user is None or user.is_active:
            continue
        if _done_earlier(row):
            left.append((user, row, 'done_earlier'))
        elif _changed_by_admin(user, row):
            left.append((user, row, 'admin'))
        elif user.last_login is not None and user.last_login > row.created_at:
            left.append((user, row, 'signed_in'))
        else:
            enable.append((user, row))
    return enable, left


def _enable(user, row):
    """Enable one account again and write its audit entry, in one transaction. False when it was enabled meanwhile (nothing written)."""
    from django.contrib.auth import get_user_model

    from dashboard.models import AuditLog
    tokens = revoked_tokens(user, row.created_at)
    with transaction.atomic():
        if not get_user_model().objects.filter(pk=user.pk, is_active=False).update(is_active=True):
            return False, tokens
        AuditLog.objects.create(actor=None, actor_name=ACTOR_NAME, action=DONE_ACTION, target=user.username[:300],
                                detail={'guard_audit_id': row.id, 'disabled_at': row.created_at.isoformat(), 'restored': ['is_active'],
                                        'tokens_restored': 0, 'tokens_revoked_before_guard': tokens, 'note': TOKENS_NOTE})
    return True, tokens


def run(apply=False, write=print):
    """Review (and with ``apply`` enable) the accounts; ``write`` gets one line per account and then the summary line with the counts. Returns
    ``{enabled, left, earlier, tokens}``. Running it again finds nothing to change."""
    from dashboard.models import AuditLog
    enable, left = review()
    enabled = tokens = 0
    for user, row in enable:
        if apply:
            done, listed = _enable(user, row)
            if not done:
                continue
        else:
            listed = revoked_tokens(user, row.created_at)
        enabled += 1
        tokens += len(listed)
        names = ', '.join(f"{t['name']} ({t['hint']})" for t in listed) or 'none'
        write(f"{'enabled again' if apply else 'would enable again'}: {user.username} (disabled by the abuse guard at "
              f"{row.created_at:%Y-%m-%d %H:%M} UTC); revoked API tokens not restored, reissue if still needed: {names}")
    for user, row, why in left:
        write(f'left disabled: {user.username}: {LEFT_WHY[why]}')
    earlier = AuditLog.objects.filter(action=DONE_ACTION).count() - (enabled if apply else 0)
    verb = 'enabled again' if apply else 'would be enabled again'
    write(f'Accounts the old abuse guard disabled: {enabled} {verb}, {len(left)} left disabled (an administrator acted, or the account was '
          f'used since), {earlier} enabled by an earlier run; {tokens} revoked API tokens not restored (listed in the audit log, '
          f'{DONE_ACTION}).')
    return {'enabled': enabled, 'left': len(left), 'earlier': earlier, 'tokens': tokens}
