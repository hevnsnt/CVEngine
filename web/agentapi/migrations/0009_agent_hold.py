"""What the rule that holds a user's new agents back (``agent_broker.suspension_culprit``) needs to tell a decision from an accident:

- ``status_changed_at``: when the status last changed, so an old suspension or revocation stops holding new agents back after
  ``CVENGINE_AGENT_HOLD_DAYS``. Filled in here for agents already suspended or revoked from ``updated_at``: nothing else saves a suspended or
  revoked agent (its own calls are refused), so that is when an administrator last changed it.
- ``status_inherited`` and ``held_by``: the rule suspended this agent itself, because of that other agent. Agents already held back this way are
  recognised by the note the rule used to write (no administrator decided them), so they do not hold back further agents in turn. Which agent
  caused it was not recorded then: it is taken to be the user's most recent agent an administrator suspended or revoked, and the note is
  rewritten to name it, as a new hold's is.

Additive and reversible (the reverse drops the three columns)."""
import django.db.models.deletion
from django.db import migrations, models

NOTE = 'another agent of this user is suspended or revoked; an administrator must reinstate this one'  # agent_broker.INHERITED_SUSPENSION_NOTE


def note_for(culprit):
    # agent_broker.hold_note as it is now; a copy, because a migration must not import live code
    name = culprit.name if len(culprit.name) <= 40 else culprit.name[:37] + '...'
    when = culprit.status_changed_at.date().isoformat() if culprit.status_changed_at else 'a date not recorded'
    what = 'Sentinel' if culprit.kind == 'scanner' else 'agent'
    return (f'{what} "{name}" (#{culprit.pk}) of the same user was {culprit.status} on {when}. Reinstate this one to use it, '
            f'and reinstate or delete #{culprit.pk} so new agents start normally')[:200]


def backfill(apps, schema_editor):
    Agent = apps.get_model('agentapi', 'Agent')
    Agent.objects.filter(status__in=('suspended', 'revoked'), status_changed_at__isnull=True).update(status_changed_at=models.F('updated_at'))
    Agent.objects.filter(status='suspended', status_note=NOTE).update(status_inherited=True)
    # name the agent that most likely caused each of them: the user's most recent agent an administrator suspended or revoked (the note then
    # says which one and what to do, as a new hold does). None left (deleted or reinstated since): the old note stays.
    for held in Agent.objects.filter(status='suspended', status_inherited=True, held_by__isnull=True).select_related('token'):
        culprit = (Agent.objects.filter(token__user_id=held.token.user_id, status__in=('suspended', 'revoked'), status_inherited=False)
                   .exclude(pk=held.pk).order_by(models.F('status_changed_at').desc(nulls_last=True), '-id').first())
        if culprit is not None:
            Agent.objects.filter(pk=held.pk).update(held_by=culprit, status_note=note_for(culprit))


class Migration(migrations.Migration):

    dependencies = [('agentapi', '0008_clear_stale_status_note')]

    operations = [
        migrations.AddField(
            model_name='agent',
            name='held_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='agentapi.agent'),
        ),
        migrations.AddField(model_name='agent', name='status_changed_at', field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name='agent', name='status_inherited', field=models.BooleanField(db_default=False, default=False)),
        migrations.RunPython(backfill, migrations.RunPython.noop),
    ]
