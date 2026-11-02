from datetime import timedelta

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

NOTE = 'another agent of this user is suspended or revoked; an administrator must reinstate this one'  # the note the old rule wrote
BEFORE_HOLD = ('agentapi', '0007_sentinel_network')
HOLD = ('agentapi', '0009_agent_hold')


class AgentHoldUpgradeTests(TransactionTestCase):
	"""Run the real 0008 and 0009 from the state before them (1.3.1), with agents the old rule held back. 0009 adds the deferrable ``held_by``
	foreign key and backfills in the same transaction: a row updated twice there used to leave a foreign key check pending, and the index
	Django creates at the end of the migration then failed with "cannot CREATE INDEX ... because it has pending trigger events"."""

	def tearDown(self):
		executor = MigrationExecutor(connection)
		executor.migrate(executor.loader.graph.leaf_nodes())  # leave the schema at the latest state for the next test

	def before(self, executor):
		return [node for node in executor.loader.graph.leaf_nodes() if node[0] != 'agentapi'] + [BEFORE_HOLD]

	def agent(self, old, user, name, status, note='', changed=None):
		token = old.get_model('dashboard', 'ApiToken').objects.create(user=user, name=name, key_hash=f'hash-{name}', prefix=name[:12])
		Agent = old.get_model('agentapi', 'Agent')
		pk = Agent.objects.create(token=token, name=name, status=status, status_note=note).pk
		if changed is not None:
			Agent.objects.filter(pk=pk).update(updated_at=changed)  # auto_now: the time an administrator last changed it
		return pk

	def test_agents_the_old_rule_held_back_upgrade_and_are_backfilled(self):
		executor = MigrationExecutor(connection)
		before = self.before(executor)
		executor.migrate(before)
		old = executor.loader.project_state(before).apps
		User = old.get_model('auth', 'User')
		alice, bob = User.objects.create(username='alice'), User.objects.create(username='bob')
		now = timezone.now()
		revoked = self.agent(old, alice, 'alice-revoked', 'revoked', changed=now - timedelta(days=400))
		suspended = self.agent(old, alice, 'alice-suspended', 'suspended', note='decommissioned', changed=now - timedelta(days=3))
		held = self.agent(old, alice, 'alice-held', 'suspended', note=NOTE)
		orphan = self.agent(old, bob, 'bob-held', 'suspended', note=NOTE)  # no agent of bob's an administrator suspended or revoked
		active = self.agent(old, bob, 'bob-active', 'active')

		executor = MigrationExecutor(connection)
		executor.migrate([HOLD])  # used to raise OperationalError: pending trigger events

		from agentapi import agent_broker as broker
		from agentapi.models import Agent
		rows = {a.pk: a for a in Agent.objects.all()}
		self.assertEqual((rows[revoked].status_changed_at, rows[revoked].status_inherited, rows[revoked].held_by_id),
						 (rows[revoked].updated_at, False, None))
		self.assertEqual(rows[revoked].updated_at, now - timedelta(days=400))
		self.assertEqual((rows[suspended].status_changed_at, rows[suspended].status_inherited, rows[suspended].status_note),
						 (now - timedelta(days=3), False, 'decommissioned'))
		# held back by the old rule: marked inherited, and the user's most recent administrator decision is named in a rewritten note
		self.assertTrue(rows[held].status_inherited)
		self.assertEqual(rows[held].status_changed_at, rows[held].updated_at)
		self.assertEqual(rows[held].held_by_id, suspended)
		self.assertEqual(rows[held].status_note, broker.hold_note(rows[suspended]))
		self.assertIn(f'(#{suspended}) of the same user was suspended on', rows[held].status_note)
		# nobody to name: inherited, but the old note stays
		self.assertEqual((rows[orphan].status_inherited, rows[orphan].held_by_id, rows[orphan].status_note), (True, None, NOTE))
		self.assertIsNotNone(rows[orphan].status_changed_at)
		self.assertEqual((rows[active].status_changed_at, rows[active].status_inherited, rows[active].held_by_id), (None, False, None))
		# the index on held_by that failed to be created is there
		with connection.cursor() as cursor:
			constraints = connection.introspection.get_constraints(cursor, Agent._meta.db_table)
		self.assertTrue(any(c['columns'] == ['held_by_id'] and c['index'] for c in constraints.values()), constraints)
