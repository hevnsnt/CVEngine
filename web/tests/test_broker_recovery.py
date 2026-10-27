import uuid

from django.test import TestCase
from kombu import Queue

from cveFeed.broker_recovery import requeue_unacked
from reNgine.celery import app


class RequeueUnackedTests(TestCase):
	"""Against the real broker: a message taken and never acknowledged is what a killed worker leaves behind."""

	def setUp(self):
		self.queue = f'recovery_test_{uuid.uuid4().hex[:8]}'
		self.connection = app.connection_for_write()
		self.channel = self.connection.default_channel
		self.client = self.channel.client
		self.client.delete('unacked', 'unacked_index')
		self.addCleanup(lambda: (self.client.delete(self.queue, 'unacked', 'unacked_index'), self.connection.release()))

	def publish(self, body):
		with self.connection.Producer() as producer:
			producer.publish(body, routing_key=self.queue, declare=[Queue(self.queue, routing_key=self.queue)], serializer='json')

	def test_a_message_a_dead_worker_took_goes_back_to_its_queue(self):
		self.publish({'task': 'assess_host', 'n': 1})
		self.publish({'task': 'assess_host', 'n': 2})
		self.assertTrue(self.channel.basic_get(self.queue, no_ack=False))  # taken, never acknowledged
		self.assertTrue(self.channel.basic_get(self.queue, no_ack=False))
		self.assertEqual((self.client.llen(self.queue), self.client.hlen('unacked')), (0, 2))
		self.assertEqual(requeue_unacked(), 2)
		self.assertEqual((self.client.llen(self.queue), self.client.hlen('unacked')), (2, 0))

	def test_an_acknowledged_message_is_not_brought_back(self):
		self.publish({'task': 'assess_host', 'n': 1})
		message = self.channel.basic_get(self.queue, no_ack=False)
		message.ack()
		self.assertEqual(requeue_unacked(), 0)
		self.assertEqual(self.client.llen(self.queue), 0)

	def test_nothing_unacknowledged_is_nothing_to_do_and_a_broker_error_is_not_raised(self):
		self.assertEqual(requeue_unacked(), 0)
		from unittest import mock
		with mock.patch.object(app, 'connection_for_write', side_effect=OSError('broker down')):
			self.assertEqual(requeue_unacked(app), 0)

	def test_the_worker_container_runs_it_before_its_workers_start(self):
		import os
		text = open(os.path.join(os.path.dirname(__file__), '..', 'celery-entrypoint.sh')).read()
		self.assertLess(text.index('manage.py requeue_unacked'), text.index('echo "Starting Celery Workers..."'))
