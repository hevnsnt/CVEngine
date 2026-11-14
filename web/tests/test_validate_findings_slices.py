"""The validate_findings task hands what is left of a batch back to the queue (cveFeed.tasks)."""
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import tasks, validation


class SliceTests(SimpleTestCase):
    def test_what_a_slice_leaves_goes_back_to_the_queue_and_is_counted(self):
        with mock.patch.object(validation, 'run_validation', return_value={'rows': 5, 'ran': 1, 'deferred_ids': [8, 9]}) as run, \
                mock.patch.object(tasks.validate_findings, 'apply_async') as again:
            out = tasks.validate_findings.run(3, [7, 8, 9], 11)
        self.assertEqual(run.call_args.kwargs['budget_seconds'], tasks.VALIDATE_SLICE_SECONDS)
        again.assert_called_once_with((3, [8, 9], 11))
        self.assertEqual(out, {'rows': 5, 'ran': 1, 'deferred': 2})

    def test_a_finished_batch_queues_nothing(self):
        with mock.patch.object(validation, 'run_validation', return_value={'rows': 2, 'ran': 2}), \
                mock.patch.object(tasks.validate_findings, 'apply_async') as again:
            out = tasks.validate_findings.run(3, [7, 8])
        again.assert_not_called()
        self.assertEqual(out, {'rows': 2, 'ran': 2})
