"""The result contract is a 60 KB JSON file in the installed Sentinel library. It was read and parsed on every question about it: eight times per Sentinel
for its rights (``can_run``), once per heartbeat reply, once per result. At 50 Sentinels that was 1,804 parses (273 ms) of a 600 ms Sentinels page."""
import os
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from agentapi import sentinel_contract


class ContractReadOnceTests(SimpleTestCase):
    def test_many_questions_parse_the_file_once(self):
        sentinel_contract.load()
        with mock.patch.object(sentinel_contract._library, 'load', wraps=sentinel_contract._library.load) as parse:
            for _ in range(200):
                sentinel_contract.can_run(2, 'nmap')
                sentinel_contract.version()
                sentinel_contract.min_supported()
                sentinel_contract.state(1)
        self.assertEqual(parse.call_count, 0)

    def test_the_answers_are_the_librarys_own(self):
        from cvengine_scanner import contract
        self.assertEqual(sentinel_contract.version(), contract.version())
        self.assertEqual(sentinel_contract.min_supported(), contract.min_supported())
        self.assertEqual(sentinel_contract.load(), contract.load())

    def test_a_changed_file_is_read_again(self):
        """An update of the library (a new contract file in the same place) is seen without a restart of the process."""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'c.json'
            path.write_text('{"contract_version": 1, "kind_since": {}}')
            with mock.patch.object(sentinel_contract, 'PATH', path), \
                    mock.patch.object(sentinel_contract, '_cached', {'stamp': None, 'doc': None}), \
                    mock.patch.object(sentinel_contract._library, 'load', side_effect=lambda: __import__('json').loads(path.read_text())):
                self.assertEqual(sentinel_contract.load()['contract_version'], 1)
                path.write_text('{"contract_version": 2, "kind_since": {}}  ')
                os.utime(path, (1, 1))
                self.assertEqual(sentinel_contract.load()['contract_version'], 2)
