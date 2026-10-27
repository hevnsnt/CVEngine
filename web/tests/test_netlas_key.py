from unittest import mock

import netlas
from django.test import SimpleTestCase

from reNgine import tasks


class NetlasKeyTests(SimpleTestCase):
	"""The Netlas key reaches Netlas in a request header through its client: never on a command line any local user can read."""

	def run_fetch(self, key='nl-secret-key-123', result=None, error=None):
		holder = mock.Mock(key=key)
		with mock.patch.object(tasks, 'get_netlas_key', return_value=holder), \
				mock.patch.object(tasks, 'run_command') as command, \
				mock.patch.object(netlas.Netlas, 'host', side_effect=error, return_value=result) as host, \
				mock.patch.object(netlas.Netlas, '__init__', return_value=None) as init:
			out = tasks.fetch_whois_data_using_netlas('example.test')
		return out, command, host, init

	def test_the_key_goes_to_the_client_and_no_command_is_run(self):
		out, command, host, init = self.run_fetch(result={'whois': {'registrar': 'x'}})
		self.assertEqual(out, {'status': True, 'data': {'whois': {'registrar': 'x'}}})
		command.assert_not_called()
		init.assert_called_once_with(api_key='nl-secret-key-123')
		host.assert_called_once_with(host='example.test')

	def test_an_empty_answer_a_bad_key_and_a_limit_are_reported_in_words(self):
		self.assertEqual(self.run_fetch(result={})[0]['message'], 'No data available for the given domain or IP.')
		self.assertEqual(self.run_fetch(error=netlas.exception.APIError("api key doesn't exist"))[0]['message'], 'Invalid Netlas API Key!')
		self.assertEqual(self.run_fetch(error=netlas.exception.ThrottlingError(30))[0]['message'], 'Netlas request limit exceeded.')

	def test_an_error_never_echoes_the_key(self):
		out = self.run_fetch(error=RuntimeError('boom nl-secret-key-123 boom'))[0]
		self.assertFalse(out['status'])
		self.assertNotIn('nl-secret-key-123', out['message'])

	def test_no_key_still_asks_without_one(self):
		out, _command, _host, init = self.run_fetch(key='None', result={'a': 1})
		init.assert_called_once_with(api_key='')
		self.assertTrue(out['status'])
