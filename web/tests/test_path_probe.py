import os
import socket
import unittest
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import path_probe
from startScan.models import IpAddress


def result(ip='93.184.216.34', plain=True, odd=True):
	return {'ip': ip, 'port': 81, 'plain': plain, 'odd': odd if plain else None}


class VerdictTests(SimpleTestCase):
	def test_a_clean_path_answers_the_odd_probe_too(self):
		self.assertEqual(path_probe.verdict([result(), result(), result(), result()]), ('direct', 4, 0))

	def test_a_translating_path_loses_it_on_most_hosts(self):
		self.assertEqual(path_probe.verdict([result(odd=False)] * 4), ('interfering', 4, 4))
		self.assertEqual(path_probe.verdict([result(odd=False)] * 3 + [result()]), ('interfering', 4, 3))

	def test_hosts_that_did_not_answer_the_control_say_nothing(self):
		many_dead = [result(plain=False)] * 10
		self.assertEqual(path_probe.verdict(many_dead + [result(odd=False)] * 2), ('unknown', 2, 2))

	def test_too_few_hosts_or_a_split_is_no_verdict(self):
		self.assertEqual(path_probe.verdict([result()] * 2)[0], 'unknown')
		self.assertEqual(path_probe.verdict([result(), result(), result(odd=False), result(odd=False)])[0], 'unknown')

	def test_one_host_with_its_own_firewall_does_not_make_a_clean_path_interfering(self):
		self.assertEqual(path_probe.verdict([result()] * 5 + [result(odd=False)])[0], 'direct')


class SurveyTests(SimpleTestCase):
	def test_the_odd_probe_is_only_sent_where_the_control_was_answered(self):
		sent = []

		def probe(ip, port, flags):
			sent.append((ip, flags))
			return ip != '203.0.113.9'
		got = path_probe.survey([('93.184.216.34', 81), ('203.0.113.9', 82)], probe=probe, sleep=lambda s: None)
		self.assertEqual([(r['ip'], r['plain'], r['odd']) for r in got], [('93.184.216.34', True, True), ('203.0.113.9', False, None)])
		self.assertEqual(sent, [('93.184.216.34', path_probe.SYN), ('93.184.216.34', path_probe.ODD_FLAGS), ('203.0.113.9', path_probe.SYN)])

	def test_a_host_that_cannot_be_reached_is_skipped(self):
		def probe(ip, port, flags):
			raise OSError('network is unreachable')
		self.assertEqual(path_probe.survey([('93.184.216.34', 81)], probe=probe, sleep=lambda s: None), [])

	def test_raw_sockets_not_allowed_is_reported_not_swallowed(self):
		def probe(ip, port, flags):
			raise path_probe.RawSocketsUnavailable('no CAP_NET_RAW')
		with self.assertRaises(path_probe.RawSocketsUnavailable):
			path_probe.survey([('93.184.216.34', 81)], probe=probe, sleep=lambda s: None)


class CandidateTests(TestCase):
	def make(self, address, port, days=1):
		import datetime
		fingerprint = {'closed_tcp': port, 'closed_tcp_at': (timezone.now() - datetime.timedelta(days=days)).isoformat()} if port else {}
		return IpAddress.objects.create(address=address, fingerprint=fingerprint)

	def test_one_address_per_network_with_a_known_closed_port_that_a_scanner_may_reach(self):
		for address, port in (('93.184.216.34', 81), ('93.184.216.35', 82), ('8.8.8.8', 83), ('1.1.1.1', 84), ('192.168.1.5', 85), ('9.9.9.9', None)):
			self.make(address, port)
		self.make('4.4.4.4', 86, days=60)
		got = dict(path_probe.candidates())
		self.assertEqual(got.get('8.8.8.8'), 83)
		self.assertEqual(got.get('1.1.1.1'), 84)
		self.assertEqual(len([a for a in got if a.startswith('93.184.')]), 1)  # one per /16
		self.assertNotIn('192.168.1.5', got)  # private addresses are refused unless the install scans its own network
		self.assertNotIn('9.9.9.9', got)      # no closed port known
		self.assertNotIn('4.4.4.4', got)      # not fingerprinted lately

	def test_check_needs_enough_hosts_and_reports_why_it_cannot_say(self):
		self.assertEqual(path_probe.check(probe=lambda *a: True)['state'], 'unknown')
		for address in ('8.8.8.8', '1.1.1.1', '9.9.9.9', '4.4.4.4'):
			self.make(address, 81)
		out = path_probe.check(probe=lambda ip, port, flags: flags == path_probe.SYN)
		self.assertEqual((out['state'], out['lost']), ('interfering', 4))
		out = path_probe.check(probe=lambda ip, port, flags: True)
		self.assertEqual(out['state'], 'direct')

		def no_raw(*a):
			raise path_probe.RawSocketsUnavailable('x')
		self.assertIn('raw', path_probe.check(probe=no_raw)['why'])


@unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'raw sockets need root')
class RealPacketTests(SimpleTestCase):
	"""The packets themselves, against the kernel's own stack on the loopback: a closed port answers both the plain and the odd segment with a
	reset, and a port nobody answers on (a dropped packet) answers neither."""

	def closed_port(self):
		with socket.socket() as sock:
			sock.bind(('127.0.0.1', 0))
			return sock.getsockname()[1]

	def test_a_closed_port_resets_both(self):
		try:
			port = self.closed_port()
			self.assertTrue(path_probe.send_probe('127.0.0.1', port, path_probe.SYN, timeout=1))
			self.assertTrue(path_probe.send_probe('127.0.0.1', port, path_probe.ODD_FLAGS, timeout=1))
		except path_probe.RawSocketsUnavailable:
			self.skipTest('no raw sockets in this environment')

	def test_a_filtered_port_answers_nothing(self):
		import subprocess
		port = self.closed_port()
		rule = ['-p', 'tcp', '--dport', str(port), '-j', 'DROP']
		try:
			subprocess.run(['iptables', '-I', 'INPUT', *rule], check=True, capture_output=True)
		except (OSError, subprocess.CalledProcessError):
			self.skipTest('no iptables here')
		try:
			self.assertFalse(path_probe.send_probe('127.0.0.1', port, path_probe.SYN, timeout=0.5))
		except path_probe.RawSocketsUnavailable:
			self.skipTest('no raw sockets in this environment')
		finally:
			subprocess.run(['iptables', '-D', 'INPUT', *rule], capture_output=True)
