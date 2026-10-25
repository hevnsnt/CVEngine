import json
import unittest
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import fingerprint, fullscan, hosting, nmap_scan, route_auth
from cveFeed.models import RouteAuth
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Technology
from targetApp.models import Domain


def names(found):
	return [f['name'] for f in found]


class FingerprintTests(unittest.TestCase):
	def test_a_netlify_nextjs_site(self):
		found = fingerprint.from_response(server='Netlify', content_type='text/html', body='<script id="__NEXT_DATA__"></script>')
		self.assertEqual(names(found), ['Netlify', 'Next.js'])
		self.assertEqual([f['source'] for f in found], ['header:server', 'page:_next'])

	def test_server_and_powered_by_headers_carry_versions(self):
		found = fingerprint.from_response(server='nginx/1.25.3 (Ubuntu)', powered_by='PHP/8.2.30')
		self.assertEqual(names(found), ['nginx:1.25.3', 'PHP:8.2.30'])
		self.assertEqual(names(fingerprint.from_response(server='Apache/2.4.58 (Ubuntu)')), ['Apache HTTP Server:2.4.58'])
		self.assertEqual(names(fingerprint.from_response(server='Microsoft-IIS/10.0')), ['Microsoft IIS:10.0'])

	def test_several_powered_by_values(self):
		self.assertEqual(names(fingerprint.from_response(server='cloudflare', powered_by='Craft CMS, SEOmatic')),
			['Cloudflare', 'Craft CMS', 'SEOmatic'])

	def test_generator_meta_and_wordpress_paths(self):
		body = '<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/x.css">'
		self.assertEqual(names(fingerprint.from_response(body=body, content_type='text/html')), ['WordPress:6.4.2'])

	def test_a_php_link_names_php_and_a_header_version_replaces_it(self):
		body = '<a href="/index.php?x=1">x</a>'
		self.assertEqual(names(fingerprint.from_response(body=body, content_type='text/html')), ['PHP'])
		found = fingerprint.from_response(powered_by='PHP/8.2.30', body=body, content_type='text/html')
		self.assertEqual(names(found), ['PHP:8.2.30'])

	def test_a_page_with_no_php_signs_names_no_php(self):
		body = '<script src="/_next/static/a.js"></script><img src="https://www.datocms-assets.com/1/a.png">'
		self.assertNotIn('PHP', ' '.join(names(fingerprint.from_response(server='Netlify', body=body, content_type='text/html'))))

	def test_a_hostile_header_cannot_inject_a_name(self):
		for value in ('<script>alert(1)</script>/9', 'x' * 80, 'a"b', 'Robert\'); DROP TABLE'):
			self.assertEqual(names(fingerprint.from_response(powered_by=value)), [], value)
		found = fingerprint.from_response(server='nginx/1.2<b>', powered_by='')
		for name in names(found):
			self.assertNotRegex(name, r'[<>"\']')

	def test_names_are_capped(self):
		body = ''.join(f'<meta name="x{i}">' for i in range(100)) + '__NEXT_DATA__ /_nuxt/ /wp-content/ Drupal.settings cdn.shopify.com csrfmiddlewaretoken .php'
		self.assertLessEqual(len(fingerprint.from_response(server='Netlify', powered_by=', '.join(f'P{i}' for i in range(50)), body=body, content_type='text/html')),
			fingerprint.MAX_FINGERPRINTS)

	def test_a_body_that_is_not_html_is_not_searched(self):
		self.assertEqual(fingerprint.from_response(body='/wp-content/', content_type='application/json'), [])

	def test_categories(self):
		self.assertEqual(fingerprint.categorize('PHP:8.2.30'), 'language')
		self.assertEqual(fingerprint.categorize('nginx:1.25.3'), 'web server')
		self.assertEqual(fingerprint.categorize('Next.js'), 'framework')
		self.assertEqual(fingerprint.categorize('google-tag-manager'), 'analytics')
		self.assertEqual(fingerprint.categorize('datocms'), 'cms')
		self.assertEqual(fingerprint.categorize('Netlify'), 'hosting')
		self.assertEqual(fingerprint.categorize('mystery'), '')


class ClassifyTests(unittest.TestCase):
	def test_a_netlify_cname_is_a_shared_platform(self):
		info = hosting.classify(name='archive.acme-example.org', cname='acme-website.netlify.app.')
		self.assertEqual((info['provider'], info['kind'], info['shared_ip']), ('Netlify', 'paas', True))
		self.assertIn('CNAME acme-website.netlify.app', info['evidence'])

	def test_the_name_itself_and_the_server_header_also_say_so(self):
		self.assertEqual(hosting.classify(name='site.vercel.app')['provider'], 'Vercel')
		self.assertTrue(hosting.classify(name='x.example.org', webserver='Netlify')['shared_ip'])
		self.assertEqual(hosting.classify(name='x.example.org', webserver='GitHub.com')['provider'], 'GitHub Pages')

	def test_a_cdn_edge_is_shared(self):
		info = hosting.classify(name='www.example.org', webserver='cloudflare')
		self.assertEqual((info['provider'], info['kind'], info['shared_ip']), ('Cloudflare', 'cdn', True))
		info = hosting.classify(name='a.example.org', is_cdn=True, cdn_name='Imperva')
		self.assertEqual((info['provider'], info['shared_ip']), ('Imperva', True))

	def test_a_cloud_vm_is_infrastructure_not_a_shared_ip(self):
		info = hosting.classify(name='mail.example.org', reverse_pointers=['ec2-203-0-113-9.compute-1.amazonaws.com'])
		self.assertEqual((info['provider'], info['kind'], info['shared_ip'], info['infrastructure']),
			('', 'cloud', False, 'Amazon Web Services (EC2)'))

	def test_netlify_on_aws_reports_both(self):
		info = hosting.classify(name='a.example.org', cname='x.netlify.app', reverse_pointers=['ec2-1-2-3-4.compute-1.amazonaws.com'])
		self.assertEqual((info['provider'], info['infrastructure'], info['shared_ip']), ('Netlify', 'Amazon Web Services (EC2)', True))

	def test_an_ordinary_host_is_not_shared(self):
		info = hosting.classify(name='www.example.org', webserver='nginx/1.25')
		self.assertEqual((info['provider'], info['kind'], info['shared_ip'], info['evidence']), ('', '', False, []))

	def test_a_lookalike_suffix_does_not_count(self):
		for cname in ('netlify.app.evil.com', 'notnetlify.app', 'xnetlify.app', 'netlify.app.example.org'):
			self.assertFalse(hosting.classify(name='a.example.org', cname=cname)['shared_ip'], cname)

	def test_odd_input_does_not_raise(self):
		self.assertFalse(hosting.classify(name=None, cname=None, webserver=None, reverse_pointers=None)['shared_ip'])
		self.assertFalse(hosting.classify(name='\u202e\x00', cname='\n')['shared_ip'])


class CanonicalNameTests(unittest.TestCase):
	def setUp(self):
		hosting._canon.clear()
		self.addCleanup(hosting._canon.clear)

	def test_the_end_of_the_cname_chain_is_returned_and_cached(self):
		with mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, 'acme-website.netlify.app', ('1.2.3.4', 0))]) as lookup:
			self.assertEqual(hosting.canonical_name('archive.acme-example.org'), 'acme-website.netlify.app')
			self.assertEqual(hosting.canonical_name('ARCHIVE.acme-example.org.'), 'acme-website.netlify.app')
		self.assertEqual(lookup.call_count, 1)

	def test_a_plain_host_and_a_failed_lookup_have_no_canonical_name(self):
		with mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, 'www.example.org', ('1.2.3.4', 0))]):
			self.assertEqual(hosting.canonical_name('www.example.org'), '')
		with mock.patch('socket.getaddrinfo', side_effect=OSError('nope')):
			self.assertEqual(hosting.canonical_name('gone.example.org'), '')

	def test_the_cache_is_bounded(self):
		with mock.patch('socket.getaddrinfo', return_value=[]), mock.patch.object(hosting, 'CANON_MAX', 5):
			for i in range(40):
				hosting.canonical_name(f'h{i}.example.org')
		self.assertLessEqual(len(hosting._canon), 5)


class Fixture(TestCase):
	def setUp(self):
		now = timezone.now()
		self.project = Project.objects.create(name='P', slug='hr', insert_date=now, org=Org.objects.create(name='H', slug='hr'))
		self.domain = Domain.objects.create(name='acme.test', project=self.project, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=now, scan_status=2, results_dir='/tmp')
		patch = mock.patch('cveFeed.hosting.canonical_name', return_value='')
		patch.start()
		self.addCleanup(mock.patch.stopall)

	def host(self, name, address, **kw):
		sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name=name, **kw)
		ip = IpAddress.objects.get_or_create(address=address)[0]
		sub.ip_addresses.add(ip)
		return sub, ip


class SharedAddressTests(Fixture):
	def test_an_address_with_a_platform_cname_is_found_and_flagged(self):
		self.host('archive.acme.test', '198.51.100.7', cname='acme-website.netlify.app')
		self.host('www.plain.test', '198.51.100.8')
		found = hosting.shared_by_address(['198.51.100.7', '198.51.100.8'])
		self.assertEqual(list(found), ['198.51.100.7'])
		self.assertEqual(hosting.mark_shared(found), 1)
		self.assertTrue(IpAddress.objects.get(address='198.51.100.7').is_cdn)
		self.assertFalse(IpAddress.objects.get(address='198.51.100.8').is_cdn)

	def test_a_cname_that_was_never_stored_is_looked_up(self):
		self.host('archive.acme.test', '198.51.100.7')
		found = hosting.shared_by_address(['198.51.100.7'], lookup=lambda name: 'acme-website.netlify.app')
		self.assertEqual(found['198.51.100.7']['provider'], 'Netlify')

	def test_lookups_per_call_are_bounded(self):
		for i in range(40):
			self.host(f'h{i}.acme.test', f'198.51.100.{i + 10}')
		seen = []
		hosting.shared_by_address([f'198.51.100.{i + 10}' for i in range(40)], lookup=lambda n: seen.append(n) or '')
		self.assertEqual(len(seen), hosting.MAX_LOOKUPS)

	def test_the_server_header_alone_is_enough(self):
		self.host('x.acme.test', '198.51.100.9', webserver='Netlify')
		self.assertIn('198.51.100.9', hosting.shared_by_address(['198.51.100.9']))

	def test_empty_input(self):
		self.assertEqual(hosting.shared_by_address([]), {})
		self.assertEqual(hosting.shared_by_address([None, '']), {})


class PortScanGuardTests(Fixture):
	def setUp(self):
		super().setUp()
		for p in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
				  mock.patch('cveFeed.fullscan.CLAIM_KEY', 'cvengine:fullscan:hostrecord')):
			p.start()

	def test_the_background_sweep_never_scans_a_shared_platform_address(self):
		_, shared = self.host('archive.acme.test', '192.0.2.50', cname='acme-website.netlify.app')
		_, own = self.host('www.own.test', '192.0.2.51')
		self.assertFalse(fullscan.in_scope(shared))
		self.assertTrue(IpAddress.objects.get(pk=shared.pk).is_cdn)  # flagged, so the queue never offers it again
		self.assertTrue(fullscan.in_scope(own))
		self.assertEqual([i.address for i in fullscan.candidates()], ['192.0.2.51'])

	def test_the_host_nmap_pass_leaves_a_shared_platform_address_alone(self):
		self.host('archive.acme.test', '192.0.2.50', cname='acme-website.netlify.app')
		runner = mock.Mock()
		out = nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
		runner.assert_not_called()
		self.assertEqual(out, {'targets': 0, 'shared': 1})
		self.assertTrue(IpAddress.objects.get(address='192.0.2.50').is_cdn)

	def test_the_host_nmap_pass_still_scans_the_rest(self):
		self.host('archive.acme.test', '192.0.2.50', cname='acme-website.netlify.app')
		self.host('www.own.test', '192.0.2.51')
		seen = []

		def runner(targets, flags, host_timeout):
			seen.append(list(targets))
			return '<?xml version="1.0"?><nmaprun></nmaprun>'
		with mock.patch('cveFeed.naabu_scan.discover', return_value=None):
			nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner)
		self.assertEqual(seen, [['192.0.2.51']])


class RouteFingerprintTests(Fixture):
	def _probe(self, **kw):
		base = {'url': 'https://archive.acme.test/', 'status': 200, 'location': '', 'www_authenticate': '', 'cookies': [],
				'content_type': 'text/html', 'body': '', 'title': 'T', 'bytes': 0, 'server': '', 'powered_by': ''}
		return {**base, **kw}

	def test_evidence_keeps_the_headers_and_fingerprints_never_the_body(self):
		_, evidence = route_auth.classify(self._probe(server='nginx/1.25.3', powered_by='PHP/8.2.30', body='<p>secretbody</p>'))
		self.assertEqual((evidence['server'], evidence['powered_by']), ('nginx/1.25.3', 'PHP/8.2.30'))
		self.assertEqual(names(evidence['fingerprints']), ['nginx:1.25.3', 'PHP:8.2.30'])
		self.assertNotIn('secretbody', json.dumps(evidence))

	def test_a_response_with_nothing_to_say_adds_no_keys(self):
		_, evidence = route_auth.classify(self._probe())
		for key in ('server', 'powered_by', 'fingerprints'):
			self.assertNotIn(key, evidence)

	def test_headers_are_cut_short(self):
		_, evidence = route_auth.classify(self._probe(server='s' * 500))
		self.assertEqual(len(evidence['server']), 100)

	def _result(self, fingerprints):
		return {'evidence': {'fingerprints': [{'name': n, 'source': 'header:x-powered-by'} for n in fingerprints]}}

	def test_the_root_page_names_the_hosts_technologies_once(self):
		sub, _ = self.host('archive.acme.test', '192.0.2.60')
		probed = {'https://archive.acme.test/': self._result(['PHP:8.2.30', 'nginx:1.25.3']),
				  'http://archive.acme.test/': self._result(['PHP:8.2.30']),
				  'https://archive.acme.test/admin': self._result(['Secret:9'])}
		self.assertEqual(route_auth.link_technologies(self.scan, probed), 2)
		self.assertEqual(sorted(t.name for t in sub.technologies.all()), ['PHP:8.2.30', 'nginx:1.25.3'])
		self.assertEqual(route_auth.link_technologies(self.scan, probed), 0)  # nothing added twice
		self.assertEqual(Technology.objects.filter(name='PHP:8.2.30').count(), 1)

	def test_a_host_that_is_not_in_the_scan_is_left_alone(self):
		self.assertEqual(route_auth.link_technologies(self.scan, {'https://nobody.acme.test/': self._result(['PHP:8.2.30'])}), 0)
		self.assertEqual(route_auth.link_technologies(self.scan, {}), 0)


class HostRecordTests(Fixture):
	def _record(self, sub):
		from agentapi import services
		return services.host_group(self.project, sub)

	def test_the_route_check_fills_what_the_host_row_lacks(self):
		sub, ip = self.host('archive.acme.test', '192.0.2.70', cname='acme-website.netlify.app')
		ip.reverse_pointer = 'ec2-192-0-2-70.compute-1.amazonaws.com'
		ip.save()
		self.host('other.acme.test', '192.0.2.70')
		RouteAuth.objects.create(
			project=self.project, domain=self.domain, host='archive.acme.test', url='https://archive.acme.test/', path='/',
			auth_state='open', http_status=200, title='Acme', content_type='text/html',
			evidence={'server': 'Netlify', 'powered_by': 'PHP/8.2.30',
					  'fingerprints': [{'name': 'Netlify', 'source': 'header:server'}, {'name': 'PHP:8.2.30', 'source': 'header:x-powered-by'}]})
		sub.technologies.add(Technology.objects.create(name='next.js'))
		record = self._record(sub)
		self.assertEqual((record['http_status'], record['title']), (200, 'Acme'))
		self.assertEqual(record['http']['webserver'], 'Netlify')
		self.assertEqual(record['http']['powered_by'], 'PHP/8.2.30')
		self.assertEqual((record['http']['source'], record['http']['cname']), ('web route check', 'acme-website.netlify.app'))
		self.assertEqual((record['hosting']['provider'], record['hosting']['shared_ip'], record['hosting']['infrastructure']),
			('Netlify', True, 'Amazon Web Services (EC2)'))
		details = {d['name']: d for d in record['technology_details']}
		self.assertEqual((details['PHP']['version'], details['PHP']['category'], details['PHP']['source']), ('8.2.30', 'language', 'header:x-powered-by'))
		self.assertEqual((details['next.js']['source'], details['Netlify']['category']), ('scan', 'hosting'))
		self.assertEqual(record['ips'][0]['reverse'], 'ec2-192-0-2-70.compute-1.amazonaws.com')
		self.assertEqual(record['ips'][0]['names_on_ip'], 2)

	def test_the_host_rows_own_values_win(self):
		sub, _ = self.host('archive.acme.test', '192.0.2.71', http_status=301, page_title='Own', webserver='Caddy')
		RouteAuth.objects.create(project=self.project, domain=self.domain, host='archive.acme.test', url='https://archive.acme.test/', path='/',
			auth_state='open', http_status=200, title='Route', evidence={'server': 'Netlify'})
		record = self._record(sub)
		self.assertEqual((record['http_status'], record['title'], record['http']['webserver'], record['http']['source']),
			(301, 'Own', 'Caddy', 'host scan'))

	def test_a_host_nobody_probed_is_shown_as_unprobed_not_invented(self):
		sub, _ = self.host('quiet.acme.test', '192.0.2.72')
		record = self._record(sub)
		self.assertEqual((record['http_status'], record['title'], record['http']['source']), (0, None, ''))
		self.assertEqual((record['hosting']['provider'], record['hosting']['shared_ip']), ('', False))
		self.assertEqual(record['technology_details'], [])

	def test_a_retired_route_does_not_speak_for_the_host(self):
		sub, _ = self.host('gone.acme.test', '192.0.2.73')
		RouteAuth.objects.create(project=self.project, domain=self.domain, host='gone.acme.test', url='https://gone.acme.test/', path='/',
			auth_state='not_found', http_status=404, retired_at=timezone.now(), evidence={'server': 'Netlify'})
		self.assertEqual(self._record(sub)['http']['webserver'], '')

	def test_another_projects_route_never_leaks_in(self):
		other = Project.objects.create(name='O', slug='other', insert_date=timezone.now(), org=Org.objects.create(name='O', slug='other'))
		domain = Domain.objects.create(name='o.test', project=other, insert_date=timezone.now())
		sub, _ = self.host('shared-name.acme.test', '192.0.2.74')
		RouteAuth.objects.create(project=other, domain=domain, host='shared-name.acme.test', url='https://shared-name.acme.test/', path='/',
			auth_state='open', http_status=200, title='Other project', evidence={'server': 'Netlify'})
		record = self._record(sub)
		self.assertEqual((record['title'], record['http']['webserver']), (None, ''))
