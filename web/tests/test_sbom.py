import importlib.util
import json
import os
import re

from django.test import SimpleTestCase

PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts', 'generate_sbom.py')
spec = importlib.util.spec_from_file_location('generate_sbom', PATH)
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)


class SbomTests(SimpleTestCase):
	"""The bill of materials is built from the pins in the repository, so these checks are against the real files."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.doc = sbom.build()
		# the operating system packages are kept apart: tzdata is both an apt package and a PyPI package
		cls.apt = {c['name']: c for c in cls.doc['components'] if c.get('purl', '').startswith('pkg:deb/')}
		cls.by_name = {c['name']: c for c in cls.doc['components'] if c['name'] not in cls.apt or not c.get('purl', '').startswith('pkg:deb/')}

	def test_it_is_a_cyclonedx_document_about_this_version(self):
		self.assertEqual((self.doc['bomFormat'], self.doc['specVersion']), ('CycloneDX', '1.5'))
		self.assertRegex(self.doc['serialNumber'], r'^urn:uuid:[0-9a-f-]{36}$')
		self.assertRegex(self.doc['metadata']['timestamp'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
		self.assertEqual(self.doc['metadata']['component']['version'], sbom.read('web/.version').strip())
		refs = [c['bom-ref'] for c in self.doc['components']]
		self.assertEqual(len(refs), len(set(refs)))
		self.assertEqual(self.doc['dependencies'][0]['dependsOn'], refs)

	def test_every_scanner_tool_is_listed_with_its_pinned_version(self):
		dockerfile = sbom.read('web/Dockerfile')
		for name, argname in (('nmap', 'NMAPVERSION'), ('nuclei', 'NUCLEI_VERSION'), ('naabu', 'NAABU_VERSION'), ('bbot', 'BBOT_VERSION'),
				('wpscan', 'WPSCAN_VERSION'), ('go', 'GOVERSION'), ('tzdata', 'TZDATA_VERSION'), ('testssl.sh', 'TESTSSL_VERSION')):
			self.assertEqual(self.by_name[name]['version'], sbom.arg(dockerfile, argname), name)
			self.assertEqual(self.by_name[name]['properties'][0], {'name': 'cvengine:pinned', 'value': 'true'}, name)
		self.assertEqual(self.by_name['nuclei']['purl'], f"pkg:golang/github.com/projectdiscovery/nuclei/v3@v{self.by_name['nuclei']['version']}")

	def test_downloads_carry_their_checksums(self):
		for name in ('nmap', 'go', 'testssl.sh'):
			hashes = [h['content'] for h in self.by_name[name]['hashes']]
			self.assertTrue(hashes and all(re.fullmatch(r'[0-9a-f]{64}', h) for h in hashes), name)
		self.assertEqual(len(self.by_name['nmap']['hashes']), 2)  # the source tarball and the amd64 RPM

	def test_what_is_not_pinned_is_marked_as_such(self):
		self.assertEqual(self.by_name['nuclei-templates']['properties'][0]['value'], 'false')
		self.assertEqual(self.by_name['ubuntu']['properties'][0]['value'], 'false')
		self.assertEqual(self.by_name['Pillow']['properties'][0]['value'], 'false')  # a version range in requirements.txt
		self.assertNotIn('version', self.by_name['Pillow'])
		self.assertEqual(self.by_name['Django']['purl'], f"pkg:pypi/django@{self.by_name['Django']['version']}")

	def test_the_service_images_are_listed_and_the_application_image_is_not(self):
		self.assertIn('postgres', self.by_name)
		self.assertIn('tailscale/tailscale', self.by_name)
		self.assertRegex(self.by_name['tailscale/tailscale']['version'], r'^\d+\.\d+\.\d+$')
		self.assertNotIn('cvengine/web', self.by_name)

	def test_the_openvas_add_on_is_listed(self):
		requirements = sbom.read('web/requirements.txt')
		pinned = re.search(r'(?m)^python-gvm==([0-9.]+)\s*$', requirements).group(1)
		self.assertEqual(self.by_name['python-gvm']['version'], pinned)
		self.assertEqual(self.by_name['python-gvm']['properties'][0], {'name': 'cvengine:pinned', 'value': 'true'})
		images = {n: c for n, c in self.by_name.items() if n.split('/', 1)[0] == 'registry.community.greenbone.net'}
		compose = sbom.read('docker-compose.yml')
		self.assertEqual(set(images), {'registry.community.greenbone.net/community/' + n for n in set(re.findall(
			r'registry\.community\.greenbone\.net/community/([a-z-]+):', compose))})
		self.assertIn('registry.community.greenbone.net/community/ospd-openvas', images)
		for name, item in images.items():
			digested = bool(item.get('hashes'))
			self.assertEqual(item['properties'][0]['value'], 'true' if digested else 'false', name)
			if digested:
				self.assertTrue(all(re.fullmatch(r'[0-9a-f]{64}', h['content']) for h in item['hashes']), name)
			else:  # the feed images float on purpose and the bill says so
				self.assertIn('moving tag on purpose', item['properties'][1]['value'], name)
		self.assertTrue(images['registry.community.greenbone.net/community/vulnerability-tests']['properties'][1]['value'])

	def test_a_digest_pin_is_read_as_a_pin_and_a_moving_tag_as_one(self):
		listed = {c['name']: c for c in sbom.service_images(
			'image: "example.test/a/b:stable@sha256:' + '0' * 64 + '"\nimage: nginx:alpine\nimage: registry.community.greenbone.net/community/x-data:community\n')}
		self.assertEqual(listed['example.test/a/b']['version'], 'stable')
		self.assertEqual(listed['example.test/a/b']['hashes'][0]['content'], '0' * 64)
		self.assertEqual(listed['example.test/a/b']['properties'][0]['value'], 'true')
		self.assertEqual(listed['nginx']['properties'][0]['value'], 'false')
		self.assertIn('moving tag on purpose', listed['registry.community.greenbone.net/community/x-data']['properties'][1]['value'])

	def test_the_same_commit_gives_the_same_document(self):
		self.assertEqual(json.dumps(sbom.build(), sort_keys=True), json.dumps(self.doc, sort_keys=True))

	def test_requirement_lines_are_parsed_defensively(self):
		parsed = {c['name']: c for c in sbom.python_packages('# comment\n\n-r other.txt\nfoo_bar==1.2.3  # pinned\nbaz>=1,<2\nqux\n')}
		self.assertEqual(parsed['foo_bar']['purl'], 'pkg:pypi/foo-bar@1.2.3')
		self.assertEqual(parsed['baz']['properties'][0]['value'], 'false')
		self.assertEqual(parsed['qux']['properties'][0]['value'], 'false')
		self.assertNotIn('-r', parsed)

	def test_the_apt_packages_and_the_report_dependencies_are_listed(self):
		for name in ('fonts-dejavu-core', 'bind9-dnsutils', 'libpango-1.0-0'):
			self.assertEqual(self.apt[name]['purl'], f"pkg:deb/ubuntu/{name}?distro=ubuntu-26.04", name)
			self.assertEqual(self.apt[name]['properties'][0]['value'], 'false', name)  # apt installs whatever the release holds that day
		self.assertNotIn('libarchive-tools', self.apt)  # installed and purged in the same build
		self.assertEqual(self.by_name['tzdata']['purl'], f"pkg:pypi/tzdata@{self.by_name['tzdata']['version']}")
		self.assertEqual(self.by_name['pypdf']['version'], re.search(r'(?m)^pypdf==(\S+)', sbom.read('web/requirements.txt')).group(1))
		self.assertEqual(self.by_name['pypdf']['properties'][0]['value'], 'true')

	def test_apt_lines_are_parsed_defensively(self):
		text = 'RUN apt-get update -y && \\\n    apt-get install -y --no-install-recommends \\\n    foo \\\n    bar && \\\n    rm -rf /x\nRUN (apt-get install -y baz || echo "no") && apt-get purge -y baz qux\n'
		self.assertEqual([c['name'] for c in sbom.apt_packages(text)], ['bar', 'foo'])
