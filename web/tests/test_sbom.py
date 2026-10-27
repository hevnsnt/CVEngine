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
		cls.by_name = {c['name']: c for c in cls.doc['components']}

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

	def test_the_same_commit_gives_the_same_document(self):
		self.assertEqual(json.dumps(sbom.build(), sort_keys=True), json.dumps(self.doc, sort_keys=True))

	def test_requirement_lines_are_parsed_defensively(self):
		parsed = {c['name']: c for c in sbom.python_packages('# comment\n\n-r other.txt\nfoo_bar==1.2.3  # pinned\nbaz>=1,<2\nqux\n')}
		self.assertEqual(parsed['foo_bar']['purl'], 'pkg:pypi/foo-bar@1.2.3')
		self.assertEqual(parsed['baz']['properties'][0]['value'], 'false')
		self.assertEqual(parsed['qux']['properties'][0]['value'], 'false')
		self.assertNotIn('-r', parsed)
