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

	def test_no_scan_tool_or_template_set_is_in_this_image(self):
		for gone in ('nuclei', 'go', 'nuclei-templates', 'nmap', 'naabu', 'bbot', 'tzdata', 'wpscan', 'testssl.sh'):  # every scan tool runs on the Sentinels
			self.assertNotIn(gone, self.by_name)

	def test_what_is_not_pinned_is_marked_as_such(self):
		self.assertEqual(self.by_name['ubuntu']['properties'][0]['value'], 'false')
		self.assertEqual(self.by_name['Pillow']['properties'][0]['value'], 'false')  # a version range in requirements.txt
		self.assertNotIn('version', self.by_name['Pillow'])
		self.assertEqual(self.by_name['Django']['purl'], f"pkg:pypi/django@{self.by_name['Django']['version']}")

	def test_the_pinned_interpreter_is_listed(self):
		# the image's Python is a pinned CPython build, not Ubuntu's python3 (tests/test_image_python.py)
		self.assertRegex(self.by_name['cpython']['version'], r'^3\.\d+\.\d+$')
		self.assertEqual(self.by_name['cpython']['properties'][0]['value'], 'true')
		self.assertEqual(self.by_name['ubuntu']['version'], '26.04')  # the uv stage before it is not read as the base

	def test_the_service_images_are_listed_and_the_application_image_is_not(self):
		self.assertIn('postgres', self.by_name)
		self.assertIn('tailscale/tailscale', self.by_name)
		self.assertRegex(self.by_name['tailscale/tailscale']['version'], r'^\d+\.\d+\.\d+$')
		self.assertNotIn('cvengine/web', self.by_name)

	def test_the_openvas_add_on_is_not_part_of_the_server(self):
		# OpenVAS runs on a Sentinel: the server image has no python-gvm and its compose file no Greenbone image
		self.assertNotIn('python-gvm', self.by_name)
		self.assertFalse([n for n in self.by_name if n.split('/', 1)[0] == 'registry.community.greenbone.net'])

	def test_a_digest_pin_is_read_as_a_pin_and_a_moving_tag_as_one(self):
		listed = {c['name']: c for c in sbom.service_images(
			'image: "example.test/a/b:stable@sha256:' + '0' * 64 + '"\nimage: nginx:alpine\nimage: example.test/c/x-data:community\n')}
		self.assertEqual(listed['example.test/a/b']['version'], 'stable')
		self.assertEqual(listed['example.test/a/b']['hashes'][0]['content'], '0' * 64)
		self.assertEqual(listed['example.test/a/b']['properties'][0]['value'], 'true')
		self.assertEqual(listed['nginx']['properties'][0]['value'], 'false')
		self.assertEqual(listed['example.test/c/x-data']['properties'][0]['value'], 'false')
		self.assertIn('refreshed with every update', listed['nginx']['properties'][1]['value'])

	def test_the_same_commit_gives_the_same_document(self):
		self.assertEqual(json.dumps(sbom.build(), sort_keys=True), json.dumps(self.doc, sort_keys=True))

	def test_requirement_lines_are_parsed_defensively(self):
		parsed = {c['name']: c for c in sbom.python_packages('# comment\n\n-r other.txt\nfoo_bar==1.2.3  # pinned\nbaz>=1,<2\nqux\n')}
		self.assertEqual(parsed['foo_bar']['purl'], 'pkg:pypi/foo-bar@1.2.3')
		self.assertEqual(parsed['baz']['properties'][0]['value'], 'false')
		self.assertEqual(parsed['qux']['properties'][0]['value'], 'false')
		self.assertNotIn('-r', parsed)

	def test_the_apt_packages_and_the_report_dependencies_are_listed(self):
		for name in ('fonts-dejavu-core', 'libpq-dev', 'libpango-1.0-0', 'tzdata'):
			self.assertEqual(self.apt[name]['purl'], f"pkg:deb/ubuntu/{name}?distro=ubuntu-26.04", name)
			self.assertEqual(self.apt[name]['properties'][0]['value'], 'false', name)  # apt installs whatever the release holds that day
		self.assertNotIn('libarchive-tools', self.apt)  # installed and purged in the same build
		for gone in ('bind9-dnsutils', 'ruby', 'cargo', 'cmake', 'libpcap-dev'):  # only the scan tools needed them
			self.assertNotIn(gone, self.apt)
		self.assertEqual(self.by_name['pypdf']['version'], re.search(r'(?m)^pypdf==(\S+)', sbom.read('web/requirements.txt')).group(1))
		self.assertEqual(self.by_name['pypdf']['properties'][0]['value'], 'true')

	def test_apt_lines_are_parsed_defensively(self):
		text = 'RUN apt-get update -y && \\\n    apt-get install -y --no-install-recommends \\\n    foo \\\n    bar && \\\n    rm -rf /x\nRUN (apt-get install -y baz || echo "no") && apt-get purge -y baz qux\n'
		self.assertEqual([c['name'] for c in sbom.apt_packages(text)], ['bar', 'foo'])
