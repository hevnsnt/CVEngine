"""A page must never show unstyled content: an icon without a size ballooned to the container width and painted a giant black glyph (the
filled #i-pulse path is a triangle) while a slow link was still fetching the stylesheet. Three guards, all source-level (no browser):
every inline icon carries width and height; a small inline critical style comes before the stylesheet and never owns a colour of its own;
/staticfiles/ is cached for a year only at a content-versioned URL."""
import json
import os
import re
import tempfile

from django.test import SimpleTestCase, override_settings

from cveFeed.templatetags import assets

WEB = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
REPO = os.path.abspath(os.path.join(WEB, '..'))


def read(*parts):
	with open(os.path.join(*parts), encoding='utf-8') as handle:
		return handle.read()


def files(root, suffix, skip=('node_modules', 'tests', 'staticfiles')):
	for base, dirs, names in os.walk(root):
		dirs[:] = [d for d in dirs if d not in skip]
		for name in sorted(names):
			if name.endswith(suffix):
				yield os.path.join(base, name)


class InlineIconSizeTests(SimpleTestCase):
	def test_every_inline_svg_in_a_template_has_width_and_height(self):
		bad = []
		seen = 0
		for path in files(WEB, '.html'):
			text = read(path)
			for m in re.finditer(r'<svg\b[^>]*>', text):
				seen += 1
				tag = m.group(0)
				if not (re.search(r'\swidth=', tag) and re.search(r'\sheight=', tag)):
					bad.append(f'{os.path.relpath(path, WEB)}: {tag[:90]}')
		self.assertGreater(seen, 20)  # the walk found the shell's icons
		self.assertEqual(bad, [], 'inline <svg> without width and height renders at the container width until the stylesheet applies')

	def test_every_svg_the_scripts_build_gets_width_and_height(self):
		# a vendored library (qrcode.js sizes its own output; the graph library draws its own svg) is not ours to patch
		vendored = {'qrcode.js', 'vivagraph.min.js'}
		bad = []
		for path in list(files(os.path.join(WEB, 'static'), '.js')):
			name = os.path.basename(path)
			if name in vendored or name.endswith('.min.js'):
				continue
			text = read(path)
			lines = text.split('\n')
			for i, line in enumerate(lines):
				creates = re.search(r'''createElementNS\([^)]*,\s*["']svg["']\)|\bs\(\s*["']svg["']''', line)
				literal = re.search(r'<svg\b[^>]*>', line)
				if creates:
					window = '\n'.join(lines[i:i + 8])
					if not (re.search(r'''["']width["']|\bwidth:''', window) and re.search(r'''["']height["']|\bheight:''', window)):
						bad.append(f'{name}:{i + 1}')
				elif literal and not (re.search(r'\swidth=', literal.group(0)) and re.search(r'\sheight=', literal.group(0))):
					bad.append(f'{name}:{i + 1}')
		self.assertEqual(bad, [], 'script-built <svg> without width and height')

	def test_the_standalone_maintenance_page_sizes_its_illustration(self):
		text = read(WEB, 'static', 'cve', 'maintenance.html')
		tag = re.search(r'<svg\b[^>]*>', text).group(0)
		self.assertRegex(tag, r'\swidth=')
		self.assertRegex(tag, r'\sheight=')


class CriticalStyleTests(SimpleTestCase):
	PAGES = ('cveFeed/templates/cveFeed/base.html', 'cveFeed/templates/cveFeed/welcome.html', 'templates/tenancy/base.html',
		'templates/error.html', 'templates/404.html')

	def test_the_block_renders_as_one_inline_style(self):
		out = str(assets.critical_style())
		self.assertTrue(out.startswith('<style>') and out.endswith('</style>'))
		self.assertEqual(out.count('<style>'), 1)

	def test_every_page_that_loads_the_stylesheet_inlines_it_first(self):
		for page in self.PAGES:
			text = read(WEB, page)
			self.assertIn('{% critical_style %}', text, page)
			self.assertLess(text.index('{% critical_style %}'), text.index("{% asset 'cve/cve.css' %}"), page)  # before: cve.css wins ties
			self.assertIn('{% load static assets %}', text, page)

	def test_it_holds_the_rules_that_stop_a_giant_glyph_and_a_jumping_layout(self):
		css = assets.CRITICAL_CSS
		self.assertIn('.skip{position:absolute;left:-999px', css)  # 'Skip to content' stays out of sight
		self.assertRegex(css, r':where\(svg\[viewBox="0 0 24 24"\]\)\{fill:none;stroke:currentColor')  # the sprite icons are strokes, not filled shapes
		self.assertRegex(css, r'@media \(min-width:1024px\)\{[^@]*grid-template-columns:var\(--rail,260px\)')  # the rail has its width before the sheet
		self.assertIn('.rail{display:none}', css)

	def test_it_keeps_the_design_tokens_as_the_single_source(self):
		css = assets.CRITICAL_CSS
		sheet = read(WEB, 'static', 'cve', 'cve.css')
		# no colour of its own: a hex value may only appear as the fallback inside var(--token, ...)
		bare = re.sub(r'var\(--[a-z0-9-]+,\s*#[0-9a-fA-F]{3,8}\)', '', css)
		self.assertNotRegex(bare, r'#[0-9a-fA-F]{3,8}')
		self.assertNotRegex(bare, r'\brgba?\(')
		light = re.search(r':root\{(.*?)\n\}', sheet, re.S).group(1)
		dark = re.search(r':root\[data-theme="dark"\]\{(.*?)\n\}', sheet, re.S).group(1)
		token = lambda block, name: re.search(rf'--{name}:([^;]+);', block).group(1).strip()
		fallbacks = re.findall(r'var\(--([a-z0-9-]+),\s*(#[0-9a-fA-F]{3,8})\)', css)
		self.assertEqual({n for n, _ in fallbacks}, {'bg', 'ink'})
		light_part, dark_part = css.split('html[data-theme="dark"] body')
		for name, value in re.findall(r'var\(--([a-z0-9-]+),\s*(#[0-9a-fA-F]{3,8})\)', light_part):
			self.assertEqual(value, token(light, name), f'--{name} fallback drifted from cve.css :root')
		for name, value in re.findall(r'var\(--([a-z0-9-]+),\s*(#[0-9a-fA-F]{3,8})\)', dark_part):
			self.assertEqual(value, token(dark, name), f'--{name} fallback drifted from the dark theme')
		for name in ('rail', 'tab'):  # sizes mirror the sheet's own tokens
			self.assertIn(f'var(--{name},{token(light, name)})', css)


class StaticCachePolicyTests(SimpleTestCase):
	conf = staticmethod(lambda: read(REPO, 'config', 'nginx', 'rengine.conf'))

	def test_only_a_well_formed_content_version_earns_a_year(self):
		conf = self.conf()
		block = re.search(r'map \$arg_v \$cvengine_static_cache \{(.*?)\n\}', conf, re.S).group(1)
		self.assertRegex(block, r'default\s+"no-cache";')
		entry = re.search(r'"~(\^[^"]+\$)"\s+"([^"]+)";', block)
		self.assertEqual(entry.group(2), 'public, max-age=31536000, immutable')
		pattern = re.compile(entry.group(1))
		self.assertEqual(conf.count('immutable'), 1)  # the map value only: nothing unversioned is ever immutable
		self.assertIsNone(pattern.match(''))
		self.assertIsNone(pattern.match('1'))
		self.assertIsNone(pattern.match('latest'))
		self.assertIsNone(pattern.match('abcdef0123/../x'))
		self.assertTrue(pattern.match(assets.version('cve/cve.css')))  # what the {% asset %} tag really emits

	def test_the_static_location_uses_the_map_and_keeps_nosniff(self):
		conf = self.conf()
		loc = conf[conf.index('location /staticfiles/'):]
		loc = loc[:loc.index('\n    }')]
		self.assertIn('add_header Cache-Control $cvengine_static_cache always;', loc)
		self.assertNotIn('"no-cache"', loc)  # the default lives in the map
		self.assertIn('add_header X-Content-Type-Options "nosniff" always;', loc)

	def test_text_assets_stay_compressed(self):
		conf = self.conf()
		self.assertRegex(conf, r'gzip\s+on;')
		for kind in ('text/css', 'application/javascript', 'text/javascript'):
			self.assertIn(kind, re.search(r'gzip_types\s+([^;]+);', conf).group(1))

	def test_every_script_and_stylesheet_url_carries_the_version(self):
		for path in files(WEB, '.html'):
			text = read(path)
			for m in re.finditer(r'''(?:src|href)="\{% static '([^']+\.(?:js|css))' %\}"''', text):
				self.fail(f'{os.path.relpath(path, WEB)} links {m.group(1)} without {{% asset %}}, so it would be revalidated on every page')

	def test_the_import_map_gives_every_module_its_version(self):
		out = str(assets.importmap())
		imports = json.loads(re.search(r'>(.*)</script>', out, re.S).group(1))['imports']
		self.assertGreater(len(imports), 30)
		for plain, versioned in imports.items():
			self.assertRegex(versioned, rf'^{re.escape(plain)}\?v=[0-9a-f]{{10}}$')

	def test_two_releases_never_share_a_url_for_different_bytes(self):
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, 'cve'))
			target = os.path.join(root, 'cve', 'x.js')
			with override_settings(STATICFILES_DIRS=[root]):
				saved = dict(assets._hashes)
				try:
					assets._hashes.clear()
					open(target, 'w').write('export const a = 1;\n')
					first = assets.asset('cve/x.js')
					assets._hashes.clear()  # a new release is a new process
					open(target, 'w').write('export const a = 2;\n')
					second = assets.asset('cve/x.js')
				finally:
					assets._hashes.clear()
					assets._hashes.update(saved)
		self.assertNotEqual(first, second)
		self.assertIn('?v=', first)
