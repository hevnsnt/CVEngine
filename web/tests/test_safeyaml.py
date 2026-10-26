import time

import yaml
from django.test import SimpleTestCase

from cveFeed import templategen, validation
from cveFeed.safeyaml import load_template

BOMB = ('a: &a [x,x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n'
		'd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]\ne: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d,*d]\nf: [*e,*e,*e,*e,*e,*e,*e,*e,*e,*e]\n')
TEMPLATE = 'id: CVE-2099-0001\ninfo:\n  name: x\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/x"\n'


class AliasRefusalTests(SimpleTestCase):
	def test_a_plain_template_still_loads(self):
		self.assertEqual(load_template(TEMPLATE)['id'], 'CVE-2099-0001')

	def test_anchors_and_aliases_are_refused(self):
		with self.assertRaises(yaml.YAMLError):
			load_template('a: &x [1]\nb: *x\n')
		with self.assertRaises(yaml.YAMLError):
			load_template('a: &x 1\n')

	def test_an_alias_bomb_is_rejected_quickly_by_each_gate(self):
		started = time.monotonic()
		ok, reason = templategen.static_check('id: CVE-2099-0001\n' + BOMB)
		self.assertFalse(ok)
		self.assertIn('invalid YAML', reason)
		self.assertTrue(validation.readonly_problem('id: x\n' + BOMB))
		self.assertLess(time.monotonic() - started, 2)
