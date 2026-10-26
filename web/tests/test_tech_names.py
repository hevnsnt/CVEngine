"""What the nuclei technology pass stores as a host's technology. Found on real hosts: a technology literally named "WAF" (the waf-detect
template's own name, the vendor that fired it thrown away), "AWS Service -", and a favicon hash stored as the version of "favicon-detection"."""
import unittest

from cveFeed.nuclei_scan import tech_name_from


class TechNameTests(unittest.TestCase):
    def test_a_waf_template_names_the_vendor_that_fired(self):
        line = {'template-id': 'waf-detect', 'matcher-name': 'cloudflare', 'info': {'name': 'WAF Detection'}}
        self.assertEqual(tech_name_from(line), 'cloudflare')
        dns = {'template-id': 'dns-waf-detect', 'matcher-name': 'imperva', 'info': {'name': 'DNS WAF Detection'}}
        self.assertEqual(tech_name_from(dns), 'imperva')

    def test_a_waf_result_without_a_vendor_names_nothing(self):
        self.assertEqual(tech_name_from({'template-id': 'waf-detect', 'info': {'name': 'WAF Detection'}}), '')

    def test_a_favicon_hash_is_not_a_version(self):
        line = {'template-id': 'favicon-detection', 'info': {'name': 'favicon-detection'}, 'extracted-results': ['307296554']}
        self.assertEqual(tech_name_from(line), '')
        named = {**line, 'matcher-name': 'Jenkins'}
        self.assertEqual(tech_name_from(named), 'Jenkins')

    def test_the_other_templates_still_read_their_name_and_version(self):
        self.assertEqual(tech_name_from({'template-id': 'tech-detect', 'matcher-name': 'nginx', 'info': {'name': 'Wappalyzer Technology Detection'}}), 'nginx')
        self.assertEqual(tech_name_from({'template-id': 'nginx-version', 'info': {'name': 'Nginx version detect'}, 'extracted-results': ['1.18.0']}), 'Nginx version:1.18.0')
        self.assertEqual(tech_name_from({'template-id': 'aws-detect', 'info': {'name': 'AWS Service - Detection'}}), 'AWS Service')


if __name__ == '__main__':
    unittest.main()
