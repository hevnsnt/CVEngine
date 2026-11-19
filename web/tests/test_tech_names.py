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
        self.assertEqual(tech_name_from({'template-id': 'nginx-version', 'info': {'name': 'Nginx version detect'}, 'extracted-results': ['1.18.0']}), 'Nginx:1.18.0')
        self.assertEqual(tech_name_from({'template-id': 'aws-detect', 'info': {'name': 'AWS Service - Detection'}}), 'AWS Service')


    def test_every_trailing_template_word_is_dropped(self):
        line = {'template-id': 'microsoft-iis-version', 'info': {'name': 'Microsoft IIS version detect'}, 'extracted-results': ['Microsoft-IIS/10.0']}
        self.assertEqual(tech_name_from(line), 'Microsoft IIS:10.0')
        self.assertEqual(tech_name_from({'template-id': 'x', 'info': {'name': 'Apache HTTP Server Detection'}}), 'Apache HTTP Server')

    def test_a_version_inside_an_extracted_value_is_read_after_the_product_name(self):
        # what the dedicated version templates extract on real hosts: a product/version token, a whole Server header (apache-detect, a kval
        # extractor), a name with a space; the version that follows the product's own name, never another product's
        cases = [('nginx-version', 'Nginx version detect', ['nginx/1.18.0'], 'Nginx:1.18.0'),
                 ('apache-detect', 'Apache Detection', ['Apache/2.4.41 (Ubuntu)'], 'Apache:2.4.41'),
                 ('openssl-detect', 'OpenSSL Detect', ['OpenSSL/1.0.2k'], 'OpenSSL:1.0.2k'),
                 ('cleo-vltrader-detect', 'Cleo VLTrader Detect', ['Cleo VLTrader/5.8.0.21'], 'Cleo VLTrader:5.8.0.21'),
                 ('php-detect', 'PHP Detect', ['Apache/2.4.41 (Ubuntu) PHP/7.4.3'], 'PHP:7.4.3'),
                 ('apache-detect', 'Apache Detection', ['Apache'], 'Apache'),  # a value with no version states none
                 ('apache-detect', 'Apache Detection', ['nginx/1.18.0'], 'Apache')]  # another product's version is not Apache's
        for template, name, values, want in cases:
            self.assertEqual(tech_name_from({'template-id': template, 'info': {'name': name}, 'extracted-results': values}), want, values)
        # a bare version and a token: the highest is kept, as before
        line = {'template-id': 'nginx-version', 'info': {'name': 'Nginx version detect'}, 'extracted-results': ['1.18.0', 'nginx/1.20.1']}
        self.assertEqual(tech_name_from(line), 'Nginx:1.20.1')


if __name__ == '__main__':
    unittest.main()
