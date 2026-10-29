"""Unit tests for the deterministic CVE<->asset matching logic.

`cveFeed.correlation`'s matching core (`_match_candidates`, `build_product_index`
and the version/name helpers) is pure Python with only lazy Django imports, so
these run without a database. The same `_match_candidates` backs both the "tech"
(httpx fingerprint) and "port" (nmap -sV service) correlation paths, so testing
it here covers the step-5 port matching without a DB fixture.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cveFeed.correlation import (
    _match_candidates,
    affected_product_tokens,
    build_product_index,
    confidence_for,
    parse_cpe,
    parse_version,
    split_name_version,
    version_in_range,
    _norm,
)


class FakeCVE:
    def __init__(self, cid, affected, kev=False):
        self.id = cid
        self.affected = affected
        self.kev = kev


def _nginx_cve(cid=1, introduced="1.0.0", fixed="1.20.0", kev=False):
    return FakeCVE(cid, [{
        "product": "nginx",
        "vendor": "f5",
        "ranges": [{"introduced": introduced, "fixed": fixed}],
    }], kev=kev)


class TestMatchCandidates(unittest.TestCase):
    def setUp(self):
        self.cves = [_nginx_cve(1, kev=True), FakeCVE(2, [{"product": "apache_http_server",
                                                           "ranges": [{"introduced": "2.4.0", "fixed": "2.4.58"}]}])]
        self.index = build_product_index(self.cves)
        self.by_id = {c.id: c for c in self.cves}

    def _match(self, product, version):
        token = _norm(product)
        ver = parse_version(version)
        return list(_match_candidates(product, ver, token, self.index, self.by_id))

    def test_version_in_range_matches(self):
        results = self._match("nginx", "1.18.0")
        self.assertEqual(len(results), 1)
        cve, matched_product, in_range = results[0]
        self.assertEqual(cve.id, 1)
        self.assertEqual(matched_product, "nginx")
        self.assertIs(in_range, True)
        # KEV CVE with confirmed in-range version -> strong confidence.
        self.assertGreaterEqual(confidence_for(parse_version("1.18.0"), in_range, cve.kev), 0.9)

    def test_version_out_of_range_dropped(self):
        results = self._match("nginx", "1.21.0")  # >= fixed 1.20.0
        self.assertEqual(len(results), 1)
        _, _, in_range = results[0]
        self.assertIs(in_range, False)
        # out of range -> zero confidence -> correlate_subdomain would drop it.
        self.assertEqual(confidence_for(parse_version("1.21.0"), in_range, True), 0.0)

    def test_unknown_version_is_weak_candidate(self):
        results = self._match("nginx", "")  # no version captured
        self.assertEqual(len(results), 1)
        _, _, in_range = results[0]
        self.assertIsNone(in_range)
        self.assertEqual(confidence_for(None, in_range, False), 0.5)

    def test_unrelated_product_no_match(self):
        self.assertEqual(self._match("postgresql", "14.2"), [])

    def test_fuzzy_product_name_matches(self):
        # nmap often reports "Apache Tomcat" / "Apache httpd"; token containment
        # should still reach the apache CVE.
        results = self._match("Apache", "2.4.50")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0].id, 2)
        self.assertIs(results[0][2], True)


def _hits(cves, tech_or_product, version="", cpe=None):
    """(cve id, in_range, confidence) for each candidate a host product/tech string produces."""
    index = build_product_index(cves)
    by_id = {c.id: c for c in cves}
    name, ver_text = split_name_version(tech_or_product)
    ver_text = version or ver_text or (parse_cpe(cpe) or ("", "", ""))[2]
    ver = parse_version(ver_text)
    out = []
    for cve, _matched, in_range in _match_candidates(name, ver, _norm(name), index, by_id, cpe=cpe):
        out.append((cve.id, in_range, confidence_for(ver, in_range, cve.kev)))
    return sorted(out, key=lambda r: r[0])


LOG4J = FakeCVE(10, [{"vendor": "apache", "product": "log4j", "ranges": [{"introduced": "2.0", "fixed": "2.17.1"}]}], kev=True)
HTTPD = FakeCVE(11, [{"vendor": "apache", "product": "http_server", "ranges": [{"introduced": "2.4.0", "fixed": "2.4.58"}]}])
EXCHANGE = FakeCVE(12, [{"vendor": "microsoft", "product": "exchange_server", "ranges": [{"introduced": "15.0", "fixed": "15.2"}]}])


class TestVendorTokens(unittest.TestCase):
    """Review 1.1: a vendor is not a product; another product's ranges must never confirm a match."""

    def test_vendor_is_not_a_token(self):
        self.assertEqual(affected_product_tokens({"vendor": "apache", "product": "log4j"}), {"log4j"})
        self.assertEqual(affected_product_tokens({"vendor": "microsoft"}), set())

    def test_apache_httpd_host_is_not_a_log4j_host(self):
        self.assertEqual(_hits([LOG4J], "Apache HTTP Server:2.4.52"), [])
        self.assertEqual(_hits([LOG4J], "Apache", "2.4.52"), [])

    def test_apache_httpd_matches_http_server_cve(self):
        self.assertEqual(_hits([LOG4J, HTTPD], "Apache httpd", "2.4.52"), [(11, True, 0.85)])
        self.assertEqual(_hits([LOG4J, HTTPD], "Apache HTTP Server:2.4.52"), [(11, True, 0.85)])

    def test_iis_is_not_an_exchange_host(self):
        self.assertEqual(_hits([EXCHANGE], "Microsoft IIS httpd", "10.0"), [])

    def test_iis_matches_its_own_cve(self):
        iis = FakeCVE(13, [{"vendor": "microsoft", "product": "internet_information_services",
                            "ranges": [{"introduced": "7.0", "fixed": "10.1"}]}])
        self.assertEqual(_hits([EXCHANGE, iis], "Microsoft IIS httpd", "10.0"), [(13, True, 0.85)])

    def test_alias_does_not_reach_another_vendors_http_server(self):
        oracle = FakeCVE(14, [{"vendor": "oracle", "product": "http_server", "ranges": [{"introduced": "1.0", "fixed": "9.0"}]}])
        self.assertEqual(_hits([oracle], "Apache httpd", "2.4.52"), [])
        self.assertEqual(_hits([oracle], "Oracle HTTP Server", "2.4.52"), [(14, True, 0.85)])

    def test_cpe_names_the_product_without_name_matching(self):
        cpe = "cpe:/a:apache:http_server:2.4.52"
        self.assertEqual(parse_cpe(cpe), ("apache", "httpserver", "2.4.52"))
        self.assertEqual(_hits([LOG4J, HTTPD], "totally unrelated banner", "2.4.52", cpe=cpe), [(11, True, 0.85)])
        self.assertEqual(parse_cpe("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"), ("f5", "nginx", "1.18.0"))
        self.assertIsNone(parse_cpe("cpe:/o:canonical:ubuntu_linux"))

    def test_cpe_vendor_must_agree(self):
        oracle = FakeCVE(14, [{"vendor": "oracle", "product": "http_server", "ranges": [{"introduced": "1.0", "fixed": "9.0"}]}])
        self.assertEqual(_hits([oracle], "x", "2.4.52", cpe="cpe:/a:apache:http_server:2.4.52"), [])

    def test_cpe_version_fills_a_missing_version_in_record_matches(self):
        from cveFeed.correlation import _record_matches

        class Sub:
            id, scan_history_id = 5, 7
        index = build_product_index([HTTPD])
        rows = []
        _record_matches(Sub, "Apache httpd", "", "apachehttpd", "port", index, {11: HTTPD}, 0.0, None, rows,
                        cpe="cpe:/a:apache:http_server:2.4.52")
        self.assertEqual([(r["version_in_range"], r["matched_version"]) for r in rows], [(True, "2.4.52")])

    def test_cpe_with_unknown_product_falls_back_to_the_name(self):
        self.assertEqual(_hits([HTTPD], "Apache httpd", "2.4.52", cpe="cpe:/a:somevendor:unheardof:1"), [(11, True, 0.85)])


class TestRealWorldVendorFalsePositive(unittest.TestCase):
	"""A host whose service is 'AWS Cloudfront service' matched CVEs of 'Amazon Web Services Multi Model Server' and 'AWS MCP Server'."""

	MMS = FakeCVE(50, [{"vendor": "Amazon Web Services", "product": "Multi Model Server", "ranges": [{"introduced": "0", "fixed": "1.1.11"}]}])
	MCP = FakeCVE(51, [{"vendor": "AWS", "product": "AWS MCP Server", "ranges": [{"introduced": "0", "fixed": "9.9"}]}])
	VENDOR_ONLY = FakeCVE(52, [{"vendor": "aws", "ranges": [{"introduced": "0", "fixed": "9.9"}]}])

	def test_cloudfront_is_not_an_aws_server(self):
		for version in ("", "1.0"):
			self.assertEqual(_hits([self.MMS, self.MCP, self.VENDOR_ONLY], "AWS Cloudfront service", version), [], version)
		self.assertEqual(_hits([self.MMS, self.MCP], "Amazon CloudFront", "1.0"), [])

	def test_generic_aws_service_fingerprint_does_not_identify_a_product(self):
		for label in ('AWS Service -', 'AWS Service', 'Amazon Web Services'):
			self.assertEqual(_hits([self.MMS, self.MCP], label), [], label)
		broad = FakeCVE(53, [{'vendor': 'AWS', 'product': 'AWS Service Multi Model Server',
			'ranges': [{'introduced': '0', 'fixed': '1.1.11'}]}])
		self.assertEqual(_hits([broad], 'AWS Service -'), [])
		self.assertEqual([row[0] for row in _hits([broad], 'Multi Model Server', '1.1.5')], [53])

	def test_the_real_products_still_match_themselves(self):
		self.assertEqual([i for i, _r, _c in _hits([self.MMS, self.MCP], "Multi Model Server", "1.1.5")], [50])
		self.assertEqual([i for i, _r, _c in _hits([self.MMS, self.MCP], "AWS MCP Server", "1.0")], [51])


class TestEmptyRanges(unittest.TestCase):
    """Review 1.2: an advisory naming the product with no version bound is unknown (0.4), never in range."""

    def test_no_ranges_is_unknown(self):
        cve = FakeCVE(20, [{"product": "nginx", "ranges": []}])
        self.assertEqual(_hits([cve], "nginx", "1.26.0"), [(20, None, 0.4)])

    def test_missing_ranges_key_and_empty_range_dict_are_unknown(self):
        self.assertEqual(_hits([FakeCVE(21, [{"product": "nginx"}])], "nginx", "1.26.0"), [(21, None, 0.4)])
        self.assertEqual(_hits([FakeCVE(22, [{"product": "nginx", "ranges": [{}]}])], "nginx", "1.26.0"), [(22, None, 0.4)])

    def test_version_in_range_with_no_bound_is_unknown(self):
        self.assertIsNone(version_in_range((1, 2), {}))
        self.assertIsNone(version_in_range((1, 2), {"introduced": None}))

    def test_a_real_bound_still_decides(self):
        cve = FakeCVE(23, [{"product": "nginx", "ranges": [{"fixed": "1.20.0"}]}])
        self.assertEqual(_hits([cve], "nginx", "1.18.0"), [(23, True, 0.85)])
        self.assertEqual(_hits([cve], "nginx", "1.26.0"), [(23, False, 0.0)])

    def test_a_bounded_entry_out_of_range_does_not_clear_a_boundless_one(self):
        cve = FakeCVE(24, [{"product": "nginx", "ranges": []}, {"product": "nginx", "ranges": [{"fixed": "1.20.0"}]}])
        self.assertEqual(_hits([cve], "nginx", "1.26.0"), [(24, None, 0.4)])


class TestKnownVulnerableMatches(unittest.TestCase):
    """Positive fixtures: real exposures that must be found."""

    def test_nginx_1_18_in_range(self):
        cve = _nginx_cve(30, introduced="1.0.0", fixed="1.20.0")
        self.assertEqual(_hits([cve], "nginx", "1.18.0"), [(30, True, 0.85)])

    def test_apache_cpe_2_4_49_and_2_4_50(self):
        c41773 = FakeCVE(41773, [{"vendor": "apache", "product": "http_server",
                                  "ranges": [{"introduced": "2.4.49", "fixed": "2.4.50"}]}])
        c42013 = FakeCVE(42013, [{"vendor": "apache", "product": "http_server",
                                  "ranges": [{"introduced": "2.4.49", "fixed": "2.4.51"}]}])
        both = [c41773, c42013]
        cpe49, cpe50 = "cpe:/a:apache:http_server:2.4.49", "cpe:/a:apache:http_server:2.4.50"
        self.assertEqual([(i, r) for i, r, _ in _hits(both, "Apache httpd", "", cpe=cpe49)], [(41773, True), (42013, True)])
        self.assertEqual([(i, r) for i, r, _ in _hits(both, "Apache httpd", "", cpe=cpe50)], [(41773, False), (42013, True)])

    def test_jquery_tech_in_range(self):
        cve = FakeCVE(11022, [{"vendor": "jquery", "product": "jquery", "ranges": [{"introduced": "1.2", "fixed": "3.5.0"}]}])
        self.assertEqual(_hits([cve], "jQuery:1.12.4"), [(11022, True, 0.85)])

    def test_a_wrapper_package_named_like_the_product_does_not_decide_the_match(self):
        # CVE-2020-11023 lists jquery (fixed 3.5.0) next to the Ruby gem jquery-rails (fixed 4.4.0) and repackagings of jQuery. The
        # gem's version numbers are its own: jQuery 3.5.1, already patched, is not "before 4.4.0".
        cve = FakeCVE(11023, [
            {"vendor": "jquery", "product": "jquery", "ranges": [{"introduced": "1.0.3", "fixed": "3.5.0"}]},
            {"package": "jquery-rails", "ranges": [{"introduced": "0", "fixed": "4.4.0"}]},
            {"package": "org.webjars.npm:jquery", "ranges": [{"introduced": "1.0.3", "fixed": "3.5.0"}]},
            {"package": "components/jquery", "ranges": [{"introduced": "1.0.3", "fixed": "3.5.0"}]}])
        self.assertEqual(_hits([cve], "jQuery:3.5.1"), [(11023, False, 0.0)])
        self.assertEqual(_hits([cve], "jQuery:3.4.1"), [(11023, True, 0.85)])
        # the evidence names the product that decided it, not the wrapper
        found = list(_match_candidates("jQuery", (3, 4, 1), "jquery", build_product_index([cve]), {11023: cve}))
        self.assertEqual([(c.id, product, ok) for c, product, ok in found], [(11023, "jquery", True)])

    def test_fixed_is_exclusive_and_last_affected_inclusive(self):
        fixed = FakeCVE(31, [{"product": "nginx", "ranges": [{"introduced": "1.0", "fixed": "1.20.0"}]}])
        last = FakeCVE(32, [{"product": "nginx", "ranges": [{"introduced": "1.0", "lastAffected": "1.20.0"}]}])
        self.assertEqual(_hits([fixed], "nginx", "1.20.0"), [(31, False, 0.0)])
        self.assertEqual(_hits([last], "nginx", "1.20.0"), [(32, True, 0.85)])


class TestParseVersion(unittest.TestCase):
    """Review 1.3: epochs, pre-releases, hashes and refs."""

    def test_matrix(self):
        from cveFeed.correlation import _vcmp
        self.assertEqual(parse_version("1:8.9p1-3ubuntu0.6"), (8, 9, 0, 1))  # the epoch is dropped; p1 is a patch level
        self.assertEqual(parse_version("v1.2.3"), (1, 2, 3))
        self.assertEqual(parse_version("2.4.52+deb11u2"), (2, 4, 52))
        self.assertEqual(parse_version("1.18.0-1ubuntu1"), (1, 18, 0))
        self.assertEqual(parse_version("8.5.0.1"), (8, 5, 0, 1))
        self.assertEqual(parse_version("2024.1"), (2024, 1))
        self.assertEqual(parse_version("8.9p1 Ubuntu 3ubuntu0.6"), (8, 9, 0, 1))
        self.assertIsNone(parse_version("abc"))
        self.assertIsNone(parse_version("deadbeef"))
        self.assertIsNone(parse_version("3f2a1b9c0d4e5f60718293a4b5c6d7e8f9012345"))
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version(None))
        self.assertLess(_vcmp(parse_version("2.0-beta9"), parse_version("2.0")), 0)
        self.assertLess(_vcmp(parse_version("2.0-beta5"), parse_version("2.0-beta9")), 0)
        self.assertLess(_vcmp(parse_version("2.0-beta9"), parse_version("2.0-rc1")), 0)
        self.assertLess(_vcmp(parse_version("1.0rc1"), parse_version("1.0")), 0)
        self.assertLess(_vcmp(parse_version("9.0.0-M1"), parse_version("9.0.0")), 0)
        self.assertGreater(_vcmp(parse_version("2.0.1"), parse_version("2.0-rc1")), 0)
        self.assertEqual(_vcmp(parse_version("1.18"), parse_version("1.18.0")), 0)

    def test_an_openssl_patch_letter_or_a_distro_word_is_not_a_pre_release(self):
        from cveFeed.correlation import _vcmp
        self.assertGreater(_vcmp(parse_version("1.0.2k"), parse_version("1.0.2")), 0)  # a patch letter is later, never a pre-release
        self.assertEqual(parse_version("2.4.52-alpine"), (2, 4, 52))
        self.assertEqual(parse_version("1.2.3-RELEASE"), (1, 2, 3))

    def test_a_bound_must_start_with_a_digit(self):
        self.assertIsNone(parse_version("main", strict=True))
        self.assertIsNone(parse_version("release-1.2", strict=True))
        self.assertEqual(parse_version("v2.1", strict=True), (2, 1))

    def test_epoch_host_is_compared_as_its_upstream_version(self):
        # 1:9.6p1-3ubuntu13 against "fixed 9.6p1": (9, 6) is not below 9.6, not (1,) which is below everything
        self.assertIs(version_in_range(parse_version("1:9.6p1-3ubuntu13"), {"introduced": "8.5", "fixed": "9.6p1"}), False)
        self.assertIs(version_in_range(parse_version("1:8.9p1-3ubuntu0.6"), {"introduced": "8.5", "fixed": "9.8p1"}), True)

    def test_a_patch_suffixed_build_is_inside_a_bound_that_names_only_the_release(self):
        # "up to 8.9" and a single listed 1.0.2 cover 8.9p1 and 1.0.2k; a bound that names a patch level still compares it
        self.assertIs(version_in_range(parse_version("8.9p1"), {"introduced": "8.9", "lastAffected": "8.9"}), True)
        self.assertIs(version_in_range(parse_version("1.0.2k"), {"introduced": "1.0.2", "lastAffected": "1.0.2"}), True)
        self.assertIs(version_in_range(parse_version("8.9p2"), {"introduced": "8.0", "lastAffected": "8.9p1"}), False)
        self.assertIs(version_in_range(parse_version("1.0.2k"), {"introduced": "1.0.2", "lastAffected": "1.0.2j"}), False)
        self.assertIs(version_in_range(parse_version("9.0p1"), {"introduced": "8.0", "lastAffected": "8.9"}), False)
        self.assertIs(version_in_range(parse_version("1.2.3.4"), {"introduced": "1.2.3", "lastAffected": "1.2.3"}), False)  # a real fourth part
        self.assertIs(version_in_range(parse_version("8.9p1"), {"introduced": "8.0", "fixed": "8.9"}), False)  # fixed in the release itself

    def test_a_prerelease_host_is_before_the_fix_and_the_boundary_is_inclusive(self):
        # a host on 2.0-beta9 with fixed 2.0 is still affected (it used to parse as 2.0 and fall out of range)
        self.assertIs(version_in_range(parse_version("2.0-beta9"), {"introduced": "1.0", "fixed": "2.0"}), True)
        log4j = {"introduced": "2.0-beta9", "fixed": "2.17.1"}
        self.assertIs(version_in_range(parse_version("2.0-beta9"), log4j), True)
        self.assertIs(version_in_range(parse_version("2.0-beta8"), log4j), False)
        self.assertIs(version_in_range(parse_version("2.17.0"), log4j), True)
        self.assertIs(version_in_range(parse_version("2.17.1"), log4j), False)
        cve = FakeCVE(40, [{"vendor": "apache", "product": "log4j", "ranges": [log4j]}], kev=True)
        self.assertEqual(_hits([cve], "log4j", "2.0-beta9"), [(40, True, 0.95)])

    def test_git_ranges_and_hash_bounds_are_unknown_not_in_range(self):
        self.assertIsNone(version_in_range((3, 1), {"type": "GIT", "introduced": "0", "fixed": "3f2a1b9c0d4e5f60718293a4b5c6d7e8f9012345"}))
        self.assertIsNone(version_in_range((3, 1), {"introduced": "0", "fixed": "3f2a1b9c0d4e5f60718293a4b5c6d7e8f9012345"}))
        self.assertIsNone(version_in_range((3, 1), {"introduced": "unspecified"}))
        cve = FakeCVE(41, [{"product": "nginx", "ranges": [{"type": "GIT", "introduced": "0", "fixed": "deadbeefcafe1234"}]}])
        self.assertEqual(_hits([cve], "nginx", "3.1"), [(41, None, 0.4)])

    def test_multiple_ranges_are_or_ed_and_an_unusable_one_does_not_hide_a_real_hit(self):
        item = {"product": "nginx", "ranges": [{"type": "GIT", "introduced": "0", "fixed": "abcdef1234"},
                                               {"introduced": "1.0", "fixed": "1.20"}]}
        self.assertEqual(_hits([FakeCVE(42, [item])], "nginx", "1.18.0"), [(42, True, 0.85)])
        self.assertEqual(_hits([FakeCVE(43, [item])], "nginx", "1.26.0"), [(43, False, 0.0)])  # the usable range decides


if __name__ == '__main__':
    unittest.main()


CRAFT = FakeCVE(70, [{"vendor": "craftcms", "product": "cms", "package": "craftcms/cms",
                      "ranges": [{"introduced": "4.0.0", "fixed": "4.18.9"}, {"introduced": "5.0.0", "fixed": "5.11.2"}]}], kev=False)
PHP_RANGES = [{"introduced": "8.2.*", "fixed": "8.2.35"}, {"introduced": "8.3.*", "fixed": "8.3.36"},
              {"introduced": "8.4.*", "fixed": "8.4.27"}, {"introduced": "8.5.*", "fixed": "8.5.12"}]
PHP2SHELL = FakeCVE(71, [{"vendor": "PHP Group", "product": "PHP", "package": "php-src", "ranges": PHP_RANGES}], kev=True)


MOVEIT_WAF = FakeCVE(72, [{"vendor": "progress", "product": "MOVEit WAF", "ranges": [{"introduced": "1.0", "fixed": "9.9"}]}], kev=False)


class TestCategoryLabelsAreNotProducts(unittest.TestCase):
    """bbot labels a host "WAF" when it sees any web application firewall. That says a firewall answered, not which one, so it must
    not stand for a product whose name merely contains the word (found on a host matched to the MOVEit WAF advisories)."""

    def test_a_generic_waf_label_does_not_match_a_named_waf_product(self):
        for label in ("WAF", "waf", "Web Application Firewall"):
            self.assertEqual(_hits([MOVEIT_WAF], label, "1.0"), [], label)

    def test_a_host_that_is_the_named_product_still_matches(self):
        for label in ("MOVEit WAF", "moveitwaf"):
            self.assertEqual([row[0] for row in _hits([MOVEIT_WAF], label, "1.0")], [72], label)

    def test_a_cve_whose_product_is_just_waf_names_nothing_to_match(self):
        bare = FakeCVE(73, [{"vendor": "acme", "product": "WAF", "ranges": [{"introduced": "1.0", "fixed": "9.9"}]}], kev=False)
        self.assertEqual(_hits([bare], "WAF", "1.0"), [])


class TestWordBoundaryMatching(unittest.TestCase):
    """A shorter name matches a longer one only as whole words. Found on a Netlify site tagged "datocms" that matched Craft CMS
    advisories because the advisory's product is "cms"."""

    def test_datocms_is_not_craft_cms(self):
        self.assertEqual(_hits([CRAFT], "datocms"), [])
        self.assertEqual(_hits([CRAFT], "datocms", "1.0"), [])

    def test_a_craft_host_still_matches_craft_advisories(self):
        for label in ("Craft CMS", "craftcms", "CraftCMS"):
            self.assertEqual([row[0] for row in _hits([CRAFT], label, "4.10.0")], [70], label)

    def test_a_generic_product_word_names_nothing_on_its_own(self):
        self.assertEqual(affected_product_tokens({"vendor": "craftcms", "product": "cms"}), {"craftcms"})
        self.assertEqual(_hits([CRAFT], "Drupal CMS", "4.10.0"), [])
        self.assertEqual(_hits([CRAFT], "cms", "4.10.0"), [])

    def test_php_is_not_every_php_prefixed_product(self):
        for label in ("phpMyAdmin", "PHPUnit", "PHPMailer", "phpBB", "PhpSpreadsheet"):
            self.assertEqual(_hits([PHP2SHELL], label, "8.2.30"), [], label)

    def test_php_and_its_own_variants_match_php(self):
        for label in ("PHP", "php", "PHP-FPM"):
            self.assertEqual([row[0] for row in _hits([PHP2SHELL], label, "8.2.30")], [71], label)

    def test_substrings_inside_one_word_never_match(self):
        js = FakeCVE(72, [{"product": "javascript", "ranges": [{"introduced": "1.0", "fixed": "9.0"}]}])
        self.assertEqual(_hits([js], "java", "1.5"), [])
        sp = FakeCVE(73, [{"product": "spring", "ranges": [{"introduced": "1.0", "fixed": "9.0"}]}])
        self.assertEqual(_hits([sp], "ring", "1.5"), [])

    def test_whole_words_of_a_longer_name_still_match(self):
        tomcat = FakeCVE(74, [{"vendor": "apache", "product": "tomcat", "ranges": [{"introduced": "9.0.0", "fixed": "9.0.50"}]}])
        self.assertEqual([row[0] for row in _hits([tomcat], "Apache Tomcat", "9.0.10")], [74])
        server = FakeCVE(75, [{"product": "http_server", "vendor": "oracle", "ranges": [{"introduced": "1.0", "fixed": "9.0"}]}])
        self.assertEqual([row[0] for row in _hits([server], "Oracle HTTP Server", "2.0")], [75])

    def test_one_generic_word_left_over_is_not_a_product(self):
        server = FakeCVE(76, [{"product": "server", "ranges": [{"introduced": "1.0", "fixed": "9.0"}]}])
        self.assertEqual(_hits([server], "Apache Server", "2.0"), [])

    def test_nextjs_reaches_the_next_package(self):
        nxt = FakeCVE(77, [{"vendor": "vercel", "product": "next.js", "package": "next",
                            "ranges": [{"introduced": "13.0.0", "fixed": "13.5.9"}]}])
        self.assertEqual([row[0] for row in _hits([nxt], "Next.js", "13.1.0")], [77])
        only_pkg = FakeCVE(78, [{"package": "next", "ranges": [{"introduced": "13.0.0", "fixed": "13.5.9"}]}])
        self.assertEqual([row[0] for row in _hits([only_pkg], "Next.js", "13.1.0")], [78])

    def test_host_strings_cannot_use_up_the_catalogue_word_table(self):
        from cveFeed import correlation
        saved, saved_host = dict(correlation._WORDS), dict(correlation._HOST_WORDS)
        try:
            correlation._HOST_WORDS.clear()
            original = correlation._HOST_WORDS_MAX_TOKENS
            correlation._HOST_WORDS_MAX_TOKENS = 20
            before = len(correlation._WORDS)
            for i in range(200):
                correlation._norm(f"Hostile Banner Product {i}")
            self.assertEqual(len(correlation._WORDS), before)  # nothing a host says reaches the catalogue's registry
            self.assertLessEqual(len(correlation._HOST_WORDS), 20)  # and the host table drops its oldest entry instead of growing
            token = correlation._norm("Hostile Banner Product 199")
            self.assertTrue(correlation.name_matches_token(token, token))
            self.assertFalse(correlation.name_matches_token(token, correlation._norm("Product 199")))
            correlation._HOST_WORDS_MAX_TOKENS = original
            # a catalogue name registers however many host names came first, and the lookup sees it
            correlation._norm("Zzyzx Directory Server", True)
            self.assertIn(("zzyzx", "directory", "server"), correlation._words_for("zzyzxdirectoryserver"))
        finally:
            correlation._HOST_WORDS_MAX_TOKENS = 2000
            correlation._WORDS.clear()
            correlation._WORDS.update(saved)
            correlation._HOST_WORDS.clear()
            correlation._HOST_WORDS.update(saved_host)

    def test_a_full_catalogue_table_is_logged_once_and_fails_closed(self):
        from cveFeed import correlation
        saved = dict(correlation._WORDS)
        try:
            correlation._WORDS_MAX_TOKENS, original = len(correlation._WORDS), correlation._WORDS_MAX_TOKENS
            correlation._words_full_logged = False
            with self.assertLogs("cveFeed.correlation", level="WARNING") as logs:
                correlation._norm("Another Catalogue Product", True)
                correlation._norm("Yet Another Catalogue Product", True)
            self.assertEqual(len(logs.records), 1)
            self.assertEqual(len(correlation._WORDS), correlation._WORDS_MAX_TOKENS)
        finally:
            correlation._WORDS_MAX_TOKENS = original
            correlation._words_full_logged = False
            correlation._WORDS.clear()
            correlation._WORDS.update(saved)

    def test_overlong_and_many_word_names_are_not_recorded(self):
        from cveFeed import correlation
        n = len(correlation._WORDS) + len(correlation._HOST_WORDS)
        for catalogue in (False, True):
            correlation._norm("a " * 120, catalogue)
            correlation._norm(" ".join(f"w{i}x" for i in range(20)), catalogue)
        self.assertEqual(len(correlation._WORDS) + len(correlation._HOST_WORDS), n)


class TestUnlistedBranch(unittest.TestCase):
    """PHP2Shell lists only the branches that got a fix (8.2 to 8.5). PHP 7.4 to 8.1 are older than all of them: not cleared."""

    def _verdict(self, version, cve=PHP2SHELL, label="PHP"):
        rows = _hits([cve], label, version)
        return rows[0][1] if rows else "no match"

    def test_older_branches_are_unknown_not_cleared(self):
        for version in ("7.4.33", "8.0.30", "8.1.30", "7.3.0", "5.6.40"):
            self.assertIsNone(self._verdict(version), version)

    def test_listed_branches_are_decided_by_their_own_range(self):
        self.assertIs(self._verdict("8.2.30"), True)
        self.assertIs(self._verdict("8.3.20"), True)
        self.assertIs(self._verdict("8.4.26"), True)
        self.assertIs(self._verdict("8.5.11"), True)
        for fixed in ("8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.5.13", "8.6.0", "9.0.0"):
            self.assertIs(self._verdict(fixed), False, fixed)

    def test_an_unlisted_branch_keeps_a_usable_confidence(self):
        self.assertEqual(_hits([PHP2SHELL], "PHP", "8.1.30"), [(71, None, 0.5)])

    def test_the_evidence_says_why_it_is_unknown(self):
        index = build_product_index([PHP2SHELL])
        details = {}
        list(_match_candidates("PHP", parse_version("8.1.30"), "php", index, {71: PHP2SHELL}, details=details))
        self.assertEqual(details[71]["branch_unlisted"], True)
        self.assertEqual(details[71]["lowest_listed_branch"], "8.2")

    def test_a_cold_advisory_does_not_add_noise_for_old_versions(self):
        cold = FakeCVE(79, [{"product": "PHP", "ranges": PHP_RANGES}], kev=False)  # no cvss, no kev, no epss: ice
        self.assertIs(self._verdict("8.1.30", cold), False)

    def test_other_shapes_of_range_are_unchanged(self):
        self.assertIs(self._verdict("1.18.0", _nginx_cve(80, "1.20.0", "1.25.0", kev=True), "nginx"), False)  # one range
        two = FakeCVE(81, [{"product": "widget", "ranges": [{"introduced": "1.0", "fixed": "1.9"}, {"introduced": "2.0", "fixed": "2.5"}]}], kev=True)
        self.assertIs(self._verdict("0.5", two, "widget"), False)  # not branch-style: the fix is not a patch of the branch
        mixed = FakeCVE(82, [{"product": "PHP", "ranges": PHP_RANGES + [{"introduced": "9.0", "lastAffected": "9.1"}]}], kev=True)
        self.assertIs(self._verdict("8.1.30", mixed), False)  # one odd range: do not guess

    def test_helpers(self):
        from cveFeed.correlation import branch_unlisted, lowest_listed_branch
        self.assertEqual(lowest_listed_branch(PHP_RANGES), (8, 2))
        self.assertIsNone(lowest_listed_branch(PHP_RANGES[:1]))
        self.assertTrue(branch_unlisted((8, 1, 30), PHP_RANGES))
        self.assertFalse(branch_unlisted((8, 2, 0), PHP_RANGES))
        self.assertFalse(branch_unlisted(None, PHP_RANGES))
