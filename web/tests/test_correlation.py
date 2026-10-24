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

    def test_fixed_is_exclusive_and_last_affected_inclusive(self):
        fixed = FakeCVE(31, [{"product": "nginx", "ranges": [{"introduced": "1.0", "fixed": "1.20.0"}]}])
        last = FakeCVE(32, [{"product": "nginx", "ranges": [{"introduced": "1.0", "lastAffected": "1.20.0"}]}])
        self.assertEqual(_hits([fixed], "nginx", "1.20.0"), [(31, False, 0.0)])
        self.assertEqual(_hits([last], "nginx", "1.20.0"), [(32, True, 0.85)])


class TestParseVersion(unittest.TestCase):
    """Review 1.3: epochs, pre-releases, hashes and refs."""

    def test_matrix(self):
        from cveFeed.correlation import _vcmp
        self.assertEqual(parse_version("1:8.9p1-3ubuntu0.6"), (8, 9))
        self.assertEqual(parse_version("v1.2.3"), (1, 2, 3))
        self.assertEqual(parse_version("2.4.52+deb11u2"), (2, 4, 52))
        self.assertEqual(parse_version("1.18.0-1ubuntu1"), (1, 18, 0))
        self.assertEqual(parse_version("8.5.0.1"), (8, 5, 0, 1))
        self.assertEqual(parse_version("2024.1"), (2024, 1))
        self.assertEqual(parse_version("8.9p1 Ubuntu 3ubuntu0.6"), (8, 9))
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
        self.assertEqual(parse_version("1.0.2k"), (1, 0, 2))
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
