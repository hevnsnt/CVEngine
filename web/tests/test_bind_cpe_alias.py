"""Regression tests: ISC BIND is one product across CPE, product string and advisory naming."""

import unittest

from tests.test_correlation import FakeCVE, _hits

CPE = "cpe:/a:isc:bind:9.11.3-1ubuntu1.11"
RANGE = [{"introduced": "9.11.0", "fixed": "9.11.31"}]


def _isc_cve(cid="CVE-2099-0001", ranges=None):
    return FakeCVE(
        cid,
        [{"vendor": "ISC", "product": "BIND9", "ranges": RANGE if ranges is None else ranges}],
    )


class BindAliasTests(unittest.TestCase):
    def test_cpe_and_product_string_in_range(self):
        hits = _hits([_isc_cve()], "ISC BIND", "9.11.3-1ubuntu1.11", cpe=CPE)
        self.assertEqual(hits, [("CVE-2099-0001", True, 0.85)])

    def test_bare_bind_product_without_cpe(self):
        hits = _hits([_isc_cve()], "BIND", "9.11.3", cpe=None)
        self.assertEqual(hits, [("CVE-2099-0001", True, 0.85)])

    def test_isc_bind_product_without_cpe(self):
        hits = _hits([_isc_cve()], "ISC BIND", "9.11.3", cpe=None)
        self.assertEqual(hits, [("CVE-2099-0001", True, 0.85)])

    def test_fixed_version_is_out_of_range(self):
        hits = _hits([_isc_cve()], "ISC BIND", "9.11.31", cpe=CPE)
        self.assertEqual(hits, [("CVE-2099-0001", False, 0.0)])

    def test_no_known_range(self):
        hits = _hits([_isc_cve(ranges=[])], "ISC BIND", "9.11.3", cpe=CPE)
        self.assertEqual(hits, [("CVE-2099-0001", None, 0.4)])

    def test_other_vendor_bind9_does_not_match_without_cpe(self):
        cve = FakeCVE(
            "CVE-2099-0002",
            [{"vendor": "example", "product": "BIND9", "ranges": RANGE}],
        )
        self.assertEqual(_hits([cve], "ISC BIND", "9.11.3", cpe=None), [])


if __name__ == "__main__":
    unittest.main()
