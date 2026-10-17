"""露出期間（crt.sh の not_before）:《露出年数》判定のテスト."""

from __future__ import annotations

import unittest

from miharun.models import HostResult
from miharun.sources.crtsh import _issuer_short_name, parse_certificates

SAMPLE = [
    {
        "issuer_name": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=GeoTrust TLS RSA CA G1",
        "common_name": "www.example.com",
        "name_value": "www.example.com",
        "not_before": "2020-01-15T00:00:00",
    },
    {
        "issuer_name": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=GeoTrust TLS RSA CA G1",
        "common_name": "www.example.com",
        "name_value": "www.example.com",
        "not_before": "2024-06-01T00:00:00",
    },
    {
        "issuer_name": "C=JP, O=JPRS, CN=JPRS OV RSA CA 2024 G1",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
        "not_before": "2022-03-10T00:00:00",
    },
    {"name_value": "other.com", "not_before": "2010-01-01T00:00:00"},
    {"name_value": "no-date.example.com"},
]


class TestParseCertificates(unittest.TestCase):
    def test_takes_earliest_and_latest(self):
        result = parse_certificates(SAMPLE, "example.com")
        record = result["www.example.com"]
        self.assertEqual(record["first_seen"], "2020-01-15T00:00:00")
        self.assertEqual(record["last_seen"], "2024-06-01T00:00:00")

    def test_multi_name_entry_applies_to_each(self):
        result = parse_certificates(SAMPLE, "example.com")
        self.assertIn("example.com", result)
        self.assertIn("www.example.com", result)

    def test_excludes_unrelated_domain(self):
        result = parse_certificates(SAMPLE, "example.com")
        self.assertNotIn("other.com", result)

    def test_skips_entries_without_not_before(self):
        result = parse_certificates(SAMPLE, "example.com")
        self.assertNotIn("no-date.example.com", result)

    def test_records_issuer_short_name(self):
        result = parse_certificates(SAMPLE, "example.com")
        self.assertIn("GeoTrust TLS RSA CA G1", result["www.example.com"]["issuers"])

    def test_empty_payload(self):
        self.assertEqual(parse_certificates([], "example.com"), {})


class TestIssuerShortName(unittest.TestCase):
    def test_extracts_cn(self):
        self.assertEqual(
            _issuer_short_name("C=US, O=DigiCert, CN=GeoTrust TLS RSA CA G1"),
            "GeoTrust TLS RSA CA G1",
        )

    def test_handles_none(self):
        self.assertEqual(_issuer_short_name(None), "")

    def test_handles_plain_string(self):
        self.assertEqual(_issuer_short_name("SomeCA"), "SomeCA")


class TestExposureDays(unittest.TestCase):
    def test_none_without_first_seen(self):
        self.assertIsNone(HostResult(host="a.example.com").exposure_days)

    def test_computes_days(self):
        host = HostResult(host="a.example.com", first_seen="2000-01-01T00:00:00")
        self.assertIsNotNone(host.exposure_days)
        self.assertGreater(host.exposure_days, 8000)

    def test_computes_years(self):
        host = HostResult(host="a.example.com", first_seen="2000-01-01T00:00:00")
        self.assertGreater(host.exposure_years, 20.0)

    def test_invalid_date_returns_none(self):
        host = HostResult(host="a.example.com", first_seen="not-a-date")
        self.assertIsNone(host.exposure_days)

    def test_future_date_is_zero(self):
        host = HostResult(host="a.example.com", first_seen="2999-01-01T00:00:00")
        self.assertEqual(host.exposure_days, 0)


if __name__ == "__main__":
    unittest.main()