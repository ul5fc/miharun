"""sources/http_probe.py のテスト（マーカー抽出）と insights.py のテスト."""

from __future__ import annotations

import unittest

from miharun.insights import build_findings
from miharun.models import HostResult, SurfaceReport
from miharun.sources.http_probe import find_markers


class TestFindMarkers(unittest.TestCase):
    def test_detects_wordpress_marker(self):
        body = b'<html><link href="/wp-content/themes/x/style.css"></html>'
        self.assertIn("wp-content", find_markers(body))

    def test_detects_ec_cube_marker(self):
        self.assertIn("ec-cube", find_markers(b"<title>EC-CUBE</title>"))

    def test_detects_movable_type(self):
        self.assertIn("movable type", find_markers(b"<meta name='generator' content='Movable Type'>"))

    def test_no_markers(self):
        self.assertEqual(find_markers(b"<html><body>hello</body></html>"), [])

    def test_case_insensitive(self):
        self.assertIn("wp-json", find_markers(b'<link rel="alternate" href="/wp-json/">'))

    def test_empty_body(self):
        self.assertEqual(find_markers(b""), [])


class TestInsights(unittest.TestCase):
    def _report(self):
        report = SurfaceReport(target="example.co.jp", input_kind="domain", domain="example.co.jp")
        return report

    def test_flags_missing_spf(self):
        report = self._report()
        report.apex = {"TXT": []}
        build_findings(report)
        titles = [f.title for f in report.findings]
        self.assertTrue(any("SPF" in title for title in titles))

    def test_flags_missing_dmarc(self):
        report = self._report()
        report.apex = {"TXT": ["v=spf1 -all"]}
        build_findings(report)
        titles = [f.title for f in report.findings]
        self.assertTrue(any("DMARC" in title for title in titles))

    def test_no_missing_email_findings_when_present(self):
        report = self._report()
        report.apex = {"TXT": ["v=spf1 -all", "v=DMARC1; p=reject"]}
        build_findings(report)
        titles = [f.title for f in report.findings]
        self.assertFalse(any("SPF" in title for title in titles))
        self.assertFalse(any("DMARC" in title for title in titles))

    def test_flags_non_production_host(self):
        report = self._report()
        report.apex = {"TXT": ["v=spf1 -all", "v=DMARC1; p=reject"]}
        report.hosts = [HostResult(host="dev.example.co.jp", addresses=["203.0.113.5"])]
        build_findings(report)
        warns = [f for f in report.findings if f.level == "warn"]
        self.assertTrue(any("本番環境ではない" in f.title for f in warns))

    def test_flags_admin_host(self):
        report = self._report()
        report.apex = {"TXT": ["v=spf1 -all", "v=DMARC1; p=reject"]}
        report.hosts = [HostResult(host="admin.example.co.jp", addresses=["203.0.113.5"])]
        build_findings(report)
        titles = [f.title for f in report.findings]
        self.assertTrue(any("管理系" in title for title in titles))

    def test_no_warnings_for_normal_hosts(self):
        report = self._report()
        report.apex = {"TXT": ["v=spf1 -all", "v=DMARC1; p=reject"]}
        report.hosts = [
            HostResult(host="example.co.jp", addresses=["203.0.113.5"]),
            HostResult(host="www.example.co.jp", addresses=["203.0.113.6"]),
        ]
        build_findings(report)
        self.assertEqual([f for f in report.findings if f.level == "warn"], [])

    def test_wildcard_flag_is_reported(self):
        report = self._report()
        report.apex = {"TXT": ["v=spf1 -all", "v=DMARC1; p=reject"], "_wildcard": ["1"]}
        build_findings(report)
        titles = [f.title for f in report.findings]
        self.assertTrue(any("ワイルドカード" in title for title in titles))

    def test_add_finding_is_idempotent(self):
        report = self._report()
        report.add_finding("notice", "同じ件名", "本文")
        report.add_finding("notice", "同じ件名", "別本文")
        self.assertEqual(len(report.findings), 1)

    def test_add_technology_is_idempotent(self):
        report = self._report()
        report.add_technology("DNS", "Cloudflare")
        report.add_technology("DNS", "Cloudflare")
        self.assertEqual(report.technologies, [("DNS", "Cloudflare")])


if __name__ == "__main__":
    unittest.main()