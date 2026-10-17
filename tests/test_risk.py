"""危険度スコアと変化検知（diff）のテスト.

すべてネットワークを使わず、純関数のみを検証します。
"""

from __future__ import annotations

import unittest

from miharun.diff import compare, render_diff_markdown
from miharun.insights import host_risks
from miharun.models import Finding, HostResult, SurfaceReport, risk_level


def live(host: str) -> HostResult:
    return HostResult(host=host, addresses=["203.0.113.10"])


def dead(host: str) -> HostResult:
    return HostResult(host=host)


class TestHostRisks(unittest.TestCase):
    def test_dev_host_scores(self):
        risks = host_risks(live("dev.example.com"))
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["score"], 40)
        self.assertIn("dev.example.com", risks[0]["title"])

    def test_admin_host_scores_higher(self):
        risks = host_risks(live("admin.example.com"))
        self.assertEqual(risks[0]["score"], 45)

    def test_normal_host_has_no_risk(self):
        self.assertEqual(host_risks(live("www.example.com")), [])

    def test_unresolved_host_is_not_flagged(self):
        # 名前解決できない dev.example.com は「公開されている」と言えない
        self.assertEqual(host_risks(dead("dev.example.com")), [])

    def test_auth_wall_host_scores(self):
        host = HostResult(host="api.example.com", addresses=["203.0.113.1"])
        host.http_status = 401
        risks = host_risks(host)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["score"], 25)

    def test_dev_and_auth_combined(self):
        host = HostResult(host="dev.example.com", addresses=["203.0.113.1"])
        host.http_status = 403
        risks = host_risks(host)
        self.assertEqual(len(risks), 2)
        self.assertEqual(max(r["score"] for r in risks), 40)

    def test_risk_items_have_why(self):
        for risk in host_risks(live("dev.example.com")):
            self.assertTrue(risk["why"])
            self.assertIsInstance(risk["score"], int)


class TestRiskLevel(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(risk_level(0), "low")
        self.assertEqual(risk_level(14), "low")
        self.assertEqual(risk_level(15), "medium")
        self.assertEqual(risk_level(40), "high")
        self.assertEqual(risk_level(70), "critical")
        self.assertEqual(risk_level(100), "critical")


class TestOverallRisk(unittest.TestCase):
    def test_empty_is_zero(self):
        report = SurfaceReport(target="x", input_kind="domain")
        self.assertEqual(report.overall_risk, 0)

    def test_takes_max(self):
        report = SurfaceReport(target="x", input_kind="domain")
        report.add_finding("notice", "a", score=10)
        report.add_finding("warn", "b", score=45)
        report.add_finding("info", "c", score=25)
        self.assertEqual(report.overall_risk, 45)


class TestCompare(unittest.TestCase):
    def _previous(self):
        return {
            "hosts": [{"host": "www.example.com"}, {"host": "old.example.com"}],
            "technologies": [{"name": "Cloudflare", "category": "CDN", "confidence": "high"}],
            "findings": [
                {
                    "level": "warn",
                    "title": "古いホスト",
                    "detail": "",
                    "score": 40,
                    "host": "old.example.com",
                }
            ],
        }

    def _current(self):
        report = SurfaceReport(target="example.com", input_kind="domain", domain="example.com")
        report.hosts = [HostResult(host="www.example.com"), HostResult(host="new.example.com")]
        report.add_technology("DNS", "Cloudflare")
        report.add_technology("メール", "Google Workspace")
        report.add_finding("warn", "新しい危険", score=25, host="new.example.com")
        return report

    def test_new_hosts(self):
        result = compare(self._previous(), self._current())
        self.assertEqual(result["new_hosts"], ["new.example.com"])

    def test_gone_hosts(self):
        result = compare(self._previous(), self._current())
        self.assertEqual(result["gone_hosts"], ["old.example.com"])

    def test_new_risks(self):
        result = compare(self._previous(), self._current())
        self.assertEqual(len(result["new_risks"]), 1)
        self.assertIn("new.example.com", result["new_risks"][0])

    def test_resolved_risks(self):
        result = compare(self._previous(), self._current())
        self.assertEqual(len(result["resolved_risks"]), 1)
        self.assertIn("old.example.com", result["resolved_risks"][0])

    def test_tech_added_and_removed(self):
        result = compare(self._previous(), self._current())
        self.assertEqual(result["tech_added"], ["Google Workspace"])
        self.assertEqual(result["tech_removed"], [])

    def test_risk_delta(self):
        # 前回 40 / 今回 25 → -15
        result = compare(self._previous(), self._current())
        self.assertEqual(result["risk_delta"], -15)

    def test_no_changes(self):
        report = SurfaceReport(target="example.com", input_kind="domain", domain="example.com")
        report.hosts = [HostResult(host="www.example.com"), HostResult(host="old.example.com")]
        report.add_technology("CDN", "Cloudflare")
        report.add_finding("warn", "古いホスト", score=40, host="old.example.com")
        result = compare(self._previous(), report)
        self.assertEqual(result["new_hosts"], [])
        self.assertEqual(result["gone_hosts"], [])
        self.assertEqual(result["new_risks"], [])
        self.assertEqual(result["resolved_risks"], [])
        self.assertEqual(result["risk_delta"], 0)


class TestRenderDiff(unittest.TestCase):
    def test_contains_domain_and_delta(self):
        text = render_diff_markdown(
            {
                "new_hosts": ["a.example.com"],
                "gone_hosts": [],
                "new_risks": [],
                "resolved_risks": [],
                "risk_delta": 15,
                "tech_added": [],
                "tech_removed": [],
            },
            "example.com",
        )
        self.assertIn("example.com", text)
        self.assertIn("+15", text)
        self.assertIn("a.example.com", text)

    def test_no_change_message(self):
        text = render_diff_markdown(
            {
                "new_hosts": [],
                "gone_hosts": [],
                "new_risks": [],
                "resolved_risks": [],
                "risk_delta": 0,
                "tech_added": [],
                "tech_removed": [],
            },
            "example.com",
        )
        self.assertIn("変化は検出されませんでした", text)


if __name__ == "__main__":
    unittest.main()