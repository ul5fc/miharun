"""fingerprint.py と rules.py のテスト.

日本向けの判定（XSERVER / さくら / Trend Micro など）が
DNS レコードから正しく取り出せることを確認します。
"""

from __future__ import annotations

import unittest

from miharun.fingerprint import detect, match_rule, summarize
from miharun.rules import RULES, all_categories


def names(records):
    return {name for _category, name, _confidence in detect(records)}


def category_of(records, name):
    for category, found, _confidence in detect(records):
        if found == name:
            return category
    return None


class TestDetect(unittest.TestCase):
    def test_detects_japanese_rental_server_from_ns(self):
        self.assertIn("エックスサーバー", names({"NS": ["ns1.xserver.jp"]}))

    def test_detects_sakura_from_ptr(self):
        self.assertIn("さくらインターネット", names({"PTR": ["host123.sakura.ne.jp"]}))

    def test_detects_lolipop(self):
        self.assertIn("ロリポップ！", names({"NS": ["ns1.lolipop.jp"]}))

    def test_detects_onamae_dns_via_ns(self):
        self.assertIn("お名前.com", names({"NS": ["ns1.dnsv.jp"]}))

    def test_detects_google_workspace_from_mx(self):
        self.assertIn("Google Workspace", names({"MX": ["aspmx.l.google.com"]}))

    def test_detects_microsoft365_from_mx(self):
        self.assertIn("Microsoft 365", names({"MX": ["example.mail.protection.outlook.com"]}))

    def test_detects_trendmicro_from_mx(self):
        self.assertIn(
            "Trend Micro Email Security",
            names({"MX": ["jprs.in.tmems-jp.trendmicro.com"]}),
        )

    def test_detects_sakura_mailbox_from_mx(self):
        self.assertIn("さくらのメールボックス", names({"MX": ["www.mx.sakura.ne.jp"]}))

    def test_detects_cf_cdn_from_cname(self):
        self.assertIn("Cloudflare", names({"CNAME": ["example.com.cdn.cloudflare.net"]}))

    def test_detects_gitHub_pages_from_cname(self):
        self.assertIn("GitHub Pages", names({"CNAME": ["example.github.io"]}))

    def test_detects_google_site_verification(self):
        self.assertIn(
            "Google Search Console",
            names({"TXT": ["google-site-verification=abc123"]}),
        )

    def test_detects_spf_provider(self):
        self.assertIn(
            "Microsoft 365（SPF）",
            names({"TXT": ["v=spf1 include:spf.protection.outlook.com ~all"]}),
        )

    def test_wordpress_from_http_marker(self):
        self.assertIn("WordPress", names({"HTTP": ["wp-content"]}))

    def test_nginx_from_server_header(self):
        self.assertIn("nginx", names({"HTTP": ["nginx/1.25.3"]}))

    def test_dmarc_from_txt(self):
        self.assertIn("DMARC 設定あり", names({"TXT": ["v=DMARC1; p=none"]}))

    def test_unknown_records_yield_nothing(self):
        self.assertEqual(detect({"NS": ["ns1.unrelated-hosting.example"]}), [])

    def test_empty_input(self):
        self.assertEqual(detect({}), [])


class TestConfidence(unittest.TestCase):
    def test_keeps_highest_confidence_for_same_technology(self):
        records = {
            "NS": ["ns1.cloudflare.com"],
            "CNAME": ["example.com.cdn.cloudflare.net"],
        }
        entries = {name: conf for _cat, name, conf in detect(records)}
        self.assertEqual(entries.get("Cloudflare"), "high")

    def test_category_assignment(self):
        records = {"MX": ["aspmx.l.google.com"]}
        self.assertEqual(category_of(records, "Google Workspace"), "メール")


class TestMatchRule(unittest.TestCase):
    def test_is_case_insensitive(self):
        from miharun.rules import Rule

        rule = Rule("メール", "テスト", ("example.com",), ("MX",))
        self.assertTrue(match_rule(rule, "MX.EXAMPLE.COM"))
        self.assertFalse(match_rule(rule, "mail.other.net"))


class TestRulesIntegrity(unittest.TestCase):
    def test_all_rules_have_confident_names(self):
        for rule in RULES:
            self.assertTrue(rule.name)
            self.assertTrue(rule.category)
            self.assertTrue(rule.patterns)
            self.assertIn(rule.confidence, ("high", "medium", "low"))

    def test_categories_have_no_empty_name(self):
        for category in all_categories():
            self.assertTrue(category.strip())


class TestSummarize(unittest.TestCase):
    def test_groups_by_category(self):
        technologies = detect(
            {
                "NS": ["ns1.cloudflare.com"],
                "MX": ["aspmx.l.google.com"],
            }
        )
        summary = summarize(technologies)
        self.assertIn("Cloudflare", summary.get("DNS", []))
        self.assertIn("Google Workspace", summary.get("メール", []))


if __name__ == "__main__":
    unittest.main()