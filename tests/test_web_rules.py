"""Wappalyzer 由来 Web ルールのテスト.

主に誤検知が起きないこと（precision）を検証します。
"""

from __future__ import annotations

import unittest

from miharun.fingerprint import detect, rule_count
from miharun.rules import rules_for_source
from miharun.rules_web import WEB_RULES
from miharun.sources.http_probe import find_markers


def names_for(body: bytes) -> set[str]:
    return {name for _c, name, _conf in detect({"HTTP": find_markers(body)})}


class TestRuleVolume(unittest.TestCase):
    def test_web_rules_are_substantial(self):
        self.assertGreater(len(WEB_RULES), 1500)

    def test_total_rule_count_is_large(self):
        self.assertGreater(rule_count(), 1500)

    def test_all_web_rules_use_http_source(self):
        for rule in WEB_RULES:
            self.assertTrue(
                "HTTP" in rule.sources or "HTTP_HEADER" in rule.sources,
                msg=f"{rule.name} の sources が不正: {rule.sources}",
            )

    def test_header_rules_exist(self):
        header_rules = [r for r in WEB_RULES if "HTTP_HEADER" in r.sources]
        self.assertGreater(len(header_rules), 0)
        # ヘッダ由来のルールは「ヘッダ名: 値」の形になっていること
        for rule in header_rules:
            for pattern in rule.patterns:
                self.assertIn(": ", pattern, msg=f"{rule.name}: {pattern}")

    def test_all_web_rules_have_patterns(self):
        for rule in WEB_RULES:
            self.assertTrue(rule.patterns)
            self.assertTrue(rule.category)

    def test_technology_count_is_wide(self):
        self.assertGreater(len({rule.name for rule in WEB_RULES}), 1000)


class TestDetection(unittest.TestCase):
    def test_detects_wordpress(self):
        self.assertIn("WordPress", names_for(b"<script src=/wp-content/plugins/x/x.js>"))

    def test_detects_shopify(self):
        self.assertIn("Shopify", names_for(b"<script src=https://cdn.shopify.com/s.js>"))

    def test_detects_drupal(self):
        self.assertIn("Drupal", names_for(b"<script src=/sites/default/files/js/drupal.js>"))

    def test_wordpress_is_categorised_as_cms(self):
        found = detect({"HTTP": find_markers(b"<script src=/wp-content/plugins/x/x.js>")})
        categories = {category for category, _name, _conf in found}
        self.assertIn("CMS", categories)

    def test_shopify_is_not_categorised_as_cms(self):
        found = detect({"HTTP": find_markers(b"<script src=https://cdn.shopify.com/s.js>")})
        for category, name, _conf in found:
            if name == "Shopify":
                self.assertNotEqual(category, "CMS")


class TestPrecision(unittest.TestCase):
    """通常ページで誤検知しないことが最も重要."""

    def test_minimal_html_is_clean(self):
        self.assertEqual(names_for(b"<html><body><div>hello</div></body></html>"), set())

    def test_titled_page_is_clean(self):
        body = b"<!doctype html><head><title>Test</title></head><body>content</body>"
        self.assertEqual(names_for(body), set())

    def test_japanese_page_is_clean(self):
        body = "<html lang=ja><head><title>テスト</title></head><body>こんにちは</body></html>"
        self.assertEqual(names_for(body.encode("utf-8")), set())

    def test_empty_body(self):
        self.assertEqual(names_for(b""), set())

    def test_generic_words_do_not_trigger(self):
        body = b"<div class=content><script src=/assets/app.js></script><p>hello</p></div>"
        self.assertEqual(names_for(body), set())

    def test_header_names_in_body_do_not_trigger(self):
        """ヘッダ名を本文の文字列として扱っていた頃の誤検知を防ぐ.

        `platform` という値や `hosting` という語、`parentNode` が本文に
        あるだけでホスティング業者や CMS を検出してはいけません。
        """
        body = (
            b"<title>Blog Tool, Publishing Platform, and CMS</title>"
            b"<div>we offer hosting and hosting plans</div>"
            b"<script>f.parentNode.insertBefore(x, y)</script>"
            b"<a href=https://example.com/hosting/>hosting</a>"
        )
        self.assertEqual(names_for(body), set())

    def test_body_cannot_impersonate_a_response_header(self):
        """本文にヘッダ行を書いても、ヘッダ判定ルールは反応しないこと."""
        found = {
            name
            for _c, name, _conf in detect({"HTTP": ["platform: hostinger"]})
        }
        self.assertNotIn("Hostinger", found)

    def test_response_header_triggers_header_rule(self):
        """実際の応答ヘッダ（"ヘッダ名: 値"）ではきちんと判定できること."""
        found = {name for _c, name, _conf in detect({"HTTP_HEADER": ["platform: hostinger"]})}
        self.assertIn("Hostinger", found)

    def test_header_patterns_are_not_scanned_in_body(self):
        markers = find_markers(b"<p>platform: hostinger</p>")
        self.assertNotIn("platform: hostinger", markers)


class TestFindMarkers(unittest.TestCase):
    def test_finds_known_marker(self):
        self.assertIn("wp-content", find_markers(b"/wp-content/x.js"))

    def test_returns_lowercase(self):
        for marker in find_markers(b"<script src=https://CDN.SHOPIFY.COM/s.js>"):
            self.assertEqual(marker, marker.lower())

    def test_deduplicates(self):
        markers = find_markers(b"/wp-content/a /wp-content/b")
        self.assertEqual(len(markers), len(set(markers)))


class TestSpeed(unittest.TestCase):
    def test_detection_is_fast_enough(self):
        import time

        body = b"<script src=/wp-content/x.js><script src=https://cdn.shopify.com/s.js>"
        start = time.perf_counter()
        find_markers(body)
        elapsed = time.perf_counter() - start
        # 1 ホストあたり 1 秒未満であれば実用上問題ない
        self.assertLess(elapsed, 1.0)


class TestSourcesIndex(unittest.TestCase):
    def test_rules_for_source_filters(self):
        http_rules = rules_for_source("HTTP")
        self.assertGreater(len(http_rules), 1500)

    def test_unknown_source_returns_empty(self):
        self.assertEqual(rules_for_source("NOPE"), [])


if __name__ == "__main__":
    unittest.main()