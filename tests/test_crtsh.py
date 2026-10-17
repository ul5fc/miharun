"""sources/crtsh.py のテスト."""

from __future__ import annotations

import unittest

from miharun.sources.crtsh import build_url, parse_entries

SAMPLE = [
    {"name_value": "example.com\n*.example.com", "common_name": "example.com"},
    {"name_value": "www.example.com", "common_name": "www.example.com"},
    {"name_value": "api.example.com", "common_name": "api.example.com"},
    {"name_value": "other.example.com", "common_name": "other.example.com"},
    # 別ドメインやメールアドレスは除外される
    {"name_value": "notexample.com", "common_name": "notexample.com"},
    {"name_value": "admin@notexample.com", "common_name": ""},
    # 重複
    {"name_value": "www.example.com", "common_name": "www.example.com"},
]


class TestParseEntries(unittest.TestCase):
    def test_filters_and_sorts(self):
        result = parse_entries(SAMPLE, "example.com")
        self.assertEqual(result, ["api.example.com", "example.com", "other.example.com", "www.example.com"])

    def test_wildcard_prefix_is_stripped(self):
        result = parse_entries(SAMPLE, "example.com")
        self.assertNotIn("*.example.com", result)
        self.assertIn("example.com", result)

    def test_excludes_unrelated_domain(self):
        result = parse_entries(SAMPLE, "example.com")
        self.assertNotIn("notexample.com", result)

    def test_excludes_email_like_entry(self):
        result = parse_entries(SAMPLE, "example.com")
        self.assertNotIn("admin@notexample.com", result)

    def test_accepts_comma_separated_names(self):
        payload = [{"name_value": "a.example.com,b.example.com"}]
        self.assertEqual(parse_entries(payload, "example.com"), ["a.example.com", "b.example.com"])

    def test_empty_payload(self):
        self.assertEqual(parse_entries([], "example.com"), [])

    def test_domain_is_case_insensitive(self):
        payload = [{"name_value": "WWW.Example.COM"}]
        self.assertEqual(parse_entries(payload, "EXAMPLE.COM"), ["www.example.com"])


class TestBuildUrl(unittest.TestCase):
    def test_uses_wildcard_query_and_json_output(self):
        url = build_url("example.com")
        self.assertIn("crt.sh", url)
        self.assertIn("output=json", url)
        # %.example.com の % は %25 にエンコードされる
        self.assertIn("%25.example.com", url)


if __name__ == "__main__":
    unittest.main()