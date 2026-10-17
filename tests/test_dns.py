"""sources/dns.py のテスト.

ネットワークには接続せず、値の整形とパースだけを検証します。
"""

from __future__ import annotations

import unittest

from miharun.sources.dns import format_value, parse_answers

SAMPLE_PAYLOAD = {
    "Status": 0,
    "Answer": [
        {"name": "example.com", "type": 15, "data": "10 aspmx.l.google.com."},
        {"name": "example.com", "type": 15, "data": "20 alt1.aspmx.l.google.com."},
        {"name": "example.com", "type": 15, "data": "10 aspmx.l.google.com."},
        {"name": "example.com", "type": 16, "data": '"v=spf1 include:_spf.google.com ~all"'},
        {"name": "example.com", "type": 5, "data": "target.example.net."},
        {"name": "example.com", "type": 1, "data": "203.0.113.10"},
        {"name": "example.com", "type": 1, "data": "203.0.113.11"},
    ],
}


class TestFormatValue(unittest.TestCase):
    def test_mx_drops_priority_and_trailing_dot(self):
        self.assertEqual(format_value("MX", "10 aspmx.l.google.com."), "aspmx.l.google.com")

    def test_txt_removes_quotes(self):
        self.assertEqual(
            format_value("TXT", '"v=spf1 include:_spf.google.com ~all"'),
            "v=spf1 include:_spf.google.com ~all",
        )

    def test_txt_joins_multiple_quoted_chunks_with_space(self):
        # DoH は 255 文字ごとに文字列分割するため "abc" "def" 形式になる
        self.assertEqual(format_value("TXT", '"abc" "def"'), "abc def")

    def test_a_keeps_value(self):
        self.assertEqual(format_value("A", "203.0.113.10"), "203.0.113.10")

    def test_cname_lowercases_and_strips_dot(self):
        self.assertEqual(format_value("CNAME", "Target.Example.NET."), "target.example.net")

    def test_empty_input(self):
        self.assertEqual(format_value("TXT", "   "), "")


class TestParseAnswers(unittest.TestCase):
    def test_filters_by_requested_type(self):
        self.assertEqual(
            parse_answers(SAMPLE_PAYLOAD, "MX"),
            ["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
        )

    def test_deduplicates(self):
        answers = parse_answers(SAMPLE_PAYLOAD, "MX")
        self.assertEqual(len(answers), 2)

    def test_txt(self):
        self.assertEqual(
            parse_answers(SAMPLE_PAYLOAD, "TXT"),
            ["v=spf1 include:_spf.google.com ~all"],
        )

    def test_cname(self):
        self.assertEqual(parse_answers(SAMPLE_PAYLOAD, "CNAME"), ["target.example.net"])

    def test_a_keeps_all_addresses(self):
        self.assertEqual(parse_answers(SAMPLE_PAYLOAD, "A"), ["203.0.113.10", "203.0.113.11"])

    def test_missing_answer_key_returns_empty(self):
        self.assertEqual(parse_answers({"Status": 3}, "A"), [])


if __name__ == "__main__":
    unittest.main()