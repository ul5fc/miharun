"""パターンマッチングの共通処理のテスト."""

from __future__ import annotations

import unittest

from miharun.matching import compile_pattern, find_matches, matches


class TestCompilePattern(unittest.TestCase):
    def test_is_cached(self):
        """同じパターンは同じオブジェクトを返す（性能の要）."""
        self.assertIs(compile_pattern("wp-content"), compile_pattern("wp-content"))

    def test_matches_literal(self):
        self.assertIsNotNone(compile_pattern("wp-content").search("/wp-content/x.js"))

    def test_space_matches_any_whitespace(self):
        pattern = compile_pattern("movable type")
        self.assertIsNotNone(pattern.search("movable type"))
        self.assertIsNotNone(pattern.search("movable  type"))
        self.assertIsNotNone(pattern.search("movable\ntype"))

    def test_special_characters_are_literal(self):
        """正規表現の特殊文字を含むパターンでも安全に扱える."""
        pattern = compile_pattern("a.b*c?")
        self.assertIsNotNone(pattern.search("a.b*c?"))
        self.assertIsNone(pattern.search("axbbc"))


class TestMatches(unittest.TestCase):
    def test_case_insensitive(self):
        self.assertTrue(matches("x-powered-by", "X-Powered-By"))

    def test_no_match(self):
        self.assertFalse(matches("hello", "nginx"))


class TestFindMatches(unittest.TestCase):
    def test_returns_only_matching_patterns(self):
        found = find_matches("/wp-content/x.js", ("wp-content", "nginx"))
        self.assertEqual(found, ["wp-content"])

    def test_preserves_input_order(self):
        found = find_matches("a nginx b wp-content", ("wp-content", "nginx"))
        self.assertEqual(found, ["wp-content", "nginx"])

    def test_duplicates_are_reported_once(self):
        found = find_matches("wp-content", ("wp-content", "WP-Content"))
        self.assertEqual(len(found), 1)

    def test_empty_patterns(self):
        self.assertEqual(find_matches("anything", ()), [])

    def test_matches_inside_large_text(self):
        text = "x" * 100000 + "calendly.com/a.js"
        self.assertEqual(find_matches(text, ("calendly.com/a.js",)), ["calendly.com/a.js"])


if __name__ == "__main__":
    unittest.main()
