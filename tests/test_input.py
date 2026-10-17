"""入力の振り分け（ドメイン / 企業名）のテスト.

ネットワークを使わず、判定だけを検証します。
"""

from __future__ import annotations

import unittest

from miharun.cli import detect_input


class TestDetectInput(unittest.TestCase):
    def test_plain_domains(self):
        self.assertEqual(detect_input("example.com"), ("domain", "example.com"))
        self.assertEqual(detect_input("example.co.jp"), ("domain", "example.co.jp"))
        self.assertEqual(
            detect_input("sub.example.co.jp"), ("domain", "sub.example.co.jp")
        )

    def test_normalises_case_and_trailing_dot(self):
        self.assertEqual(detect_input("Example.COM"), ("domain", "example.com"))
        self.assertEqual(detect_input("example.com."), ("domain", "example.com"))

    def test_url_is_reduced_to_host(self):
        self.assertEqual(
            detect_input("https://example.com/path?q=1"), ("domain", "example.com")
        )

    def test_punycode_domain_is_a_domain(self):
        """punycode（xn--）のドメインを企業名と誤判定しないこと.

        以前は最上位ラベルを英字だけ ([a-z]{2,}) としていたため、
        xn--zckzah のような punycode のドメインが企業名として扱われ、
        「ドメインを決められませんでした」で終わっていました。
        """
        self.assertEqual(
            detect_input("xn--r8jz45g.xn--zckzah"),
            ("domain", "xn--r8jz45g.xn--zckzah"),
        )

    def test_japanese_domain_becomes_punycode(self):
        """日本語ドメインが punycode に直され、ドメインとして扱われること."""
        self.assertEqual(
            detect_input("例え.テスト"), ("domain", "xn--r8jz45g.xn--zckzah")
        )

    def test_japanese_domain_in_url(self):
        self.assertEqual(
            detect_input("https://例え.テスト/path"),
            ("domain", "xn--r8jz45g.xn--zckzah"),
        )

    def test_japanese_company_name_is_organization(self):
        """日本語の企業名はドメインと誤判定しないこと."""
        for name in ("株式会社サンプル", "N高等学校", "トヨタ自動車"):
            self.assertEqual(detect_input(name), ("organization", name), msg=name)

    def test_garbage_is_not_a_domain(self):
        for text in ("", "-", "not a domain!", "http://", "例え", "a..b"):
            self.assertEqual(detect_input(text)[0], "organization", msg=text)


if __name__ == "__main__":
    unittest.main()
