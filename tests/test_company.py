"""sources/company.py のパース部分のテスト.

ネットワークには接続せず、API 応答のパースだけを検証します。
"""

from __future__ import annotations

import unittest

from miharun.sources.company import (
    _parse_gbizinfo,
    _parse_houjin_csv,
    _parse_houjin_xml,
)

GBIZINFO_SAMPLE = {
    "hojin-infos": [
        {
            "corporate_number": "1234567890123",
            "name": "株式会社サンプル",
            "location": "東京都千代田区丸の内1-1-1",
            "company_url": "https://sample.example.co.jp",
        },
        {
            "corporate_number": "9876543210987",
            "name": "サンプル合同会社",
            "location": "大阪府大阪市北区",
            "company_url": "",
        },
    ]
}

HOUJIN_CSV_SAMPLE = """\
1,1234567890123,,20250101,変更,新設,20250101,株式会社サンプル,,有限责任公司,東京都,千代田区,丸の内1-1-1,,13,1000001,,,20250101,,1,新規設立,20250101,1,
2,9876543210987,,20250101,変更,新設,20250101,サンプル合同会社,,合同会社,大阪府,大阪市,北区,,13,5300001,,,20250101,,1,新規設立,20250101,1,
"""

HOUJIN_XML_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<corporations>
  <corporation>
    <corporateNumber>1234567890123</corporateNumber>
    <name>株式会社サンプル</name>
    <prefectureName>東京都</prefectureName>
    <cityName>千代田区</cityName>
    <streetNumber>丸の内1-1-1</streetNumber>
  </corporation>
</corporations>
"""


class TestParseGbizinfo(unittest.TestCase):
    def test_extracts_key_fields(self):
        results = _parse_gbizinfo(GBIZINFO_SAMPLE, limit=5)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].corporate_number, "1234567890123")
        self.assertEqual(results[0].name, "株式会社サンプル")
        self.assertEqual(results[0].website, "https://sample.example.co.jp")
        self.assertEqual(results[0].source, "gBizINFO（経済産業省）")

    def test_blank_url_becomes_none(self):
        results = _parse_gbizinfo(GBIZINFO_SAMPLE, limit=5)
        self.assertIsNone(results[1].website)

    def test_respects_limit(self):
        self.assertEqual(len(_parse_gbizinfo(GBIZINFO_SAMPLE, limit=1)), 1)

    def test_empty_payload(self):
        self.assertEqual(_parse_gbizinfo({}, limit=5), [])

    def test_alternate_key_name(self):
        payload = {"hojin_infos": [{"name": "株式会社テスト", "companyUrl": "https://t.example"}]}
        results = _parse_gbizinfo(payload, limit=5)
        self.assertEqual(results[0].website, "https://t.example")


class TestParseHoujinCsv(unittest.TestCase):
    def test_extracts_name_number_and_location(self):
        results = _parse_houjin_csv(HOUJIN_CSV_SAMPLE)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].name, "株式会社サンプル")
        self.assertEqual(results[0].corporate_number, "1234567890123")
        self.assertEqual(results[0].location, "東京都千代田区丸の内1-1-1")
        self.assertIsNone(results[0].website)

    def test_skips_short_rows(self):
        self.assertEqual(_parse_houjin_csv("1,2,3\n"), [])

    def test_empty_body(self):
        self.assertEqual(_parse_houjin_csv(""), [])


class TestParseHoujinXml(unittest.TestCase):
    def test_extracts_fields(self):
        results = _parse_houjin_xml(HOUJIN_XML_SAMPLE)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "株式会社サンプル")
        self.assertEqual(results[0].corporate_number, "1234567890123")
        self.assertEqual(results[0].location, "東京都千代田区丸の内1-1-1")

    def test_broken_xml_returns_empty(self):
        self.assertEqual(_parse_houjin_xml("<not-xml"), [])


if __name__ == "__main__":
    unittest.main()