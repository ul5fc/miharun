"""企業名から法人情報と公式サイトを探す（日本向け）.

2 つの公開 API に対応しています。どちらも無料ですが利用登録が必要です。

1. gBizINFO（経済産業省）— JSON
   https://info.gbiz.go.jp/
   環境変数 GBIZINFO_TOKEN に API トークンを設定します。
   法人情報と「企業URL」を返すため、ドメインの特定に向いています。

2. 国税庁 法人番号システム Web-API — CSV
   https://www.houjin-bangou.nta.go.jp/webapi/
   環境変数 HOUJIN_APP_ID にアプリケーションIDを設定します。

どちらも未設定の場合でも miharun はドメイン指定で動作します。
企業名で調べるときだけ、これらのキーが必要です。
"""

from __future__ import annotations

import csv
import io
import json
import os
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from ..models import Organization
from ..safety import USER_AGENT

GBIZINFO_ENDPOINTS = (
    "https://api.info.gbiz.go.jp/hojin/v2/hojin",
    "https://info.gbiz.go.jp/hojin/v1/hojin",
)
HOUJIN_ENDPOINT = "https://api.houjin-bangou.nta.go.jp/4/name"


def has_gbizinfo() -> bool:
    return bool(os.environ.get("GBIZINFO_TOKEN"))


def has_houjin() -> bool:
    return bool(os.environ.get("HOUJIN_APP_ID"))


def available_sources() -> list[str]:
    """利用可能なデータソース名を返す。"""
    sources: list[str] = []
    if has_gbizinfo():
        sources.append("gBizINFO（経済産業省）")
    if has_houjin():
        sources.append("法人番号システム Web-API（国税庁）")
    return sources


def setup_hint() -> str:
    """キーが未設定のときの案内文を返す。"""
    return (
        "企業名で調べるには、無料の API キーが必要です（どちらか一方でかまいません）。\n"
        "  1) gBizINFO      … https://info.gbiz.go.jp/ で登録し、"
        "環境変数 GBIZINFO_TOKEN にトークンを設定\n"
        "  2) 法人番号 API   … https://www.houjin-bangou.nta.go.jp/webapi/ で申請し、"
        "環境変数 HOUJIN_APP_ID にアプリケーションIDを設定\n"
        "ドメインを直接指定する場合は、キーは不要です。"
    )


def search(name: str, limit: int = 5, timeout: float = 20.0) -> list[Organization]:
    """企業名で検索し、見つかった法人情報を返す.

    gBizINFO を優先し、無ければ法人番号 API を使います。
    どちらも使えない場合は空リストを返します（理由は notes でなく setup_hint を参照）。
    """
    results: list[Organization] = []

    if has_gbizinfo():
        results.extend(_search_gbizinfo(name, limit=limit, timeout=timeout))
    if not results and has_houjin():
        results.extend(_search_houjin(name, timeout=timeout))

    # 公式サイトが分かっているものを前に出す
    results.sort(key=lambda org: (org.website is None, org.name or ""))
    return results[:limit]


# ----------------------------------------------------------------------
# gBizINFO（JSON）
# ----------------------------------------------------------------------


def _search_gbizinfo(name: str, limit: int, timeout: float) -> list[Organization]:
    token = os.environ.get("GBIZINFO_TOKEN", "")
    params = urllib.parse.urlencode({"name": name, "limit": limit})
    headers = {
        "accept": "application/json",
        "user-agent": USER_AGENT,
        "X-hojinInfo-api-token": token,
    }

    for endpoint in GBIZINFO_ENDPOINTS:
        try:
            request = urllib.request.Request(f"{endpoint}?{params}", headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            continue

        return _parse_gbizinfo(payload, limit)
    return []


def _parse_gbizinfo(payload: dict, limit: int) -> list[Organization]:
    """gBizINFO の JSON を Organization に変換する（純関数）. """
    infos = payload.get("hojin-infos") or payload.get("hojin_infos") or []
    results: list[Organization] = []
    for info in infos[:limit]:
        if not isinstance(info, dict):
            continue
        url = (
            info.get("company_url")
            or info.get("companyUrl")
            or info.get("url")
            or None
        )
        results.append(
            Organization(
                name=info.get("name"),
                corporate_number=info.get("corporate_number"),
                location=info.get("location"),
                website=url.strip() if isinstance(url, str) and url.strip() else None,
                source="gBizINFO（経済産業省）",
            )
        )
    return results


# ----------------------------------------------------------------------
# 国税庁 法人番号システム Web-API（CSV / XML）
# ----------------------------------------------------------------------


def _search_houjin(name: str, timeout: float) -> list[Organization]:
    app_id = os.environ.get("HOUJIN_APP_ID", "")
    params = urllib.parse.urlencode({"id": app_id, "name": name})
    request = urllib.request.Request(
        f"{HOUJIN_ENDPOINT}?{params}",
        headers={"accept": "text/csv, application/xml", "user-agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except Exception:
        return []

    text = body.lstrip()
    if text.startswith("<"):
        return _parse_houjin_xml(body)
    return _parse_houjin_csv(body)


def _parse_houjin_csv(body: str) -> list[Organization]:
    """法人番号 API の CSV を Organization に変換する（純関数）. """
    results: list[Organization] = []
    reader = csv.reader(io.StringIO(body))
    for row in reader:
        if len(row) < 8:
            continue
        number = row[1].strip() if len(row) > 1 else ""
        name = row[7].strip() if len(row) > 7 else ""
        if not name:
            continue
        location = "".join(
            part.strip() for part in row[10:13] if part.strip()
        ) if len(row) >= 13 else ""
        results.append(
            Organization(
                name=name,
                corporate_number=number or None,
                location=location or None,
                website=None,
                source="法人番号システム Web-API（国税庁）",
            )
        )
    return results


def _parse_houjin_xml(body: str) -> list[Organization]:
    """法人番号 API の XML を Organization に変換する（純関数）. """
    results: list[Organization] = []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return results

    def text_of(element, tag: str) -> str:
        child = element.find(tag)
        return child.text.strip() if child is not None and child.text else ""

    for corp in root.iter("corporation"):
        name = text_of(corp, "name")
        if not name:
            continue
        prefecture = text_of(corp, "prefectureName")
        city = text_of(corp, "cityName")
        street = text_of(corp, "streetNumber")
        results.append(
            Organization(
                name=name,
                corporate_number=text_of(corp, "corporateNumber") or None,
                location=(prefecture + city + street) or None,
                website=None,
                source="法人番号システム Web-API（国税庁）",
            )
        )
    return results
