"""証明書透明性ログ（crt.sh）からサブドメインを集める.

crt.sh は、発行された TLS 証明書のログを公開しているサービスです。
証明書には「どのホスト名に対して発行されたか」が記録されるため、
そこからサブドメインの一覧を推定できます。

これは完全に公開情報の読み取りであり、対象ホストへのアクセスは一切行いません。
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request

from ..safety import USER_AGENT

CRT_SH_ENDPOINT = "https://crt.sh/"


def build_url(domain: str) -> str:
    """crt.sh の検索 URL を組み立てる（純関数）."""
    query = urllib.parse.quote(f"%.{domain}")
    return f"{CRT_SH_ENDPOINT}?q={query}&output=json"


def parse_entries(payload: list[dict], domain: str) -> list[str]:
    """crt.sh の JSON から、対象ドメイン配下のホスト名を抽出する（純関数）.

    - ワイルドカード（*.example.com）は * を外して扱う
    - 対象ドメイン自身と、そのサブドメインだけを残す
    - 小文字にそろえ、重複を除いてソートする
    """
    domain = domain.lower().strip().rstrip(".")
    hosts: set[str] = set()

    for entry in payload:
        raw_names: list[str] = []
        raw_names.extend(str(entry.get("name_value", "")).split("\n"))
        if entry.get("common_name"):
            raw_names.append(str(entry["common_name"]))

        for raw in raw_names:
            # crt.sh は 1 フィールドに改行区切り・カンマ区切りの
            # どちらでも複数のホスト名を格納することがあるため、両方に対応する。
            for piece in re.split(r"[\s,]+", raw):
                name = piece.strip().lower().rstrip(".")
                if not name:
                    continue
                if name.startswith("*."):
                    name = name[2:]
                # メールアドレスが混ざることがあるので除外する
                if "@" in name:
                    continue
                if name == domain or name.endswith("." + domain):
                    hosts.add(name)

    return sorted(hosts)


def parse_certificates(payload: list[dict], domain: str) -> dict[str, dict]:
    """crt.sh の JSON から、ホストごとの「露出期間」をまとめる（純関数）.

    戻り値:
        {"www.example.com": {"first_seen": ..., "last_seen": ..., "issuers": [...]}, ...}

    not_before は証明書の発行日なので、そのホストが少なくとも
    この日からは公開されているとみなせます（＝露出期間の開始点）。
    """
    domain = domain.lower().strip().rstrip(".")
    result: dict[str, dict] = {}

    for entry in payload:
        raw_names: list[str] = []
        raw_names.extend(str(entry.get("name_value", "")).split("\n"))
        if entry.get("common_name"):
            raw_names.append(str(entry["common_name"]))

        not_before = entry.get("not_before")
        issuer = _issuer_short_name(entry.get("issuer_name"))

        for raw in raw_names:
            for piece in re.split(r"[\s,]+", raw):
                name = piece.strip().lower().rstrip(".")
                if not name:
                    continue
                if name.startswith("*."):
                    name = name[2:]
                if "@" in name:
                    continue
                if name != domain and not name.endswith("." + domain):
                    continue
                if not not_before:
                    continue

                record = result.setdefault(
                    name, {"first_seen": not_before, "last_seen": not_before, "issuers": []}
                )
                if not_before < record["first_seen"]:
                    record["first_seen"] = not_before
                if not_before > record["last_seen"]:
                    record["last_seen"] = not_before
                if issuer and issuer not in record["issuers"]:
                    record["issuers"].append(issuer)

    return result


def _issuer_short_name(issuer: str | None) -> str:
    """認証局のDNから CN を取り出す（例: GeoTrust TLS RSA CA G1）."""
    if not issuer:
        return ""
    match = re.search(r"CN=([^,]+)", issuer)
    return match.group(1).strip() if match else issuer.strip()[:40]


def fetch_subdomains(domain: str, timeout: float = 30.0, retries: int = 3) -> list[str]:
    """crt.sh に問い合わせてサブドメイン一覧を返す（公開済みテスト互換の簡易版）."""
    payload = fetch_payload(domain, timeout=timeout, retries=retries)
    if not payload:
        return []
    return parse_entries(payload, domain)


def fetch_with_windows(
    domain: str, timeout: float = 30.0, retries: int = 3
) -> tuple[list[str], dict[str, dict]]:
    """サブドメイン一覧と露出期間をまとめて取得する（1 回の HTTP で両方）.

    戻り値: (["www.example.com", ...], {"www.example.com": {"first_seen":...}})
    """
    payload = fetch_payload(domain, timeout=timeout, retries=retries)
    if not payload:
        return [], {}
    return parse_entries(payload, domain), parse_certificates(payload, domain)


def fetch_payload(
    domain: str, timeout: float = 30.0, retries: int = 3
) -> list[dict]:
    """crt.sh から生の JSON を取得する（パース前）.

    失敗した場合は空リストを返します（例外は投げません）。
    crt.sh は混雑すると HTML を返すことがあるため、
    JSON として解釈できない場合はリトライします。
    """
    url = build_url(domain)
    for attempt in range(max(1, retries)):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "accept": "application/json",
                    "user-agent": USER_AGENT,
                },
            )
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
            payload = json.loads(body)
            if isinstance(payload, list):
                return payload
            return []
        except Exception:
            # 混雑している可能性があるので少し待って再試行する
            if attempt < retries - 1:
                time.sleep(1.5 * (attempt + 1))
    return []
