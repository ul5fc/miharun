"""DNS を DNS over HTTPS (DoH) で引く.

外部ライブラリを使わず、標準ライブラリだけで完結させています。
Cloudflare と Google の公開 DoH エンドポイントを順に試します。

「パッシブ」である理由:
    DoH の問い合わせは解決サーバー（Cloudflare / Google）に対して行われるもので、
    対象ホストそのものにパケットを送るわけではありません。
    したがって通常の DNS 逆引き／正引きと同じ扱いで、安全に実行できます。
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from ..safety import USER_AGENT

# 使う順に並べた公開 DoH リゾルバ
RESOLVERS: tuple[str, ...] = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)

# DNS レコードタイプの番号表
TYPE_NUMBER: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "CAA": 257,
}

# 逆引きに使うタイプ
COMMON_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "TXT", "NS")


class DnsError(RuntimeError):
    """DoH での問い合わせに失敗したときに送出する。"""


def _fetch(resolver: str, name: str, rtype: str, timeout: float) -> dict:
    params = urllib.parse.urlencode({"name": name, "type": rtype})
    url = f"{resolver}?{params}"
    request = urllib.request.Request(
        url,
        headers={"accept": "application/dns-json", "user-agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
    return json.loads(body)


def format_value(rtype: str, data: str) -> str:
    """DoH が返す生の値を、人間が読みやすい形に整える.

    MX は優先度を落とし、TXT は引用符を外し、
    ドメイン系は末尾のドットを外して小文字にします。
    """
    rtype = rtype.upper()
    data = (data or "").strip()
    if not data:
        return ""

    if rtype == "MX":
        # "10 aspmx.l.google.com." -> "aspmx.l.google.com"
        parts = data.split(None, 1)
        host = parts[1] if len(parts) == 2 else data
        return host.rstrip(".").lower()

    if rtype == "TXT":
        # 引用符を取り除いて結合する。
        # DoH は 255 文字ごとに文字列を分割するため、"abc" "def" の形になることがある。
        # その場合は "abc def" のように空白区切りで並べる（SPF 文字列と同じ扱いでよい）。
        return " ".join(data.replace('"', " ").split())

    if rtype in ("A", "AAAA"):
        return data

    return data.rstrip(".").lower()


def parse_answers(payload: dict, rtype: str) -> list[str]:
    """DoH の JSON から、指定タイプの値だけを取り出す（純関数）.

    ネットワークに触れないため、単体テストの対象にできます。
    """
    want = TYPE_NUMBER.get(rtype.upper())
    values: list[str] = []
    for answer in payload.get("Answer") or []:
        if want is not None and answer.get("type") != want:
            continue
        value = format_value(rtype, str(answer.get("data", "")))
        if value and value not in values:
            values.append(value)
    return values


def query(name: str, rtype: str, timeout: float = 10.0) -> list[str]:
    """名前とレコードタイプを指定して DNS を引く.

    リゾルバを順に試し、最初に成功した結果を返します。
    すべて失敗した場合は空リストを返します（例外は投げません）。
    """
    for resolver in RESOLVERS:
        try:
            payload = _fetch(resolver, name, rtype, timeout)
        except Exception:
            continue
        return parse_answers(payload, rtype)
    return []


def reverse(ip: str, timeout: float = 10.0) -> list[str]:
    """IP アドレスから PTR レコード（逆引き）を引く.

    逆引きで得られるホスト名は、その IP を運用している組織の
    手がかりになります（例: 133.242.x.x -> xxx.sakura.ne.jp）。
    """
    if ":" in ip:
        # IPv6 は nibble 形式に変換する
        import ipaddress

        try:
            reversed_name = ipaddress.ip_address(ip).reverse_pointer
        except ValueError:
            return []
    else:
        octets = ip.split(".")
        if len(octets) != 4:
            return []
        reversed_name = ".".join(reversed(octets)) + ".in-addr.arpa"

    return query(reversed_name, "PTR", timeout=timeout)


def reverse_short(ip: str, timeout: float = 10.0) -> str:
    """逆引きして、最初の 1 件だけを返す（無ければ空文字）。"""
    results = reverse(ip, timeout=timeout)
    return results[0] if results else ""
