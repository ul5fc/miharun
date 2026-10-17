"""HTTP ヘッダを控えめに取得する（--probe 時のみ）.

このモジュールは miharun の中で唯一「対象ホストにリクエストを送る」部分です。
そのため次の制限を必ず守ります。

* 既定では使われない（--probe を指定したときだけ）
* robots.txt を確認し、拒否されていればアクセスしない
* 1 ホストにつき 1 回だけ。レート制限で間隔を空ける
* 応答本文は先頭だけ読み、保存しない

得られる情報は Server ヘッダや <title> 程度です。
脆弱性を探すためのものではなく、技術スタックの手がかりを増やすためだけに使います。
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from functools import lru_cache

from ..matching import find_matches
from ..safety import USER_AGENT, RateLimiter, robots_allows

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
MAX_BODY_BYTES = 256 * 1024  # 256KB まで読む（判定材料を増やすため）

# 常に先に探す軽量な目印（高速化のため先に当たりを付ける）
BODY_MARKERS: tuple[str, ...] = (
    "wp-content",
    "wp-includes",
    "wp-json",
    "ec-cube",
    "movable type",
    "mt-static",
    "shopify",
    "peraichi",
    "jimdo",
    "goope",
    "makeshop",
    "shop-pro",
)


@lru_cache(maxsize=1)
def _all_web_patterns() -> tuple[str, ...]:
    """HTTP ルールが使うパターン文字列をすべて集める（キャッシュ）. """
    from ..rules import rules_for_source

    patterns: list[str] = []
    seen: set[str] = set()
    for rule in rules_for_source("HTTP"):
        for pattern in rule.patterns:
            lowered = pattern.lower()
            if lowered and lowered not in seen:
                seen.add(lowered)
                patterns.append(lowered)
    return tuple(patterns)


def find_markers(body: bytes) -> list[str]:
    """応答本文から、技術判定に使える目印を集める（純関数）.

    まず軽量な BODY_MARKERS を調べ、その後に Wappalyzer 由来の
    パターンすべてを走査します。
    """
    lowered = body.lower()
    found: list[str] = []

    for marker in BODY_MARKERS:
        if marker.encode("utf-8") in lowered and marker not in found:
            found.append(marker)

    text = lowered.decode("utf-8", "replace")
    for pattern in find_matches(text, _all_web_patterns()):
        if pattern not in found:
            found.append(pattern)
    return found


def probe_host(host: str, limiter: RateLimiter | None = None, timeout: float = 8.0):
    """1 つのホストに 1 回だけアクセスして、ヘッダとタイトルを返す.

    戻り値は {"status": int, "server": str|None, "title": str|None, "url": str}。
    アクセスできない場合や robots.txt で拒否された場合は None を返します。
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        if not robots_allows(url, user_agent=USER_AGENT, timeout=timeout):
            continue
        if limiter is not None:
            limiter.wait()
        result = _fetch(url, timeout)
        if result is not None:
            return result
    return None


def _header_lines(headers) -> list[str]:
    """応答ヘッダを "ヘッダ名: 値" の形にそろえる（ヘッダ名は小文字）.

    ヘッダ名で判定するルール（HTTP_HEADER）だけがこれを使います。
    """
    if not headers:
        return []
    return [f"{name.lower()}: {value}" for name, value in headers.items()]


def _fetch(url: str, timeout: float):
    request = urllib.request.Request(
        url,
        headers={
            "user-agent": USER_AGENT,
            "accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            server = resp.headers.get("Server")
            header_lines = _header_lines(resp.headers)
            body = resp.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as exc:
        # 401/403 なども「応答があった」という情報になる
        status = exc.code
        server = exc.headers.get("Server") if exc.headers else None
        header_lines = _header_lines(exc.headers)
        try:
            body = exc.read(MAX_BODY_BYTES)
        except Exception:
            body = b""
    except Exception:
        return None

    title = None
    match = TITLE_RE.search(body)
    if match:
        raw = match.group(1)
        title = raw.decode("utf-8", "replace").strip()
        title = re.sub(r"\s+", " ", title)[:120] or None

    return {
        "status": status,
        "server": server,
        "title": title,
        "url": url,
        "markers": find_markers(body),
        "headers": header_lines,
    }
