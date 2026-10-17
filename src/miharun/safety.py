"""安全性のための共通処理.

miharun は「パッシブ・ファースト」を設計方針にしています。
既定では対象ホストに一切リクエストを送りません。
--probe を指定したときだけ、控えめな HTTP アクセスを行います。

このモジュールは次の 3 つを提供します。

1. USER_AGENT: ツールを名乗る正しい User-Agent
2. RateLimiter: アクセス間隔を空けるための待機
3. robots_allows(): robots.txt の確認（--probe 時のみ）

詳細は docs/SAFETY.md を参照してください。
"""

from __future__ import annotations

import time
import urllib.parse
import urllib.request

from . import __repository__, __version__

# 連絡先を明示した User-Agent。匿名の連打は行わない。
USER_AGENT = f"miharun/{__version__} (passive surface mapping; +{__repository__})"

DEFAULT_TIMEOUT = 15.0


class RateLimiter:
    """連続アクセスの間隔を空けるための単純なレート制限。"""

    def __init__(self, min_interval: float = 1.0) -> None:
        self.min_interval = max(0.0, min_interval)
        self._last = 0.0

    def wait(self) -> None:
        """前回から min_interval 秒経つまで待つ。"""
        if self.min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last
        remaining = self.min_interval - elapsed
        if remaining > 0:
            time.sleep(remaining)
        self._last = time.monotonic()


_robots_cache: dict[str, "urllib.robotparser.RobotFileParser | None"] = {}


def robots_allows(
    url: str, user_agent: str = USER_AGENT, timeout: float = DEFAULT_TIMEOUT
) -> bool:
    """対象 URL が robots.txt で許可されているかを確認する.

    判定できない場合（robots.txt が無い・読めない）は True を返します。
    robots.txt は「クロールの可否」を示すもので許可の代わりではありませんが、
    礼儀として尊重します。
    """
    parts = urllib.parse.urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"

    if origin not in _robots_cache:
        parser = _load_robots(origin, user_agent, timeout)
        _robots_cache[origin] = parser

    parser = _robots_cache[origin]
    if parser is None:
        return True
    try:
        return parser.can_fetch(user_agent, url)
    except Exception:
        return True


def _load_robots(origin: str, user_agent: str, timeout: float):
    """robots.txt を取得してパーサを返す。取得できなければ None。"""
    import urllib.robotparser

    robots_url = f"{origin}/robots.txt"
    try:
        request = urllib.request.Request(
            robots_url, headers={"user-agent": user_agent}
        )
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except Exception:
        return None

    parser = urllib.robotparser.RobotFileParser()
    parser.parse(body.splitlines())
    return parser
