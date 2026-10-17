"""パターンマッチングの共通処理（コンパイル済み正規表現のキャッシュ）.

判定パターンは 1,900 個以上あり、1 ホストごとに全部を走査します。
`re.escape()` と `re.search()` を毎回呼ぶとかなり遅くなるため、
コンパイル結果をキャッシュして使い回します。

Python の `re` モジュールには 512 件の内部キャッシュがあります。
1,900 件のパターンを毎回コンパイルさせるとこのキャッシュが
あふれて再コンパイルが繰り返されるため、無制限のキャッシュを
自前で持つのがこのモジュールの役割です。
"""

from __future__ import annotations

import re
from functools import lru_cache

#: パターン中のスペースは「連続する空白」に一致させる
_SPACE = r"\ "
_SPACE_RE = r"\s+"


@lru_cache(maxsize=None)
def compile_pattern(pattern: str) -> re.Pattern[str]:
    """1 つのパターンをコンパイル済み正規表現にする（キャッシュ付き）.

    パターンは小文字化してから扱います（呼び出し側の文字列は
    小文字化済みであることが前提のため）。
    """
    escaped = re.escape(pattern).replace(_SPACE, _SPACE_RE)
    return re.compile(escaped)


def find_matches(text: str, patterns: tuple[str, ...] | list[str]) -> list[str]:
    """text に含まれるパターンだけを返す（順序は patterns の順）.

    text は小文字化されている前提です。戻り値のパターンは
    ``patterns`` に渡された元の表記のままです。

    空白を含まないパターンは正規表現を経由せず、Python の文字列
    ``in`` 演算で判定します。こちらの方が桁違いに速いためです。
    """
    found: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        lowered = pattern.lower()
        if lowered in seen:
            continue
        seen.add(lowered)

        if " " in lowered:
            # 空白は連続する空白に一致させる必要があるため正規表現を使う
            hit = compile_pattern(lowered).search(text) is not None
        else:
            hit = lowered in text

        if hit:
            found.append(pattern)
    return found


def matches(text: str, pattern: str) -> bool:
    """text が 1 つのパターンに一致するかどうか."""
    return compile_pattern(pattern.lower()).search(text) is not None
