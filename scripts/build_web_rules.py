"""Wappalyzer（enthec/webappanalyzer）の署名データを
miharun の判定ルールへ変換する生成スクリプト（開発時のみ使用）.

このスクリプトは src/miharun/rules_web.py を自動生成します。
生成済みファイルはリポジトリにコミットされるため、
miharun の実行時には外部通信も Wappalyzer データも一切不要です。

Wappalyzer は MIT ライセンスで公開されています。
    https://github.com/enthec/webappanalyzer

使い方:
    python scripts/build_web_rules.py
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT / "src"))

from miharun.console import setup_console  # noqa: E402

BASE = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/"
TECH_DIR = "technologies/"
LETTERS = [chr(c) for c in range(ord("a"), ord("z") + 1)] + ["_"]

# 生成元を明示するための User-Agent（開発時のみ実行する）
UA = "miharun-rules-builder/1.0 (+https://github.com/ul5fc/miharun)"

# ---------------------------------------------------------------------------
# カテゴリ定義（categories.json より。ID → 表示名・重要度）
# 重要度 1〜2 のカテゴリだけを採用する。
# priority が 9 のもの（フォント・地図・広告など）は情報過多で
# 実務上の判断材料にならないため、意図的に除外している。
# ---------------------------------------------------------------------------

CATEGORY_NAMES: dict[int, str] = {
    1: "CMS", 2: "メッセージボード", 3: "データベース管理", 4: "ドキュメント",
    6: "EC", 7: "写真ギャラリー", 8: "Wiki", 9: "ホスティングパネル",
    11: "ブログ", 12: "JSフレームワーク", 13: "イシュートラッカー",
    14: "動画プレーヤー", 15: "コメントシステム", 16: "セキュリティ",
    18: "Webフレームワーク", 20: "エディタ", 21: "LMS", 22: "Webサーバー",
    23: "キャッシュ", 24: "リッチテキストエディタ", 26: "モバイルフレームワーク",
    27: "プログラミング言語", 29: "検索エンジン", 30: "Webメール",
    31: "CDN", 33: "Webサーバー拡張", 34: "データベース", 35: "マップ",
    37: "ネットワーク機器", 38: "メディアサーバー", 41: "決済代行",
    44: "CI・CD", 45: "制御システム", 46: "リモートアクセス", 47: "開発ツール",
    48: "ネットワークストレージ", 49: "フィードリーダー", 50: "DMS",
    51: "ページビルダー", 53: "CRM", 54: "SEO", 55: "会計・経理",
    57: "静的サイトジェネレーター", 59: "JSライブラリ", 60: "コンテナ",
    62: "PaaS", 63: "IaaS", 64: "リバースプロキシ", 65: "ロードバランサー",
    66: "UIフレームワーク", 69: "認証", 70: "SSL/TLS認証局",
    80: "WordPressテーマ", 82: "Drupalテーマ", 87: "WordPressプラグイン",
    88: "ホスティング", 100: "Shopifyアプリ", 110: "フォームビルダー",
}

# --- 誤検知を避けるため、パターンとして使わない汎用語 ---

GENERIC_WORDS = {
    "content", "script", "styles", "assets", "static", "public",
    "media", "images", "image", "fonts", "font", "css", "javascript",
    "html", "body", "head", "div", "span", "index", "main", "page",
    "site", "home", "data", "info", "files", "file", "docs", "doc",
    "api", "app", "web", "net", "com", "org", "io", "js", "php",
}

# --- meta / headers のキーとして現れたとき、意味を持たない汎用語 ---
GENERIC_KEYS = {
    "content", "generator", "author", "description", "keywords", "robots",
    "viewport", "charset", "language", "copyright", "rating", "theme-color",
    "format-detection", "referrer", "date", "server", "via", "age", "etag",
    "expires", "last-modified", "pragma", "cache-control", "vary",
    "accept-ranges", "content-type", "content-length", "x-frame-options",
    "p3p", "x-xss-protection", "x-ua-compatible", "link", "allow",
    "accept", "x-request-id", "x-served-by", "location", "refresh",
    "title", "name", "value", "type", "id", "class", "style", "width",
    "height", "url", "src", "href", "target", "rel", "lang", "dir",
    "http-equiv", "property", "itemprop", "scheme", "media", "async",
    "defer", "role", "alt", "srcset", "sizes", "loading", "decoding",
}

# パターンとして採用する最小長（これより短いと誤検知太多）
MIN_PATTERN_LENGTH = 8

# html シグナルからパターンを作る際の最小長（html は誤検知しやすいので長めに）
MIN_HTML_PATTERN_LENGTH = 14

# 1 技術あたり保持するパターン数の上限
MAX_PATTERNS_PER_TECH = 6

# HTML タグ名や meta 属性など、どのページにも現れる語（誤検知の元）
HTML_GENERIC = (
    "og:", "twitter:", "fb:", "itemprop", "http-equiv", "<meta", "<link",
    "<div", "<span", "<a ", "platform", "version", "generator",
    "image", "images", "icon", "favicon", "viewport", "canonical",
    "stylesheet", "javascript", "manifest", "sitemap", "robots.txt",
    "www.", "http", "https", "index.html", "src=", "href=", "class=",
)


def fetch_json(path: str) -> dict:
    url = f"{BASE}{path}"
    request = urllib.request.Request(url, headers={"user-agent": UA})
    with urllib.request.urlopen(request, timeout=90) as resp:
        return json.loads(resp.read().decode("utf-8"))


def regex_to_literal(
    pattern: str,
    *,
    from_html: bool = False,
    min_length: int | None = None,
) -> str | None:
    """Wappalyzer の正規表現を miharun のリテラル部分一致に変換する.

    戻り値が None のときは「使う価値がない（曖昧すぎる／依存表現あり）」。
    from_html=True の場合は html シグナル由来としてより厳しく判定する。
    min_length を渡すと、採用する最小長を上書きする（ヘッダ値は短いため）。
    """
    value = pattern.strip()
    if not value:
        return None
    # バージョンキャプチャや後方参照を含むものは変換できない
    if "\\;" in value or "version:" in value:
        return None

    literal = re.sub(r"\([^)]*\)", "", value)   # (...) を除去
    literal = re.sub(r"\[[^\]]*\]", "", literal)  # [...] を除去
    literal = literal.replace("\\.", ".")
    literal = re.sub(r"[*+?]", "", literal)      # 量指定を外す
    literal = literal.replace("\\^", "").replace("\\$", "")
    literal = literal.replace("\\", "")
    literal = literal.replace("?", "").replace("+", "").replace("*", "")
    literal = literal.replace("^", "").replace("$", "")
    literal = literal.strip()

    lowered = literal.lower()
    if lowered in GENERIC_WORDS:
        return None
    # HTML タグ名や meta 属性など、どのページにも現れる語は除外
    if any(word in lowered for word in HTML_GENERIC):
        return None

    minimum = (
        min_length
        if min_length is not None
        else (MIN_HTML_PATTERN_LENGTH if from_html else MIN_PATTERN_LENGTH)
    )
    if len(literal) < minimum:
        return None
    if not re.search(r"[a-zA-Z]", literal):
        return None
    if literal.startswith("http://") or literal.startswith("https://"):
        literal = literal.split("//", 1)[-1]
        if len(literal) < minimum:
            return None
    return literal


# ヘッダの値は短いことが多い（"nginx" など）ため、本文より短くてよい。
# ただし 1 文字・2 文字では誤検知するため 4 文字を下限にする。
MIN_HEADER_PATTERN_LENGTH = 4


def collect() -> tuple[list[tuple[str, str, str, str, str]], int]:
    """(category, name, pattern, confidence, source) のリストと統計を作る。"""
    results: list[tuple[str, str, str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    skipped_category = 0

    for letter in LETTERS:
        try:
            data = fetch_json(f"{TECH_DIR}{letter}.json")
        except Exception as exc:  # noqa: BLE001
            print(f"  ! {letter}.json を取得できませんでした: {exc}")
            continue

        for name, tech in data.items():
            cats = tech.get("cats") or []
            if not cats:
                continue

            # 採用するカテゴリでなければスキップする
            categories = [c for c in cats if c in CATEGORY_NAMES]
            if not categories:
                skipped_category += 1
                continue
            category = CATEGORY_NAMES[categories[0]]

            body_patterns: list[str] = []

            for src in tech.get("scriptSrc") or []:
                lit = regex_to_literal(src)
                if lit:
                    lowered_lit = lit.lower()
                    # scriptSrc でも HTML 共通語を含むものは弾く
                    if any(word in lowered_lit for word in HTML_GENERIC):
                        continue
                    body_patterns.append(lit)

            for html in tech.get("html") or []:
                lit = regex_to_literal(html, from_html=True)
                if lit:
                    body_patterns.append(lit)

            # headers は「ヘッダ名 → 値の正規表現」の対応表です。
            # ヘッダ名そのもの（Host・platform・Node など）を本文の文字列として
            # 登録してはいけません。"hosting" や "publishing platform"、
            # "parentNode" に誤って一致してしまうためです。
            # 応答ヘッダとだけ突き合わせるため、"ヘッダ名: 値" の形にします。
            header_patterns: list[str] = []
            for header_name, header_value in (tech.get("headers") or {}).items():
                lit = regex_to_literal(
                    header_value, min_length=MIN_HEADER_PATTERN_LENGTH
                )
                if not lit:
                    continue
                lowered_lit = lit.lower()
                if lowered_lit in GENERIC_WORDS:
                    continue
                if not re.search(r"[a-z0-9]", lowered_lit):
                    continue
                if len(lowered_lit) < MIN_HEADER_PATTERN_LENGTH:
                    continue
                header_patterns.append(f"{header_name.lower()}: {lowered_lit}")

            # meta キー（og:image などの HTML 共通語を含むものはここで弾く）
            for key in (tech.get("meta") or {}).keys():
                lowered_key = key.lower()
                if lowered_key in GENERIC_KEYS:
                    continue
                if any(word in lowered_key for word in HTML_GENERIC):
                    continue
                if len(lowered_key) < MIN_HTML_PATTERN_LENGTH:
                    continue
                body_patterns.append(key)

            if not body_patterns and not header_patterns:
                continue

            # 固有性の高い（長い）パターンを優先し、種別ごとに上限で切る
            for source, pool in (
                ("HTTP", body_patterns),
                ("HTTP_HEADER", header_patterns),
            ):
                unique: list[str] = []
                for pattern in pool:
                    key = (source, name, pattern)
                    if key not in seen:
                        seen.add(key)
                        unique.append(pattern)
                for pattern in sorted(unique, key=len, reverse=True)[
                    :MAX_PATTERNS_PER_TECH
                ]:
                    results.append((category, name, pattern, "medium", source))

    return results, skipped_category


def render(rows: list[tuple[str, str, str, str, str]]) -> str:
    lines = [
        '"""Wappalyzer 由来の Web 技術判定ルール（自動生成・手で編集しないこと）.',
        "",
        "出典: https://github.com/enthec/webappanalyzer （MIT ライセンス）",
        "生成: python scripts/build_web_rules.py",
        "",
        "これらのルールは HTTP 応答のみを使うため、`--probe` 指定時のみ有効です。",
        "ブラウザが読み込む HTML の中に眠る指紋を読み取るためのルールです。",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from .rules import Rule",
        "",
        "WEB_RULES: list[Rule] = [",
    ]
    current_category = None
    for category, name, pattern, confidence, source in rows:
        if category != current_category:
            lines.append(f"    # --- {category} ---")
            current_category = category
        escaped = pattern.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(
            f'    Rule("{category}", "{name}", ("{escaped}",), ("{source}",), "{confidence}"),'
        )
    lines.append("]")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    setup_console()
    print("Wappalyzer の署名データを取得しています…")
    rows, skipped = collect()
    categories = {row[0] for row in rows}
    technologies = {row[1] for row in rows}
    print(f"  {len(rows)} 件のルールを生成しました")
    print(f"  対象技術: {len(technologies)} 種類 / カテゴリ: {len(categories)} 種類")
    print(f"  カテゴリ対象外でスキップ: {skipped} 技術")

    out_path = ROOT / "src" / "miharun" / "rules_web.py"
    out_path.write_text(render(rows), encoding="utf-8")
    print(f"  {out_path} に出力しました。")


if __name__ == "__main__":
    main()