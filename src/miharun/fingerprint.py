"""DNS レコードと HTTP 応答から「使っている技術」を推定する.

ルールは rules.py（DNS ベース・手書き）と rules_web.py（Wappalyzer 由来・
HTTP ベース・自動生成）にあります。

ネットワークに触れないため、単体テストの対象にできます。

ルールの総数が 2,000 を超えるため、単純な線形走査では遅くなります。
そこでレコード種別ごとにルールを索引化し、正規表現のコンパイル結果は
matching モジュールのキャッシュで使い回します。
"""

from __future__ import annotations

from functools import lru_cache

from .matching import matches
from .rules import CONFIDENCE_ORDER, Rule, all_categories
from .rules import RULES as _BASE_RULES

# 統合済みの全ルール（rules.py で WEB_RULES が追加されている）
_ALL_RULES = _BASE_RULES


@lru_cache(maxsize=1)
def _rules_by_source() -> dict[str, list[Rule]]:
    """レコード種別ごとに、その種別だけを見るルールを索引化（キャッシュ）."""
    index: dict[str, list[Rule]] = {}
    for rule in _ALL_RULES:
        for source in rule.sources:
            index.setdefault(source.upper(), []).append(rule)
    return index


@lru_cache(maxsize=1)
def _category_order() -> dict[str, int]:
    order = {category: i for i, category in enumerate(all_categories())}
    return order


def match_rule(rule: Rule, value: str) -> bool:
    """1 つのレコード値がルールに一致するか（純関数）."""
    lowered = value.lower()
    return any(matches(lowered, pattern) for pattern in rule.patterns)


def detect(records: dict[str, list[str]]) -> list[tuple[str, str, str]]:
    """レコードの集合から技術を推定する.

    引数:
        records: {"NS": [...], "MX": [...], "TXT": [...], "HTTP": [...], ...}

    戻り値:
        [(カテゴリ, 技術名, 確度), ...] をカテゴリ順・名前順に返す。
        同じ技術が複数のレコードから見つかった場合は最も高い確度を採用する。
    """
    hits: dict[tuple[str, str], str] = {}
    rules_by_source = _rules_by_source()

    for source, values in records.items():
        if not values:
            continue
        candidates = rules_by_source.get(source.upper())
        if not candidates:
            continue

        for value in values:
            lowered = str(value).lower()
            for rule in candidates:
                # そのレコードがこのルールのパターンに一致するか
                if not any(matches(lowered, pattern) for pattern in rule.patterns):
                    continue

                key = (rule.category, rule.name)
                previous = hits.get(key)
                if previous is None or (
                    CONFIDENCE_ORDER.get(rule.confidence, 0)
                    > CONFIDENCE_ORDER.get(previous, 0)
                ):
                    hits[key] = rule.confidence

    order = _category_order()
    ordered = sorted(
        hits.items(),
        key=lambda item: (order.get(item[0][0], 99), item[0][1]),
    )
    return [(category, name, confidence) for (category, name), confidence in ordered]


def summarize(technologies: list[tuple[str, str, str]]) -> dict[str, list[str]]:
    """カテゴリごとにまとめた辞書にする（レポート表示用）."""
    summary: dict[str, list[str]] = {}
    for category, name, _confidence in technologies:
        summary.setdefault(category, [])
        if name not in summary[category]:
            summary[category].append(name)
    return summary


def rule_count() -> int:
    """登録されているルール数（統計表示用）."""
    return len(_ALL_RULES)