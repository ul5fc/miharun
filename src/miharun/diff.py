"""前回結果との比較（変化検知）.

セキュリティ確認で本当に効くのは「一度見ただけ」ではなく
「前回と比べて何か増えていないか」を定期的に回すことです。

    miharun example.com --json --out baseline
    （1週間後）
    miharun example.com --json --diff

--diff は前回の JSON を読みhosts と危険度を比較し、
「新增された」「消えた」「危険度が増えた」を表示します。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .models import SurfaceReport


def load_snapshot(path: Path) -> Optional[dict]:
    """前回のレポート JSON を読み込む（無ければ None）. """
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def find_snapshot(out_dir: Path, domain: str) -> Path:
    return out_dir / f"miharun-{domain}-report.json"


def compare(previous: dict, current: SurfaceReport) -> dict:
    """前回と今回を比較する（純関数）.

    戻り値:
        {
          "new_hosts":     [...],   # 新たに現れたホスト
          "gone_hosts":    [...],   # 消えたホスト
          "new_risks":     [...],   # 新たに検出された危険度
          "resolved_risks":[...],   # 解消された危険度
          "risk_delta":    int,     # 危険度スコアの増減
          "tech_added":    [...],
          "tech_removed":  [...],
        }
    """
    prev_hosts = {h.get("host") for h in previous.get("hosts", [])}
    curr_hosts = {h.host for h in current.hosts}
    prev_tech = {t["name"] for t in previous.get("technologies", [])}
    # report.technologies は (category, name) の 2 要素タプル
    curr_tech = {name for _category, name in current.technologies}

    def risk_key(finding):
        return (finding.host or "", finding.title)

    prev_risks = {
        risk_key(f) for f in (
            _finding_from_dict(d) for d in previous.get("findings", [])
        ) if f.score > 0
    }
    curr_risks = {risk_key(f) for f in current.findings if f.score > 0}

    prev_score = max(
        (f.get("score", 0) for f in previous.get("findings", [])), default=0
    )

    def to_pairs(keys):
        return sorted(f"{host} — {title}" for host, title in keys)

    return {
        "new_hosts": sorted(curr_hosts - prev_hosts),
        "gone_hosts": sorted(prev_hosts - curr_hosts),
        "new_risks": to_pairs(curr_risks - prev_risks),
        "resolved_risks": to_pairs(prev_risks - curr_risks),
        "risk_delta": current.overall_risk - prev_score,
        "tech_added": sorted(curr_tech - prev_tech),
        "tech_removed": sorted(prev_tech - curr_tech),
    }


def _finding_from_dict(data: dict):
    """JSON の dict から Finding を作る（比較用）."""
    from .models import Finding

    return Finding(
        level=data.get("level", "info"),
        title=data.get("title", ""),
        detail=data.get("detail", ""),
        score=data.get("score", 0),
        host=data.get("host", ""),
    )


def render_diff_markdown(diff: dict, domain: str) -> str:
    """比較結果を Markdown にする."""
    lines = [f"# {domain} の変化検知レポート", ""]
    lines.append(f"総合危険度スコアの変化: **{diff['risk_delta']:+,}**")
    lines.append("")

    sections = (
        ("新增されたホスト", diff["new_hosts"], "+"),
        ("消えたホスト", diff["gone_hosts"], "-"),
        ("新たに検出された危険度", diff["new_risks"], "!"),
        ("解消された危険度", diff["resolved_risks"], "ok"),
        ("新しく検出された技術", diff["tech_added"], "+"),
        ("検出されなくなった技術", diff["tech_removed"], "-"),
    )

    any_change = False
    for title, items, mark in sections:
        if not items:
            continue
        any_change = True
        lines.append(f"## {title}（{len(items)} 件）")
        lines.append("")
        for item in items[:100]:
            lines.append(f"- `{item}`")
        if len(items) > 100:
            lines.append(f"- …ほか {len(items) - 100} 件")
        lines.append("")

    if not any_change:
        lines.append("**前回からの変化は検出されませんでした。**")
        lines.append("")

    return "\n".join(lines)