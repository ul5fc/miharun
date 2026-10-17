"""日本語の HTML レポートを組み立てる（1 ファイル完結・依存なし）.

デザイン方針は、次のギャラリー群の実測から決めています。

* details.so / 60fps.design … dark 対応、半径 8–20px と 9999px のピル
* curated.design … dark + gradient + backdrop-filter
* typeui.sh … 濃い ink 色のアクセント、多彩なステータス色
* glass.samasante.com … 淡い青のアクセント
* supahero.io … カラフルなチャンク

CSS 変数で 1 箇所にまとめ、`prefers-color-scheme` でライト/ダークを切り替えます。
"""

from __future__ import annotations

from html import escape

from . import __repository__
from .fingerprint import summarize
from .models import SurfaceReport, risk_level

MAX_HOST_ROWS = 500


# ----------------------------------------------------------------------
# スタイル（CSS 変数でテーマを定義）
# ----------------------------------------------------------------------

STYLE = """
*,*::before,*::after { box-sizing: border-box; }

:root {
  color-scheme: light dark;

  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Hiragino Sans",
    "Noto Sans JP", "Yu Gothic UI", Meiryo, system-ui, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
    "Liberation Mono", monospace;

  /* ライト（既定） */
  --bg: #fbfbfd;
  --bg-soft: #f4f5f7;
  --surface: #ffffff;
  --surface-2: #fafbfc;
  --ink: #16181d;
  --ink-2: #3d4451;
  --muted: #6b7280;
  --line: #e4e7ec;
  --line-2: #eef0f3;

  --accent: #2f6df6;
  --accent-soft: #eaf1ff;
  --accent-ink: #1a49b8;

  --ok: #0f9d58;
  --ok-soft: #e6f6ed;
  --warn: #c2410c;
  --warn-soft: #fff2e8;
  --warn-line: #f6c9a8;
  --info: #0369a1;
  --info-soft: #e6f4fb;
  --info-line: #a9d8ef;
  --note: #52525b;
  --note-soft: #f4f4f5;

  --r-sm: 8px;
  --r-md: 12px;
  --r-lg: 20px;
  --r-pill: 9999px;

  --shadow-1: 0 1px 2px rgba(16,24,40,.05);
  --shadow-2: 0 6px 20px -6px rgba(16,24,40,.14), 0 2px 6px rgba(16,24,40,.05);
  --shadow-3: 0 18px 44px -18px rgba(16,24,40,.28);

  --maxw: 1080px;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0b0d11;
    --bg-soft: #10131a;
    --surface: #151922;
    --surface-2: #1b2029;
    --ink: #e8ebf1;
    --ink-2: #c3cad8;
    --muted: #8b94a7;
    --line: #262c38;
    --line-2: #1e2430;

    --accent: #6ea3ff;
    --accent-soft: #16233d;
    --accent-ink: #a9c7ff;

    --ok: #4ade80;
    --ok-soft: #10251a;
    --warn: #fbbf6e;
    --warn-soft: #2a1d0f;
    --warn-line: #5a3f1d;
    --info: #7dd3fc;
    --info-soft: #0d2029;
    --info-line: #1d4459;
    --note: #b6bdc9;
    --note-soft: #191d25;

    --shadow-1: 0 1px 2px rgba(0,0,0,.4);
    --shadow-2: 0 8px 24px -8px rgba(0,0,0,.6);
    --shadow-3: 0 24px 60px -24px rgba(0,0,0,.75);
  }
}

html { scroll-behavior: smooth; }

section[id] { scroll-margin-top: 18px; }

.jump {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 14px;
}
.jump a {
  font-size: 12.5px;
  text-decoration: none;
  color: var(--fg-dim);
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 4px 11px;
  transition: color .15s ease, border-color .15s ease;
}
.jump a:hover { color: var(--fg); border-color: var(--accent); }

body {
  margin: 0;
  background:
    radial-gradient(1100px 520px at 12% -8%, color-mix(in oklab, var(--accent) 12%, transparent), transparent 62%),
    radial-gradient(900px 460px at 92% 0%, color-mix(in oklab, var(--info) 10%, transparent), transparent 60%),
    var(--bg);
  color: var(--ink);
  font-family: var(--font-sans);
  font-size: 15px;
  line-height: 1.8;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

/* うっすらしたグリッド（texture） */
body::before {
  content: "";
  position: fixed; inset: 0;
  background-image:
    linear-gradient(to right, color-mix(in oklab, var(--line) 55%, transparent) 1px, transparent 1px),
    linear-gradient(to bottom, color-mix(in oklab, var(--line) 55%, transparent) 1px, transparent 1px);
  background-size: 56px 56px;
  mask-image: radial-gradient(ellipse 120% 70% at 50% 0%, #000 20%, transparent 78%);
  -webkit-mask-image: radial-gradient(ellipse 120% 70% at 50% 0%, #000 20%, transparent 78%);
  pointer-events: none;
  z-index: 0;
}

.wrap { position: relative; z-index: 1; max-width: var(--maxw); margin: 0 auto; padding: 40px 20px 88px; }

/* ---------- ヘッダー ---------- */

header.top {
  border: 1px solid var(--line);
  border-radius: var(--r-lg);
  background: color-mix(in oklab, var(--surface) 78%, transparent);
  backdrop-filter: blur(14px) saturate(150%);
  -webkit-backdrop-filter: blur(14px) saturate(150%);
  box-shadow: var(--shadow-2);
  padding: 28px 28px 24px;
  position: relative;
  overflow: hidden;
}

.eyebrow {
  display: inline-flex; align-items: center; gap: 8px;
  font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase;
  color: var(--accent-ink);
  background: var(--accent-soft);
  border: 1px solid color-mix(in oklab, var(--accent) 24%, transparent);
  border-radius: var(--r-pill);
  padding: 5px 12px;
}

.dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }

h1 {
  font-size: clamp(26px, 4.4vw, 38px);
  line-height: 1.28;
  letter-spacing: -.015em;
  margin: 16px 0 6px;
  word-break: break-all;
}

.target-line {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--muted);
  word-break: break-all;
}

.meta-row {
  display: flex; flex-wrap: wrap; gap: 8px;
  margin-top: 18px; padding-top: 16px;
  border-top: 1px dashed var(--line);
}

.chip {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 12.5px; color: var(--ink-2);
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: var(--r-pill);
  padding: 4px 12px;
}

/* ---------- セクション ---------- */

section { margin-top: 34px; }

h2 {
  display: flex; align-items: center; gap: 10px;
  font-size: 13px; font-weight: 700;
  letter-spacing: .09em; text-transform: uppercase;
  color: var(--muted);
  margin: 0 0 14px;
}

h2::after {
  content: ""; flex: 1; height: 1px;
  background: linear-gradient(to right, var(--line), transparent);
}

.card {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: var(--r-lg);
  box-shadow: var(--shadow-1);
  padding: 22px 24px;
}

/* ---------- 統計（ Bento ） ---------- */

.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-top: 16px;
}

.stat {
  position: relative;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: var(--r-md);
  padding: 16px 18px 14px;
  box-shadow: var(--shadow-1);
  overflow: hidden;
  transition: transform .18s ease, box-shadow .18s ease;
}

.stat:hover { transform: translateY(-2px); box-shadow: var(--shadow-2); }

/* 5年以上公開され続けているホスト */
.old { color: var(--warn); font-weight: 700; }

.stat::after {
  content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
  background: var(--accent); opacity: .85;
}

.stat.warn::after { background: var(--warn); }
.stat.ok::after { background: var(--ok); }

.stat .n {
  font-size: 30px; font-weight: 700; letter-spacing: -.02em;
  line-height: 1.1; font-variant-numeric: tabular-nums;
}

.stat .k { font-size: 12.5px; color: var(--muted); margin-top: 4px; }

/* ---------- 表 ---------- */

.table-scroll {
  overflow-x: auto;
  border: 1px solid var(--line);
  border-radius: var(--r-lg);
  background: var(--surface);
  box-shadow: var(--shadow-1);
  -webkit-overflow-scrolling: touch;
}

table { border-collapse: collapse; width: 100%; font-size: 13.5px; }

thead th {
  position: sticky; top: 0; z-index: 2;
  background: var(--surface-2);
  color: var(--muted);
  font-size: 11.5px; font-weight: 700;
  letter-spacing: .06em; text-transform: uppercase;
  text-align: left;
  padding: 12px 14px;
  border-bottom: 1px solid var(--line);
  white-space: nowrap;
}

tbody td {
  padding: 11px 14px;
  border-bottom: 1px solid var(--line-2);
  vertical-align: top;
}

tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--surface-2); }

td code, .mono { font-family: var(--font-mono); font-size: 12.5px; }
td code { word-break: break-all; }

td.num { font-variant-numeric: tabular-nums; color: var(--muted); white-space: nowrap; }

/* ---------- 定義リスト ---------- */

dl.kv { display: grid; grid-template-columns: auto 1fr; gap: 0; margin: 0; }
dl.kv > dt {
  padding: 11px 20px 11px 0;
  color: var(--muted); font-size: 13px;
  border-bottom: 1px solid var(--line-2);
  white-space: nowrap;
}
dl.kv > dd {
  margin: 0; padding: 11px 0;
  border-bottom: 1px solid var(--line-2);
  word-break: break-word;
}
dl.kv > dt:last-of-type, dl.kv > dd:last-of-type { border-bottom: none; }

/* ---------- タグ ---------- */

.tag-group + .tag-group { margin-top: 16px; }

.tag-label {
  font-size: 11.5px; font-weight: 700; letter-spacing: .06em;
  color: var(--muted); text-transform: uppercase;
  margin-bottom: 8px;
}

.tags { display: flex; flex-wrap: wrap; gap: 7px; }

.tag {
  display: inline-flex; align-items: center; gap: 7px;
  font-size: 13px; font-weight: 500;
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: var(--r-pill);
  padding: 5px 13px;
}

.tag .conf {
  font-family: var(--font-mono); font-size: 10.5px;
  color: var(--muted);
  background: var(--bg-soft);
  border-radius: var(--r-pill);
  padding: 1px 7px;
}

/* ---------- 所見 ---------- */

.finding {
  border: 1px solid var(--line);
  border-left-width: 3px;
  border-radius: var(--r-md);
  background: var(--surface);
  padding: 15px 18px;
  margin-bottom: 10px;
  box-shadow: var(--shadow-1);
}

.finding .h {
  display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap;
  font-weight: 700; font-size: 15px;
}

.finding .p {
  margin-top: 6px; font-size: 13.5px; color: var(--ink-2);
}

.finding.warn    { border-left-color: var(--warn); background: var(--warn-soft); }
.finding.notice  { border-left-color: var(--note); background: var(--note-soft); }
.finding.info    { border-left-color: var(--info); background: var(--info-soft); }

/* ---------- 危険度スコア ---------- */

.risk-box { margin-bottom: 14px; }

.risk-head { display: flex; align-items: center; gap: 18px; }

.risk-num {
  font-size: 46px; font-weight: 800; line-height: 1;
  letter-spacing: -.03em; font-variant-numeric: tabular-nums;
  color: var(--ok);
}
.risk-num.low      { color: var(--ok); }
.risk-num.medium   { color: var(--warn); }
.risk-num.high     { color: var(--warn); }
.risk-num.critical { color: #dc2626; }

.risk-label { font-size: 12px; color: var(--muted); letter-spacing: .05em; }
.risk-level {
  font-size: 19px; font-weight: 700;
}
.risk-level.low      { color: var(--ok); }
.risk-level.medium   { color: var(--warn); }
.risk-level.high     { color: var(--warn); }
.risk-level.critical { color: #dc2626; }

.risk-bar {
  height: 10px; border-radius: var(--r-pill);
  background: var(--bg-soft);
  overflow: hidden; margin-top: 16px;
  border: 1px solid var(--line);
}

.risk-fill { display: block; height: 100%; border-radius: var(--r-pill); transition: width .4s ease; }
.risk-fill.low      { background: linear-gradient(to right, #34d399, #10b981); }
.risk-fill.medium   { background: linear-gradient(to right, #fbbf24, #f59e0b); }
.risk-fill.high     { background: linear-gradient(to right, #fb923c, #ea580c); }
.risk-fill.critical { background: linear-gradient(to right, #f87171, #dc2626); }

.badge.score {
  color: var(--ink-2);
  background: var(--surface);
  font-family: var(--font-mono);
}

.badge {
  flex: none;
  font-size: 10.5px; font-weight: 700; letter-spacing: .06em;
  text-transform: uppercase;
  border-radius: var(--r-pill);
  padding: 3px 9px;
  border: 1px solid currentColor;
}

.badge.warn   { color: var(--warn); }
.badge.notice { color: var(--note); }
.badge.info   { color: var(--info); }

ul.plain { margin: 0; padding-left: 20px; }
ul.plain li { margin: 4px 0; color: var(--ink-2); }

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.disclaimer {
  margin-top: 26px;
  border: 1px solid var(--warn-line);
  border-radius: var(--r-md);
  background: var(--warn-soft);
  padding: 16px 18px;
  font-size: 13px;
  color: var(--ink-2);
}

.disclaimer strong { color: var(--ink); }

footer {
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--line);
  color: var(--muted);
  font-size: 12.5px;
  display: flex; flex-wrap: wrap; gap: 8px 20px; justify-content: space-between;
}

@media (max-width: 720px) {
  .wrap { padding: 22px 14px 60px; }
  header.top { padding: 22px 18px 18px; }
  .card, .table-scroll { border-radius: var(--r-md); }
  h2 { font-size: 12px; }
  body { font-size: 14.5px; }
}

@media print {
  body { background: #fff; }
  body::before { display: none; }
  .wrap { max-width: none; padding: 0; }
  header.top, .card, .stat, .table-scroll, .finding {
    box-shadow: none; break-inside: avoid;
  }
}
"""


# ----------------------------------------------------------------------
# レンダリング
# ----------------------------------------------------------------------

def render_html(report: SurfaceReport, technologies: list[tuple[str, str, str]]) -> str:
    e = escape
    target = report.domain or report.target

    head: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="ja">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{e(target)} の外部公開マップ — miharun</title>",
        '<meta name="robots" content="noindex, nofollow">',
        '<meta name="color-scheme" content="light dark">',
        f"<style>{STYLE}</style>",
        "</head>",
        f'<body><div class="wrap">',
    ]

    _header(head, report, e)
    _stats(head, report, e)
    _organization(head, report, e)
    _technologies(head, technologies, e)
    _findings(head, report, e)
    _hosts(head, report, e)
    _dns(head, report, e)
    _sources(head, report, e)
    _footer(head, e)

    head.extend(["</div></body></html>"])
    return "\n".join(head)


def _header(parts: list[str], report: SurfaceReport, e) -> None:
    parts.append('<header class="top">')
    parts.append(
        '<span class="eyebrow"><span class="dot"></span>miharun report</span>'
    )
    parts.append(f"<h1>{e(target_of(report))}</h1>")
    parts.append(f'<p class="target-line">調査対象: {e(report.target)}</p>')

    stamp = report.generated_at.strftime("%Y-%m-%d %H:%M")
    chips = [
        f'<span class="chip">生成 {e(stamp)} JST</span>',
        f'<span class="chip">入力 {e("ドメイン" if report.input_kind == "domain" else "企業名")}</span>',
        '<span class="chip">パッシブ調査（対象への通信なし）</span>',
    ]
    parts.append(f'<div class="meta-row">{"".join(chips)}</div>')
    parts.append(
        '<nav class="jump">'
        '<a href="#summary">概要</a>'
        '<a href="#technologies">技術</a>'
        '<a href="#findings">危険度</a>'
        '<a href="#hosts">ホスト一覧</a>'
        '<a href="#dns">DNS</a>'
        '<a href="#sources">情報源</a>'
        "</nav>"
    )
    parts.append("</header>")
    parts.append('<section id="summary">')


def target_of(report: SurfaceReport) -> str:
    return report.domain or report.target


def _stats(parts: list[str], report: SurfaceReport, e) -> None:
    risk = report.overall_risk
    lvl = risk_level(risk)
    kind = {"low": "ok", "medium": "warn", "high": "warn", "critical": "warn"}[lvl]
    stats = [
        ("危険度スコア", risk, kind),
        ("ホスト", len(report.hosts), ""),
        ("解決できたホスト", len(report.live_hosts), "ok"),
        ("推定した技術", len(report.technologies), ""),
        ("気づいた点", len(report.findings), "warn" if report.findings else "ok"),
    ]
    parts.append('<div class="stats">')
    for label, value, kind in stats:
        cls = f"stat {kind}".strip()
        parts.append(
            f'<div class="{cls}"><div class="n">{value}</div>'
            f'<div class="k">{e(label)}</div></div>'
        )
    parts.append("</div>")
    parts.append("</section>")


def _organization(parts: list[str], report: SurfaceReport, e) -> None:
    if report.organization is None:
        return
    org = report.organization
    rows = [
        (label, value)
        for label, value in (
            ("法人名", org.name),
            ("法人番号", org.corporate_number),
            ("所在地", org.location),
            ("公式サイト", org.website),
            ("出典", org.source),
        )
        if value
    ]
    if not rows:
        return
    body = "".join(
        f"<dt>{e(label)}</dt><dd>{e(str(value))}</dd>" for label, value in rows
    )
    parts.append('<section id="organization">')
    parts.append("<h2>法人情報</h2>")
    parts.append(f'<div class="card"><dl class="kv">{body}</dl></div>')
    parts.append("</section>")


def _technologies(parts: list[str], technologies: list[tuple[str, str, str]], e) -> None:
    parts.append('<section id="technologies">')
    parts.append("<h2>推定される技術</h2>")

    if not technologies:
        parts.append('<div class="card"><p class="muted">特定できませんでした。</p></div>')
        parts.append("</section>")
        return

    label = {"high": "high", "medium": "med", "low": "low"}
    for category, names in summarize(technologies).items():
        tags = "".join(
            f'<span class="tag">{e(name)}'
            f'<span class="conf">{e(label.get(confidence, "?"))}</span></span>'
            for cat, name, confidence in technologies
            if cat == category
        )
        parts.append('<div class="card tag-group">')
        parts.append(f'<div class="tag-label">{e(category)}</div>')
        parts.append(f'<div class="tags">{tags}</div>')
        parts.append("</div>")

    parts.append(
        '<p class="muted" style="font-size:12.5px;margin-top:10px">'
        "※ DNS レコードの文字列一致による推定です。実際と異なる場合があります。"
        "</p>"
    )
    parts.append("</section>")


def _findings(parts: list[str], report: SurfaceReport, e) -> None:
    parts.append('<section id="findings">')
    parts.append("<h2>危険度と気づいた点</h2>")

    risk = report.overall_risk
    level_name = {"critical": "重大", "high": "高", "medium": "中", "low": "低"}
    lvl = risk_level(risk)
    parts.append('<div class="card risk-box">')
    parts.append(
        f'<div class="risk-head"><span class="risk-num {lvl}">{risk}</span>'
        f'<div><div class="risk-label">総合危険度スコア</div>'
        f'<div class="risk-level {lvl}">{e(level_name.get(lvl, "低"))}</div></div></div>'
    )
    pct = max(0, min(100, risk))
    parts.append(
        f'<div class="risk-bar"><span class="risk-fill {lvl}" '
        f'style="width:{pct}%"></span></div>'
    )
    parts.append(
        '<p class="muted" style="font-size:12.5px;margin:12px 0 0">'
        "スコアは miharun の推定値です。検出された所見のうち最も危険度の高い"
        "ものを全体スコアとして採用しています。</p>"
    )
    parts.append("</div>")

    if not report.findings:
        parts.append(
            '<div class="card"><p class="muted">'
            "特に注意を要する点は見つかりませんでした。</p></div>"
        )
        parts.append("</section>")
        return

    labels = {"warn": "要確認", "notice": "参考", "info": "情報"}
    ordered = sorted(report.findings, key=lambda f: (-f.score, f.level != "warn"))
    for finding in ordered:
        level = finding.level if finding.level in labels else "info"
        badge = f'<span class="badge {level}">{e(labels[level])}</span>'
        if finding.score:
            badge += f' <span class="badge score">{finding.score}</span>'
        parts.append(f'<div class="finding {level}">')
        parts.append(f'<div class="h">{badge}<span>{e(finding.title)}</span></div>')
        if finding.host:
            parts.append(f'<div class="p mono">{e(finding.host)}</div>')
        if finding.detail:
            parts.append(f'<div class="p">{e(finding.detail)}</div>')
        parts.append("</div>")
    parts.append("</section>")


def _hosts(parts: list[str], report: SurfaceReport, e) -> None:
    parts.append('<section id="hosts">')
    parts.append("<h2>ホスト一覧</h2>")

    if not report.hosts:
        parts.append('<div class="card"><p class="muted">見つかりませんでした。</p></div>')
        parts.append("</section>")
        return

    parts.append('<div class="table-scroll">')
    parts.append("<table>")
    parts.append(
        "<thead><tr><th>ホスト</th><th>状態</th><th>露出年数</th><th>アドレス</th>"
        "<th>逆引き</th><th>技術の手がかり</th></tr></thead><tbody>"
    )
    for host in report.hosts[:MAX_HOST_ROWS]:
        if host.http_status is not None:
            state = f"HTTP {host.http_status}"
        elif host.addresses:
            state = "解決可"
        else:
            state = "—"
        years = host.exposure_years
        if years is None:
            exposure = '<span class="muted">—</span>'
        elif years >= 5:
            exposure = f'<strong class="old">{years} 年</strong>'
        else:
            exposure = f'{years} 年'
        parts.append(
            "<tr>"
            f'<td><code>{e(host.host)}</code></td>'
            f'<td class="num">{e(state)}</td>'
            f'<td class="num">{exposure}</td>'
            f'<td class="mono"><code>{e(", ".join(host.addresses[:2]) or "—")}</code></td>'
            f'<td class="mono"><code>{e(", ".join(host.reverse[:1]) or "—")}</code></td>'
            f'<td class="mono"><code>{e(", ".join(host.technologies[:3]) or "—")}</code></td>'
            "</tr>"
        )
    parts.append("</tbody></table>")
    parts.append(
        '<p class="muted" style="padding:10px 14px 0">'
        "露出年数は証明書透明性ログの記録（証明書の最初の発行日）基準です。</p>"
    )
    if len(report.hosts) > MAX_HOST_ROWS:
        parts.append(
            f'<p class="muted" style="padding:10px 14px">先頭 {MAX_HOST_ROWS} 件のみ表示。</p>'
        )
    parts.append("</div>")
    parts.append("</section>")


def _dns(parts: list[str], report: SurfaceReport, e) -> None:
    order = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR")
    groups: list[tuple[str, list[str]]] = []
    for rtype in order:
        values = report.apex.get(rtype) or []
        if values:
            groups.append((rtype, values))

    if not groups:
        return

    parts.append('<section id="dns">')
    parts.append("<h2>DNS レコード（頂点ドメイン）</h2>")
    parts.append('<div class="table-scroll"><table><tbody>')
    for rtype, values in groups:
        for index, value in enumerate(values[:20]):
            first = index == 0
            parts.append(
                "<tr>"
                f'<td class="num" style="width:84px;vertical-align:top">'
                f"{e(rtype)}</td>"
                f'<td class="mono"><code>{e(value)}</code></td>'
                "</tr>"
            )
    parts.append("</tbody></table></div>")
    parts.append("</section>")


def _sources(parts: list[str], report: SurfaceReport, e) -> None:
    parts.append('<section id="sources">')
    parts.append("<h2>情報源</h2>")
    parts.append('<div class="card">')
    parts.append('<ul class="plain">')
    for source in report.sources:
        parts.append(f"<li>{e(source)}</li>")
    parts.append("</ul>")

    if report.errors:
        parts.append('<p class="muted" style="margin-top:12px">取得できなかった情報:</p>')
        parts.append('<ul class="plain">')
        for error in report.errors:
            parts.append(f'<li style="color:var(--warn)">{e(error)}</li>')
        parts.append("</ul>")

    parts.append(
        '<div class="disclaimer"><strong>重要</strong><br>'
        "このレポートは推定を含みます。重要な判断の前に、必ず一次情報を"
        "確認してください。自分の資産、または許可を得た対象に対してのみ"
        "使用してください。</div>"
    )
    parts.append("</div>")
    parts.append("</section>")

    _footer(parts, e)


def _footer(parts: list[str], e) -> None:
    parts.append(
        "<footer>"
        "<span>このレポートは <strong>miharun</strong> で生成しました。"
        f'<a href="{e(__repository__)}">GitHub</a></span>'
        "<span>パッシブ調査 / 推定情報を含む</span>"
        "</footer>"
    )