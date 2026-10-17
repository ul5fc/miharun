"""日本語の Markdown レポートを組み立てる."""

from __future__ import annotations

from . import __repository__
from .fingerprint import summarize
from .models import SurfaceReport

MAX_HOST_ROWS = 120  # 表が長くなりすぎないようにする


def render_markdown(report: SurfaceReport, technologies: list[tuple[str, str, str]]) -> str:
    lines: list[str] = []

    title_target = report.domain or report.target
    lines.append(f"# {title_target} の外部公開マップ")
    lines.append("")
    lines.append(
        f"生成日時: {report.generated_at.strftime('%Y-%m-%d %H:%M')} (JST)  "
        f"／ 調査対象: `{report.target}`"
    )
    lines.append("")
    lines.append(
        "> このレポートは公開情報（証明書透明性ログ・DNS・公開 API）のみから作成した推定です。"
    )
    lines.append(
        "> 対象サイトへの能動的な調査は行っていません。内容は事実と異なる場合があります。"
    )
    lines.append("")

    _section_summary(lines, report)
    _section_technologies(lines, technologies)
    _section_dns(lines, report)
    _section_hosts(lines, report)
    _section_findings(lines, report)
    _section_sources(lines, report)
    _section_footer(lines)

    return "\n".join(lines).rstrip() + "\n"


def _section_summary(lines: list[str], report: SurfaceReport) -> None:
    lines.append("## 概要")
    lines.append("")
    lines.append("| 項目 | 内容 |")
    lines.append("|---|---|")

    if report.organization is not None:
        org = report.organization
        if org.name:
            lines.append(f"| 法人名 | {org.name} |")
        if org.corporate_number:
            lines.append(f"| 法人番号 | {org.corporate_number} |")
        if org.location:
            lines.append(f"| 所在地 | {org.location} |")
        if org.website:
            lines.append(f"| 公式サイト | {org.website} |")
        if org.source:
            lines.append(f"| 法人情報の出典 | {org.source} |")

    lines.append(f"| 調査したドメイン | `{report.domain or '(不明)'}` |")
    lines.append(f"| 見つかったホスト数 | {len(report.hosts)} 件 |")
    lines.append(f"| 名前解決できたホスト数 | {len(report.live_hosts)} 件 |")
    lines.append("")


def _section_technologies(lines: list[str], technologies: list[tuple[str, str, str]]) -> None:
    lines.append("## 推定される技術")
    lines.append("")
    if not technologies:
        lines.append("DNS レコードからは、これといった技術を特定できませんでした。")
        lines.append("")
        return

    label = {"high": "高", "medium": "中", "low": "低"}
    summary = summarize(technologies)
    for category, names in summary.items():
        lines.append(f"**{category}**")
        lines.append("")
        for category_name, name, confidence in technologies:
            if category_name != category:
                continue
            lines.append(f"- {name}（確度: {label.get(confidence, confidence)}）")
        lines.append("")

    lines.append(
        "> 判定は DNS レコードの文字列一致による推定です。"
        "同じサービスを使っていても判定を誤ることがあります。"
    )
    lines.append("")


def _section_dns(lines: list[str], report: SurfaceReport) -> None:
    lines.append("## DNS レコード（頂点ドメイン）")
    lines.append("")
    order = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR")
    wrote_any = False
    for rtype in order:
        values = report.apex.get(rtype) or []
        if not values:
            continue
        wrote_any = True
        lines.append(f"**{rtype}**")
        lines.append("")
        for value in values[:20]:
            lines.append(f"- `{value}`")
        if len(values) > 20:
            lines.append(f"- …ほか {len(values) - 20} 件")
        lines.append("")
    if not wrote_any:
        lines.append("DNS レコードを取得できませんでした。")
        lines.append("")


def _section_hosts(lines: list[str], report: SurfaceReport) -> None:
    lines.append("## ホスト一覧")
    lines.append("")
    if not report.hosts:
        lines.append("サブドメインは見つかりませんでした。")
        lines.append("")
        return

    lines.append("| ホスト | 状態 | 露出年数 | アドレス | 逆引き | 技術の手がかり |")
    lines.append("|---|---|---|---|---|---|")
    for host in report.hosts[:MAX_HOST_ROWS]:
        if host.http_status is not None:
            state = f"HTTP {host.http_status}"
        elif host.addresses:
            state = "解決可"
        else:
            state = "—"
        years = host.exposure_years
        exposure = f"{years} 年" if years is not None else "—"
        if years is not None and years >= 5:
            exposure = f"**{years} 年**"
        address = ", ".join(host.addresses[:2]) or "—"
        reverse = ", ".join(host.reverse[:1]) or "—"
        tech = ", ".join(host.technologies[:3]) or "—"
        lines.append(
            f"| `{host.host}` | {state} | {exposure} | {address} | {reverse} | {tech} |"
        )

    lines.append("")
    lines.append(
        "> 露出年数は証明書透明性ログの記録（証明書の最初の発行日）基準です。"
        "その証明書が発行された時点から、少なくともそのホストは公開されています。"
    )

    remaining = len(report.hosts) - MAX_HOST_ROWS
    if remaining > 0:
        lines.append("")
        lines.append(f"※ 表は先頭 {MAX_HOST_ROWS} 件のみ表示しています（残り {remaining} 件）。")
    lines.append("")


def _section_findings(lines: list[str], report: SurfaceReport) -> None:
    risk = report.overall_risk
    lines.append("## 危険度と気づいた点")
    lines.append("")

    # --- 総合危険度スコア ---
    if risk > 0:
        bar = "#" * min(20, max(1, round(risk / 5)))
        lines.append(f"**総合危険度スコア: {risk} / 100**")
        lines.append("")
        lines.append(f"```\n{bar:<20} {risk:>3}\n```")
        lines.append("")
    else:
        lines.append("**総合危険度スコア: 0 / 100**（検出された所見はありません）")
        lines.append("")

    if not report.findings:
        lines.append("特に注意を要する点は見つかりませんでした。")
        lines.append("")
        return

    # スコアの高い順に並べる
    ordered = sorted(
        report.findings, key=lambda f: (-f.score, f.level != "warn")
    )
    mark = {"warn": "⚠ **[要確認]**", "notice": "・参考", "info": "・情報"}
    for finding in ordered:
        score_badge = f"（危険度 {finding.score}）" if finding.score else ""
        lines.append(f"### {mark.get(finding.level, '')} {finding.title}{score_badge}")
        lines.append("")
        if finding.host:
            lines.append(f"対象ホスト: `{finding.host}`")
            lines.append("")
        if finding.detail:
            lines.append(finding.detail)
            lines.append("")


def _section_sources(lines: list[str], report: SurfaceReport) -> None:
    lines.append("## 情報源")
    lines.append("")
    for source in report.sources:
        lines.append(f"- {source}")
    lines.append("")
    if report.errors:
        lines.append("### 取得できなかった情報")
        lines.append("")
        for error in report.errors:
            lines.append(f"- {error}")
        lines.append("")


def _section_footer(lines: list[str]) -> None:
    lines.append("---")
    lines.append("")
    lines.append(
        f"このレポートは [miharun]({__repository__}) で生成しました。"
    )
    lines.append("")
    lines.append(
        "**利用にあたって**: このレポートは自分の資産、または許可を得た対象の確認にのみ"
        "使用してください。第三者のサイトに対して無断で調査を行うことは、"
        "法律や利用規約に反する場合があります。"
    )
    lines.append("")
