"""miharun のコマンドライン入口.

    miharun example.co.jp
    miharun 株式会社サンプル
    miharun example.co.jp --html --json

既定は「パッシブ」です。対象ホストへは一切リクエストを送りません。
--probe を指定したときだけ、HTTP ヘッダを控えめに取得します。
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import string
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .diff import (
    compare,
    find_snapshot,
    load_snapshot,
    render_diff_markdown,
    report_stem,
)
from .fingerprint import detect
from .insights import build_findings, host_risks
from .models import HostResult, SurfaceReport, risk_level
from .report_html import render_html
from .report_md import render_markdown
from .safety import RateLimiter
from .sources import company, crtsh, dns, http_probe

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE
)
APEX_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS")
MAX_SUBDOMAIN_RESOLVE = 300


# ----------------------------------------------------------------------
# コンソール表示のための小さなヘルパ
# ----------------------------------------------------------------------

class Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap(text, "1")

    def dim(self, text: str) -> str:
        return self._wrap(text, "2")

    def green(self, text: str) -> str:
        return self._wrap(text, "32")

    def yellow(self, text: str) -> str:
        return self._wrap(text, "33")

    def blue(self, text: str) -> str:
        return self._wrap(text, "36")

    def red(self, text: str) -> str:
        return self._wrap(text, "31")


# ----------------------------------------------------------------------
# 入力の判定
# ----------------------------------------------------------------------

def detect_input(text: str) -> tuple[str, str]:
    """入力がドメインか企業名かを判定する.

    戻り値: ("domain" | "organization", 正規化した値)
    """
    text = text.strip()
    if "://" in text:
        host = urlsplit(text).hostname
        if host:
            return "domain", host.lower()
    candidate = text.rstrip(".").lower()
    if DOMAIN_RE.match(candidate):
        return "domain", candidate
    return "organization", text


# ----------------------------------------------------------------------
# 調査の本体
# ----------------------------------------------------------------------

def build_report(
    target: str,
    *,
    timeout: float,
    workers: int,
    probe: bool,
    skip_subdomains: bool,
    resolve_limit: int,
    palette: Palette,
) -> SurfaceReport:
    kind, normalized = detect_input(target)
    report = SurfaceReport(target=target, input_kind=kind)

    domain = None
    if kind == "domain":
        domain = normalized
    else:
        domain = _resolve_organization(report, normalized, timeout, palette)
        if domain is None:
            return report

    report.domain = domain

    # --- 頂点ドメインの DNS レコード ---
    apex: dict[str, list[str]] = {}
    for rtype in APEX_TYPES:
        apex[rtype] = dns.query(domain, rtype, timeout=timeout)
    # DMARC は _dmarc.<domain> に置かれるため、別途照会して TXT に加える
    dmarc_values = dns.query(f"_dmarc.{domain}", "TXT", timeout=timeout)
    if dmarc_values:
        apex["TXT"] = list(apex.get("TXT", [])) + dmarc_values
    if apex["A"]:
        reverse_values = []
        for ip in apex["A"][:3]:
            name = dns.reverse_short(ip, timeout=timeout)
            if name:
                reverse_values.append(name)
        apex["PTR"] = reverse_values
    report.apex = apex
    report.sources.append("DNS over HTTPS（Cloudflare / Google）")

    # --- ワイルドカード DNS の確認（DNS を引くだけ） ---
    if _wildcard_dns_in_use(domain, timeout):
        report.apex["_wildcard"] = ["1"]

    # --- サブドメインの列挙（＋露出期間） ---
    hosts: list[str] = []
    windows: dict[str, dict] = {}
    if not skip_subdomains:
        print(palette.dim("  証明書透明性ログを照会しています…"))
        hosts, windows = crtsh.fetch_with_windows(
            domain, timeout=max(30.0, timeout)
        )
        if hosts:
            report.sources.append("証明書透明性ログ（crt.sh）")
        else:
            report.errors.append(
                "証明書透明性ログ（crt.sh）からサブドメインを取得できませんでした"
                "（混雑しているか、公開された証明書が無い可能性があります）"
            )

    host_results: list[HostResult] = []
    to_resolve = hosts[: min(resolve_limit, MAX_SUBDOMAIN_RESOLVE)]
    if to_resolve:
        print(palette.dim(f"  {len(to_resolve)} 件のホストを確認しています…"))
        limiter = RateLimiter(0.0)
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            host_results = list(
                pool.map(
                    lambda h: _resolve_host(h, timeout, limiter),
                    to_resolve,
                )
            )

    # 解決できなかったホストも一覧には残す
    resolved_names = {h.host for h in host_results}
    for host in hosts:
        if host not in resolved_names:
            host_results.append(HostResult(host=host, note="名前解決できませんでした"))

    # 露出期間（証明書ログ）を各ホストに紐付ける
    for host in host_results:
        _apply_exposure(host, windows.get(host.host))

    # 頂点ドメイン自身も一覧の先頭に入れる
    apex_host = HostResult(
        host=domain,
        addresses=list(apex.get("A", [])) + list(apex.get("AAAA", [])),
        cname=list(apex.get("CNAME", [])),
        reverse=list(apex.get("PTR", [])),
    )
    _apply_exposure(apex_host, windows.get(domain))
    host_results.insert(0, apex_host)

    # --- 任意の HTTP ヘッダ取得 ---
    if probe:
        print(palette.dim("  HTTP ヘッダを控えめに取得しています（--probe）…"))
        probe_limiter = RateLimiter(1.0)
        _probe_hosts(host_results, probe_limiter, timeout)
        report.sources.append("HTTP レスポンスヘッダ（--probe による 1 回のみの取得）")

    report.hosts = host_results

    # --- 技術判定 ---
    for host in host_results:
        host.technologies = [
            name for _category, name, _confidence in detect(_host_records(host))
        ]

    # --- 危険度スコア ---
    for host in host_results:
        for risk in host_risks(host):
            report.add_finding(
                "warn",
                risk["title"],
                risk["why"],
                score=risk["score"],
                host=host.host,
            )

    technologies = detect(_collect_all_records(report))
    for category, name, _confidence in technologies:
        report.add_technology(category, name)

    # --- 気づき ---
    build_findings(report)

    return report


def _resolve_organization(
    report: SurfaceReport, name: str, timeout: float, palette: Palette
) -> str | None:
    """企業名から公式サイトのドメインを探す。"""
    sources = company.available_sources()
    if not sources:
        report.errors.append("企業名で調べるための API キーが設定されていません")
        print()
        print(palette.yellow("企業名で調べるには API キーが必要です。"))
        print(palette.dim(company.setup_hint()))
        print()
        return None

    print(palette.dim(f"  {name} を法人情報から探しています…"
                      f"（{', '.join(sources)}）"))
    results = company.search(name, timeout=timeout)
    if not results:
        report.errors.append(f"「{name}」に一致する法人が見つかりませんでした")
        return None

    chosen = next((org for org in results if org.website), results[0])
    report.organization = chosen

    if not chosen.website:
        report.errors.append(
            "法人情報から公式サイトの URL を特定できませんでした。"
            "ドメインを直接指定して再度お試しください"
        )
        return None

    host = urlsplit(chosen.website).hostname
    if not host:
        report.errors.append(f"公式サイトの URL を解釈できませんでした: {chosen.website}")
        return None
    return host.lower()


def _resolve_host(host: str, timeout: float, limiter: RateLimiter) -> HostResult:
    result = HostResult(host=host)
    result.addresses = dns.query(host, "A", timeout=timeout) + dns.query(
        host, "AAAA", timeout=timeout
    )
    result.cname = dns.query(host, "CNAME", timeout=timeout)
    if result.addresses:
        name = dns.reverse_short(result.addresses[0], timeout=timeout)
        if name:
            result.reverse.append(name)
    return result


def _apply_exposure(host: HostResult, window: dict | None) -> None:
    """証明書ログの窓（first_seen 等）をホストに紐付ける."""
    if not window:
        return
    host.first_seen = window.get("first_seen")
    host.last_seen = window.get("last_seen")
    host.issuers = list(window.get("issuers", []))


def _probe_hosts(hosts: list[HostResult], limiter: RateLimiter, timeout: float) -> None:
    targets = [h for h in hosts if h.addresses or h.cname][:50]
    for host in targets:
        info = http_probe.probe_host(host.host, limiter=limiter, timeout=timeout)
        if info is None:
            continue
        host.http_status = info.get("status")
        host.http_server = info.get("server")
        host.http_title = info.get("title")
        host.http_markers = list(info.get("markers") or [])
        host.http_header_lines = list(info.get("headers") or [])


def _host_records(host: HostResult) -> dict[str, list[str]]:
    """1 つのホストから、技術判定に使うレコードを作る。"""
    records: dict[str, list[str]] = {"CNAME": list(host.cname), "PTR": list(host.reverse)}
    http_values = list(host.http_markers)
    if host.http_server:
        http_values.insert(0, host.http_server)
    if http_values:
        records["HTTP"] = http_values
    # 応答ヘッダそのもの（"server: nginx" の形）で判定するルール用
    if host.http_header_lines:
        records["HTTP_HEADER"] = list(host.http_header_lines)
    return records


def _collect_all_records(report: SurfaceReport) -> dict[str, list[str]]:
    """レポート全体（頂点 + 全ホスト）のレコードをまとめる。"""
    combined = _merge_records(report.apex)
    for host in report.hosts:
        combined = _merge_records(combined, _host_records(host))
    return combined


def _merge_records(
    base: dict[str, list[str]], extra: dict[str, list[str]] | None = None
) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {key: list(values) for key, values in base.items()}
    if not extra:
        return merged
    for key, values in extra.items():
        bucket = merged.setdefault(key, [])
        for value in values:
            if value and value not in bucket:
                bucket.append(value)
    return merged


def _wildcard_dns_in_use(domain: str, timeout: float) -> bool:
    """無作為なラベルが解決できるかで、ワイルドカード DNS を判定する.

    DNS を引くだけなので、対象ホストには触れません。
    """
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    probe = f"{label}.{domain}"
    try:
        return bool(dns.query(probe, "A", timeout=timeout))
    except Exception:
        return False


# ----------------------------------------------------------------------
# 出力
# ----------------------------------------------------------------------

def write_outputs(
    report: SurfaceReport,
    technologies: list[tuple[str, str, str]],
    out_dir: Path,
    want_html: bool,
    want_json: bool,
) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = report_stem(report.domain)
    written: list[Path] = []

    md_path = out_dir / f"miharun-{stem}-report.md"
    md_path.write_text(render_markdown(report, technologies), encoding="utf-8")
    written.append(md_path)

    if want_html:
        html_path = out_dir / f"miharun-{stem}-report.html"
        html_path.write_text(render_html(report, technologies), encoding="utf-8")
        written.append(html_path)

    if want_json:
        json_path = out_dir / f"miharun-{stem}-report.json"
        json_path.write_text(
            json.dumps(to_json(report, technologies), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        written.append(json_path)

    return written


def to_json(report: SurfaceReport, technologies: list[tuple[str, str, str]]) -> dict:
    return {
        "tool": "miharun",
        "version": __version__,
        "generated_at": report.generated_at.isoformat(),
        "target": report.target,
        "input_kind": report.input_kind,
        "domain": report.domain,
        "organization": (
            {
                "name": report.organization.name,
                "corporate_number": report.organization.corporate_number,
                "location": report.organization.location,
                "website": report.organization.website,
                "source": report.organization.source,
            }
            if report.organization
            else None
        ),
        "technologies": [
            {"category": category, "name": name, "confidence": confidence}
            for category, name, confidence in technologies
        ],
        "dns": {key: values for key, values in report.apex.items() if not key.startswith("_")},
        "hosts": [
            {
                "host": host.host,
                "addresses": host.addresses,
                "cname": host.cname,
                "reverse": host.reverse,
                "first_seen": host.first_seen,
                "last_seen": host.last_seen,
                "issuers": host.issuers,
                "exposure_days": host.exposure_days,
                "exposure_years": host.exposure_years,
                "technologies": host.technologies,
                "http_status": host.http_status,
                "http_server": host.http_server,
                "http_title": host.http_title,
                "http_markers": host.http_markers,
                "note": host.note,
            }
            for host in report.hosts
        ],
        "overall_risk": report.overall_risk,
        "risk_level": risk_level(report.overall_risk),
        "findings": [
            {
                "level": f.level,
                "title": f.title,
                "detail": f.detail,
                "score": f.score,
                "host": f.host,
            }
            for f in report.findings
        ],
        "sources": report.sources,
        "errors": report.errors,
    }


def print_summary(report: SurfaceReport, technologies: list[tuple[str, str, str]], palette: Palette) -> None:
    print()
    target = report.domain or report.target
    print(palette.bold(f"{target} の外部公開マップ"))
    if report.organization and report.organization.name:
        print(palette.dim(f"  法人: {report.organization.name}"))
    print()

    if report.apex.get("A"):
        print(f"  A    {', '.join(report.apex['A'][:4])}")
    if report.apex.get("MX"):
        print(f"  MX   {', '.join(report.apex['MX'][:4])}")
    if report.apex.get("NS"):
        print(f"  NS   {', '.join(report.apex['NS'][:4])}")
    print()

    print(f"  見つかったホスト: {palette.bold(str(len(report.hosts)))} 件"
          f"（うち名前解決可 {len(report.live_hosts)} 件）")

    risk = report.overall_risk
    level_names = {"low": "低", "medium": "中", "high": "高", "critical": "重大"}
    lvl = risk_level(risk)
    risk_colour = {
        "low": palette.green,
        "medium": palette.yellow,
        "high": palette.yellow,
        "critical": palette.red,
    }[lvl]
    bar_len = 20
    filled = int(round(risk / 100 * bar_len))
    bar = "#" * filled + "." * (bar_len - filled)
    print()
    print(f"  危険度スコア: {risk_colour(palette.bold(str(risk)))}/100 "
          f"（{level_names[lvl]}）  {risk_colour(bar)}")
    print()

    if technologies:
        print(palette.blue("  推定される技術"))
        for category, name, confidence in technologies[:24]:
            print(f"    - [{category}] {name} ({confidence})")
        if len(technologies) > 24:
            print(palette.dim(f"    …ほか {len(technologies) - 24} 件"))
        print()

    if report.findings:
        print(palette.blue("  気づいた点"))
        for finding in sorted(
            report.findings, key=lambda f: -f.score
        ):
            color = palette.yellow if finding.level == "warn" else palette.dim
            score_tag = (
                f" [危険度 {finding.score}]" if finding.score else ""
            )
            print(f"    {color('・' + finding.title + score_tag)}")
        print()

    for error in report.errors:
        print(palette.dim(f"  ※ {error}"))
    if report.errors:
        print()


# ----------------------------------------------------------------------
# argparse
# ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="miharun",
        description=(
            "組織の外部公開マップを日本語で作るパッシブ偵察ツール。"
            "公開情報だけを読み取り、既定では対象にリクエストを送りません。"
        ),
        epilog=(
            "例:\n"
            "  miharun example.co.jp\n"
            "  miharun 株式会社サンプル\n"
            "  miharun example.co.jp --html --json --out out\n\n"
            "自分の資産、または許可を得た対象にのみ使用してください。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="ドメイン（example.co.jp）または企業名")
    parser.add_argument("--html", action="store_true", help="HTML レポートも出力する")
    parser.add_argument("--json", action="store_true", help="JSON も出力する")
    parser.add_argument("--out", default="out", help="出力先ディレクトリ（既定: out）")
    parser.add_argument(
        "--probe",
        action="store_true",
        help="HTTP ヘッダも取得する（既定は取得しない。許可を得た対象のみ）",
    )
    parser.add_argument(
        "--no-subdomains", action="store_true", help="サブドメイン列挙を行わない"
    )
    parser.add_argument(
        "--resolve-limit",
        type=int,
        default=150,
        help="名前解決するホスト数の上限（既定: 150）",
    )
    parser.add_argument("--workers", type=int, default=8, help="並列数（既定: 8）")
    parser.add_argument("--timeout", type=float, default=10.0, help="1 回の待ち時間 [秒]")
    parser.add_argument(
        "--diff",
        action="store_true",
        help="前回の JSON と比較して変化を報告する（変化検知）",
    )
    parser.add_argument(
        "--fail-on",
        type=int,
        default=0,
        metavar="SCORE",
        help=(
            "危険度スコアが指定値以上なら終了コード 1 で異常終了する"
            "（CI・定期実行向け。0 で無効）"
        ),
    )
    parser.add_argument("--no-color", action="store_true", help="色を使わない")
    parser.add_argument("--version", action="version", version=f"miharun {__version__}")
    return parser


def _setup_console() -> None:
    """Windows のコンソールでも日本語で落ちないようにする.

    - 画面（TTY）に出すとき: 現在の文字コードを保ち、変換できない文字は置換する
    - ファイルやパイプに流すとき: UTF-8 で書き出す
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    args = build_parser().parse_args(argv)
    use_color = (not args.no_color) and sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    palette = Palette(use_color)

    print()
    print(palette.bold(f"miharun {__version__}") + palette.dim(" - 外部公開マップを作成します"))
    print(palette.dim(f"  対象: {args.target}"))
    print()

    try:
        report = build_report(
            args.target,
            timeout=args.timeout,
            workers=args.workers,
            probe=args.probe,
            skip_subdomains=args.no_subdomains,
            resolve_limit=max(1, args.resolve_limit),
            palette=palette,
        )
    except KeyboardInterrupt:
        print(palette.yellow("\n中断しました。"))
        return 130

    # 技術一覧（確度つき）をレポート全体から作り直す
    technologies = detect(_collect_all_records(report))

    print_summary(report, technologies, palette)

    if report.domain is None:
        # 調べる対象のドメインが決まらなかった（企業名の解決に失敗した等）。
        # 中身の無いレポートを書いても意味がなく、同じ名前で上書きされ続けるため、
        # ここで終了する。
        print(
            palette.yellow(
                "  調査対象のドメインを決められなかったため、レポートは出力しません。"
            )
        )
        print()
        return 2

    # 変化検知は「前回の JSON」と比べる機能です。今回の結果で上書きした後に
    # 比較すると、常に自分自身と比べて「変化なし」になってしまいます。
    # そのため、write_outputs より先に実行します。
    if args.diff and report.domain:
        _run_diff(report, Path(args.out), palette)

    written = write_outputs(
        report, technologies, Path(args.out), args.html, args.json
    )
    print(palette.green("  レポートを出力しました:"))
    for path in written:
        print(f"    {path}")
    print()

    # 危険度に応じて終了コードを返す（CI / スケジュールタスク向け）
    if args.fail_on:
        threshold = args.fail_on
        actual = report.overall_risk
        if actual >= threshold:
            print(
                palette.red(
                    f"  危険度スコア {actual} が閾値 {threshold} 以上のため "
                    "異常終了します。"
                )
            )
            print()
            return 1
        print(
            palette.green(
                f"  危険度スコア {actual} は閾値 {threshold} 未満です。"
            )
        )
        print()

    return 0


def _run_diff(report: SurfaceReport, out_dir: Path, palette: Palette) -> None:
    """前回結果と比較する。JSON が無ければ案内して終了する."""
    snapshot = find_snapshot(out_dir, report.domain or "")
    previous = load_snapshot(snapshot)
    if previous is None:
        print(palette.yellow(
            "  前回の結果が見つかりません。--json 付きで一度実行してから "
            "--diff を使ってください。"
        ))
        print()
        return

    result = compare(previous, report)
    delta = result["risk_delta"]
    arrow = palette.red if hasattr(palette, "red") else palette.yellow
    colour = palette.green if delta <= 0 else arrow
    print(palette.blue("  前回との比較"))
    print(f"    危険度スコアの変化: {colour(f'{delta:+d}')}")
    for label, key in (
        ("新規ホスト", "new_hosts"),
        ("消えたホスト", "gone_hosts"),
        ("新規の危険度", "new_risks"),
        ("解消された危険度", "resolved_risks"),
    ):
        count = len(result[key])
        marker = palette.green if count == 0 else palette.yellow
        print(f"    {label}: {marker(str(count))}")
        for item in result[key][:8]:
            print(f"      - {item}")
        if count > 8:
            print(palette.dim(f"      …ほか {count - 8} 件"))
    print()

    diff_path = out_dir / f"miharun-{report_stem(report.domain)}-diff.md"
    diff_path.write_text(
        render_diff_markdown(result, report.domain or ""), encoding="utf-8"
    )
    print(palette.green(f"  変化レポートを出力しました:\n    {diff_path}"))
    print()


if __name__ == "__main__":
    raise SystemExit(main())
