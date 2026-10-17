"""サンプルのレポートを生成する（ネットワークに一切アクセスしない）.

README やスクリーンショット用の見本を、実在の組織に触れずに作るための
スクリプトです。架空のドメインとホストを使います。

    python examples/make_example.py

出力先: examples/out/
    miharun-example-corp.co.jp-report.html
    miharun-example-corp.co.jp-report.md
    miharun-example-corp-report.json
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from miharun import insights  # noqa: E402
from miharun.cli import to_json  # noqa: E402
from miharun.models import (  # noqa: E402
    HostResult,
    Organization,
    SurfaceReport,
    now_jst,
)
from miharun.report_html import render_html  # noqa: E402
from miharun.report_md import render_markdown  # noqa: E402

OUT = Path(__file__).resolve().parent / "out"

DOMAIN = "example-corp.co.jp"


def _days_ago(days: int) -> str:
    """days 日前の日付を ISO8601（UTC）で返す。"""
    moment = now_jst() - timedelta(days=days)
    return moment.replace(tzinfo=None).isoformat(timespec="seconds")


def build_report() -> SurfaceReport:
    report = SurfaceReport(
        target=DOMAIN,
        input_kind="domain",
        domain=DOMAIN,
        generated_at=now_jst(),
    )
    report.organization = None

    report.apex = {
        "A": ["203.0.113.10"],
        "MX": ["example-corp-co-jp.mail.protection.outlook.com"],
        "NS": ["ns1.example-corp.co.jp", "ns2.example-corp.co.jp"],
        "TXT": [
            "v=spf1 include:spf.protection.outlook.com -all",
            "google-site-verification=EXAMPLEONLYEXAMPLEONLYEXAMPLEONLY",
        ],
    }
    report.sources = [
        "証明書透明性ログ（crt.sh）",
        "DNS（Google Public DNS / DNS over HTTPS）",
        "robots.txt",
    ]

    # (ホスト名, アドレス, 露出日数, HTTP 状態, サーバー)
    hosts = [
        ("www.example-corp.co.jp", ["203.0.113.10"], 2640, 200, "nginx"),
        ("api.example-corp.co.jp", ["203.0.113.11"], 1120, 403, "nginx"),
        ("shop.example-corp.co.jp", ["203.0.113.12"], 1980, 200, "Apache"),
        ("mail.example-corp.co.jp", ["203.0.113.13"], 2900, 200, "nginx"),
        ("blog.example-corp.co.jp", ["203.0.113.14"], 2460, 200, "nginx"),
        ("dev.example-corp.co.jp", ["203.0.113.15"], 190, 200, "nginx"),
        ("staging.example-corp.co.jp", ["203.0.113.16"], 95, 401, "nginx"),
        ("admin.example-corp.co.jp", ["203.0.113.17"], 720, 200, "IIS"),
        ("cdn.example-corp.co.jp", ["203.0.113.18"], 540, 200, ""),
        ("old.example-corp.co.jp", ["203.0.113.19"], 3100, 200, "Apache"),
        ("test.example-corp.co.jp", ["203.0.113.20"], 60, 403, "nginx"),
        ("status.example-corp.co.jp", ["203.0.113.21"], 400, 200, ""),
    ]

    for name, addresses, age, status, server in hosts:
        last_octet = addresses[0].rsplit(".", 1)[-1]
        host = HostResult(
            host=name,
            addresses=addresses,
            reverse=[f"ec2-203-0-113-{last_octet}.ap-northeast-1.compute.amazonaws.com"],
            http_status=status,
            http_server=server or None,
            http_title=f"{name.split('.')[0]} | Example Corporation",
            first_seen=_days_ago(age),
            last_seen=_days_ago(30),
            issuers=["Let's Encrypt", "DigiCert"],
        )
        report.hosts.append(host)

    # 名前解決できなかったホスト（露出の記録だけがある）
    report.hosts.append(
        HostResult(
            host="old-api.example-corp.co.jp",
            first_seen=_days_ago(1500),
            last_seen=_days_ago(1400),
            issuers=["Let's Encrypt"],
        )
    )

    for category, name in [
        ("CMS", "WordPress"),
        ("Webサーバー", "nginx"),
        ("ホスティング", "Amazon Web Services"),
        ("メール", "Microsoft 365"),
        ("CDN・WAF", "Cloudflare"),
        ("EC", "WooCommerce"),
        ("SaaS", "Google Search Console"),
        ("セキュリティ", "DMARC 設定あり"),
        ("DNS", "お名前.com"),
    ]:
        report.add_technology(category, name)

    # 所見（DNS ベース）＋ ホストごとの危険度
    insights.build_findings(report)
    for host in report.hosts:
        for risk in insights.host_risks(host):
            report.add_finding(
                "warn", risk["title"], risk["why"], score=risk["score"], host=host.host
            )

    return report


def main() -> None:
    report = build_report()
    technologies = [
        (category, name, "medium") for category, name in report.technologies
    ]
    stem = DOMAIN

    OUT.mkdir(parents=True, exist_ok=True)

    html_path = OUT / f"miharun-{stem}-report.html"
    html_path.write_text(render_html(report, technologies), encoding="utf-8")

    md_path = OUT / f"miharun-{stem}-report.md"
    md_path.write_text(render_markdown(report, technologies), encoding="utf-8")

    json_path = OUT / f"miharun-{stem.replace('.', '-')}-report.json"
    json_path.write_text(
        json.dumps(to_json(report, technologies), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"生成しました: {html_path}")
    print(f"生成しました: {md_path}")
    print(f"生成しました: {json_path}")


if __name__ == "__main__":
    main()
