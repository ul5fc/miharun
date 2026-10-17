"""レポートに載せる「気づき（所見）」を作る.

miharun の付加価値は、単に情報を並べるだけでなく
「ここは確認したほうがよい」という日本語のコメントを添えることです。

断定はしません。「〜の可能性があります」という書き方に統一します。
"""

from __future__ import annotations

from .models import SurfaceReport

# 本番環境ではない可能性が高いサブドメインのラベル
NON_PRODUCTION_LABELS = {
    "dev",
    "develop",
    "test",
    "testing",
    "staging",
    "stage",
    "stg",
    "uat",
    "beta",
    "sandbox",
    "demo",
    "old",
    "backup",
    "bak",
    "tmp",
    "temp",
    "local",
    "preview",
}

# そのままだと情報が漏れやすいラベル
SENSITIVE_LABELS = {
    "admin",
    "internal",
    "intranet",
    "jenkins",
    "gitlab",
    "git",
    "phpmyadmin",
    "db",
    "database",
    "backup",
}


def build_findings(report: SurfaceReport) -> None:
    """レポートに所見を追加する（その場で書き換える）. """
    _check_email_authentication(report)
    _check_non_production_hosts(report)
    _check_sensitive_hosts(report)
    _check_subdomain_count(report)
    _check_wildcard(report)
    _check_http_observations(report)


def _check_http_observations(report: SurfaceReport) -> None:
    """--probe の実測から、直接観測できる安全上の所見。"""
    for host in report.hosts:
        if host.http_status is None:
            continue
        if host.http_status in (401, 403):
            report.add_finding(
                "warn",
                f"認証が必要なホストが公開されています: {host.host}",
                f"HTTP {host.http_status} が返されます。ログイン画面や管理 API が"
                "外部から到達できます。認証強度（多要素認証の可否・セッション管理）を"
                "確認することをおすすめします。",
            )


def host_risks(host) -> list[dict]:
    """1 ホスト分の危険度を返す（純関数・単体テストの対象）.

    戻り値: [{"title": str, "score": int, "why": str}, ...]
    """
    risks: list[dict] = []
    label = host.host.split(".")[0].lower()

    if label in NON_PRODUCTION_LABELS and host.is_live:
        years = getattr(host, "exposure_years", None)
        why = "dev や test、staging などのホストは認証が弱く、" \
              "本番データやデバッグ端点が外部から到達できる状態です。"
        if years and years >= 3:
            why += f" 証明書の記録があり、{years} 年間公開されている可能性があります。"
        risks.append(
            {
                "title": f"開発/検証系ホストが外部公開されています: {host.host}",
                "score": 40,
                "why": why,
            }
        )

    if label in SENSITIVE_LABELS and host.is_live:
        risks.append(
            {
                "title": f"管理系ホストが外部公開されています: {host.host}",
                "score": 45,
                "why": "admin や internal、jenkins などのホストは認証が弱く、"
                "パスワード推測や既知の脆弱性の影響を受けやすい環境です。",
            }
        )

    if host.http_status in (401, 403) and host.is_live:
        risks.append(
            {
                "title": f"認証の向こうに API が露出しています: {host.host}",
                "score": 25,
                "why": "HTTP 401 または 403 が返されます。認証を突破できれば"
                "内部 API に到達できます。IDOR（水平権限移動）の影響範囲を"
                "確認することをおすすめします。",
            }
        )

    # --- 放置年数（露出期間）によるリスク加重 ---
    years = getattr(host, "exposure_years", None)
    if years is not None and years >= 5 and host.is_live:
        risks.append(
            {
                "title": f"長年公開され続けているホスト: {host.host}",
                "score": 20,
                "why": f"証明書透明性ログの記録より、少なくとも {years} 年間"
                "外部に公開されている可能性があります。長期間手つかずの"
                "ホストは、更新が停止している可能性があり、"
                "既知の脆弱性が放置されている可能性があります。",
            }
        )

    return risks


def _check_email_authentication(report: SurfaceReport) -> None:
    txt_records = [value.lower() for value in report.apex.get("TXT", [])]
    has_spf = any(value.startswith("v=spf1") for value in txt_records)
    has_dmarc = any(value.startswith("v=dmarc1") for value in txt_records)

    if not has_spf:
        report.add_finding(
            "notice",
            "SPF レコードが見つかりませんでした",
            "メールのなりすまし対策（SPF）が未設定の可能性があります。"
            "送信元ドメインの検証が行われていないおそれがあります。",
        )
    if not has_dmarc:
        report.add_finding(
            "notice",
            "DMARC レコードが見つかりませんでした",
            "DMARC が未設定の場合、なりすましメールを防ぐ仕組みが弱くなります。"
            "あわせて SPF / DKIM / DMARC の設定を確認することをおすすめします。",
        )


def _check_non_production_hosts(report: SurfaceReport) -> None:
    """名前解決できる dev/test 系ホストの露出."""
    found = [
        h.host
        for h in report.hosts
        if h.is_live and h.host.split(".")[0].lower() in NON_PRODUCTION_LABELS
    ]
    if found:
        preview = "、".join(found[:8])
        report.add_finding(
            "warn",
            "本番環境ではない可能性があるホストが公開されています",
            f"{preview}"
            + (" ほか" if len(found) > 8 else "")
            + "。開発・検証用のホストが外部から名前解決できる状態です。"
            "意図した公開かどうかを確認することをおすすめします。",
        )


def _check_sensitive_hosts(report: SurfaceReport) -> None:
    """名前解決できる管理系ホストの露出."""
    found = [
        h.host
        for h in report.hosts
        if h.is_live and h.host.split(".")[0].lower() in SENSITIVE_LABELS
    ]
    if found:
        preview = "、".join(found[:8])
        report.add_finding(
            "warn",
            "管理系とみられるホストが公開されています",
            f"{preview}"
            + (" ほか" if len(found) > 8 else "")
            + "。管理画面やリポジトリが外部から到達できる場合、"
            "アクセス制限の有無を確認することをおすすめします。",
        )


def _check_subdomain_count(report: SurfaceReport) -> None:
    count = len(report.hosts)
    if count >= 100:
        report.add_finding(
            "notice",
            f"サブドメインが非常に多く公開されています（{count} 件）",
            "公開しているホストが多いほど、管理から漏れるものが生まれやすくなります。"
            "不要なホストの削除・棚卸しを検討することをおすすめします。",
        )


def _check_wildcard(report: SurfaceReport) -> None:
    """証明書透明性ログでワイルドカード証明書が使われていた場合の注意. """
    if report.apex.get("_wildcard"):
        report.add_finding(
            "info",
            "ワイルドカード証明書が使われている可能性があります",
            "ワイルドカード証明書は運用が楽な一方、"
            "1 つの秘密鍵が漏れると配下の全ホストに影響します。"
            "鍵の管理方法を確認することをおすすめします。",
        )
