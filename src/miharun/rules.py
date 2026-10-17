"""miharun の技術判定ルール（日本向け + Web 技術）.

DNS レコード（NS / MX / TXT / CNAME / PTR）の値に含まれる文字列で
「どのサービスを使っているか」を推定します。
Web 技術（CMS・フレームワーク・分析ツールなど）は HTTP 答応を使って判定します。

このファイルを編集するだけで DNS ベースの判定を増やせます。
Web 技術のルールは rules_web.py にあり、Wappalyzer 由来で自動生成です。

各ルールの意味::

    Rule(category, name, patterns, sources, confidence)

    category   … レポートでの分類（例: "メール"）
    name       … 表示名（例: "Google Workspace"）
    patterns   … 小文字で部分一致させる文字列のタプル
    sources    … どのレコード種別を見るか（"NS" "MX" "TXT" "CNAME" "PTR" "HTTP"）
    confidence … "high" | "medium" | "low"

注意:
    これは「推定」です。同じ IP を共有していても判定を誤ることがあります。
    レポートには推定であることを明記します。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    category: str
    name: str
    patterns: tuple[str, ...]
    sources: tuple[str, ...]
    confidence: str = "medium"


CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}

# 全文一致ではなく部分一致で判定するため、誤検知しにくい長さの文字列を使う
RULES: list[Rule] = [
    # ------------------------------------------------------------------
    # レンタルサーバー・ホスティング（日本の個人・中小企業で圧倒的多数）
    # ------------------------------------------------------------------
    Rule(
        "レンタルサーバー",
        "さくらインターネット",
        ("sakura.ne.jp", "sakura.ad.jp", "sakuraweb.com", "sakuragawa"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "エックスサーバー",
        ("xserver.jp", "xdomain.jp", "xserver.ne.jp", "xsrv.jp"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "ロリポップ！",
        ("lolipop.jp", "lolipop.ne.jp", "loho.ne.jp", "lolipop"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "ConoHa",
        ("conoha.io", "conoha.jp", "conoha.ne.jp"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "スターサーバー",
        ("star-server.jp", "star.ne.jp", "starserver"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "mixhost",
        ("mixhost.jp", "mixhost.net"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "お名前.com レンタルサーバー",
        ("onamae.com", "onamae.ne.jp", "dnsv.jp", "onamae-server"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "バリュードメイン",
        ("value-domain.com", "value-domain.ne.jp", "valuedomain"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "カゴヤ・ジャパン",
        ("kagoya.net", "kagoya.com"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "CPI",
        ("cpi.ad.jp", "cpi.ne.jp"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "ファーストサーバ",
        ("firstserver.ne.jp", "firstserver.jp"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "コアサーバー",
        ("coreserver.jp", "coreblog.jp"),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "ミニバード",
        ("minibird.jp",),
        ("NS", "MX", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "レンタルサーバー",
        "ヘテムル",
        ("heteml.jp",),
        ("NS", "MX", "CNAME", "PTR"),
        "medium",
    ),
    Rule(
        "レンタルサーバー",
        "ラピッドサイト",
        ("rapidsite.jp", "rs-sys.com"),
        ("NS", "MX", "CNAME", "PTR"),
        "medium",
    ),
    Rule(
        "レンタルサーバー",
        "ロケットネット",
        ("rocketnet.ne.jp",),
        ("NS", "MX", "CNAME", "PTR"),
        "medium",
    ),
    Rule(
        "レンタルサーバー",
        "シン・レンタルサーバー",
        ("shin-server.jp", "shinserver"),
        ("NS", "MX", "CNAME", "PTR"),
        "medium",
    ),
    Rule(
        "レンタルサーバー",
        "ウィックス",
        ("wixdns.net", "wix.com"),
        ("CNAME", "NS", "MX"),
        "high",
    ),
    # ------------------------------------------------------------------
    # クラウド（日本での採用も多い）
    # ------------------------------------------------------------------
    Rule(
        "クラウド",
        "Amazon Web Services",
        ("amazonaws.com", "awsdns", "cloudfront.net", "amazonaws"),
        ("NS", "CNAME", "PTR", "MX"),
        "high",
    ),
    Rule(
        "クラウド",
        "Google Cloud",
        ("googleusercontent.com", "googledomains.com", "1e100.net", "google.com"),
        ("NS", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "クラウド",
        "Microsoft Azure",
        ("azure-dns.com", "azure-dns.net", "azurewebsites.net", "azure.com", "windows.net"),
        ("NS", "CNAME", "PTR"),
        "high",
    ),
    Rule(
        "クラウド",
        "さくらのクラウド",
        ("sakura.ad.jp", "sacla.ne.jp"),
        ("PTR", "CNAME"),
        "high",
    ),
    # ------------------------------------------------------------------
    # CDN・WAF
    # ------------------------------------------------------------------
    Rule(
        "CDN・WAF",
        "Cloudflare",
        ("cloudflare.com", "cloudflare.net", "cloudflare"),
        ("NS", "CNAME"),
        "high",
    ),
    Rule(
        "CDN・WAF",
        "Fastly",
        ("fastly.net", "fastlylb.net"),
        ("CNAME", "NS"),
        "high",
    ),
    Rule(
        "CDN・WAF",
        "Amazon CloudFront",
        ("cloudfront.net",),
        ("CNAME",),
        "high",
    ),
    Rule(
        "CDN・WAF",
        "Akamai",
        ("akamai.net", "akamaiedge.net", "akamaized.net", "edgekey.net", "edgesuite.net"),
        ("CNAME", "PTR"),
        "high",
    ),
    Rule(
        "CDN・WAF",
        "Azure Front Door / CDN",
        ("azureedge.net", "azurefd.net", "trafficmanager.net"),
        ("CNAME",),
        "high",
    ),
    Rule(
        "CDN・WAF",
        "IIJ（インターネットイニシアティブ）",
        ("iij.ad.jp", "iij4u.ne.jp"),
        ("NS", "PTR"),
        "high",
    ),
    Rule(
        "CDN・WAF",
        "NTT",
        ("ntt.net", "ocn.ne.jp", "ntt.com"),
        ("NS", "PTR"),
        "medium",
    ),
    Rule(
        "CDN・WAF",
        "Bunny CDN",
        ("b-cdn.net",),
        ("CNAME",),
        "high",
    ),
    # ------------------------------------------------------------------
    # DNS プロバイダ
    # ------------------------------------------------------------------
    Rule("DNS", "Cloudflare", ("cloudflare.com",), ("NS",), "high"),
    Rule("DNS", "Amazon Route 53", ("awsdns",), ("NS",), "high"),
    Rule("DNS", "Google Cloud DNS", ("googledomains.com",), ("NS",), "high"),
    Rule("DNS", "Azure DNS", ("azure-dns.com", "azure-dns.net"), ("NS",), "high"),
    Rule("DNS", "お名前.com", ("dnsv.jp", "onamae.com"), ("NS",), "high"),
    Rule("DNS", "バリュードメイン", ("value-domain.com",), ("NS",), "high"),
    Rule("DNS", "ムームードメイン", ("muumuu-domain.com",), ("NS",), "high"),
    Rule("DNS", "さくらインターネット", ("sakura.ne.jp",), ("NS",), "high"),
    Rule("DNS", "エックスサーバー", ("xserver.jp", "xdomain.jp"), ("NS",), "high"),
    Rule("DNS", "IIJ", ("iij.ad.jp",), ("NS",), "high"),
    Rule("DNS", "@nifty", ("nifty.com", "nifty.ne.jp"), ("NS",), "high"),
    Rule("DNS", "BIGLOBE", ("biglobe.ne.jp", "biglobe.com"), ("NS",), "high"),
    Rule("DNS", "So-net", ("so-net.ne.jp", "sonet.ne.jp"), ("NS",), "high"),
    Rule("DNS", "JPRS", ("jprs.co.jp", "jprs.jp"), ("NS",), "medium"),
    # ------------------------------------------------------------------
    # メール（MX で判定できるので確度が高い）
    # ------------------------------------------------------------------
    Rule(
        "メール",
        "Google Workspace",
        ("aspmx.l.google.com", "google.com", "googlemail.com", "smtp.google.com"),
        ("MX",),
        "high",
    ),
    Rule(
        "メール",
        "Microsoft 365",
        ("mail.protection.outlook.com", "outlook.com", "office365"),
        ("MX",),
        "high",
    ),
    Rule("メール", "さくらのメールボックス", ("sakura.ne.jp",), ("MX",), "high"),
    Rule("メール", "エックスサーバー メール", ("xserver.jp", "xserver.ne.jp"), ("MX",), "high"),
    Rule("メール", "ロリポップ！メール", ("lolipop.jp", "lolipop.ne.jp"), ("MX",), "high"),
    Rule("メール", "お名前メール", ("onamae.com", "value-domain.com"), ("MX",), "high"),
    Rule("メール", "ConoHa メール", ("conoha.io", "conoha.jp"), ("MX",), "high"),
    Rule("メール", "カゴヤ メール", ("kagoya.net", "kagoya.com"), ("MX",), "high"),
    Rule("メール", "BIGLOBE メール", ("biglobe.ne.jp",), ("MX",), "high"),
    Rule("メール", "@nifty メール", ("nifty.com", "nifty.ne.jp"), ("MX",), "high"),
    Rule("メール", "So-net メール", ("so-net.ne.jp", "sonet.ne.jp"), ("MX",), "high"),
    Rule("メール", "Yahoo!メール", ("yahoo.co.jp", "yahoodns.net", "ymail"), ("MX",), "medium"),
    Rule("メール", "Zoho Mail", ("zoho.com", "zoho.jp", "zohomail"), ("MX",), "high"),
    Rule("メール", "Proton Mail", ("protonmail.ch", "proton.me"), ("MX",), "high"),
    Rule("メール", "Mimecast", ("mimecast.com",), ("MX",), "high"),
    Rule("メール", "Barracuda", ("barracudanetworks.com",), ("MX",), "high"),
    Rule("メール", "Proofpoint", ("pphosted.com", "proofpoint.com"), ("MX",), "high"),
    Rule(
        "メール",
        "Trend Micro Email Security",
        ("tmems-jp.trendmicro.com", "tmes.trendmicro.com", "trendmicro.com", "tmems"),
        ("MX",),
        "high",
    ),
    Rule("メール", "大塚商会（SecureMail）", ("securemail", "otsuka-shokai.co.jp"), ("MX",), "medium"),
    Rule("メール", "Amazon SES", ("amazonses.com",), ("MX", "TXT"), "high"),
    Rule("メール", "SendGrid", ("sendgrid.net",), ("MX", "TXT"), "high"),
    Rule("メール", "Mailgun", ("mailgun.org",), ("MX", "TXT"), "high"),
    Rule("メール", "さくら（その他）", ("sakura.ne.jp",), ("MX",), "medium"),
    # ------------------------------------------------------------------
    # メール送信・SPF（TXT から推定）
    # ------------------------------------------------------------------
    Rule("メール送信", "Google Workspace（SPF）", ("_spf.google.com",), ("TXT",), "high"),
    Rule("メール送信", "Microsoft 365（SPF）", ("spf.protection.outlook.com",), ("TXT",), "high"),
    Rule("メール送信", "Amazon SES（SPF）", ("amazonses.com",), ("TXT",), "high"),
    Rule("メール送信", "SendGrid（SPF）", ("sendgrid.net",), ("TXT",), "high"),
    Rule("メール送信", "Mailgun（SPF）", ("mailgun.org",), ("TXT",), "high"),
    Rule("メール送信", "Salesforce", ("spf.salesforce.com",), ("TXT",), "high"),
    Rule("メール送信", "Mailchimp", ("spf.mcsv.net", "servers.mcsv.net"), ("TXT", "CNAME"), "high"),
    Rule("メール送信", "HubSpot", ("spf.hubspot.com",), ("TXT",), "high"),
    Rule("メール送信", "さくら（SPF）", ("_spf.sakura.ne.jp",), ("TXT",), "high"),
    Rule("メール送信", "Fastmail", ("spf.messagingengine.com",), ("TXT",), "high"),
    # ------------------------------------------------------------------
    # SaaS・外部サービス（TXT の所有確認レコードで判定・確度が高い）
    # ------------------------------------------------------------------
    Rule("SaaS", "Google Search Console", ("google-site-verification",), ("TXT",), "high"),
    Rule("SaaS", "Google Workspace（所有確認）", ("google-gws-recovery-domain-verification",), ("TXT",), "high"),
    Rule("SaaS", "Microsoft 365（所有確認）", ("ms=ms",), ("TXT",), "high"),
    Rule("SaaS", "Meta（Facebook）", ("facebook-domain-verification",), ("TXT",), "high"),
    Rule("SaaS", "Apple", ("apple-domain-verify", "apple-domain-verification"), ("TXT",), "high"),
    Rule("SaaS", "Atlassian", ("atlassian-domain-verification",), ("TXT",), "high"),
    Rule("SaaS", "Adobe", ("adobe-idp-site-verification", "adobe-sign-verification"), ("TXT",), "high"),
    Rule("SaaS", "Stripe", ("stripe-verification",), ("TXT",), "high"),
    Rule("SaaS", "Shopify", ("shopify-verification", "myshopify.com"), ("TXT", "CNAME"), "high"),
    Rule("SaaS", "Have I Been Pwned", ("have-i-been-pwned-verification",), ("TXT",), "high"),
    Rule("SaaS", "Zoom", ("zoom-verify",), ("TXT",), "high"),
    Rule("SaaS", "DocuSign", ("docusign",), ("TXT",), "medium"),
    Rule("SaaS", "Dropbox", ("dropbox-domain-verification",), ("TXT",), "high"),
    Rule("SaaS", "Notion", ("notion-domain-verification",), ("TXT",), "high"),
    Rule("SaaS", "Slack", ("slack-domain-verification",), ("TXT",), "high"),
    Rule("SaaS", "1Password", ("1password-domain-verification", "1password-site-verification"), ("TXT",), "high"),
    Rule("SaaS", "Canva", ("canva-site-verification",), ("TXT",), "high"),
    Rule("SaaS", "Zendesk", ("zendesk.com",), ("CNAME",), "high"),
    Rule("SaaS", "Intercom", ("intercom.help", "intercom.io"), ("CNAME",), "high"),
    Rule("SaaS", "Salesforce", ("salesforce.com", "force.com"), ("CNAME", "TXT"), "high"),
    Rule("SaaS", "Cybozu（サイボウズ）", ("cybozu.com", "kintone.com"), ("CNAME", "TXT"), "high"),
    Rule("SaaS", "Money Forward（マネーフォワード）", ("moneyforward.com",), ("CNAME", "TXT"), "medium"),
    Rule("SaaS", "freee", ("freee.co.jp", "freee.com"), ("CNAME", "TXT"), "medium"),
    # ------------------------------------------------------------------
    # 静的ホスティング・開発系
    # ------------------------------------------------------------------
    Rule("静的ホスティング", "GitHub Pages", ("github.io",), ("CNAME",), "high"),
    Rule("静的ホスティング", "Netlify", ("netlify.app", "netlify.com", "netlifydns"), ("CNAME", "NS"), "high"),
    Rule("静的ホスティング", "Vercel", ("vercel-dns.com", "vercel.app", "now.sh"), ("CNAME", "NS"), "high"),
    Rule("静的ホスティング", "Cloudflare Pages", ("pages.dev",), ("CNAME",), "high"),
    Rule("静的ホスティング", "Heroku", ("herokudns.com", "herokuapp.com"), ("CNAME",), "high"),
    Rule("静的ホスティング", "Firebase Hosting", ("web.app", "firebaseapp.com"), ("CNAME",), "high"),
    # ------------------------------------------------------------------
    # 日本のEC・サイト作成サービス
    # ------------------------------------------------------------------
    Rule("CMS・EC", "Shopify", ("myshopify.com",), ("CNAME",), "high"),
    Rule("CMS・EC", "BASE（ベイス）", ("thebase.in", "base.ec"), ("CNAME",), "high"),
    Rule("CMS・EC", "STORES", ("stores.jp",), ("CNAME",), "high"),
    Rule("CMS・EC", "カラーミーショップ（GMO）", ("shop-pro.jp", "color-me.jp"), ("CNAME", "HTTP"), "high"),
    Rule("CMS・EC", "MakeShop（GMO）", ("makeshop.jp",), ("CNAME", "HTTP"), "high"),
    Rule("CMS・EC", "ジンドゥー", ("jimdo.com", "jimdofree.com"), ("CNAME", "NS", "HTTP"), "high"),
    Rule("CMS・EC", "ペライチ", ("peraichi.com",), ("CNAME", "HTTP"), "high"),
    Rule("CMS・EC", "グーペ", ("goope.jp",), ("CNAME", "HTTP"), "high"),
    Rule("CMS・EC", "Wix", ("wixdns.net", "wixsite.com"), ("CNAME", "NS"), "high"),
    Rule("CMS・EC", "Squarespace", ("squarespace.com", "sqsp.net"), ("CNAME", "NS"), "high"),
    # ------------------------------------------------------------------
    # セキュリティ関連
    # ------------------------------------------------------------------
    Rule("セキュリティ", "DMARC 設定あり", ("v=dmarc1",), ("TXT",), "high"),
    Rule("セキュリティ", "Google Postmaster", ("_dmarc",), ("TXT",), "low"),

    # ------------------------------------------------------------------
    # Web サーバー・CMS（--probe で HTTP 応答を取得したときだけ判定できる）
    # ------------------------------------------------------------------
    Rule("Webサーバー", "nginx", ("nginx",), ("HTTP",), "medium"),
    Rule("Webサーバー", "Apache", ("apache",), ("HTTP",), "medium"),
    Rule("Webサーバー", "LiteSpeed", ("litespeed",), ("HTTP",), "medium"),
    Rule("Webサーバー", "Microsoft IIS", ("microsoft-iis",), ("HTTP",), "medium"),
    Rule("Webサーバー", "Caddy", ("caddy",), ("HTTP",), "medium"),
    Rule("Webサーバー", "OpenResty", ("openresty",), ("HTTP",), "medium"),
    Rule("Webサーバー", "さくらのサービス", ("sakura",), ("HTTP",), "low"),
    Rule(
        "CMS",
        "WordPress",
        ("wp-content", "wp-includes", "wp-json", "wordpress"),
        ("HTTP",),
        "medium",
    ),
    Rule("CMS", "EC-CUBE", ("ec-cube",), ("HTTP",), "medium"),
    Rule("CMS", "Movable Type", ("movable type", "mt-static"), ("HTTP",), "medium"),
]


def rules_for_source(source: str) -> list[Rule]:
    """指定したレコード種別を見るルールだけを返す。"""
    source = source.upper()
    return [r for r in ALL_RULES if source in r.sources]


# ---------------------------------------------------------------------------
# Web 技術ルール（Wappalyzer 由来・自動生成）を統合する
# ---------------------------------------------------------------------------

# 循環 import を避けるため、rules_web は このモジュールの Rule 定義だけを参照する
try:  # pragma: no cover - 生成ファイルが無い環境でも動くように
    from .rules_web import WEB_RULES  # type: ignore

    RULES.extend(WEB_RULES)
except ImportError:  # pragma: no cover
    pass

# 統合済みの全ルール
ALL_RULES: list[Rule] = list(RULES)


def all_categories() -> list[str]:
    """ルールに登場するカテゴリの一覧（重複なし・出現順）。"""
    seen: list[str] = []
    for rule in ALL_RULES:
        if rule.category not in seen:
            seen.append(rule.category)
    return seen
