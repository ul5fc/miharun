"""Wappalyzer 由来の Web 技術判定ルール（自動生成・手で編集しないこと）.

出典: https://github.com/enthec/webappanalyzer （MIT ライセンス）
生成: python scripts/build_web_rules.py

これらのルールは HTTP 応答のみを使うため、`--probe` 指定時のみ有効です。
ブラウザ将领ある HTML の中に眠る指紋を読み取るためのルールです。
"""

from __future__ import annotations

from .rules import Rule

WEB_RULES: list[Rule] = [
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Aasaan", ("assets.aasaan.app",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Accesso", ("/embed/accesso.js",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Accredible", ("Access-Control-Allow-Headers",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "AceShop", ("/aceshopjquery/aceshopjquery/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Acquia Cloud Platform", ("X-AH-Environment",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Acquia Cloud Site Factory", ("sites/g/files",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Acquia Site Studio", ("sites/w/files/cohesion",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "actionhero.js", ("actionheroClient.js",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "actionhero.js", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Activ8 Commerce", ("/wp-content/plugins/activ8-commerce/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Adalo", ("assets.adalo.com/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Addsearch", ("//addsearch.com/js/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Adimo", ("cdn.adimo.co/",), ("HTTP",), "medium"),
    # --- データベース管理 ---
    Rule("データベース管理", "Adminer", ("composed-by",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Adobe ColdFusion", ("<!-- START headerTags.cfm",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Adobe ColdFusion", ("/cfajax/",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Adobe ColdFusion", ("Cookie",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Adobe Experience Manager", ("/etc/clientlibs/",), ("HTTP",), "medium"),
    Rule("CMS", "Adobe Experience Manager", ("/etc.clientlibs/",), ("HTTP",), "medium"),
    Rule("CMS", "Adobe Experience Manager", ("/etc/designs/",), ("HTTP",), "medium"),
    Rule("CMS", "Adobe Experience Manager Edge Delivery Services", ("./scripts/lib-franklin.js",), ("HTTP",), "medium"),
    Rule("CMS", "Adobe Experience Manager Edge Delivery Services", ("./scripts/aem.js",), ("HTTP",), "medium"),
    Rule("CMS", "Adobe Experience Manager Franklin", ("./scripts/lib-franklin.js",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Adobe RoboHelp", ("|ehlpdhtm).js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Advin", (".advin.cz/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Adwos CMS", ("application-name",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Aedi", ("api.aedi.ai/",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Aegea", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Affilo", ("//affilo.io/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Afosto", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "AfterBuy", (".afterbuy.de/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Afterpay", ("js.stripe.com/v3/fingerprinted/js/elements-afterpay-clearpay-message-..js",), ("HTTP",), "medium"),
    Rule("決済代行", "Afterpay", ("afterpay-products.min.js",), ("HTTP",), "medium"),
    Rule("決済代行", "Afterpay", ("portal.afterpay.com",), ("HTTP",), "medium"),
    Rule("決済代行", "Afterpay", ("static.afterpay.com",), ("HTTP",), "medium"),
    Rule("決済代行", "Afterpay", ("present-afterpay.js",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "AFThemes CoverNews", ("/wp-content/themes/covernews/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Agility CMS", ("cdn.agilitycms.com/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Agora", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "Ahrefs", ("ahrefs-site-verification",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Aimerce", ("cdn.aimerce.ai/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Airship CRM", (".airship.co.uk/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "AiSpeed", ("aispeed.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Aiva", (".hireaiva.com",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Akamai", ("X-EdgeConnect-Origin-MEX-Latency",), ("HTTP",), "medium"),
    Rule("CDN", "Akamai", ("X-EdgeConnect-MidMile-RTT",), ("HTTP",), "medium"),
    Rule("CDN", "Akamai", ("X-Akamai-Transformed",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Akamai Connected Cloud", ("x-volterra-location",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Akamai Web Application Protector", ("ds-aksb-a.akamaihd.net/aksb.min.js",), ("HTTP",), "medium"),
    # --- 会計・経理 ---
    Rule("会計・経理", "Akaunting", ("X-Akaunting",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Akilli Ticaret", (".akilliticaret.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Akinon", ("cdn-mgsm.akinon.net/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "AkoCommerce", ("app.akocommerce.com",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Alboom Prosite", ("bifrost.alboompro.com",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "AlertifyJS", ("/alertify/alertify.min.js",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Algolia", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Alibaba Cloud CDN", (".alicdn.com/",), ("HTTP",), "medium"),
    # --- IaaS ---
    Rule("IaaS", "Alibaba Cloud Object Storage Service", ("x-oss-storage-class",), ("HTTP",), "medium"),
    Rule("IaaS", "Alibaba Cloud Object Storage Service", ("x-oss-object-type",), ("HTTP",), "medium"),
    Rule("IaaS", "Alibaba Cloud Object Storage Service", ("x-oss-request-id",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Alibaba Cloud Verification Code", ("cf.aliyun.com/",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "Alli", (".alliai.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "AllMyLinks", ("application-name",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Alpine.js", ("/alpine.js",), ("HTTP",), "medium"),
    # --- ホスティングパネル ---
    Rule("ホスティングパネル", "AlternC", ("js/alternc.js",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "Amap", ("webapi.amap.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Amasty", ("Content-Security-Policy-Report-Only",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Amasty", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Amazon CloudFront", ("X-Amz-Cf-Id",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Amazon Pay", (".payments-amazon.com/",), ("HTTP",), "medium"),
    Rule("決済代行", "Amazon Pay", ("/amazonpayments.js",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Amazon S3", ("Content-Security-Policy-Report-Only",), ("HTTP",), "medium"),
    Rule("CDN", "Amazon S3", ("x-amz-server-side-encryption",), ("HTTP",), "medium"),
    Rule("CDN", "Amazon S3", ("Content-Security-Policy",), ("HTTP",), "medium"),
    Rule("CDN", "Amazon S3", ("s3.amazonaws.com/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Amazon Web Services", ("x-amz-req-time-micros",), ("HTTP",), "medium"),
    Rule("PaaS", "Amazon Web Services", ("x-amz-delete-marker",), ("HTTP",), "medium"),
    Rule("PaaS", "Amazon Web Services", ("x-amz-err-message",), ("HTTP",), "medium"),
    Rule("PaaS", "Amazon Web Services", ("x-amz-request-id",), ("HTTP",), "medium"),
    Rule("PaaS", "Amazon Web Services", ("x-amz-version-id",), ("HTTP",), "medium"),
    Rule("PaaS", "Amazon Web Services", ("x-amz-err-code",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Amber", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Ametys", ("ametys.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Amex Express Checkout", ("aexp-static.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "amoCRM", (".amocrm.",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "AndersNoren Baskerville", ("/wp-content/themes/baskerville/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "AndersNoren Fukasawa", ("/wp-content/themes/fukasawa/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "AndersNoren Hemingway", ("/wp-content/themes/hemingway/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "AndersNoren Hitchcock", ("/wp-content/themes/hitchcock/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "AndersNoren Lovecraft", ("/wp-content/themes/lovecraft/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Anexis", (".cloud.anex.is",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Angular Gridster", ("angular-gridster.js",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "AngularJS", ("bangular.{0,32}.js",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Animation Addons", ("/wp-content/plugins/extension-for-animation-addons/",), ("HTTP",), "medium"),
    # --- コメントシステム ---
    Rule("コメントシステム", "Annoto", (".annoto.io",), ("HTTP",), "medium"),
    # --- フィードリーダー ---
    Rule("フィードリーダー", "AnnounceKit", ("cdn.announcekit.app/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "AntiBot.Cloud", ("/antibot8/static/peel.js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "AOS", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "Apache APISIX", ("X-APISIX-Upstream-Status",), ("HTTP",), "medium"),
    # --- Wiki ---
    Rule("Wiki", "Apache JSPWiki", ("<html xmlns:jspwiki=",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "Apache Tomcat", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "ApexPages", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Apigee", ("/profiles/apigee",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Apisearch", ("static.apisearch.cloud",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Aplazame", ("aplazame.com/static/aplazame.js",), ("HTTP",), "medium"),
    Rule("決済代行", "Aplazame", ("cdn.aplazame.com/aplazame.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Apodle", (".apodle.com",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Apollo", ("Access-Control-Allow-Headers",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Appian", ("tempo/ui/sail-client/embeddedBootstrap.nocache.js",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Appifiny", ("recently.appifiny.io/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Appjustable", ("//appjustable.com/",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "Apple MapKit JS", ("content-security-policy",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "Apple Sign-in", ("appleid-signin-client-id",), ("HTTP",), "medium"),
    Rule("認証", "Apple Sign-in", ("appleid.auth.js",), ("HTTP",), "medium"),
    # --- ロードバランサー ---
    Rule("ロードバランサー", "Application Request Routing", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "Applied CSR24", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Apruvd", (".apruvd.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Arastta", ("arastta.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Arastta", ("X-Arastta",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Arastta", ("x-arastta",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Arastta", ("Arastta",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Arc", ("arc.io/widget.js",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "ArcGIS API for JavaScript", ("basemaps.arcgis.com",), ("HTTP",), "medium"),
    Rule("マップ", "ArcGIS API for JavaScript", ("js.arcgis.com",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Arengu", ("sdk.arengu.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "ARI Network Services", (".ari-secure.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Arketa", ("app.arketa.co",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Arkose Labs", ("Content-Security-Policy-Report-Only",), ("HTTP",), "medium"),
    Rule("セキュリティ", "Arkose Labs", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Armin", (".chatarmin.com/",), ("HTTP",), "medium"),
    Rule("CRM", "Arnica", ("app.arnica.pro",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Art Schema", (".artschema.net/",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Artifactory", ("wicket/resource/org.artifactory.",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Aruba.it", ("x-servername",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "aSc EduPage", ("static.edupage.org",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Asciinema", ("<asciinema-player",), ("HTTP",), "medium"),
    Rule("動画プレーヤー", "Asciinema", ("asciinema.org/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Asgaros Forum", ("/wp-content/plugins/asgaros-forum/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "AstraFit", ("widget.astrafit.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Astute Solutions", (".iperceptions.com",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Atatus", ("/atatus.js",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "aThemes Airi", ("/wp-content/themes/airi/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "aThemes Astrid", ("/wp-content/themes/astrid/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "aThemes Hiero", ("/wp-content/themes/hiero/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "aThemes Moesia", ("/wp-content/themes/moesia/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "aThemes Sydney", ("/wp-content/themes/sydney/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Athena Search", ("wp-content/plugins/athena-search",), ("HTTP",), "medium"),
    Rule("検索エンジン", "Athos Commerce", ("cdn.searchspring.net",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Atlassian Bitbucket", ("application-name",), ("HTTP",), "medium"),
    # --- Wiki ---
    Rule("Wiki", "Atlassian Confluence", ("X-Confluence-Request-Time",), ("HTTP",), "medium"),
    Rule("Wiki", "Atlassian Confluence", ("confluence-request-time",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Atlassian Jira", ("application-name",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Atlassian Jira Issue Collector", ("atlassian.jira.collector.plugin",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Atlassian Jira Issue Collector", ("jira-issue-collector-plugin",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Atlassian Statuspage", ("X-StatusPage-Skip-Logging",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Atlassian Statuspage", ("X-StatusPage-Version",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "ATSHOP", (".atshop.io",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "Attracta", ("cdn.attracta.com/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Attraqt", ("cdn.attraqt.io",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Aurelia", ("/aurelia.js",), ("HTTP",), "medium"),
    # --- メディアサーバー ---
    Rule("メディアサーバー", "Ausha", ("widget.ausha.co",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "Auth0", ("x-auth0-requestid",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "authorize.net", ("authorizenet/directpost_payment",), ("HTTP",), "medium"),
    Rule("決済代行", "authorize.net", ("Content-Security-Policy",), ("HTTP",), "medium"),
    Rule("決済代行", "authorize.net", ("js.authorize.net",), ("HTTP",), "medium"),
    Rule("決済代行", "authorize.net", (".authorize.net/",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "authorized.by", ("app.authorized.by",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Autocommerce", (".autocommerce.io/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Autoconf", ("static.autoconf.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Automabots", (".automabots.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "AutoManager", (".automanager.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "AutoVitals", ("docs.autovitals.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Auxilia", (".theauxilia.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Avada AVASHIP", ("freeshippingbar.apps.avada.io/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Avada Boost Sales", ("boostsales.apps.avada.io/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Avada SEO", ("seo.apps.avada.io/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Avada Size Chart", ("sizechart.apps.avada.io/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Avasam", ("X-Forwarded-Host",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Avasam", ("Host",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Avizi", ("app.avizi.fr",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Awesomplete", ("/awesomplete.js",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "AWS WAF Captcha", ("captcha.awswaf.com/",), ("HTTP",), "medium"),
    Rule("セキュリティ", "AWS WAF Captcha", ("x-amzn-waf-action",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Awtomic", ("cdn/shop/.awtomic..jsv=d",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Azko CMS", ("//js.fw.azko.fr/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Azoya", ("x-azoya-webisteid",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Azure", ("x-ms-correlation-request-id",), ("HTTP",), "medium"),
    Rule("PaaS", "Azure", ("x-ms-client-request-id",), ("HTTP",), "medium"),
    Rule("PaaS", "Azure", ("x-ms-gateway-requestid",), ("HTTP",), "medium"),
    Rule("PaaS", "Azure", ("azure-regionname",), ("HTTP",), "medium"),
    Rule("PaaS", "Azure", ("azure-sitename",), ("HTTP",), "medium"),
    Rule("PaaS", "Azure", ("azure-slotname",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Azure CDN", ("X-EC-Debug",), ("HTTP",), "medium"),
    # --- ロードバランサー ---
    Rule("ロードバランサー", "Azure Front Door", ("X-Azure-Ref",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Back In Stock", ("app.backinstock.org/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Backbone.js", ("backbone..js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Backdrop", ("X-Backdrop-Cache",), ("HTTP",), "medium"),
    Rule("CMS", "Backdrop", ("X-Generator",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Balance", (".getbalance.com/",), ("HTTP",), "medium"),
    # --- エディタ ---
    Rule("エディタ", "BannerBoo", (".bannerboo.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Banshee", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Barion", ("pixel.barion.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Base", ("base-theme-name",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Base", ("thebase.in/js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Base44", ("apple-mobile-web-app-title",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Basic", ("WWW-Authenticate",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Bask Health", ("analytics.bask.health",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Batchbook", (".batchbook.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "bdok", ("cdn.ibdok.ir/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Beae", ("beae.base.min.js",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Beam AfterSell", (".aftersell.app/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Beam OutSell", ("//outsellapp.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Beddy", ("cdn.beddy.io/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Beeshop", ("/beeshop/js/BeeShop.Ajax.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Bentobox", (".getbento.com/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Bernet Cloud", ("Bc-Powered-By",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Better Price", ("/shopify-apps//js/betterprice/betterprice.js",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "BeyondMenu", ("static.beyondmenu.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "BigCommerce", ("bigcommerce/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "BigCommerce B2B Edition", ("cdn.bundleb2b.net/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Bigin", ("sdk.bigin.io/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Bikayi", ("assets.bikayi.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "BinderPOS", (".binderpos.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "BirdSeed", (".birdseed.io/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "BiteSpeed", ("cdn.bitespeed.co/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Bitrix24", (".bitrix24../bitrix/js/crm/form_loader.js",), ("HTTP",), "medium"),
    Rule("CRM", "Bitrix24", ("cdn.bitrix24.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Blackcart", (".blackcart.co/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Blade", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Blankshield", ("/js/blankshield/blankshield.min.js",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Blazor", ("blazor.webassembly.js",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Blazor", ("blazor.host.min.js",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Blazor", ("blazor.server.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Blinger", ("app.blinger.io/",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Blinklink", (".blinklink.com/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Blitz.js", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Blocksy Companion", ("/wp-content/plugins/blocksy-companion/",), ("HTTP",), "medium"),
    # --- 写真ギャラリー ---
    Rule("写真ギャラリー", "Bloom Portfolio", ("application-name",), ("HTTP",), "medium"),
    Rule("写真ギャラリー", "Bloom Portfolio", ("code.bloom.io",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Bloomreach", ("</binaries/content/gallery/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Bloomreach Discovery", (".brsrvr.com/",), ("HTTP",), "medium"),
    Rule("検索エンジン", "Bloomreach Discovery", (".brcdn.com/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Blue Triangle", (".btttag.com/btt.js",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Bluehost", ("host-header",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Blutui", ("cdn.blutui.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "BMT Micro", ("secure.bmtmicro.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Bobonus", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Bodygram", (".bodygram.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "BoidCMS", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Bold Brain", ("brain-assets.boldapps.net/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Bold Bundles", ("bundles.boldapps.net/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Bold Custom Pricing", ("cp..boldapps.net/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Bold Motivator", ("motivate.boldapps.net/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Bold Options", ("option.boldapps.net",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Bold Page Builder", ("/wp-content/plugins/bold-page-builder/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Bold Product Options", ("option.boldapps.net/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Bold Subscriptions", ("sub.boldapps.net/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Bold Upsell", ("upsells.boldapps.net/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "BoldGrid", ("/wp-content/plugins/post-and-page-builder",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Bolt Payments", ("connect.bolt.com/",), ("HTTP",), "medium"),
    Rule("決済代行", "Bolt Payments", ("account.bolt.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "BON Loyalty", ("app.bonloyalty.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Bonsai", ("apple-mobile-web-app-title",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Bontii", ("api.bontii.dk/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Bookboost", ("web-messenger.bookboost.io",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "BookingKoala", ("cdn.bookingkoala.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "BookManager", (".bookmanager.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Bookster", ("cdn.booksterhq.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "BookThatApp", (".bookthatapp.com/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Bool TypeScript", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "BOOM", ("X-Supplied-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Boost.ai", (".boost.ai/chatPanel/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Booster Page Speed Optimizer", ("/assets/booster-page-speed-optimizer.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Bootpay", (".bootpay.co.kr/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Bootstrap Table", ("bootstrap-table.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Botble CMS", ("CMS-Version",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Boutir", ("static.boutir.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Boxmode", ("storage.boxmode.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Braintree", ("js.braintreegateway.com",), ("HTTP",), "medium"),
    Rule("決済代行", "Bread", (".getbread.com",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Bricks", ("/wp-content/themes/bricks/assets/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "BridgerPay", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- 静的サイトジェネレーター ---
    Rule("静的サイトジェネレーター", "Bridgetown", ("/_bridgetown/static/..js",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "BrightEdge", (".brightedge.com/",), ("HTTP",), "medium"),
    Rule("SEO", "BrightLocal", (".brightlocal.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Brightspot", (".brightspotcdn.com",), ("HTTP",), "medium"),
    Rule("CMS", "Brightspot", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Brilliant Web-to-Lead", ("/wp-content/plugins/salesforce-wordpress-to-lead/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Brimble", ("x-brimble-id",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Briqpay", ("api.briqpay.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Brivity", ("cdn1.brivityidx.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Brizy Cloud", ("b-cloud.b-cdn.net/builds//d-cloud",), ("HTTP",), "medium"),
    Rule("CMS", "Brownie", ("assets.youthsrl.com/brownie",), ("HTTP",), "medium"),
    Rule("CMS", "Brownie", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Brushd", ("assets.brushd.co/",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Brushd", ("X-Computed-Host",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Bubble", ("x-bubble-capacity-limit",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Bubble", ("x-bubble-capacity-used",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Bubble", ("x-bubble-perf",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "BugHerd", (".bugherd.com/",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Buglog", ("api.buglog.io/",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "BugSnag", ("/bugsnag..js",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Bugzilla", ("<main id=\"bugzilla-body\"",), ("HTTP",), "medium"),
    # --- プログラミング言語 ---
    Rule("プログラミング言語", "bun", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Business Catalyst", ("<!-- BC_OBNW -->",), ("HTTP",), "medium"),
    Rule("CMS", "Business Catalyst", ("CatalystScripts",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "ButterMove", ("widget.buttermove.com",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "BuySafe", ("seal.buysafe.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Buz Club", ("secure.buzclubsoftware.com",), ("HTTP",), "medium"),
    # --- プログラミング言語 ---
    Rule("プログラミング言語", "C", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "c/side", (".cside.dev",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "CacheFly", ("X-CF1",), ("HTTP",), "medium"),
    Rule("CDN", "CacheFly", ("X-CF2",), ("HTTP",), "medium"),
    # --- コメントシステム ---
    Rule("コメントシステム", "Cackle", ("k.cackle.me/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "CakePHP", ("application-name",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Candid", ("api.getcandid.com",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "CanJS", ("/canjs/can.custom.min.js",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Canny", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Canvas LMS", ("x-canvas-meta",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Caramella", ("assets.caramel.la",), ("HTTP",), "medium"),
    # --- リモートアクセス ---
    Rule("リモートアクセス", "Cardina", ("static.cohere.so",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "CareCart", ("app.carecart.io/api/abandoned-cart/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "CareCart Cartly Abandoned Cart Recovery", ("app.carecart.io/api/abandoned-cart/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "CareCart Sales Pop Up", ("sales-pop.carecart.io/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "CareCloud", ("community.carecloud.com/",), ("HTTP",), "medium"),
    Rule("CRM", "Caremerge", (".caremerge.com",), ("HTTP",), "medium"),
    # --- リモートアクセス ---
    Rule("リモートアクセス", "CargoServer", ("application-name",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Carro", (".getcarro.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Cart Functionality", ("googlecommerce.com/trustedstores/api/js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Cart.com", (".americommerce.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "CartBot", ("cdn-app.cart-bot.net/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Cartera", (".cartera.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Cartline", ("x-cartline-platform",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Cartline", ("application-name",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Cartpanda", (".cartpanda.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Carussel", (".carussel.dealer.toolkit",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Caspio", (".caspio.com/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Catberry.js", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Catch Themes Catch Box", ("/wp-content/themes/catch-box/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Catch Themes Fotografie", ("/wp-content/themes/fotografie/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "CDK Global", (".connectcdk.com/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "cdnjs", ("cdnjs.cloudflare.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Celerant", ("cdn.celerantwebservices.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Cendyn", ("plugins.traveltripper.io/",), ("HTTP",), "medium"),
    Rule("CMS", "Cendyn", ("x-powered-by",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Centium", ("bookings.centiumsoftware.com",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "Centminmod", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Centra", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Chabokan", ("ch-powered-by",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "Chakra UI", (".chakra-ui.",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Chamilo", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "ChargeAfter", ("cdn.chargeafter.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Chatlyn", ("app.chatlyn.com/",), ("HTTP",), "medium"),
    Rule("CRM", "ChatNode", ("embed.chatnode.ai/",), ("HTTP",), "medium"),
    Rule("CRM", "Chatsimple", ("cdn.chatsimple.ai/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Chayns", ("api.chayns-static.space",), ("HTTP",), "medium"),
    # --- 写真ギャラリー ---
    Rule("写真ギャラリー", "Chevereto", ("/chevereto.js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Choices", ("/modules/choices/js/choices.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Citizen Space", ("/static/vendor/dlb-admin-ui/",), ("HTTP",), "medium"),
    # --- リモートアクセス ---
    Rule("リモートアクセス", "Citrix", ("/ctxs.core.min.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "CitrusPay", ("checkout-static.citruspay.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "CivicPlus", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "CiviCRM plugins", ("wp-content/plugins/civicrm/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "CJDropshipping app", ("app.cjdropshipping.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Ckan", ("Access-Control-Allow-Headers",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Clarifai", ("sdk.clarifai.com",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "Clarity", ("clr-angular.js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Classnames", ("classnames.w{0,20}.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Clayful", (".clayful.io",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "CleanTalk", ("moderate.cleantalk.org/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Clearpay", (".clearpay.co.uk/",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Cleeng", ("cdn.cleeng.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Cleverbridge", ("static-cf.cleverbridge.w/js/Shop.js",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "ClickCease", (".clickcease.com/monitor/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "ClickFunnels", ("cf:app_domain:",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "ClickHelp", ("Content-Security-Policy-Report-Only",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "ClickReport", ("service.clickreport.com",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "ClickUp", ("/app-cdn.clickup.com/",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Clipara", (".getclipara.com",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Clockwork", ("x-clockwork-version",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Cloud Guard", ("cg-server-tag",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "CloudCannon", ("cc-build-id",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "CloudCart", ("/cloudcart-/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Cloudflare", ("cf-cache-status",), ("HTTP",), "medium"),
    Rule("CDN", "Cloudflare", ("cf-ray",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Cloudfy", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Cloudinary", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Cloudways", ("cache-provider",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Cludo", ("customer.cludo.com/",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "ClustrMaps Widget", ("clustrmaps.com",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "CodeIgniter", ("<inputname=\"ci_csrf_token\"",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Coin Currency Converter", ("/apps/coin/coin.js..myshopify.com",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Colorlib Activello", ("/wp-content/themes/activello/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Colorlib Illdy", ("/wp-content/themes/illdy/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Colorlib Shapely", ("/wp-content/themes/shapely/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Colorlib Sparkling", ("/wp-content/themes/sparkling/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Colorlib Travelify", ("/wp-content/themes/travelify/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Comarch e-Sklep", ("static.comarchesklep.pl",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Combahton FlowShield", ("X-Flowproxy-Author",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "CometD", ("/cometd/jquery.cometd.js",), ("HTTP",), "medium"),
    # --- コメントシステム ---
    Rule("コメントシステム", "Commento", ("cdn.commento.io/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "CommentSold", ("s3.commentsold.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Commerce Server", ("COMMERCE-SERVER-SOFTWARE",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Commerce Vision", ("Content-Security-Policy",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Commerce.js", ("chec/commerce.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Commerce.js", ("Chec-Version",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Commerce.js", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Commerce7", ("cdn.commerce7.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Common Ground", ("static.common-ground.io/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Comms", ("cdn.startcomms.com",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "Community", (".community.com/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Complianz", ("wp-content/plugins/complianz-gdpr-premium",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "ComplyAuto", ("cdn.complyauto.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Composite Products", ("/wp-content/plugins/woocommerce-composite-products",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Concrete CMS", ("/concrete/js/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Conjured", ("app.conjured.co/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Constructor.io", (".cnstrc.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Contentful", ("x-contentful-request-id",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Conversio App", (".conversio.com/..myshopify.com",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Convertri", ("cdn.convertri.com/",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Convrrt", ("cdn.convrrt.com/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Cookie Information plugin", ("/wp-content/plugins/wp-gdpr-compliance/",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "Copiny", ("widget.copiny.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "CoreMedia", ("coremedia_content_id",), ("HTTP",), "medium"),
    Rule("CMS", "CoreMedia", (".coremedia.cloud/",), ("HTTP",), "medium"),
    Rule("CMS", "CoreMedia Content Cloud", ("coremedia_content_id",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Correos Ecommerce", (".mycorreosecommerce.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Cosmoshop", ("cosmoshop_functions.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Cosmoshop", ("cosmoshop.settings",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Cosmoshop", ("/cosmoshop/",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "Countable", ("appleid-signin-client-id",), ("HTTP",), "medium"),
    Rule("メッセージボード", "Countable", ("assets.countable.us/",), ("HTTP",), "medium"),
    # --- コメントシステム ---
    Rule("コメントシステム", "Cove", ("cdn.cove.chat",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Coveo", ("static..com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Covet.pics", (".covet.pics/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Cozy AntiTheft", ("cdncozyantitheft.addons.business/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "CPG Dragonfly", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("CMS", "CppCMS", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("CMS", "Craft CMS", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Craft Commerce", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "CreateJS", ("code.createjs.com/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Creativ.eMail", ("/wp-content/plugins/creative-mail-by-constant-contact/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "CrownPeak", ("js/crownpeak.",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "CS Cart", ("var/cache/misc/assets/js/tygh/scripts-.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Culqi", (".culqi.com",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Custom Fonts", ("/wp-content/plugins/custom-fonts/",), ("HTTP",), "medium"),
    Rule("WordPressプラグイン", "Cwicly", ("/wp-content/plugins/cwicly/",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "CyberChimps Responsive", ("/wp-content/themes/responsive/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Cybersource", ("cybersource...js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Daktela Omnichannel", (".daktela.com/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Dalue", ("api.dalue.io",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Dancer", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Danneo CMS", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "DataDome", ("X-DataDome-CID",), ("HTTP",), "medium"),
    Rule("セキュリティ", "DataDome", ("X-DataDome",), ("HTTP",), "medium"),
    Rule("セキュリティ", "DataGrail", (".datagrail.io/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Datarize", ("assets.datarize.ai/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Dataships", (".dataships.io/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "DataTables", ("dataTables..js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "DatoCMS", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("CMS", "Daxko", ("Reporting-Endpoints",), ("HTTP",), "medium"),
    Rule("CMS", "Daxko", (".daxko.com/",), ("HTTP",), "medium"),
    Rule("CMS", "DedeCMS", ("dedeajax",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Delight XR", ("cdn.delight-vr.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Delm", ("cdn.delm.io/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "DERAK.CLOUD", ("Derak-Umbrage",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Deskero", (".deskero.com/",), ("HTTP",), "medium"),
    Rule("CRM", "Desku", ("livechat.desku.io/cdn/widget.js",), ("HTTP",), "medium"),
    Rule("CRM", "Desku", ("widget.desku.io/chat-widget.js",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "Develic Omnium Maps", ("maps.develic.com",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "DHTMLX", ("/dhtmlxcommon.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "DialogTab", ("cdn.dialogtab.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Didar", ("apple-mobile-web-app-title",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Digest", ("WWW-Authenticate",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "DigitalRiver", (".digitalriver.com/",), ("HTTP",), "medium"),
    # --- データベース ---
    Rule("データベース", "Dimensions AI", (".dimensions.ai",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Dimml", (".dimml.io/",), ("HTTP",), "medium"),
    # --- ホスティングパネル ---
    Rule("ホスティングパネル", "DirectAdmin", ("<a>DirectAdmin</a> Web Control Panel",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Directus", ("x-powered-by",), ("HTTP",), "medium"),
    Rule("CMS", "Disciple", ("pwa.disciplemedia.com",), ("HTTP",), "medium"),
    # --- コメントシステム ---
    Rule("コメントシステム", "Disqus", ("disqus_url",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Distributor", ("/wp-content/plugins/distributor",), ("HTTP",), "medium"),
    Rule("WordPressプラグイン", "Distributor", ("x-distributor",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Dito", ("storage.googleapis.com/dito/sdk.js",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Divhunt", ("divhunt-site.w-cdn.net/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Divido", ("cdn.divido.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Dixa", (".dixa.io",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Django CMS", ("/djangocms_",), ("HTTP",), "medium"),
    Rule("CMS", "DNN", ("<!-- by DotNetNuke Corporation",), ("HTTP",), "medium"),
    Rule("CMS", "DNN", ("X-Compressed-By",), ("HTTP",), "medium"),
    Rule("CMS", "DNN", ("/js/dnncore.js",), ("HTTP",), "medium"),
    Rule("CMS", "DNN", ("DNNOutputCache",), ("HTTP",), "medium"),
    Rule("CMS", "DNN", ("/js/dnn.js",), ("HTTP",), "medium"),
    Rule("CMS", "DNN", ("Cookie",), ("HTTP",), "medium"),
    # --- コンテナ ---
    Rule("コンテナ", "Docker", ("<!-- This comment is expected by the docker HEALTHCHECK  -->",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Docket", ("dockethosting.com/",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Docusaurus", ("docusaurus_locale",), ("HTTP",), "medium"),
    Rule("ドキュメント", "Docusaurus", ("docusaurus_tag",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Dokeos", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Dominate WooCommerce", ("/wp-content/plugins/iwd-checkout-connector/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Dooca", (".dooca.store/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Doofinder", ("cdn.doofinder.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "DoorLoop", ("app.doorloop.com",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Dorsa Cloud", ("x-cdn-provider",), ("HTTP",), "medium"),
    Rule("CDN", "Dorsa Cloud", ("x-powered-by",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Dotclear", ("X-Dotclear-Static-Cache",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "DotPe", ("cdn.dotpe.in",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Dotter", ("apps.dotter.me",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "doxo", ("embed.doxo.com/",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "DPlayer", ("/dplayer.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Dr. Leonardo", ("sitebuilder.dr-leonardo.com",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Draftpress HFCM", ("<!--HFCMsbys99sRobots",), ("HTTP",), "medium"),
    # --- プログラミング言語 ---
    Rule("プログラミング言語", "Dragon", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- エディタ ---
    Rule("エディタ", "DreamWeaver", ("<!-- #BeginTemplates\".dwt",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "DropInBlog", (".dropinblog.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Drupal", ("X-Drupal-Cache",), ("HTTP",), "medium"),
    Rule("CMS", "Drupal", ("X-Generator",), ("HTTP",), "medium"),
    Rule("CMS", "Drupal", ("drupal.js",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Drupal Multisite", ("/sites//).//",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Duda", ("dd-cdn.multiscreensite.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Dukaan", ("apple-mobile-web-app-title",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Dukaan", ("apps.mydukaan.io/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Duopana", (".beracode.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "DX1", (".dx1app.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "e-Shop Commerce", ("/template_inc/eshopstoresframework",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "e107", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "EAD Plataforma", ("assets.eadplataforma.com",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "EaselJS", ("/easeljs.min.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Easol", ("static.myeasol.net",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Easy Accordion", ("/wp-content/plugins/easy-accordion-free/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Easy Hide PayPal", ("easyhide.herculesapps.com/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Easy Pie Chart", ("asy-ie-hart.js",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Easy Redirects", ("easy-redirects../redirect-app.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "EasyBroker", (".easybroker.com/",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "EasyEngine", ("x-powered-by",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "EasyStore", (".easystore.co/",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "EasyUI", ("/jquery.easyui.min.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Ebasnet", ("cdnebasnet.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "EC-CUBE", ("eccube.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "EC-CUBE", ("win_op.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "eCaupo", (".ecaupo./",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "EcomArtists", ("app.ecomartists.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "eComchain", ("cdn.ecomchain.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Ecomtrack", ("api.ecomtrack.io/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Ecomz", ("Access-Control-Allow-Headers",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Ecomz", ("X-Ecomz-Application",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Ecomz", (".myecomz.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "eCShop", ("cdn.ecshop.com.br",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "eCShop", ("Powered",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Edgio", ("x-0-version",), ("HTTP",), "medium"),
    Rule("CDN", "Edgio", ("x-0-status",), ("HTTP",), "medium"),
    Rule("CDN", "Edgio", ("x-0-t",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "eDirectory", (".edirectory.com",), ("HTTP",), "medium"),
    # --- リッチテキストエディタ ---
    Rule("リッチテキストエディタ", "Edit-in-Place", ("/jquery.editinplace.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Elastic Path", (".moltin.com/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "ElasticPress", ("x-elasticpress-query",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "ElasticSuite", ("/Smile_ElasticsuiteTracker/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Elcodi", ("X-Elcodi",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Elementor Cloud", ("x-powered-by",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Elexio", ("//elexiocms.com/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Elliptic", ("elliptic.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Elloha", ("Access-Control-Allow-Headers",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "Elm-ui", ("<style>.explain > .s.explain > .ctr > .s",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Eloomi", ("//cdn.eloomi.com/",), ("HTTP",), "medium"),
    Rule("LMS", "Elopage", (".myelopage.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Elromco", ("embed.elromco.com/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Email Encoder for Wordpress", ("email-encoder-bundle.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Emergent", ("assets.emergent.sh",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Empretienda", ("set-cookie",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Endurance Page Cache", ("x-endurance-cache-level",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "enduro.js", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Webサーバー拡張 ---
    Rule("Webサーバー拡張", "Engintron", ("X-Server-Powered-By",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Enigma", ("/wp-content/themes/enigma/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Enjin CMS", (".enjin.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Enlistly", ("cdn.enlistly.com/",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Enrollware", ("jquery.enrollware.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Ensi", ("X-Ensi-Platform",), ("HTTP",), "medium"),
    # --- SSL/TLS認証局 ---
    Rule("SSL/TLS認証局", "Entrust", ("seal.entrust.net/",), ("HTTP",), "medium"),
    # --- リバースプロキシ ---
    Rule("リバースプロキシ", "Envoy", ("x-envoy-upstream-service-time",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "ePages", ("X-epages-RequestId",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "EraofEcom MTL", ("mtl.eraofecom.org",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Erxes", (".app.erxes.io",), ("HTTP",), "medium"),
    Rule("CRM", "eShopCRM", ("eshopcrm.com/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Essential Addons for Elementor", ("/wp-content/uploads/essential-addons-elementor/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Essential JS 2", ("< class = \" e-libb",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Estore Shopserve", ("cartd.shopserve.jp/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "eSyndiCat", ("X-Drectory-Script",), ("HTTP",), "medium"),
    # --- リッチテキストエディタ ---
    Rule("リッチテキストエディタ", "Etherpad", ("/ep_etherpad-lite/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Eticex", (".eticex.com/",), ("HTTP",), "medium"),
    # --- DMS ---
    Rule("DMS", "Evernote", ("static.evernote.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "eWAY Payments", ("secure.ewaypayments.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Excentos", ("service.excentos.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Exemptify", (".modules4u.biz/shopify/exemptify",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "ExpertRec", ("expertrec.com/api/js/ci_common.jsid=.",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Express", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "ExtendThemes Calliope", ("/wp-content/themes/calliope/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ExtendThemes EmpowerWP", ("/wp-content/themes/empowerwp/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ExtendThemes Highlight", ("/wp-content/themes/highlight/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ExtendThemes Materialis", ("/wp-content/themes/materialis/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ExtendThemes Mesmerize", ("/wp-content/themes/mesmerize/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "ExtJS", ("ext-base.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "eZ Publish", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "EZLynx", (".ezlynx.com/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "F5 Distributed Cloud Services", ("X-Volterra-Location",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Facilita", ("cdn.appfacilita.com/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Fact Finder", ("<!-- Factfinder",), ("HTTP",), "medium"),
    Rule("検索エンジン", "Fact Finder", ("Suggest.ff",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "FalguniThemes Nisarg", ("/wp-content/themes/nisarg/",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Famous.ai", ("static.famous.ai",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "FaraPy", ("<!-- Powered by FaraPy.",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "Farazi Bilişim", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "FARFETCH Black & White", ("cdn-static.farfetch-contents.com.js",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "FASO", ("X-Faso-Server-Execution-Time",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Fast Bundle", ("api.fastbundle.co/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Fast Checkout", ("js.fast.co/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "FAST ESP", ("<formid=\"fastsearch\"",), ("HTTP",), "medium"),
    Rule("検索エンジン", "FAST Search for SharePoint", ("<input name=\"ParametricSearch",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Fast Simon", (".fastsimon.com/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Fastly", ("Fastly-Debug-Digest",), ("HTTP",), "medium"),
    Rule("CDN", "Fastly", ("X-Fastly-Request-ID",), ("HTTP",), "medium"),
    Rule("CDN", "Fastly", ("x-fastly-request-id",), ("HTTP",), "medium"),
    Rule("CDN", "Fastly", ("x-fastly-origin",), ("HTTP",), "medium"),
    Rule("CDN", "Fastly", ("x-via-fastly",), ("HTTP",), "medium"),
    # --- キャッシュ ---
    Rule("キャッシュ", "FastPixel", ("api.fastpixel.io/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Fat Zebra", ("<paynow.pmnts.io",), ("HTTP",), "medium"),
    Rule("決済代行", "Fat Zebra", ("paynow.pmnts.io",), ("HTTP",), "medium"),
    Rule("決済代行", "Fat Zebra", ("<FatZebraFrame",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Fat-Free Framework", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "FatherShops", ("fathershop/view/theme/fs/",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Faveo", ("/lb-faveo/js/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Feroot", ("pg.feroot.com",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "Ferron", ("X-Ferron-Cache",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "FilePond", ("filepond.js",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Filestack", (".filestackapi.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "FinConnect", ("app.finconnect.nl",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Findberry", (".findberry.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Finsweet", ("cdn.finsweet.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "FireApps Ali Reviews", ("//alireviews.fireapps.io/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Firepush", ("fpcdn.me/.shopify",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Firepush", ("cdn.firepush.w",), ("HTTP",), "medium"),
    # --- メディアサーバー ---
    Rule("メディアサーバー", "Fireside", ("a.fireside.fm/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Flazio", ("//flazio.org/",), ("HTTP",), "medium"),
    Rule("CMS", "FlexCMP", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("CMS", "FlexCMP", ("X-Flex-Lang",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "FlexiFunnels", (".flexifunnels.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Flexmls", ("/plugins/flexmls-idx/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "FlexyPe", ("static.flexype.in",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Flip-Pay", ("cdn.flip-pay.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "FlipBuilder", (".flipbuilder.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Flipsnack", ("cdn.flipsnack.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Floranext", ("assets.floranext.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Florist Touch", (".floristtouch.co.uk/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Florist Window", ("document-classification",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Fluid Player", ("cdn.fluidplayer.com",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Fly.io", ("fly-request-id",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Flying Analytics", ("/wp-content/plugins/flying-analytics/",), ("HTTP",), "medium"),
    Rule("WordPressプラグイン", "FlyingPress", ("/wp-content/plugins/flying-press/",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "Flyvi", ("widget.flyvi.io/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Flywheel", ("x-fw-server",), ("HTTP",), "medium"),
    Rule("PaaS", "Flywheel", ("x-fw-static",), ("HTTP",), "medium"),
    Rule("PaaS", "Flywheel", ("x-fw-serve",), ("HTTP",), "medium"),
    Rule("PaaS", "Flywheel", ("x-fw-hash",), ("HTTP",), "medium"),
    Rule("PaaS", "Flywheel", ("x-fw-type",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "FOCUS WebWall", ("/focus_webwall/./focus-webwall.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Follow Up Boss", (".followupboss.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Fontify", ("fontify.nitroapps.co/",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Forento", ("static.forento.site",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Forie", (".forie.com/",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Form.io", ("cdn.form.io",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "Formalize CSS", ("/js/jquery.formalize.js",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Formaloo", ("//formaloo.net/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Format", ("X-Format-Path",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Formcan", ("static.formcan.com/",), ("HTTP",), "medium"),
    Rule("フォームビルダー", "Formrun", ("sdk.form.run",), ("HTTP",), "medium"),
    Rule("フォームビルダー", "Formsite", (".formsite.com/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Formstone", ("jquery.formstone.min.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Forte", ("checkout.forte.net",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Forter", ("forter.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Fortune3", ("cartjs.phps=myfortune3cart.com",), ("HTTP",), "medium"),
    # --- Wiki ---
    Rule("Wiki", "Foswiki", ("foswiki.SERVERTIME",), ("HTTP",), "medium"),
    Rule("Wiki", "Foswiki", ("foswiki.WIKINAME",), ("HTTP",), "medium"),
    Rule("Wiki", "Foswiki", ("X-Foswikiaction",), ("HTTP",), "medium"),
    Rule("Wiki", "Foswiki", ("X-Foswikiuri",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Four", ("scripts.paywithfour.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Fourthwall", (".fourthwall.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Foxy.io", ("cdn.foxycart.com",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Framer Sites", ("framerusercontent.com",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Fraud Blocker", ("monitor.fraudblocker.com",), ("HTTP",), "medium"),
    Rule("セキュリティ", "FraudLabs Pro", (".fraudlabspro.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Freemius", ("checkout.freemius.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "freewebstore", ("Content-Security-Policy",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "freewebstore", ("X-Fws-Platform",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Frequently Bought Together", (".codeblackbelt.com/js/modules/frequently-bought-together/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Freshop", ("asset.freshop.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Freshworks CRM", ("cdn.freshmarketer.com",), ("HTTP",), "medium"),
    Rule("CRM", "Freshworks CRM", ("cdn.zarget.com",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Frontastic", ("frontastic-request-id",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Frontlead", ("app.frontlead.io",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Froonze", ("cdn.shopify.com/extensions//froonze-loyalty-wishlist",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Fullbay", ("app.fullbay.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "FurnitureDealer", (".furnituredealer.net/",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Furo", ("static/scripts/furo.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Future Shop", ("future-shop..js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Fuzey Channels", ("widget.fuzey.io",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Fygaro", ("api.fygaro.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Fynd Platform", (".fynd.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "GaniPara", ("apple-mobile-web-app-title",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "GaniPara", (".ganipara.com/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Gcore", ("x-id-fe",), ("HTTP",), "medium"),
    Rule("CDN", "Gcore", ("x-id",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "GeeTest", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("セキュリティ", "GeeTest", (".geetest.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Gekosale", ("bgekosale.jsb",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Gelato", (".live.gelato.tech",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "GemPages", ("/files/gempagevd.js",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Genesis blocks", ("/wp-content/themes/genesis-blocks/lib/js/",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Genesis theme", ("/wp-content/themes/genesis/lib/js/",), ("HTTP",), "medium"),
    # --- プログラミング言語 ---
    Rule("プログラミング言語", "GeneXus", ("/static/gxtimezone.js",), ("HTTP",), "medium"),
    Rule("プログラミング言語", "GeneXus", ("/static/gxgral.js",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "genezio", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Genially", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Gerrit", ("gerrit_ui/gerrit_ui",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Gestim", ("stats.gestim.biz",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Get Siimple", ("analytics.getsiimple.com/",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "GetSocial", ("api.at.getsocial.io",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "GetTerms", ("app.getterms.io",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Ghost", ("X-Ghost-Cache-Status",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "GitHub Pages", ("X-GitHub-Request-Id",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "gitweb", ("static/gitweb.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Giveffect", (".giveffect.com",), ("HTTP",), "medium"),
    Rule("CRM", "Gladly", ("cdn.gladly.com",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "GlitchTip", ("app.glitchtip.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Globo Also Bought", ("assets/globo.alsobought.js",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Globo Color Swatch", ("assets/globo.swatch.data.js",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Globo Form Builder", ("/assets/globo.formbuilder.init.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Gloo", (".gloo.us/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "GLPI", ("glpi:csrf_token",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "GlueUp", (".glueup.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "GOb2b", ("cdn.gob2b.com",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "GoCache", ("X-GoCache-CacheStatus",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "GoDaddy CoBlocks", ("/wp-content/plugins/coblocks/",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Gogs", ("js/gogs.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "GoodApps", (".goodapps.io",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Google Hosted Libraries", ("ajax.googleapis.com/ajax/libs/",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "Google Maps", ("//maps.google.com/maps/api/js",), ("HTTP",), "medium"),
    # --- キャッシュ ---
    Rule("キャッシュ", "Google PageSpeed", ("X-Mod-Pagespeed",), ("HTTP",), "medium"),
    Rule("キャッシュ", "Google PageSpeed", ("X-Page-Speed",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Google Pay", ("pay.google.com//pay.js",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "Google Sign-in", ("accounts.google.com/gsi/client",), ("HTTP",), "medium"),
    Rule("認証", "Google Sign-in", ("google-signin-client_id",), ("HTTP",), "medium"),
    Rule("認証", "Google Sign-in", ("google-signin-scope",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Google Wallet", ("checkout.google.com",), ("HTTP",), "medium"),
    Rule("決済代行", "Google Wallet", ("wallet.google.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Gorilla Dash", ("//gorilladash.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Goshly", (".goshlyanalytics.com/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "GotiPath", ("X-Cache",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "GOV.UK Template", ("govuk-template.js",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "GoZen Forms", ("signup-forms-cdn.app.gozen.io/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Grab Pay Later", ("grab-paylater.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Graffiti CMS", ("/graffiti.js",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Grain Harvest", ("cdn.harvest.graindata.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Grappos", ("locator.grappos.com",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "GreatPages", (".greatpages.com.br/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Green Valley CMS", ("<img/dsresourceobjectid=",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "GreenRope", ("app.greenrope.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "GrocerKey", ("grocerkey-widget.s3.amazonaws.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "GrocerKey", (".grocerywebsite.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Groove", (".groovehq.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "GroovePages", ("//app.groove.cm/groovepages/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "GroupBy", ("cdn.groupbycloud.com",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "Growave", (".socialshopwave.com/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "GSAP", ("TweenMax.js",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "GTranslate app", ("gtranslate.io/shopify/",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "GuideIT", ("platform",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Gumroad", ("gumroad.com/js/gumroad-embed.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Gumroad", ("gumroad.com/js/gumroad.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Gumroad", ("gumroad.com/packs/js/",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Gurucan", ("assets.gurucan.com",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Gutenberg", ("/wp-content/plugins/gutenberg/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "GX WebManager", ("<!--sPowered by GX",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Haddock", ("haddock-util.js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Hammer.js", ("hammer.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Hapana", (".hapana.com/",), ("HTTP",), "medium"),
    Rule("CRM", "HappyFox Helpdesk", (".happyfox.com/media/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Haravan", ("haravan..js",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Hashnode", ("hashnode.com",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "HashThemes Total", ("/wp-content/themes/otal/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Hatena Blog", ("cdn.blog.st-hatena.com/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "hCaptcha", ("content-security-policy",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "HCL Digital Experience", ("Itx-Generated-Timestamp",), ("HTTP",), "medium"),
    Rule("CMS", "HCL Digital Experience", ("IBM-Web2-Location",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "HeadJS", ("<data-headjs-load",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "HeadJS", ("head..js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Heartland Payment Systems", (".heartlandportico.com",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Heights Platform", ("Access-Control-Allow-Origin",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Helhost", (".helhost.com/",), ("HTTP",), "medium"),
    Rule("ホスティング", "Helhost", ("x-powered-by",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "HeliumWeb", ("helium/src/helium.js/helium_web.js",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "HeliumWeb", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Help Scout", (".helpscout.net/",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "HelpDocs", ("cdn.helpdocs.io",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Helpwise", ("cdn.helpwise.io",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Heroic", ("app.heroicnow.com/",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "HetrixTools", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "HetrixTools", (".hetrixtools.com/",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Hetzner", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Hexia", ("sdk.hexia.io",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Hextom Free Shipping Bar", (".hextom.com/js/freeshippingbar.js",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Hextom Ultimate Sales Boost", (".hextom.com/js/ultimatesalesboost.js",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Heyflow", ("static.heyflow.app/",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "HHVM", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "Higher Logic Vanilla", (" x-vanilla-version",), ("HTTP",), "medium"),
    Rule("メッセージボード", "Higher Logic Vanilla", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "HighLevel", (".leadconnectorhq.com/",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Highlight.io", ("unpkg.com/highlight.run",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Hikari CS", ("widget.hikarics.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "HiPay", (".hipay.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Hit-Mall", ("/hitmall.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Hiver", ("chat-widget.hiverhq.com/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Hono", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Hoowla", ("cdn.hoowla.com",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Hostinger", ("platform",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Hostinger Horizons", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Hostinger Website Builder", ("userapp.zyrosite.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Hosttech Website Creator", ("wsc_rendermode",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Hotbot", ("api.hotbot.ai",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "HSTS", ("Strict-Transport-Security",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "HubSpot CMS Hub", ("x-powered-by",), ("HTTP",), "medium"),
    Rule("CMS", "HubSpot CMS Hub", ("x-hs-hub-id",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "HulkApps Age Verification", ("age-verification.hulkapps.com/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "HulkApps Form Builder", ("formbuilder.hulkapps.com/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "HulkApps GDPR/CCPA Compliance Manager", ("cookiebar.hulkapps.com/hulk_cookie_bar.js",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Human Presence", ("/..humanpresence./",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Hund.io", (".hund.io/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Hydrogen", ("powered-by",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Hyperlane", (".hyperlane.co/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Hyperspeed", ("cdn.shopify.com/./assets/hs-.min.js",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Hypervisual Page Builder", ("cdn.gethypervisual.com/",), ("HTTP",), "medium"),
    # --- ホスティングパネル ---
    Rule("ホスティングパネル", "i-MSCP", ("application-name",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Ibexa DXP", ("x-powered-by",), ("HTTP",), "medium"),
    # --- リバースプロキシ ---
    Rule("リバースプロキシ", "IBM DataPower", ("X-Global-Transaction-ID",), ("HTTP",), "medium"),
    Rule("リバースプロキシ", "IBM DataPower", ("X-Backside-Transport",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "iCheck", ("//icheck.min.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Ideasoft", (".ideasoft.dev/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Identixweb iCart", ("cdnicart.identixweb.com",), ("HTTP",), "medium"),
    # --- 会計・経理 ---
    Rule("会計・経理", "Ignition", (".practiceignition.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Ikas", ("x-powered-by",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Iluria", ("template-assets.iluria.com/commons/",), ("HTTP",), "medium"),
    # --- 写真ギャラリー ---
    Rule("写真ギャラリー", "Imagekit", ("x-server",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Imagely NextGEN Gallery", ("/wp-content/plugins/nextgen-gallery/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Immerss", (".immerss.live/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Immutable.js", ("immutable.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "imperia CMS", ("x-imperia-live-info",), ("HTTP",), "medium"),
    # --- リモートアクセス ---
    Rule("リモートアクセス", "Impero", (".netop.com",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Imperva", ("/_Incapsula_Resource",), ("HTTP",), "medium"),
    Rule("セキュリティ", "Imperva", ("X-Iinfo",), ("HTTP",), "medium"),
    Rule("セキュリティ", "Imperva", ("X-CDN",), ("HTTP",), "medium"),
    Rule("セキュリティ", "Imperva", ("x-cdn",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Importify", ("app.importify.net/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Impresee", ("cdn.impresee.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "ImpressCMS", ("include/linkexternal.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Imweb", ("vendor-cdn.imweb.me/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "In Cart Upsell & Cross-Sell", (".incartupsell.com/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Incapsula", ("X-CDN",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Incident.io", ("x-webkit-csp",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Includable", ("X-Includable-Version",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Inertia.js", ("X-Inertia",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Infor", (".cloud.infor.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "InkSoft", ("cdn.inksoft.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "InnoShop", (".innoshop.cn",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Inplayer", ("assets.inplayer.com",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Inputflow", ("script.inputflow.io",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "inSales", ("insales-redefined-api-method",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Insightly CRM", (".insightly.services/",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Inso", ("Access-Control-Allow-Origin",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Instafeed", ("instafeed.nfcube.com/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Instafeed.js", ("instafeed.js",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Instana", ("eum.instana.io",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Instant.Page", ("instant.page",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "InstantClick", ("instantclick.min.js",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "InstantGeo", ("script.instantgeo.info",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "InstantGeo", ("js.instantgeo.info",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Instapage", ("heatmap-events-collector.instapage.com",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Instapage", ("cdn.instapagemetrics.com",), ("HTTP",), "medium"),
    # --- コメントシステム ---
    Rule("コメントシステム", "IntenseDebate", ("intensedebate.com",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Intersection Observer", ("/assets/intersection-observer..js",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Intervo", ("widget.intervo.ai",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Intiaro", ("libs.intiaro.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Invision Community", (".invisioncic.com/",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "Invision Power Board", ("jscripts/ips_",), ("HTTP",), "medium"),
    Rule("メッセージボード", "IPB", ("jscripts/ips_",), ("HTTP",), "medium"),
    # --- ネットワークストレージ ---
    Rule("ネットワークストレージ", "IPFS", ("x-cf-ipfs-cache-status",), ("HTTP",), "medium"),
    Rule("ネットワークストレージ", "IPFS", ("x-ipfs-gateway-host",), ("HTTP",), "medium"),
    Rule("ネットワークストレージ", "IPFS", ("x-ipfs-datasize",), ("HTTP",), "medium"),
    Rule("ネットワークストレージ", "IPFS", ("x-ipfs-root-cid",), ("HTTP",), "medium"),
    Rule("ネットワークストレージ", "IPFS", ("x-ipfs-lb-pop",), ("HTTP",), "medium"),
    Rule("ネットワークストレージ", "IPFS", ("x-ipfs-roots",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "IrisLMS", (".irislms.ir/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "iTCHYROBOT", ("/wp-content/themes/itchyrobot_parent/js/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Iteras", ("app.iteras.dk",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "iThemes Security", ("/wp-content/plugins/better-wp-security/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Itoris", (".itoris.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "iugu", ("js.iugu.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "iWiki", (".kirra.nl",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Jacklist", ("api.jacklist.jp/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Jadu", ("Node",), ("HTTP",), "medium"),
    Rule("CMS", "Jadu Central Content", ("Author-Template",), ("HTTP",), "medium"),
    Rule("CMS", "Jahia DX", ("<script id=\"staticAssetAggregatedJavascrip",), ("HTTP",), "medium"),
    Rule("CMS", "JamFeed", ("cdn.jamfeed.com",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Java Servlet", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Javadoc", ("<!-- Generated by javadoc -->",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "JavaServer Faces", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "JavaServer Pages", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "JBoss Application Server", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("Webサーバー", "JBoss Web", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 静的サイトジェネレーター ---
    Rule("静的サイトジェネレーター", "Jekyll", ("<!-- Created with Jekyll Now -",), ("HTTP",), "medium"),
    Rule("静的サイトジェネレーター", "Jekyll", ("<!-- Begin Jekyll SEO tag",), ("HTTP",), "medium"),
    # --- CI・CD ---
    Rule("CI・CD", "Jenkins", ("X-Jenkins",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "JET Enterprise", ("powered",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "JetEngine", ("/wp-content/plugins/jet-engine/",), ("HTTP",), "medium"),
    Rule("WordPressプラグイン", "Jetpack", ("/wp-content/plugins/jetpack/",), ("HTTP",), "medium"),
    Rule("WordPressプラグイン", "Jetpack Boost", ("/wp-content/plugins/jetpack-boost/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Jetshop", ("< id=\"jetshop-branding\">",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Jibres", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Jibres", ("/jibres.js",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "Jiglu", (".jiglu.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Jimdo", ("X-Jimdo-Instance",), ("HTTP",), "medium"),
    Rule("CMS", "Jimdo", ("X-Jimdo-Wid",), ("HTTP",), "medium"),
    Rule("CMS", "Joomla", ("X-Content-Encoded-By",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "JoomShopping", ("/components/com_jshopping/",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Jotform", (".jotform.com/",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "jPlayer", ("/jquery.jplayer.min.js",), ("HTTP",), "medium"),
    # --- モバイルフレームワーク ---
    Rule("モバイルフレームワーク", "jQTouch", ("jqtouch..js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "jQuery BlockUI", ("/jquery.blockUI.js",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "jQuery CDN", ("code.jquery.com/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "jQuery DevBridge Autocomplete", ("/devbridgeAutocomplete.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "jQuery Payment", ("/jquery-payment/jquery.payment.min.js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "jQuery UI", ("jquery-ui..js",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "jsDelivr", ("cdn.jsdelivr.net",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "jsPDF", ("/jspdf.min.js",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "JSZip", ("/jszip.min.js",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Jugem", ("imaging.jugem.jp",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "JumpCloud", (".jumpcloud.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Jumpseller", ("jumpseller-apps.herokuapp.w/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Jumpseller", ("assets.jumpseller.w/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Juphy", ("static.juphy.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "JUST", ("checkout-button-./just-pay-button.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Justo", (".getjusto.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Justuno App", ("//scripttags.justuno.com/shopify_justuno",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "JW Player", (".jwplayer.com",), ("HTTP",), "medium"),
    Rule("動画プレーヤー", "JW Player", (".jwpcdn.com",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Kaira Vogue", ("/wp-content/themes/vogue/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "KaliCart Bridge", ("wp-json/kalicart/v1/discovery",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Kaltura", ("api.kaltura./",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Kamva", ("cdn.mykamva.ir",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "Kangle", ("x-cache",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Kapa.ai", ("widget.kapa.ai",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Karma", ("karma.mdpcdn.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Kartmax", (".kartmax.in/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Keap", (".infusionsoft.com/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Kemal", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Kentico CMS", ("/CMSPages/GetResource.ashx",), ("HTTP",), "medium"),
    Rule("CMS", "Kentico CMS", ("/kentico.resource",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Kerberos", ("WWW-Authenticate",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "KerningJS", ("jquery.FLAutoKerning.js",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Kibana", ("<title>Kibana</title>",), ("HTTP",), "medium"),
    Rule("検索エンジン", "Kibana", ("kbn-version",), ("HTTP",), "medium"),
    Rule("検索エンジン", "Kibana", ("kbn-name",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Kibo Commerce", ("cdn-tpd.mozu.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Kilatech", ("cdn.kilatechapps.com/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Kinsta", ("x-kinsta-cache",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Kiosked", ("scripts.kiosked.com",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Kiprotect", ("cdn.kiprotect.com",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Kirki Customizer Framework", ("/wp-content/plugins/kirki/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Klara", (".klara.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Klarna Checkout", (".klarnaservices.com/lib.js",), ("HTTP",), "medium"),
    Rule("決済代行", "Klarna Checkout", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("決済代行", "Klasha", ("klasha-integration.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Kleecks", (".kleecks-stats.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Kleer", ("member.kleer.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "KlickPages", (".klickpages.com.br/",), ("HTTP",), "medium"),
    # --- データベース管理 ---
    Rule("データベース管理", "Knack", ("loader.knack.com/",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Knoma", ("api.knoma.io/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Koa", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Koala", ("cdn.getkoala.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Koala Framework", ("<!--This website is powered by Koala Web Framework CMS",), ("HTTP",), "medium"),
    # --- DMS ---
    Rule("DMS", "Koha", ("<input name=\"koha_login_context\" value=\"intranet\" type=\"hidden\">",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Kohana", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Koken", ("<!--sKOKEN DEBUGGING",), ("HTTP",), "medium"),
    Rule("CMS", "Kommand", ("kommand-bundle.min.js",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Konduto", (".k-analytix.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Kontent.ai", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("CMS", "Kooboo CMS", ("X-KoobooCMS-Version",), ("HTTP",), "medium"),
    Rule("CMS", "Kotisivukone", ("kotisivukone.js",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Kount", ("shopify.kount.net/js",), ("HTTP",), "medium"),
    # --- プログラミング言語 ---
    Rule("プログラミング言語", "KPHP", ("x-powered-by",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "KRT CDN", ("cdn.krajtilak.in",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Ktor", ("x-engine",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "KueskiPay", ("cdn.kueskipay.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Kundo", ("static-chat.kundo.se",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Kuroco", ("x-kuroco-edge-log",), ("HTTP",), "medium"),
    Rule("開発ツール", "Kuroco", ("x-rcms-hash",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Kustomer", ("cdn.kustomerapp.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Kwipped", ("api.kwipped.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "KYKLO", (".kyklo.co/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Kyvio", (".kyvio.com",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Ladipage", ("w.ladicdn.com/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Lagoon", ("X-LAGOON",), ("HTTP",), "medium"),
    Rule("PaaS", "Lagoon", ("x-lagoon",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Landingi", ("scripts.assets-landingi.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "LangShop", (".langshop.app/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Lasso CRM", (".lassocrm.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Laterpay", ("laterpay:connector:callbacks:on_user_has_access",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Launchrock", ("builder.launchrock.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Lawmatics", ("navi.lawmatics.com",), ("HTTP",), "medium"),
    Rule("CRM", "Laylo", ("embed.laylo.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "LayoutHub", ("app.layouthub.com/shopify/layouthub.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "LayUp", ("layup.co.za",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Lazada", ("aplus-auto-exp",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "LazySizes unveilhooks plugin", ("ls.unveilhooks.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Lead Generated", ("app.leadgenerated.com/",), ("HTTP",), "medium"),
    Rule("CRM", "LeadChat", ("chatsystem.io/",), ("HTTP",), "medium"),
    Rule("CRM", "LeadSimple", ("assets2.leadsimple.com/",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "Leaflet", ("leaflet.{0,32}.js",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Leaflet platform", ("scripts.leaflet.co/",), ("HTTP",), "medium"),
    # --- 会計・経理 ---
    Rule("会計・経理", "Lendi", ("Access-Control-Allow-Origin",), ("HTTP",), "medium"),
    Rule("会計・経理", "Lendi", (".lendi.pl",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "LEVERADE", ("static.leverade.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Liana", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Liberapay", ("//liberapay.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Liferay", ("Liferay-Portal",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Lift", ("X-Lift-Version",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Lightbox", ("lightbox.{0,32}.js",), ("HTTP",), "medium"),
    # --- 写真ギャラリー ---
    Rule("写真ギャラリー", "Lightfolio", ("lfpublicstatic.lightfolio.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "LightMon Engine", ("<!-- Lightmon Engine Copyright Lightmon",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Lightspeed eCom", ("<!--  'blocks/head.rain' -->",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "LightSpeed VT", (".lightspeedvt.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Ligna", (".ligna.io/",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "Linguana", ("static.linguana.io/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Liquid Web", ("x-lw-cache",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "LiteSpeed", ("X-Turbo-Charged-By",), ("HTTP",), "medium"),
    # --- キャッシュ ---
    Rule("キャッシュ", "LiteSpeed Cache", ("wp-content/plugins/litespeed-cache/",), ("HTTP",), "medium"),
    Rule("キャッシュ", "LiteSpeed Cache", ("x-turbo-charged-by",), ("HTTP",), "medium"),
    Rule("キャッシュ", "LiteSpeed Cache", ("x-litespeed-cache",), ("HTTP",), "medium"),
    Rule("キャッシュ", "Litespeed Cache", ("x-turbo-charged-by",), ("HTTP",), "medium"),
    Rule("キャッシュ", "Litespeed Cache", ("x-litespeed-cache",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "LiveCanvas", ("/wp-content/plugins/livecanvas/",), ("HTTP",), "medium"),
    # --- コメントシステム ---
    Rule("コメントシステム", "Livefyre", ("livefyre_init.js",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Livescale", (".livescale.tv/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "LiveStreet CMS", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Livewire", ("<{1,512}bwire:",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Livewire", ("livewire.js",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "LlamaLink Cloud Server", ("Serverversion",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Loadify", (".loadifyapp.ninety9.dev",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "LocalExpress", ("cdn.localexpress.io/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Locomotive Scroll", ("locomotive-scroll.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "LocomotiveCMS", ("cdn.locomotive.works/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Lodash", ("lodash..js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "LogaTech", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "LoginRadius", (".loginradius.com",), ("HTTP",), "medium"),
    Rule("認証", "LoginRadius", (".lrcontent.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Loja Integrada", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Loja Mestre", ("lojamestre.w.br",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Loja Virtual", ("cdn1.solojavirtual.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Loja2", ("loja2.com.br",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Lojas Online CTT", ("cdn.lojasonlinectt.pt",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "LoopedIn", ("app.productstash.io/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Lovable", (".lovable.app/",), ("HTTP",), "medium"),
    # --- プログラミング言語 ---
    Rule("プログラミング言語", "Lua", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Lunr.js", ("d)/)lunr.js",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Luveedu Cloud", ("cdn.luveedu.com/",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "LyraThemes Kale", ("/wp-content/themes/kale/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "MachoThemes NewsMag", ("/wp-content/themes/Newsmag/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "MageWorx Search Autocomplete", ("MageWorx_SearchSuiteAutocomplete",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "MagicLabs", (".auth.magic.link",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Magisto", (".magisto.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Magnolia CMS", ("x-magnolia-registration",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Maho", ("js/maho-load-on-intent.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Maho", ("js/maho-passkey-tools.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Maho", ("js/maho-autocomplete.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Maho", ("js/maho-captcha.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Maho", ("js/maho-dialog.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Maho", ("js/maho-tree.js",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "MailerLite Website Builder", ("cdn.mailerlite.com/moment/moment.min.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Mainstay", ("webbot.mainstay.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Makane", ("cdn.makane.com",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Makeswift", ("Access-Control-Allow-Origin",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Makeswift", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Manula", ("static.manula.com/",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "Mapbox GL JS", ("mapbox-gl.js",), ("HTTP",), "medium"),
    Rule("マップ", "Mapline", ("Access-Control-Allow-Origin",), ("HTTP",), "medium"),
    Rule("マップ", "Mappedin", ("Content-Security-Policy",), ("HTTP",), "medium"),
    Rule("マップ", "Mapplic", ("wp-content/plugins/mapplic/",), ("HTTP",), "medium"),
    Rule("マップ", "Mapplic", ("/include/mapplic/mapplic.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Marcando", (".marcando.be/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Marionette.js", ("backbone.marionette..js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Markate", (".markate.com/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Marked", ("/marked.js",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Marker", ("edge.marker.io",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Mars Flag", (".marsflag.com/",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "MarsX", ("analytic-api.marsx.dev/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "MasterkinG32 Framework", ("X-Powered-Framework",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Mastery Manager", ("cdn.masterymanager.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Matajer", ("cdn.mapp.sa/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Matjrah", ("assets.matjrah.store/",), ("HTTP",), "medium"),
    # --- リバースプロキシ ---
    Rule("リバースプロキシ", "MATORI.NET", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Mattaki", (".mattaki.com/",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "Mattermost", ("application-name",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "MaxCDN", ("X-CDN-Forward",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "MaxiCMS", ("cdn.maxicms.nl",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Mazrica", (".mazrica.com/",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Medallia", ("cf.kampyle.com/k_button.js",), ("HTTP",), "medium"),
    # --- Wiki ---
    Rule("Wiki", "MediaWiki", ("<>Powered by MediaWiki</a>",), ("HTTP",), "medium"),
    Rule("Wiki", "MediaWiki", ("<a/Special:WhatLinksHere/",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Medium", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("ブログ", "Medium", ("medium.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Melis Platform", ("<!-- Rendered with Melis CMS V2",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "MembershipWorks", ("cdn.membershipworks.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "MemberSpace", ("memberspace.com.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "MemberStack", ("memberstack.js",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Menufy Website", ("sitecontent-menufycom.netdna-ssl.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Mercado Shops", ("frontend-assets/mshops-web-home/vendor",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Mercurycloud", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("ホスティング", "Mercurycloud", ("X-Host",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "MetaMap", ("sdk.getmati.com",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "MetaSlider", ("/wp-content/plugins/ml-slider/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Methode", ("<!-- Methode uuid: \"\" -->",), ("HTTP",), "medium"),
    Rule("CMS", "Methode", ("eomportal-instanceid",), ("HTTP",), "medium"),
    Rule("CMS", "Methode", ("eomportal-lastUpdate",), ("HTTP",), "medium"),
    Rule("CMS", "Methode", ("eomportal-loid",), ("HTTP",), "medium"),
    Rule("CMS", "Methode", ("eomportal-uuid",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Metorik", ("/wp-content/plugins/metorik-helper",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Mginex", ("api.mginex.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "MGPanel", (".mgpanel.org/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Mico", (".mico-cloud.jp/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Microsoft Ajax Content Delivery Network", ("ajax.aspnetcdn.com/ajax/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Microsoft ASP.NET", ("<inputname=\"__VIEWSTATE",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Microsoft ASP.NET", ("X-AspNet-Version",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Microsoft ASP.NET", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Microsoft ASP.NET", ("set-cookie",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "Microsoft Azure Maps", ("enabled-features",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Microsoft Dynamics 365 Commerce", (".dynamics365commerce.ms/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Microsoft SharePoint", ("MicrosoftSharePointTeamServices",), ("HTTP",), "medium"),
    Rule("CMS", "Microsoft SharePoint", ("X-SharePointHealthScore",), ("HTTP",), "medium"),
    Rule("CMS", "Microsoft SharePoint", ("SharePointHealthScore",), ("HTTP",), "medium"),
    Rule("CMS", "Microsoft SharePoint", ("SPRequestGuid",), ("HTTP",), "medium"),
    Rule("CMS", "Microweber", ("icroweber{0,45}.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Midtrans", ("app.midtrans.com/",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "Mieruca", ("hm.mieru-ca.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Miestro", (".miestro.com",), ("HTTP",), "medium"),
    # --- 制御システム ---
    Rule("制御システム", "Milvus", (".api.milvus.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Mimiran", (".mimiran.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "MiniBC", ("apps.minibc.com",), ("HTTP",), "medium"),
    Rule("決済代行", "Mintpay", ("/wp-content/plugins/mintpay/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Mirai", (".mirai.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Mirvac", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "MissionSuite", ("app.themissionsuite.com",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "Misskey", ("<!-- Thank you for using Misskey! @syuilo -->",), ("HTTP",), "medium"),
    Rule("メッセージボード", "Misskey", ("application-name",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Mithril.js", ("/mithril.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Miva", ("content-disposition",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Mixitup", ("mixitup.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "mobicred", ("app.mobicredwidget.co.za",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Mobify", ("//cdn.mobify.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Mobify", ("//a.mobify.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Mobify", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "MochiKit", ("MochiKit.js",), ("HTTP",), "medium"),
    # --- Webサーバー拡張 ---
    Rule("Webサーバー拡張", "mod_rack", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("Webサーバー拡張", "mod_rails", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("Webサーバー拡張", "mod_wsgi", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Modal Forms", ("app.modalforms.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "MODX", ("<!-- Modx process time debug info -->",), ("HTTP",), "medium"),
    Rule("CMS", "MODX", ("<a>Powered by MODX</a>",), ("HTTP",), "medium"),
    Rule("CMS", "MODX", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Mojo Helpdesk", ("Content-Security-Policy",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Mojolicious", ("x-powered-by",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Mokka", ("revoiframe.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Molin AI", (".molin.ai/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Mollie", ("/wp-content/plugins/mollie-payments-for-woocommerce/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Mollom", ("<img.mollom.com",), ("HTTP",), "medium"),
    Rule("セキュリティ", "Mollom", ("mollom.js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Moment Timezone", ("moment-timezone.js",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "Moment.js", ("moment.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Moneris", ("content-security-policy",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Moneris Payment Gateway", ("/wp-content/plugins/woocommerce-gateway-moneris/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Monkcommerce", ("js.monkcommerce.app",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Mono", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Mono.net", ("monotracker.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Monto", ("cdn.monto.io/",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Moodle", ("<imgmoodlelogo",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Moon", ("/moon.js",), ("HTTP",), "medium"),
    Rule("JSフレームワーク", "MooTools", ("mootools..js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Moovin", (".moovin.",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Mopinion", ("deploy.mopinion.com/",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Motherhost", ("platform",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "MotoCMS", ("/mt-includes/js/website..js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Moyklass", ("app.moyklass.com",), ("HTTP",), "medium"),
    Rule("CRM", "MRI Box and Dice", ("assets.boxdice.com.au",), ("HTTP",), "medium"),
    Rule("CRM", "MRI Eagle", (".eaglesoftware.com.au",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "MsCode.pl", ("X-Hosting-Provider",), ("HTTP",), "medium"),
    Rule("開発ツール", "MsCode.pl", ("application-name",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "MSHOP", ("static.hotishop.com/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "MTCaptcha", ("service.mtcaptcha.com/",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "MudBlazor", ("_content/MudBlazor/MudBlazor.min.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Mul-Pay", ("static.mul-pay.jp/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Mustache", ("mustache.js",), ("HTTP",), "medium"),
    # --- メディアサーバー ---
    Rule("メディアサーバー", "Muvi", (".muvi.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "MVD Studio", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("CMS", "MVD Studio", ("X-Generator",), ("HTTP",), "medium"),
    Rule("CMS", "MVD Studio", ("X-Built-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "MyAlice", ("widget.myalice.ai",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "MyCashFlow", ("X-MCF-ID",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "MyDryCleaner", ("reviews.reviewmydrycleaner.com",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "MyPersonas", ("cdn.mypersonas.ai/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "MyPlay", (".myplay.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "MyWebsite Creator", ("mywebsite-editor.com",), ("HTTP",), "medium"),
    Rule("ページビルダー", "MyWebsite Creator", ("website-editor.net",), ("HTTP",), "medium"),
    # --- リッチテキストエディタ ---
    Rule("リッチテキストエディタ", "N1ED", (".public.n1ed.com/",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "n8n", ("n8n:config:rest-endpoint",), ("HTTP",), "medium"),
    Rule("開発ツール", "n8n", ("n8n:config:sentry",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Napps", ("//napps-storage.b-cdn.net/scripts/smartbanner.jsnapps=1",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "NativeForms", ("script.nativeforms.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Naviga", (".infomaker.io/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Neat A/B testing", ("cdn.neatab.com/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Negate", ("sapi.negate.io",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "NEO - Omnichannel Commerce Platform", ("powered",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Neos CMS", ("X-Flow-Powered",), ("HTTP",), "medium"),
    Rule("CMS", "Neos CMS", ("/Neos.Neos/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Neos Flow", ("X-Flow-Powered",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Nepso", ("X-Powered-CMS",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "Neshan", ("static.neshan.org",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Nestify", ("x-nestify-cache",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Netlify", ("X-NF-Request-ID",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Netlify Create", (".stackbit.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Neto", ("jquery.neto..js",), ("HTTP",), "medium"),
    # --- リモートアクセス ---
    Rule("リモートアクセス", "Netop", (".netop.com",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Nette Framework", ("<inputdata-nette-rules",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Nette Framework", ("<inputid=\"frm-",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Nette Framework", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Newspack by Automattic", ("host-header",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Nexcess", ("x-hostname",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Next Total", (".nextdirect.com/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Next.js", ("x-powered-by",), ("HTTP",), "medium"),
    # --- 写真ギャラリー ---
    Rule("写真ギャラリー", "NextGEN Gallery", ("/nextgen-gallery/js/",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "Nginx", ("X-Fastcgi-Cache",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Niagahoster", ("x-powered-by",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Nibiru Ecommerce", ("x-powered-by",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Nidux", ("assets.nidux.net/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Nimbu", ("cdn.nimbu.io",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "NodeBB", ("/nodebb.min.js",), ("HTTP",), "medium"),
    Rule("メッセージボード", "NodeBB", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "NoFraud", ("services.nofraud.com/",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Nolt", ("cdn.nolt.io",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Noodle Factory", ("portalapi.noodlefactory.ai",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Nootiz", ("load.nootiz.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Norce", ("< id=\"jetshop-branding\">",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Nordcraft", ("application-name",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Nordcraft", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Norse Env", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Northstar Club Management", ("Portal",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Norton Shopping Guarantee", ("nsg.symantec.com/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Nova Busca", ("api.novabusca.com.br",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "NProgress", ("/nprogress.min.js",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "NTLM", ("WWW-Authenticate",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Nucleus CMS", ("nucleuscms.er.cz/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Nuqlium", (".nuqlium.com/api",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Nuxt.js", ("<script >window.__NUXT__",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Ochanoko", ("ocnk-min.js",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "Oclocher", ("Access-Control-Allow-Origin",), ("HTTP",), "medium"),
    Rule("メッセージボード", "Oclocher", ("widget.oclocher.fr",), ("HTTP",), "medium"),
    # --- 静的サイトジェネレーター ---
    Rule("静的サイトジェネレーター", "Octopress", ("/octopress.js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Offline.js", ("//offline.min.js",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Oh Dear", (".ohdear.app/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Ohava", ("analytics.ohava.tools",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Omega Commerce", (".omegacommerce.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Omise", ("cdn.omise.co",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Omnisend Email Marketing & SMS", ("omnis.com/inShop/Embed/shopify.js",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "OneAll", ("api.oneall.com/socialize",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "OnePage Express", ("/wp-content/themes/one-page-express/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "OnePress Social Locker", ("/wp-content/plugins/social-locker/bizpanda/assets/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Onfido", ("content-security-policy",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Onlim", ("app.onlim.com/",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "OpenLayers", ("openlayers",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "OpenNemas", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "OpenPay", ("openpay.com.au",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "OpenText Web", ("<!--published by Open Text Web Solutions",), ("HTTP",), "medium"),
    Rule("CMS", "OpenText Web Solutions", ("<!--published by Open Text Web Solutions",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "OpenUI5", ("sap-ui-core.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "OperateBeyond", ("//dealer-cdn.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Optimizely Content Management", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("CMS", "Optimizely Content Management", (".episerver.net/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Oracle Commerce", ("X-ATG-Version",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Oracle Commerce Cloud", ("OracleCommerceCloud-Version",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Oracle Content Management", ("/_sitesclouddelivery/renderer/renderer.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Orbit Commerce", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Orchard Core", ("/OrchardCore.",), ("HTTP",), "medium"),
    Rule("CMS", "Orchard Core", ("x-powered-by",), ("HTTP",), "medium"),
    Rule("CMS", "Orchard Core", ("x-generator",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Orckestra", ("x-orckestra-commerce",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Orckestra", ("x-powered-by",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Ordergroove", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("決済代行", "Ordergroove", (".ordergroove.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "OrderMyGear", (".mybrightsites.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Ordersify Product Alerts", ("cdn.ordersify.com/sdk/productalerts-shopify.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "OroCommerce", ("<script data-requiremodule=\"oroui/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "OroCommerce", ("<script data-requiremodule=\"oro/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "osCommerce", ("<name=\"osCsid\"",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "otrs", ("<!--sOTRS: Copyright",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "otrs", ("/otrs-web/js/",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "otrs", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Webメール ---
    Rule("Webメール", "Outlook Web App", ("X-OWA-Version",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "OutSystems", ("scripts/OutSystems.js",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Overblog", (".over-blog-kiwi.com/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "OVHcloud", ("x-iplb-request-id",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "OWL Carousel", ("owl.carousel..js",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "Oxi Social Login", ("social-login.oxiapps.com",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Oxygen", ("wp-content/plugins/oxygen",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Pabbly Form Builder", ("forms.pabbly.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Pace", ("pay.pacenow.co",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Packlink PRO", ("packlink-spf-pro.appspot.com/.myshopify.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Packman", (".packman.app",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Paddle", ("cdn.paddle.com/paddle/paddle.js",), ("HTTP",), "medium"),
    Rule("決済代行", "Pagar.me", ("assets.pagar.me/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Pagecloud", ("app-assets.pagecloud.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Pagefai CMS", ("x-powered-by",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "PageFly", ("cdn.pagefly.io",), ("HTTP",), "medium"),
    Rule("ページビルダー", "PageFly", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Pagemaker", (".pagemaker.io",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Pagetiger", (".pagetiger.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Pagevamp", ("X-ServedBy",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "PagineGialle", ("ssc.paginegialle.it/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "PagSeguro", (".pagseguro.uol.com.br/",), ("HTTP",), "medium"),
    Rule("決済代行", "Paidy", ("apps.paidy.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Palbin", ("cdn.palbin.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Paloma", (".getpaloma.com/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Pandectes", ("pandectes-core.js|/gdpr-privacy-policy-assets/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Pantheon", ("x-pantheon-styx-hostname",), ("HTTP",), "medium"),
    Rule("PaaS", "Pantheon", ("x-styx-req-id",), ("HTTP",), "medium"),
    # --- DMS ---
    Rule("DMS", "Paperless Pipeline", ("application-name",), ("HTTP",), "medium"),
    # --- IaaS ---
    Rule("IaaS", "Parmin Cloud", ("x-powered-by",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Pars Elecom Portal", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Partial.ly", ("partial.ly",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "Passage", (".1password.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "PatientSites", (".patientsites.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "PayBright", ("app.paybright.com",), ("HTTP",), "medium"),
    Rule("決済代行", "Paydock", ("app.paydock.com",), ("HTTP",), "medium"),
    Rule("決済代行", "Payflex", ("partpayassets.blob.core.windows.net",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Payhip", ("payhip.com/js/payhip.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Payl8r", ("payl8r.com",), ("HTTP",), "medium"),
    Rule("決済代行", "Paymattic", (".paymattic.com",), ("HTTP",), "medium"),
    Rule("決済代行", "PayPal", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("決済代行", "PayPal", ("paypalobjects.com",), ("HTTP",), "medium"),
    Rule("決済代行", "Payrexx", (".payrexx.com/",), ("HTTP",), "medium"),
    Rule("決済代行", "Paysafe", ("/hosted.paysafe.com/",), ("HTTP",), "medium"),
    Rule("決済代行", "Paysera", (".paysera.com/",), ("HTTP",), "medium"),
    Rule("決済代行", "PayU Payment", (".payu.com",), ("HTTP",), "medium"),
    Rule("決済代行", "PCI Proxy", ("content-security-policy",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Peachie", ("Access-Control-Allow-Origin",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "PeerBoard", (".peerboard.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Pegboard7", ("/pegboard.min.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Pelcro", ("js.pelcro.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "PencilBlue", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Percy", ("/npm/@percy.ai/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "PerfectApps Swift", ("swift.perfectapps.io/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Perfmatters", ("/wp-content//perfmatters/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "PerimeterX", ("client.a.pxi.pub/",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Phabricator", ("/phabricator/{8}/rsrc/js/phui/.js",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Phabricator", ("<=\"phabricator-",), ("HTTP",), "medium"),
    # --- 静的サイトジェネレーター ---
    Rule("静的サイトジェネレーター", "Phenomic", ("/phenomic.browser..js",), ("HTTP",), "medium"),
    Rule("静的サイトジェネレーター", "Phenomic", ("<id=\"phenomic\"",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Phlox", ("/wp-content/themes/phlox/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Phorest", ("booking-widget.phorestcdn.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "PhotoShelter", (".psecn.photoshelter.com/",), ("HTTP",), "medium"),
    # --- プログラミング言語 ---
    Rule("プログラミング言語", "PHP", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "PHP-Nuke", ("<Powered by PHP-Nuke",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "phpBB", ("<styles/silver/theme",), ("HTTP",), "medium"),
    Rule("メッセージボード", "phpBB", ("Powered by <aphpBB",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "PHPDebugBar", ("debugbar..js",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "phpDocumentor", ("<!-- Generated by phpDocumentor",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "PHPFusion", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("CMS", "PHPFusion", ("X-PHPFusion",), ("HTTP",), "medium"),
    # --- データベース管理 ---
    Rule("データベース管理", "phpMyAdmin", ("Set-Cookie",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "phpwcms", ("X-Phpwcms-Page-Processed-In",), ("HTTP",), "medium"),
    Rule("CMS", "phpwcms", ("X-Phpwcms-Release",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "Phusion Passenger", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Picatcha", ("api.picatcha.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "PickyStory", ("cdn.pickystory.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Pico", ("widget.pico.tools",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Picture It", ("app.pictureit.co/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Pimcore", ("/pimcorecore/js/targeting.js",), ("HTTP",), "medium"),
    Rule("CMS", "Pimcore", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Pin Payments", ("api.pinpayments.com",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Pinia", ("/pinia/..js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Piperun", (".crmpiperun.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "pirobase CMS", ("</site//resourceCached/",), ("HTTP",), "medium"),
    Rule("CMS", "pirobase CMS", ("<inputcbi:///cms/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "PixelYourSite", ("/wp-content/plugins/pixelyoursite/",), ("HTTP",), "medium"),
    # --- 写真ギャラリー ---
    Rule("写真ギャラリー", "Pixpa", ("themeassets.pixpa.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Plaid", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("決済代行", "Plaid", (".plaid.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Plannit", (".plannit.io/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Planoplan", (".planoplan.com",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Platform.sh", ("x-platform-processor",), ("HTTP",), "medium"),
    Rule("PaaS", "Platform.sh", ("x-platform-cluster",), ("HTTP",), "medium"),
    Rule("PaaS", "Platform.sh", ("x-platform-router",), ("HTTP",), "medium"),
    Rule("PaaS", "Platform.sh", ("x-platform-server",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Platforma LP", (".lpcdn.site/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "PlatformOS", ("x-powered-by",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "PlatinMarket", ("//platincdn.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Plenigo", ("static.plenigo.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "plentymarkets", ("plenty.shop.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "plentymarkets", ("X-Plenty-Shop",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "PlentyONE", ("x-plenty-shop",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "plentyShop LTS", ("X-Plenty-Shop",), ("HTTP",), "medium"),
    # --- ホスティングパネル ---
    Rule("ホスティングパネル", "Plesk", ("X-Powered-By-Plesk",), ("HTTP",), "medium"),
    Rule("ホスティングパネル", "Plesk", ("common.jsplesk",), ("HTTP",), "medium"),
    Rule("ホスティングパネル", "Plesk", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Plone", ("/resource",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Plotch", ("cdnassets.plotch.io",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Plug&Pay", (".plugandpay.nl",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Podbean", (".podbean.com/",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Podia", ("cdn.podia.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Podio", ("//podio.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Podpage", ("static.getpodpage.com/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Polylang", ("x-redirected-by",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Polymer", ("polymer.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Popcorn CRM", ("app.popcorn.email",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Popmotion", ("popmotion.global.min.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Poshmark", ("//poshmark.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Posify", (".posify.me/",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Postach", (".postach.io/",), ("HTTP",), "medium"),
    # --- データベース ---
    Rule("データベース", "PouchDB", ("/js/pouchdb.min.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Power CRM", (".powercrm.com.br",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Powerboutique", ("powerboutique",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Powergap", ("<input type=\"hidden\" name=\"shopid\"",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Powergap", ("<atitle=\"POWERGAP",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "PowerSchool", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("LMS", "PowerSchool", ("application-name",), ("HTTP",), "medium"),
    # --- エディタ ---
    Rule("エディタ", "Powtoon", ("static.powtoon.co",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Preeco", ("widget.preeco.de",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Prefix-Free", ("prefixfree.js",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "Preline UI", ("/preline.js",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Premio Chaty", ("/wp-content/plugins/chaty/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Prepr", (".prepr.io/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "PreProduct", (".preproduct.io",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Pressable", ("host-header",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "PrestaShop", ("Powered by <as>PrestaShop",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "PrestaShop", ("<!-- /Block  module s-->",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "PrestaShop", ("<!-- /Module Block  -->",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "PrestaShop", ("/modules/ps_/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "PrestaShop", ("Powered-By",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Pretty Damn Quick", ("pdq-scripts.pdqprod.link",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "prettyPhoto", ("jquery.prettyPhoto.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Prima Software", ("DCTERMS.publisher",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Printify", ("printify.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Prismic", (".prismic.io/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Prive", (".tryprive.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Privy App", ("//shopify.privy.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "ProcessOut", ("js.processout.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "ProcessWire", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "ProdPad", (".prodpad.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Product Personalizer", ("/product-personalizer/pplr_common.js",), ("HTTP",), "medium"),
    # --- DMS ---
    Rule("DMS", "ProductDyno", (".productdyno.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Profeat", ("widget.profeat.team/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "ProgressBar.js", ("/progressbar.js/dist/progressbar.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Projesoft", ("projesoft.js",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "Prolo Finder", ("embed.prolofinder.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Prommt", ("app.prommt.com/",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "PRONOTE", ("application-name",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Property Shell", ("api.propertyshell.com",), ("HTTP",), "medium"),
    Rule("CRM", "Prostoy", ("analytics.prostoy.ru",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Proximis", ("widget-commerce.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Proximis Unified Commerce", ("<htmldata-ng-app=\"RbsChangeApp\"",), ("HTTP",), "medium"),
    Rule("CMS", "Public CMS", ("X-Powered-PublicCMS",), ("HTTP",), "medium"),
    Rule("CMS", "Pulse CMS", ("/PulseCMS/./tracker.php",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "PushOwl Web Push Notifications", ("/sdks/pushowl-shopify.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "PyroCMS", ("X-Streams-Distribution",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "PyWebIO", ("/js/pywebio.min.js",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "QForm", ("cdn.qform/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Qikify", ("sdk.qikify.com/",), ("HTTP",), "medium"),
    # --- データベース ---
    Rule("データベース", "Qiyeku", (".qiyeku.cn",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Qomon", ("scripts.qomon.org",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Qonnex", (".qonnex.nl/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "QoreAI", ("app.qoreai.com",), ("HTTP",), "medium"),
    Rule("CMS", "Quant", (".quant.jp/",), ("HTTP",), "medium"),
    # --- コメントシステム ---
    Rule("コメントシステム", "Question2Answer", ("<!-- Powered by Question2Answer",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Quickblog", (".quickblog.co/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Quickbutik", (".quickbutik.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "QuickSell", (".quicksell.co/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Quoli", (".quoli.io/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "QUV", (".quv.kr/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Rabfy", ("Powered-By",), ("HTTP",), "medium"),
    # --- キャッシュ ---
    Rule("キャッシュ", "RackCache", ("X-Rack-Cache",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Ractive.js", ("ractive/ractive.min.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Radial Ecommerce", (".radial.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Rain", (".rainpos.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Raku-uru Cart", (".raku-uru.jp/cms",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Rally", ("analytics.rallycms.ca",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Ramda", ("ramda..js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "RandemRetail", (".cc.randemcommerce.com",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Raneto", ("/scripts/raneto.js",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "RapidSec", ("Content-Security-Policy-Report-Only",), ("HTTP",), "medium"),
    Rule("セキュリティ", "RapidSec", ("Content-Security-Policy",), ("HTTP",), "medium"),
    Rule("セキュリティ", "RapidSec", ("report-to",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "RapidSpike", (".rapidspike.com/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "RawGit", ("cdn.rawgit.com",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Raygun", (".raygun.io",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Razorpay", ("checkout.razorpay.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "RBS Change", ("<htmlxmlns:change=",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "React", ("reactb..js",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Read the Docs", (".readthedocs.io",), ("HTTP",), "medium"),
    Rule("ドキュメント", "ReadMe", ("/cdn.readme.io/js/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Real Geeks", (".realgeeks.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "RebelMouse", ("x-rebelmouse-surrogate-control",), ("HTTP",), "medium"),
    Rule("CMS", "RebelMouse", ("<!-- Powered by RebelMouse.",), ("HTTP",), "medium"),
    Rule("CMS", "RebelMouse", ("x-rebelmouse-cache-control",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Rebuy", ("rebuyengine.com",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "reCAPTCHA", ("api-secure.recaptcha.net",), ("HTTP",), "medium"),
    Rule("セキュリティ", "reCAPTCHA", ("recaptcha_ajax.js",), ("HTTP",), "medium"),
    Rule("セキュリティ", "reCAPTCHA", ("/recaptcha/.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Recharge", ("rechargeassets-bootstrapheroes-rechargeapps.netdna-ssl.com",), ("HTTP",), "medium"),
    Rule("決済代行", "Recharge", (".rechargecdn.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Recomify", ("app.recomify.com/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "ReConvert", (".stilyoapps.com/reconvert/assets/js/store_reconvert_node.js",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "RecoverMyCart", ("cdn.recovermycart.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Recurly", ("<inputdata-recurly",), ("HTTP",), "medium"),
    Rule("決済代行", "Recurly", ("js.recurly.com",), ("HTTP",), "medium"),
    # --- キャッシュ ---
    Rule("キャッシュ", "Redis Object Cache", ("<!--sPerformance optimized by Redis Object Cache",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "ReDoc", ("/redoc.js",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Reflex", ("application-name",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Regula", ("unpkg.com/@regulaforensics/",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Released", ("embed.released.so/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "RELOOP", (".reloop.com.au/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Remarkable Commerce", ("x-powered-by",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Render", ("x-render-origin-server",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "RentCafe", (".rentcafe.com/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Replicache", ("x-replicache-requestid",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Replit", ("replit-cluster",), ("HTTP",), "medium"),
    Rule("開発ツール", "Replit", ("expect-ct",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Replo", ("replocdn.com/",), ("HTTP",), "medium"),
    # --- コメントシステム ---
    Rule("コメントシステム", "ReplyBox", ("cdn.getreplybox.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Reputon", (".reputon.com/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "RequireJS", ("require..js",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Respondi", ("embed.respondi.app",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Retisio", (".retisio.io/retisio-sdk.js",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Retool", ("retool/~.js",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Return Prime", ("//return-prime-proxy-prod.s3.amazonaws.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "RevCent", ("cdn.revcent.com",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Reveal.js", ("reveal.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Reviews Up", ("app.getreviewsup.com",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "RevolverMaps", (".revolvermaps.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Revy", ("api.revy.io/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Rich Plugins Reviews", ("/wp-content/plugins/widget-google-reviews/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Richpanel", (".richpanel.com/",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "RingCaptcha", ("cdn.ringcaptcha.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Rinsed", (".app.rinsed.co/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Ripple", ("x-sdp-app-type",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Riskified", ("<beacon.riskified.com",), ("HTTP",), "medium"),
    Rule("セキュリティ", "Riskified", ("<c.riskified.com",), ("HTTP",), "medium"),
    Rule("セキュリティ", "Riskified", (".riskified.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "RMZ", ("assets.rmz.gg/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "RND", ("/Scripts/plugins/rnd-mobilemenu/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "RND", ("apple-mobile-web-app-title",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "RND", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Roadiz CMS", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "ROC Commerce", ("Content-Security-Policy",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Rocketfy", (".rocketfy.mx/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Rocketspark", ("cdn.rocketspark.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Rofofk", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Rollick", ("widget.rollick.io",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "RomanCart", (".romancart.com/",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Rosti", ("X-Rosti",), ("HTTP",), "medium"),
    # --- Webメール ---
    Rule("Webメール", "RoundCube", ("<title>RoundCube",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "rSchoolToday", (".rschooltoday.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Rubic", ("app.rubic.no",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Ruby on Rails", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Ruffle", ("ruffle/ruffle.js",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "RunKit", (".runkit.com",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Ruttl", ("app.ruttl.com",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "RX Web Server", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "S-COREpion", ("x-powered-by",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Sails.js", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "SalesCandy", (".salescandy.com/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "SalesFire", ("cdn.salesfire.co.uk/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Salesfloor", (".salesfloor.net/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Salesforce", ("<=\"brandQuaternaryFgrs\"",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Salesforce Commerce Cloud", ("/demandware.static/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Salesforce Desk", ("/s/sfsites/auraFW/",), ("HTTP",), "medium"),
    Rule("CRM", "Salesforce Experience Cloud", ("salesforce-community",), ("HTTP",), "medium"),
    Rule("CRM", "Salesforce Experience Cloud", ("/s/sfsites/auraFW/",), ("HTTP",), "medium"),
    Rule("CRM", "Salesforce Service Cloud", ("service.force.com",), ("HTTP",), "medium"),
    Rule("CRM", "SalesMatch", (".salesmatch.ai/",), ("HTTP",), "medium"),
    Rule("CRM", "Salespype", ("app.salespype.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Salla", (".assets.salla.network",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Salla", ("x-powered-by",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Saly", ("application-name",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Sanity", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("CMS", "Sanity", ("x-sanity-shard",), ("HTTP",), "medium"),
    Rule("CMS", "Sanity.io", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("CMS", "Sanity.io", ("x-sanity-shard",), ("HTTP",), "medium"),
    Rule("CMS", "Sanity.io", ("cdn.sanity.io",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "SAP Commerce Cloud", ("<script.hybris..js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "SAP Commerce Cloud", ("X-Sap-Pad",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "SAP Customer Data Cloud Sign-in", (".gigya.com/JS/gigya.js",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Sapper", ("<script>__SAPPER__",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Sardine", ("api.sardine.ai",), ("HTTP",), "medium"),
    # --- メディアサーバー ---
    Rule("メディアサーバー", "Sardius Media", ("sardiuslive.sardius.media",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Satori Studio Bento", ("/wp-content/themes/bento/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Sauce Social Commerce", ("app.addsauce.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Scalapay", ("cdn.scalapay.com",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "Schema App", ("cdn.schemaapp.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "SchemaPlus", ("//schemaplusfiles.s3.amazonaws.com/",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Scissor Themes Writee", ("/wp-content/themes/writee/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Scorpion", ("cdn.cxc.scorpion.direct",), ("HTTP",), "medium"),
    Rule("CMS", "Scorpion", ("<id=\"HSScorpion",), ("HTTP",), "medium"),
    Rule("CMS", "SDL Tridion", ("<img_tcmd{2,3}-d{6}.",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Seal Subscriptions", (".sealsubscriptions.com/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Search Magic", ("cdn.searchmagic.com",), ("HTTP",), "medium"),
    Rule("検索エンジン", "Searchanise", ("searchanise.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "SearchFit", ("generation-copyright",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Searchine", ("app.searchine.net/",), ("HTTP",), "medium"),
    Rule("検索エンジン", "Searchspring", ("cdn.searchspring.net",), ("HTTP",), "medium"),
    Rule("検索エンジン", "Searchtap", ("cdn.searchtap.io",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "Seatics", ("tn-widget.seatics.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Secomapp", ("cdn.secomapp.com/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Section.io", ("section-io-origin-time-seconds",), ("HTTP",), "medium"),
    Rule("CDN", "Section.io", ("section-io-origin-status",), ("HTTP",), "medium"),
    Rule("CDN", "Section.io", ("section-io-id",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Securiti", (".securiti.ai",), ("HTTP",), "medium"),
    # --- 制御システム ---
    Rule("制御システム", "Sedna System", ("client.sednasystem.com",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "SeedProd Coming Soon", ("/wp-content/plugins/coming-soon/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Segmentify", (".segmentify.com/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Select2", ("select2.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "SellBe", (".sellbe.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Selldone", ("selldone-cdn-id",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Selldone", ("selldone-iframe",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Sellerdeck", ("sellerdeck.min.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "SellersCommerce", (".sellerscommerce.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Sellful", (".sellful.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Sellfy", ("sellfy.com/js/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Sellix", ("cdn.sellix.io/static/js/embed.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Sellsy", (".sellsy.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Sellwild", (".sellwild.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Selly", ("embed.selly.",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Semplice", ("/wp-content/themes/semplice/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Sencha Touch", ("sencha-touch..js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "SendOwl", ("transactions.sendowl.com",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Sentry", (".sentry-cdn.com/",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Sentry", ("Sentry-Trace",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "SEOmator", ("//seomator.com/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Seon", ("cdn.seon.io/",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "SEOPress", ("/wp-content/themes/seopress/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Seosphera", (".seosphera.com/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Seravo", ("x-powered-by",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Service Provider Pro", (".spp.io/js/",), ("HTTP",), "medium"),
    Rule("決済代行", "Sezzle", ("widget.sezzle.",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "Shapecss", ("shapecss..js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Sharetribe", (".sharetribe.com/",), ("HTTP",), "medium"),
    # --- Webサーバー拡張 ---
    Rule("Webサーバー拡張", "Shelf", ("x-powered-by",), ("HTTP",), "medium"),
    # --- リモートアクセス ---
    Rule("リモートアクセス", "ShellInABox", ("must be enabled for ShellInABox</noscript>",), ("HTTP",), "medium"),
    Rule("リモートアクセス", "ShellInABox", ("<title>Shell In A Box</title>",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Shepherd", ("shepherd.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Shift4Shop", (".asp|3d_upsell.js)",), ("HTTP",), "medium"),
    Rule("CMS", "Shift4Shop", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Shiny", ("x-powered-by",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "ShionImporter", ("app.shionimporter.site",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "ShipTection", ("app.shiptection.com/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Shogun Landing Page Builder", (".getshogun.com/..myshopify.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Shop Pay", ("cdn.shopify.com/shopifycloud/shopify_pay/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Shopapps", ("cdn.myshopapps.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Shopatron", ("mediacdn.shopatron.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "ShopBase", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopblocks", (".myshopblocks.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopery", ("X-Shopery",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopfa", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopify", ("shopify-checkout-api-token",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopify", ("shopify-digital-wallet",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopify", ("sdks.shopifycdn.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopify", ("cdn.shopify.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopify", ("x-shopify-stage",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopify", ("x-shopid",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Shopify Buy Button", ("sdk. shopifycdn.com/buy-button/latest/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Shopify Chat", ("cdn.shopify.com/shopifycloud/shopify_chat/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Shopify Consent Management", ("cookie_consent_shopify.js",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Shopify Geolocation App", ("geolocation-recommendations.shopifycloud.com/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Shopify Product Reviews", ("productreviews.shopifycdn.com",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Shopify Web Components", ("cdn.shopify.com/storefront/web-components.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Shopiteka", ("/shopiteka.lt/_shopi/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopix", (".shopixai.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "ShopKeeper Tools", ("magic-button-app.shopkeepertools.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Shoplo", ("cdn.shoplo.w/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopmatic", ("shopmatic-facebook-pixels-id",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Shoppable", ("api.shoppable.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Shopping Feed", ("tracking.shopping-flux.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shoppy", (".shoppy.gg",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shoprenter", (".cdn.shoprenter.hu/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "ShopStyle", ("ssc.shopstyle.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopthru", ("app.shopthru.xyz/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopware", ("/jquery.shopware.min.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopware", ("sw-invalidation-states",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopware", ("/engine/Shopware/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopware", ("sw-context-token",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopware", ("application-name",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Shopware", ("sw-language-id",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "ShopWired", (".amazonaws.com/shopwired-theme-assets/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "ShopWise", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Shortly", ("//shortly.shop/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Show Recent Orders", (".nice-team.net/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Showdigs", (".showdigs.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Shuttle", ("shuttle.s3.amazonaws.com",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Sift", ("cdn.sift.com/s.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "SIGE Loja", ("/shared/sige.loja.bundle.custom",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Sigma.js", ("/sigma.min.js)",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Signifyd", (".signifyd.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Simbel", ("powered",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Simla", (".retailcrm.tech/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Simplio Upsells", ("//upsell.simplio.app/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Simplo7", ("cdn.simplo7.w/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Simplébo", ("X-ServedBy",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Sirclo", ("template.sirclocdn.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Sirclo", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Sirge", ("cdn.app.sirge.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Sitecore", ("Content-Security-Policy",), ("HTTP",), "medium"),
    Rule("CMS", "Siteglide", ("siteglide.js",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "SiteGround", ("host-header",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Siteklik", ("//webstats.siteklik.nl/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "SiteManager", ("sd.sitemn.gr/",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "SiteOrigin Vantage", ("/wp-content/themes/vantage/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "SiteWright", (".sitewright.io/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Sixshop", ("static.sixshop.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Sizekick", ("widget.sizekick.io/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Sketchanet", (".sketchanet.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Skilldo", ("cms-version",), ("HTTP",), "medium"),
    Rule("CMS", "Skilldo", ("cms-name",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Skio", ("cdn.skio.com/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Skitter", ("/jquery.skitter.min.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Slate", ("slate-technolutions-net.cdn.technolutions.net/",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Sleekplan", (".sleekplan.com/",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "SlickStack", ("x-powered-by",), ("HTTP",), "medium"),
    # --- 写真ギャラリー ---
    Rule("写真ギャラリー", "Slider Revolution", ("jquery.themepunch.revolution.min.js",), ("HTTP",), "medium"),
    Rule("写真ギャラリー", "Slider Revolution", ("/wp-content/plugins/revslider/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Slimbox", ("slimbox.js",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "Slimbox 2", ("slimbox2.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Smallbox", (".smallbox.ca/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Smart Slider 3", ("/wp-content/plugins/smart-slider-3/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "SmartSite", ("</smartsite.id=",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Smartstore", ("<!--Powered by Smarttore",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Smartstore biz", ("smjslib.js",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Smash Balloon Instagram Feed", ("/wp-content/plugins/instagram-feed/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Smile App", ("js.smile.io/.smile-shopify.js",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Smilii", ("Platform",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Smootify", ("cdn.smootify.io",), ("HTTP",), "medium"),
    # --- 写真ギャラリー ---
    Rule("写真ギャラリー", "SmugMug", ("Smug-CDN",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Snap.svg", ("snap.svg.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "SniperCRM", ("app.snipercrm.io/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "SniperFast", (".sniperfast.com",), ("HTTP",), "medium"),
    # --- IaaS ---
    Rule("IaaS", "Snowplow Analytics", ("cdn.jsdelivr.net/gh/snowplow/sp-js-assets@/sp.js",), ("HTTP",), "medium"),
    Rule("IaaS", "Snowplow Analytics", ("cdnjs.cloudflare.com/ajax/libs/snowplow//sp..js",), ("HTTP",), "medium"),
    Rule("IaaS", "Snowplow Analytics", ("d1fc8wv8zag5ca.cloudfront.net/./sp.js",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Socket.io", ("socket.io..js",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "Socure", (".socure.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "SoftwareSuggest", ("trk.softwaresuggest.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Sogecommerce", ("/wp-content/plugins/woo-sogecommerce-payment/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Soldsie", ("lib.soldsie.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Solodev", ("solodev_session",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "SolutionReach", ("chat.solutionreach.com",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "SonarQube", ("<title>SonarQube</title>",), ("HTTP",), "medium"),
    Rule("開発ツール", "SonarQube", ("application-name",), ("HTTP",), "medium"),
    Rule("開発ツール", "SonarQubes", ("application-name",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Spark CMS", ("/spark-scripts/",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Speca", ("application-name",), ("HTTP",), "medium"),
    Rule("ドキュメント", "Speca", ("/js/speca.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "SpeedEcom", (".speed-ecom.eu/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "SpeedyCache", ("x-speedycache-source",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Spektrix", (".spektrix.com/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Spexo Addons", ("/wp-content/plugins/sastra-essential-addons-for-elementor/",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Sphinx", ("/sphinx-book-theme.js",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "SpiceThemes SpicePress", ("/wp-content/themes/spicepress/",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Spicy Rocket", (".spicyrocket.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Spin-a-Sale", ("client.spinasale.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "SPIP", ("X-Spip-Cache",), ("HTTP",), "medium"),
    Rule("CMS", "SPIP", ("Composed-By",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "SplitIt", (".production.splitit.com/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "SPNEGO", ("WWW-Authenticate",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Spoki", ("app.spoki.it/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "SpotHopper", ("static.spotapps.co/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Spotii", ("widget.spotii.me",), ("HTTP",), "medium"),
    Rule("決済代行", "SpotOn", (".cdn.spoton.com",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "Spotzer", (".spotzer.com/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Spring", ("X-Application-Context",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Spring for creators", (".creator-spring.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Springnest", ("b-cdn.springnest.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Sprinklr", (".sprinklr.com/",), ("HTTP",), "medium"),
    Rule("CRM", "Spruce", ("widget-api.sprucehealth.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "SpurIT Abandoned Cart Reminder", ("cdn-spurit.com/shopify-apps/abandoned-cart-reminder/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "SpurIT Loyalty App", ("cdn-spurit.com/shopify-apps/loyaltypoints/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "SpurIT Partial Payments App", ("cdn-spurit.com/shopify-apps/split-payments/",), ("HTTP",), "medium"),
    Rule("決済代行", "SpurIT Recurring Payments App", ("cdn-spurit.com/shopify-apps/recurring-invoices/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Sqreen", ("X-Protected-By",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Square", ("js.squareup.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Squarespace Commerce", ("assets.squarespace.w/universal/scripts-compressed/commerce-w-min..js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Squiz Matrix", ("<!--sRunning  Matrix",), ("HTTP",), "medium"),
    Rule("CMS", "Squiz Matrix", ("/__data/assets//",), ("HTTP",), "medium"),
    Rule("CMS", "Squiz Matrix", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Sqwiz", ("//sqwiz.com/Scripts/",), ("HTTP",), "medium"),
    Rule("ページビルダー", "Stackbit", (".stackbit.com",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Stackify", (".stackify.com/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "StackPath", ("x-backend-server",), ("HTTP",), "medium"),
    Rule("CDN", "StackPath", ("x-provided-by",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Stammer.ai", ("app.stammer.ai",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Starhost", ("X-Starhost",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "StarTest", (".startest.top",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Statamic", ("x-powered-by",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Statically", ("cdn.statically.io/",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Status.io", ("static.status.io/",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Statuspal", ("//statuspal.io/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Stax", ("staxjs.staxpayments.com/",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Stimulus", ("<data-controller",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "STN Video", ("embed.sendtonews.com/",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Stoplight", ("//stoplight.io/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Storagely", ("static.storagely.link",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Storearmy", ("/storearmy.min.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Storeden", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Storefront", (".storefront7.co.za",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Storefront", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "StorePoint", ("cdn.storepoint.co/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Storyblok", ("content-security-policy",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Strapdown.js", ("strapdown.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Strapi", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("CMS", "Strato Website", ("strato-editor.com/",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Strattic", ("x-powered-by",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Streamroll", ("analytics.streamroll.net",), ("HTTP",), "medium"),
    Rule("CMS", "Strikingly", ("<!-- Powered by Strikingly.com",), ("HTTP",), "medium"),
    Rule("CMS", "Strikingly", (".strikinglycdn.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Stripe", ("<inputdata-stripe",), ("HTTP",), "medium"),
    Rule("決済代行", "Stripe", ("js.stripe.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Subbly", ("static.subbly.me/assets/",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "SublimeVideo", ("cdn.sublimevideo.net/js/.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Subrion", ("X-Powered-CMS",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Subscrimia", ("cdn.subscrimia.com",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Substack", ("x-cluster",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Sucuri", ("x-sucuri-cache:",), ("HTTP",), "medium"),
    Rule("CDN", "Sucuri", ("x-sucuri-id",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Sugester", (".sugester.pl/",), ("HTTP",), "medium"),
    Rule("CRM", "SuiteCRM", ("themes/SuiteP/js/",), ("HTTP",), "medium"),
    Rule("CRM", "SuiteDash", ("app.suitedash.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Sulu", ("X-Generator",), ("HTTP",), "medium"),
    # --- エディタ ---
    Rule("エディタ", "Summernote", ("/ummernote.js",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Supabase", ("cdn.supabase.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Superchat", (".superchat.de/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "SuperLemon app", ("/files/superlemon_..js",), ("HTTP",), "medium"),
    # --- 静的サイトジェネレーター ---
    Rule("静的サイトジェネレーター", "Surge", ("surge.sh.js",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "SVG Support", ("/wp-content/plugins/svg-support/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Swapcard", ("app.swapcard.com",), ("HTTP",), "medium"),
    Rule("CRM", "Swat.io", (".swat.io/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Swaven", ("widgets.swaven.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Swaven", ("Set-Cookie",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "SweetAlert", ("sweetalert.js",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "SweetAlert2", ("limonte-sweetalert2//sweetalert2.js",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "SweetAlert2", ("sweetalert2@/dist/sweetalert2.js",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "SweetAlert2", ("sweetalert2.js",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Swiftype", ("swiftype.com/embed.js",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Swipe Pages", (".swipepages.com/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Swiper", ("swiper.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Sylius", ("syliusgtmenhancedecommerceplugin",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Sylius", ("syliusshop/script.js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Syncfusion", (".syncfusion.com/",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Syncle", ("api.videoly.co/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Synctrack", ("apps.synctrack.io/",), ("HTTP",), "medium"),
    # --- ネットワークストレージ ---
    Rule("ネットワークストレージ", "Synology DiskStation", ("webapi/entry.cgiapi=SYNO..Desktop.",), ("HTTP",), "medium"),
    Rule("ネットワークストレージ", "Synology DiskStation", ("application-name",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Syte", ("cdn.syteapi.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Tabarnapp", ("cdn.tabarn.app/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Tabby", ("checkout.tabby.ai",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Tada", ("cdn.trytada.com/",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "Tailwind CSS", (".tailwindcss.|/npm/@tailwindcss/browser",), ("HTTP",), "medium"),
    Rule("UIフレームワーク", "Tailwind CSS", ("application-name",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "TakeTheme", ("application-name",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Talentegy", (".talentegy.com",), ("HTTP",), "medium"),
    Rule("CRM", "Talkdesk", (".talkdeskapp.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Tamara", ("cdn.tamara.co",), ("HTTP",), "medium"),
    # --- ホスティング ---
    Rule("ホスティング", "Tangled Network", ("X-Hosting-Provider",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "TanStack", ("/static/.npm.tanstack..js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "TargetBay", ("app.targetbay.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Tauros Media", (".taurosmedia.com/",), ("HTTP",), "medium"),
    # --- 会計・経理 ---
    Rule("会計・経理", "Taxdome", (".taxdome.com/",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "TDesign", ("tdesign.gtimg.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "TDO Software", ("tdosites.com/",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Teachable", (".teachablecdn.com",), ("HTTP",), "medium"),
    # --- CI・CD ---
    Rule("CI・CD", "TeamCity", ("application-name",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "TeamSystem Commerce", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- ネットワーク機器 ---
    Rule("ネットワーク機器", "TeamViewer", ("rum.monitis.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Tebex", ("tb-cache-country",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Tebex", ("tb-cache-group",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Tebex", ("js.tebex.io/",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "TechTarget", (".techtarget.com/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Tencent Cloud", (".tencent-cloud./",), ("HTTP",), "medium"),
    # --- ホスティングパネル ---
    Rule("ホスティングパネル", "Tencent Waterproof Wall", ("captcha.qq.com/.",), ("HTTP",), "medium"),
    Rule("ホスティングパネル", "Tencent Waterproof Wall", ("/TCaptcha.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Tender Support", (".tenderapp.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Tern", ("live.tern-returns.eastsideapps.io/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Textline", (".textline.com/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "The Events Calendar", ("/wp-content/plugins/the-events-calendar/",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "The SEO Framework", ("<!--The SEO Framework by Sybre Waaijer",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "The.com", ("the-dotcom-public-cdn.s3.amazonaws.com/",), ("HTTP",), "medium"),
    # --- 写真ギャラリー ---
    Rule("写真ギャラリー", "Theasys", ("static.theasys.io",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Thelia", ("</assets/frontOffice/",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Theme Freesia Edge", ("/wp-content/themes/edge/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Theme Freesia Photograph", ("/wp-content/themes/photograph/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Theme Freesia ShoppingCart", ("/wp-content/themes/shoppingcart/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Theme Horse Attitude", ("/wp-content/themes/attitude/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Theme Horse NewsCard", ("/wp-content/themes/newscard/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Theme4Press Evolve", ("/wp-content/themes/evolve/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Themeansar Newsup", ("/wp-content/themes/newsup/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Themegraphy Graphy", ("/wp-content/themes/graphy/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemeGrill Accelerate", ("/wp-content/themes/accelerate/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemeGrill Cenote", ("/wp-content/themes/cenote/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemeGrill ColorMag", ("/wp-content/themes/colormag/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemeGrill eStore", ("/wp-content/themes/etore/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemeGrill Flash", ("/wp-content/themes/flash/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemeGrill Radiate", ("/wp-content/themes/radiate/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemeGrill Spacious", ("/wp-content/themes/spacious/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemeZee Donovan", ("/wp-content/themes/donovan/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemeZee Poseidon", ("/wp-content/themes/poseidon/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemeZee Wellington", ("/wp-content/themes/wellington/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemezHut Bam", ("/wp-content/themes/bam/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "ThemezHut HitMag", ("/wp-content/themes/hitmag/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "THG Ingenuity", ("THEHUT-..js",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Think Up Themes Consulting", ("/wp-content/themes/consulting/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Think Up Themes Minamaze", ("/wp-content/themes/minamaze/",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Thinkific", ("cdn.thinkific.com",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "ThinkPHP", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Thinkstack", ("app.thinkstack.ai/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "ThreatMetrix", (".online-metrix.net",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "ThriveCart", ("thrivecart.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Ticimax", ("cdn.ticimax./",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "TiddlyWiki", ("<type=text/vnd.tiddlywiki",), ("HTTP",), "medium"),
    Rule("CMS", "TiddlyWiki", ("application-name",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "TikShop", ("app.tikshop.co/",), ("HTTP",), "medium"),
    # --- 会計・経理 ---
    Rule("会計・経理", "Tiller", (".by.tiller.co/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Timeago", ("jquery.timeago.js",), ("HTTP",), "medium"),
    Rule("JSライブラリ", "Tinycon", ("tinycon.js",), ("HTTP",), "medium"),
    # --- リッチテキストエディタ ---
    Rule("リッチテキストエディタ", "TinyMCE", ("/tiny_mce.js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Tipso", ("/js/tipso.min.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "TNS Payments", ("secure.ap.tnspayments.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Tokeet", ("widgets.tokeet.com",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Token of Trust", ("app.tokenoftrust.com",), ("HTTP",), "medium"),
    # --- マップ ---
    Rule("マップ", "TomTom Maps", ("api.tomtom.com",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Top Producer", ("static.topproducerwebsite.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Tossdown", (".tossdown.com/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "total.js", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "TotalCode", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "TownNews", ("x-tncms",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Track123", ("track123.com/common/checkout-script-loader.js",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Trackify X", ("trackifyx.redretarget.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "TradePending", (".tradepending.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "TradePro", ("/tradepro/shop/appserv/.",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Tradift", ("cdn.tradift.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Transax", (".transax.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "TravPRO", ("data.travpromobile.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Tray", ("tcdn.com.br",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Trezor", ("connect.trezor.io",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "TRIBUS", ("embed.mytribus.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Trove Recommerce", ("x-trove-country-code",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Trove Recommerce", ("x-trove-order-uuid",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Trove Recommerce", ("x-yerdle-app-name",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Trove Recommerce", ("x-trove-app-name",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "TrueCommerce", ("cdn.nexternal.com/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "TruValidate", ("ci-mpsnare.iovation.com",), ("HTTP",), "medium"),
    Rule("セキュリティ", "TruValidate", ("mpsnare.iesnare.com",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "Tryzens", (".tryzens-analytics.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Tulo", (".worldoftulo.com/",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Tumblr", ("X-Tumblr-User",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Tunosite", ("app.tunosite.com",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "TurfJS", ("/turf.min.js",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "TutorCruncher", ("cdn.tutorcruncher.com/",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Twenty Fifteen", ("/wp-content/themes/twentyfifteen/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Fourteen", ("/wp-content/themes/twentyfourteen/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Nineteen", ("/wp-content/themes/twentynineteen/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Seventeen", ("/wp-content/themes/twentyseventeen/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Sixteen", ("/wp-content/themes/twentysixteen/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Ten", ("/wp-content/themes/twentyten/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Thirteen", ("/wp-content/themes/twentythirteen/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Twelve", ("/wp-content/themes/twentytwelve/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Twenty", ("/wp-content/themes/twentytwenty/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Twenty-Five", ("/wp-content/themes/twentytwentyfive/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Twenty-Four", ("/wp-content/themes/twentytwentyfour/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "Twenty Twenty-One", ("/wp-content/themes/twentytwentyone/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "TwicPics", ("..twic.pics",), ("HTTP",), "medium"),
    # --- コメントシステム ---
    Rule("コメントシステム", "Twikoo", ("/twikoo/dist/twikoo.all.min.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Twilight CMS", ("X-Powered-CMS",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "TwistPHP", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- DMS ---
    Rule("DMS", "Typeflo", ("analytics.typeflo.io/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Ubercart", ("uc_cart/uc_cart_block.js",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Ucalc", ("ucalc.pro/api/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Ucommerce", ("uCommerce.facets.js",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "UIKit", ("uikit..js",), ("HTTP",), "medium"),
    # --- DMS ---
    Rule("DMS", "uKnowva", ("<a>Powered by uKnowva</a>",), ("HTTP",), "medium"),
    Rule("DMS", "uKnowva", ("/media/conv/js/jquery.js",), ("HTTP",), "medium"),
    Rule("DMS", "uKnowva", ("X-Content-Encoded-By",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "Ultimate Tables", ("/wp-content/plugins/ultimate-tables/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "UltraCart", ("<form action=\"/cgi-bin/UCEditormerchantId=",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Umbraco", ("X-Umbraco-Version",), ("HTTP",), "medium"),
    Rule("CMS", "UMI.CMS", ("X-Generated-By",), ("HTTP",), "medium"),
    # --- エディタ ---
    Rule("エディタ", "Unbounce", ("X-Unbounce-PageId",), ("HTTP",), "medium"),
    Rule("エディタ", "Unbounce", ("ubembed.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Unbound Commerce", (".unboundcommerce.com/",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Unbxd", (".cloudfront.net/unbxdAnalytics.js",), ("HTTP",), "medium"),
    Rule("検索エンジン", "Unbxd", ("unbxd.sd.amazonaws.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Unchained Engine", ("api.github.com/repos/unchainedshop/",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Understrap", ("wp-content/themes/understrap/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Unilog", (".unilogcorp.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Universe Soft", (".universe-soft.ru/",), ("HTTP",), "medium"),
    Rule("CRM", "Unless", (".unless.com/",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "Unpkg", ("unpkg.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Unstack", ("cdn.unstack.com/",), ("HTTP",), "medium"),
    # --- メディアサーバー ---
    Rule("メディアサーバー", "Uplynk", ("content-security-policy",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Upsales", ("img.upsales.com/",), ("HTTP",), "medium"),
    # --- リモートアクセス ---
    Rule("リモートアクセス", "Upscope", ("js.upscope.io/",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "UptimeRobot", ("content-security-policy",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "UptimeRobot", (".uptimerobot.com/",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Uptrends", (".uptrendsdata.com/",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "UserReport", (".userreport.com/",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "Usersnap", (".usersnap.com/",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "UserVoice", (".uservoice.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Ushahidi", ("/js/ushahidi.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Uvodo", ("cdn.uvo.do/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "v4Guard Checkpoint", (".v4guard.io/checkpoint",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Vanco Payment Solutions", (".eservicepayments.com/",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "Vanilla", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Vanta", ("static.vanta.com/",), ("HTTP",), "medium"),
    Rule("セキュリティ", "Variti", ("X-VARITI-CCR",), ("HTTP",), "medium"),
    # --- キャッシュ ---
    Rule("キャッシュ", "Varnish", ("X-Varnish-Hostname",), ("HTTP",), "medium"),
    Rule("キャッシュ", "Varnish", ("X-Varnish-Action",), ("HTTP",), "medium"),
    Rule("キャッシュ", "Varnish", ("X-Varnish-Cache",), ("HTTP",), "medium"),
    Rule("キャッシュ", "Varnish", ("X-Varnish-Age",), ("HTTP",), "medium"),
    Rule("キャッシュ", "Varnish", ("X-Varnish",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "vcita", ("widgets.vcdnita.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Vendaecia", (".vendaecia.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Vendio", ("stores.vendio.com",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Venngage", ("infograph.venngage.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "VentasxMayor", ("bunny-cdn.ventasxmayor.com/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "VentryShield", ("x-ventryshield-cache-status",), ("HTTP",), "medium"),
    Rule("セキュリティ", "VentryShield", ("x-ventryshield-sid",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Vepaar", ("analytics.vepaar.com/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Vercel", ("x-vercel-cache",), ("HTTP",), "medium"),
    Rule("PaaS", "Vercel", ("x-now-trace",), ("HTTP",), "medium"),
    Rule("PaaS", "Vercel", ("x-vercel-id",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Versa Commerce", (".versacommerce.de/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "VertaFlow", ("api.vertaflow.io/v1/pixel.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "VertaFlow", ("window.__TENANT_CONFIG__=",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "VertaFlow", ("Powered by VertaFlow",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "VertaFlow Forms", ("vertaflow.io/v1/form.js",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Vertex", ("/wp-content/themes/Vertex/js/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Very Good Security", ("Content-Security-Policy",), ("HTTP",), "medium"),
    Rule("セキュリティ", "Very Good Security", ("js.verygoodvault.com/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Vev", (".vev.design/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Vextras", (".vextras.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Vfinder", ("//vfinder.io/js/viewfinder.js",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "VideoJS", ("zencdn.net/c/video.js",), ("HTTP",), "medium"),
    Rule("動画プレーヤー", "Videoly", ("api.videoly.co/",), ("HTTP",), "medium"),
    Rule("動画プレーヤー", "Videoo.tv", ("static.videoo.tv",), ("HTTP",), "medium"),
    Rule("動画プレーヤー", "Vidscrip", (".vidscrip.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "VikaOn", ("X-Vikaon-Version",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Vikreta", ("x-powered-by",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Vintcer", (".vintcer.com/",), ("HTTP",), "medium"),
    # --- ブログ ---
    Rule("ブログ", "Virgool", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Visa Checkout", ("secure.checkout.visa.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Visenze", ("cdn.visenze.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Viskan", (".viskan.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Visual Quiz Builder", ("//whai-cdn.nycd.cdn.digitaloceanspaces.com/",), ("HTTP",), "medium"),
    Rule("Shopifyアプリ", "Vitals", ("//appsolve.io/",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Vitrin.me", (".vitrin.me/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Voltage", ("btcpay0.voltageapp.io",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Vondera", ("vondera-ecommerce",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Voog", (".voog.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Voog.com Website Builder", ("voog.com/tracker.js",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Voomly", ("embed.voomly.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Vop", ("cdn.getvop.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Vox Media", (".voxmedia.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "VP-ASP", ("<a>Powered By VP-ASP Shopping Cart</a>",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "VP-ASP", ("vs350.js",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Vrio", ("readme-subdomain",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "VTEX", ("powered",), ("HTTP",), "medium"),
    # --- キャッシュ ---
    Rule("キャッシュ", "W3 Total Cache", ("<!--W3 Total Cache",), ("HTTP",), "medium"),
    Rule("キャッシュ", "W3 Total Cache", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Wabi", (".wabi-app.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Wake", ("x-powered-by",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Walla", (".hellowalla.com",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "WAR.PE", ("//war.pe/warp.js",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Wati", ("wati-integration-prod-service.clare.ai/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Wave Commerce", (".wavecommerce.hk/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "WayForPay", ("secure.wayforpay.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Wazala", (".wazala.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "wBuy", (".sistemawbuy.com.br/",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "Web CEO", ("application-name",), ("HTTP",), "medium"),
    Rule("SEO", "Web CEO", (".webceo.com/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Web2py", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Web2py", ("web2py.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "WebAdministrator CMS", ("<!--  / WebAdministrator  //-->",), ("HTTP",), "medium"),
    # --- プログラミング言語 ---
    Rule("プログラミング言語", "WebAssembly", ("/wasm_exec.js",), ("HTTP",), "medium"),
    # --- UIフレームワーク ---
    Rule("UIフレームワーク", "WebAwesome", ("/webawesome.loader.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Webcool CMS", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- エディタ ---
    Rule("エディタ", "WEBDEV", ("WebDevSrc",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Webhealer", ("umami.webhealer.net",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "Webix", ("bwebix.js",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Weblium", ("res2.weblium.site/common/core.min.js",), ("HTTP",), "medium"),
    # --- JSフレームワーク ---
    Rule("JSフレームワーク", "WeBlocks", ("//weblocks.io/",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Webriti Busiprof", ("/wp-content/themes/busiprof/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Website Creator", ("wsc_rendermode",), ("HTTP",), "medium"),
    # --- ページビルダー ---
    Rule("ページビルダー", "Webydo", ("global.webydo.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "WebZi", ("//webzi.ir/",), ("HTTP",), "medium"),
    Rule("CMS", "Weebly", ("cdnd.editmysite.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Weezbe", ("static.weezbe.com",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Welcart", ("uscesL10n",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "WEN Themes Education Hub", ("/wp-content/themes/education-hub/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Wepay", (".wepay.com/",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Widde", ("Content-Security-Policy-Report-Only",), ("HTTP",), "medium"),
    Rule("動画プレーヤー", "Widde", ("cdn.widde.io",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "WideBundle", ("//widebundle.com/",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "Winstone Servlet Container", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Wirecard", (".wirecard.com/",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "Wistia", (".wistia.com",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Wix", ("X-Wix-Server-Artifact-Id",), ("HTTP",), "medium"),
    Rule("CMS", "Wix", ("static.parastorage.com",), ("HTTP",), "medium"),
    Rule("CMS", "Wix", ("X-Wix-Renderer-Server",), ("HTTP",), "medium"),
    Rule("CMS", "Wix", ("X-Wix-Request-Id",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "WizSoft", (".wizsoft.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "Wolf CMS", ("inside|Thank you for using <a>Wolf CMS)",), ("HTTP",), "medium"),
    Rule("CMS", "Woltlab Community Framework", ("WCF...js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "WooCommerce", (").woocommerce",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "WooCommerce Stripe Payment Gateway", ("/wp-content/plugins/woocommerce-gateway-stripe/",), ("HTTP",), "medium"),
    Rule("WordPressプラグイン", "WooCommerce Subscriptions", ("/plugins/woocommerce-subscriptions/vendor/woocommerce/subscriptions-core/build",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Woostify", ("/wp-content/themes/woostify/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "WoowUp", ("assets-cdn.woowup.com/",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "WordLift", ("cloud.wordlift.io/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "WordPress", ("wp-static.assets.sh/",), ("HTTP",), "medium"),
    Rule("CMS", "WordPress", ("wp-embed.min.js",), ("HTTP",), "medium"),
    Rule("CMS", "WordPress", ("X-Pingback",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "WordPress Default", ("/wp-content/themes/default/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "WordPress Popular Posts", ("WordPressPopularPosts",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "WordPress Project Manager", ("/wp-content/plugins/wedevs-project-manager/",), ("HTTP",), "medium"),
    # --- キャッシュ ---
    Rule("キャッシュ", "WordPress Super Cache", ("<!--WP-Super-Cache",), ("HTTP",), "medium"),
    Rule("キャッシュ", "WordPress Super Cache", ("WP-Super-Cache",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "WordPress VIP", ("x-powered-by",), ("HTTP",), "medium"),
    Rule("PaaS", "WordPress.com", ("host-header",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Workadu", ("app.workadu.com",), ("HTTP",), "medium"),
    Rule("CRM", "Workbooks", ("secure.workbooks.com",), ("HTTP",), "medium"),
    Rule("CRM", "WORKetc", (".worketc.com",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Workstand", ("smartetailing.piwik.pro/",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "WP Automatic", ("/wp-content/plugins/wp-automatic/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "WP Engine", ("X-WPE-Loopback-Upstream-Addr",), ("HTTP",), "medium"),
    Rule("PaaS", "WP Engine", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("PaaS", "WP Engine", ("wpe-backend",), ("HTTP",), "medium"),
    Rule("PaaS", "WP Engine", ("X-Pass-Why",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "WP Fastest Cache", ("/wp-content/cache/wpfc-minified/",), ("HTTP",), "medium"),
    Rule("WordPressプラグイン", "WP Featherlight", ("/wpFeatherlight.pkgd.min.js",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "WP Puzzle Basic", ("/wp-content/themes/basic/",), ("HTTP",), "medium"),
    # --- キャッシュ ---
    Rule("キャッシュ", "WP Rocket", ("/wp-content/plugins/wp-rocket/",), ("HTTP",), "medium"),
    Rule("キャッシュ", "WP Rocket", ("X-Rocket-Nginx-Bypass",), ("HTTP",), "medium"),
    Rule("キャッシュ", "WP Rocket", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "WP-Optimize", ("<!--Cached by WP-Optimize",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "WP-Royal Ashe", ("/wp-content/themes/ashe/",), ("HTTP",), "medium"),
    Rule("WordPressテーマ", "WP-Royal Bard", ("/wp-content/themes/bard/",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "wp.cloud", ("host-header",), ("HTTP",), "medium"),
    # --- キャッシュ ---
    Rule("キャッシュ", "wpCache", ("X-Powered-By",), ("HTTP",), "medium"),
    Rule("キャッシュ", "WPCacheOn", ("x-powered-by",), ("HTTP",), "medium"),
    # --- WordPressプラグイン ---
    Rule("WordPressプラグイン", "WPML", ("/wp-content/plugins/sitepress-multilingual-cms/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Wurfl", (".wurfl.io",), ("HTTP",), "medium"),
    # --- 認証 ---
    Rule("認証", "WWPass", ("cdn.wwpass.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Wyre", ("verify.sendwyre.com/",), ("HTTP",), "medium"),
    # --- リッチテキストエディタ ---
    Rule("リッチテキストエディタ", "WysiBB", ("/jquery.wysibb.min.js",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Xajax", ("xajax_core..js",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Xeora", ("<input type=\"hidden\" name=\"_sys_bind_d\" id=\"_sys_bind_d\" />",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Xeora", ("/_bi_sps_v..js",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Xeora", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- メッセージボード ---
    Rule("メッセージボード", "XMB", ("<!-- Powered by XMB",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Xonic", ("core/jslib/jquery.xonic.js.php",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Xpresslane", ("apps.xpresslane.in/",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "XRegExp", ("xregexp..js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Xsolla", (".xsolla.",), ("HTTP",), "medium"),
    # --- Wiki ---
    Rule("Wiki", "XWiki", ("<htmldata-xwiki->",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Yahoo! Ecommerce", ("X-XRDS-Location",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Yampi Virtual store", ("cdn.yampi.io/",), ("HTTP",), "medium"),
    # --- セキュリティ ---
    Rule("セキュリティ", "Yandex SmartCaptcha", ("x-yandex-captcha",), ("HTTP",), "medium"),
    # --- フォームビルダー ---
    Rule("フォームビルダー", "Yay! Forms", ("embed.yayforms.link",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "Ybug", (".ybug.io/",), ("HTTP",), "medium"),
    # --- Webフレームワーク ---
    Rule("Webフレームワーク", "Yii", ("<input type=\"hidden\" value=\"{40}\" name=\"YII_CSRF_TOKEN\" />",), ("HTTP",), "medium"),
    Rule("Webフレームワーク", "Yii", ("/assets/{8}/yii.js",), ("HTTP",), "medium"),
    # --- LMS ---
    Rule("LMS", "Yo!Coach", ("Set-Cookie",), ("HTTP",), "medium"),
    # --- SEO ---
    Rule("SEO", "Yoast SEO for Shopify", ("<!-- This site is optimized with Yoast SEO for Shopify -->",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "YogaTrail", ("widget.yogatrail.com",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "YooMoney", ("Content-Security-Policy",), ("HTTP",), "medium"),
    Rule("決済代行", "YooMoney", (".yoomoney.ru/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Yopify", ("//yopify.com/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Yotpo Subscriptions", ("<!-- BEGIN app block: shopify://apps/yotpo-subscriptions/blocks/app-embed-block",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "YouCan", ("x-powered-by",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "YouPay", ("app.youpay.ai/",), ("HTTP",), "medium"),
    # --- 開発ツール ---
    Rule("開発ツール", "YourGPT", ("widget.yourgpt.ai",), ("HTTP",), "medium"),
    # --- イシュートラッカー ---
    Rule("イシュートラッカー", "YouTrack", ("type=\"application/opensearchdescriptionxml\" title=\"YouTrack\"/>",), ("HTTP",), "medium"),
    Rule("イシュートラッカー", "YouTrack", ("no-title=\"YouTrack\">",), ("HTTP",), "medium"),
    # --- 動画プレーヤー ---
    Rule("動画プレーヤー", "YouTube", (".youtube.com/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Yuno", ("sdk-web.y.uno",), ("HTTP",), "medium"),
    # --- Webメール ---
    Rule("Webメール", "Zadarma", ("my.zadarma.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Zakeke Visual Customizer", (".zakeke.com/Scripts/integration/shopify/",), ("HTTP",), "medium"),
    # --- WordPressテーマ ---
    Rule("WordPressテーマ", "Zakra", ("/wp-content/themes/zakra/",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Zalify", (".zalify.com/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Zapiet", ("app.zapiet.com",), ("HTTP",), "medium"),
    # --- PaaS ---
    Rule("PaaS", "Zeabur", ("X-Zeabur-Request-Id",), ("HTTP",), "medium"),
    # --- Webサーバー ---
    Rule("Webサーバー", "Zend", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "ZendApps", (".zend-apps.com/",), ("HTTP",), "medium"),
    # --- ドキュメント ---
    Rule("ドキュメント", "Zendesk", ("static.zdassets.com",), ("HTTP",), "medium"),
    Rule("ドキュメント", "Zendesk", ("x-zendesk-user-id",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "Zenu", ("assets.zenu.com.au",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Zepio", ("X-Powered-By",), ("HTTP",), "medium"),
    # --- JSライブラリ ---
    Rule("JSライブラリ", "Zepto", ("zepto..js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Zestard", ("zestardshop.com/shopifyapp",), ("HTTP",), "medium"),
    # --- 検索エンジン ---
    Rule("検索エンジン", "Zevi", (".zevi.ai/",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Ziadah", (".ziadah.app/",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Zip", ("static.zipmoney.com.au",), ("HTTP",), "medium"),
    Rule("決済代行", "Zip", ("quadpay.com",), ("HTTP",), "medium"),
    # --- Shopifyアプリ ---
    Rule("Shopifyアプリ", "Zipify OCU", ("/zipify-oneclickupsell-vendor.js",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Zoey", ("cdna4.zoeysite.com",), ("HTTP",), "medium"),
    # --- 静的サイトジェネレーター ---
    Rule("静的サイトジェネレーター", "Zola", (".getzola.org",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "Zoorix", (".zoorix.com/",), ("HTTP",), "medium"),
    Rule("EC・Makeshop", "Zozo", ("zozo-main.min.js",), ("HTTP",), "medium"),
    # --- 決済代行 ---
    Rule("決済代行", "Zuora", (".zuora.com/",), ("HTTP",), "medium"),
    # --- CRM ---
    Rule("CRM", "11Sight", ("app.11sight.com/",), ("HTTP",), "medium"),
    # --- CMS ---
    Rule("CMS", "1C-Bitrix", ("X-Powered-CMS",), ("HTTP",), "medium"),
    Rule("CMS", "1C-Bitrix", ("Set-Cookie",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "42stores", ("Powered-By",), ("HTTP",), "medium"),
    # --- CDN ---
    Rule("CDN", "5centsCDN", (".5centscdn.com/",), ("HTTP",), "medium"),
    Rule("CDN", "5centsCDN", ("x-cdn",), ("HTTP",), "medium"),
    # --- EC・Makeshop ---
    Rule("EC・Makeshop", "91App", ("cdn.91app.com/",), ("HTTP",), "medium"),
]
