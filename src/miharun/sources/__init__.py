"""miharun のデータソース.

いずれも公開情報を読み取るだけのモジュールです。
対象ホストへの能動的なリクエストは行いません
（http_probe.py だけが例外で、--probe 指定時のみ使われます）。

* dns.py         … DNS over HTTPS（Cloudflare / Google）
* crtsh.py       … 証明書透明性ログ（crt.sh）
* company.py     … 企業名 → 法人情報（gBizINFO / 国税庁 法人番号 API）
* http_probe.py  … 任意の HTTP ヘッダ取得（--probe 時のみ）
"""
