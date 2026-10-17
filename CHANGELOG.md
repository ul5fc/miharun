# 変更履歴

このファイルの形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に、
バージョン番号は [セマンティック バージョニング](https://semver.org/lang/ja/) に従います。

## [未リリース]

## [0.1.0] - 2026-10-17

最初のリリース。

### 追加

- ドメインまたは**企業名**からのパッシブ調査
  - 企業名は法人番号システム / gBizINFO でドメインへ解決
- 証明書透明性ログ（crt.sh）からのサブドメイン列挙
- **露出年数** — 証明書の最初の発行日から「いつから公開されているか」を算出
- **危険度スコア（0〜100）** — ホストごとに採点し、総合値を算出
- **変化検知（`--diff`）** — 前回の JSON と比較して増減を報告
- **CI 連携（`--fail-on`）** — 閾値超過で終了コード 1
- **Web 技術判定（`--probe`）** — Wappalyzer 由来の 1,800 種類以上の技術 / 66 カテゴリ
  - HTTP 応答ヘッダによる判定（`Server` など）と、本文・JavaScript の指紋による判定の 2 系統
  - HTML タグ名・`og:image` のようなどこにでも現れる語はパターンから除外
  - ヘッダの**名前**を本文の文字列として使わない（`Host` が `hosting` に一致する等の誤検知を防止）
- 日本向けの判定ルール（さくら / エックスサーバー / ConoHa / EC-CUBE /
  Trend Micro Email Security / BASE / カラーミーショップ など）
- Markdown / HTML / JSON のレポート出力（HTML はダークテーマ・印刷対応）
- 依存ライブラリ 0（Python 3.10+ の標準ライブラリのみ）
- `--probe` の安全設計（robots.txt の尊重・レート制限・1 ホスト 1 回）

### ドキュメント

- `README.md` — 使い方と設計方針
- `docs/SAFETY.md` — 安全な使い方と禁止事項
- `docs/SOURCES.md` — 情報源の一覧と仕様メモ
- `CONTRIBUTING.md` — 判定ルールの追加方法
- `examples/make_example.py` — 架空データでのサンプルレポート生成

[未リリース]: https://github.com/ul5fc/miharun/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ul5fc/miharun/releases/tag/v0.1.0
