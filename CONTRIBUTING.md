# コントリビューションガイド

miharun へのコントリビューションを歓迎します。
とくに**日本向けの判定ルールの追加**は 1 行からできるので、はじめの一歩に向いています。

---

## 大切にしている方針

1. **依存ライブラリを増やさない** — 標準ライブラリだけで動くことが miharun の売りです。
2. **パッシブ・ファースト** — 既定では対象ホストにリクエストを送りません。
   新しい情報源を足すときは、この原則を壊さないでください。
3. **断定しない** — レポートの文言は「〜の可能性があります」のように、
   推定であることを保つ書き方に統一します。
4. **誤検知を嫌う** — 検出を増やすより、誤検知を減らすことを優先します。

---

## 開発環境

Python 3.10 以上があれば動きます。仮想環境を作る場合:

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
```

インストール（開発用）:

```bash
pip install -e .
```

テストと文字化けチェック:

```bash
python -m unittest discover -s tests -t .
python scripts/check_text_health.py --strict
```

テストはネットワークに接続しません。オフラインで完結します。

---

## 判定ルールを足す（いちばん簡単な貢献）

DNS レコードから判定するルールは `src/miharun/rules.py` の 1 行です。

```python
Rule(
    "メール",                                  # レポートでの分類
    "例のメールサービス",                        # 表示名
    ("example-mail.jp",),                      # 小文字で部分一致させる文字列
    ("MX",),                                   # どのレコードを見るか（NS/MX/TXT/CNAME/PTR/HTTP）
    "high",                                    # 確度（high / medium / low）
)
```

追加したら、`tests/test_fingerprint.py` に判定のテストを足してください。

```python
def test_detects_example_mail(self):
    found = detect({"MX": ["example-mail.jp"]})
    self.assertIn(("メール", "例のメールサービス"), {(c, n) for c, n, _ in found})
```

---

## Web 技術ルールの再生成

`--probe` 用の Web 技術ルール（`src/miharun/rules_web.py`）は
[Wappalyzer（enthec/webappanalyzer・MIT）](https://github.com/enthec/webappanalyzer)
の署名データから自動生成しています。手で編集しないでください。

再生成する場合（**ネットワークに接続します**）:

```bash
python scripts/build_web_rules.py
```

生成された差分を確認し、誤検知が増えていないかをテストで確かめてください。
`rules_web.py` は生成物ですが、リポジトリにコミットします
（利用時に外部通信をさせないためです）。

---

## コードの書き方

- 型ヒントを付けます（`from __future__ import annotations` を先頭に）
- docstring とコメントは**日本語**で書きます
- 純粋なロジック（計算・判定）はネットワークから切り離し、単体テストを書きます
- 1 ファイル 1 責務を目安にします

---

## プルリクエスト

1. 変更の目的を書いてください（何を・なぜ）
2. `python -m unittest discover -s tests -t .` が通ることを確認してください
3. `python scripts/check_text_health.py --strict` が通ることを確認してください
4. 検出を増やす変更なら、**誤検知しない例**もテストに足してください

---

## 安全性

miharun は**自分の資産、または許可を得た対象**にのみ使ってください。
他者の許可なくスキャンする使い方を助長する変更は受け入れません。
詳細は [docs/SAFETY.md](docs/SAFETY.md) を参照してください。

---

## ライセンス

コントリビューションは MIT ライセンスの下で提供されます。
