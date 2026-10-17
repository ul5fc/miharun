"""miharun — 組織の外部公開マップを日本語で作るパッシブ偵察ツール.

miharun は公開情報（証明書透明性ログ・DNS・公開 API）だけを読み取り、
対象の組織が「外からどう見えているか」を日本語のレポートにまとめます。

設計方針は「パッシブ・ファースト」です。
既定では対象ホストに一切リクエストを送りません。

使い方::

    miharun example.com
    miharun example.co.jp --html --json
    miharun example.com --probe --diff

詳細は README.md と docs/SAFETY.md を参照してください。

このファイルはプロジェクトのメタ情報（バージョン・URL・作者）を
一元管理する唯一の場所です。
GitHub のユーザー名を変更する場合は、ここだけ書き換えてください
（pyproject.toml と README.md の URL も合わせて変更してください）。
"""

__version__ = "0.1.0"

#: プロジェクトの GitHub リポジトリ URL（レポートのフッターと User-Agent で使用）
__repository__ = "https://github.com/ul5fc/miharun"

#: 作者名（ライセンス表記に使用）
__author__ = "ul5fc"

__all__ = ["__version__", "__repository__", "__author__"]