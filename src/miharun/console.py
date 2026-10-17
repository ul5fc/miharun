"""標準出力・標準エラーの文字コードを整える.

Windows の既定の文字コードは、英語環境では cp1252 です。
そのまま日本語を print すると UnicodeEncodeError で異常終了します。
`miharun` 本体だけでなく examples/ や scripts/ の入口も、
出力を始める前にここを通します。
"""

from __future__ import annotations

import sys


def setup_console() -> None:
    """日本語を出力しても落ちないように標準出力・標準エラーを整える.

    - 画面（TTY）に出すとき: 現在の文字コードを保ち、変換できない文字は置換する
    - ファイルやパイプに流すとき: UTF-8 で書き出す

    出力を始めた後では文字コードを変更できないため、
    print より前に呼び出すこと。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            # 差し替えられたストリーム（テストの収集など）は
            # reconfigure を持たないことがある。その場合は何もしない。
            pass
