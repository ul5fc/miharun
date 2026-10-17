"""テキストの健全性を検査する（文字化け・文字混入の検出）.

CI で実行し、レポートやコードに文字化け（U+FFFD）や
日本語に混ざるはずのない文字（ハングル・キリル・アラビア文字など）が
紛れ込んでいないかを確認します。

    python scripts/check_text_health.py          # 文字化けだけ検査
    python scripts/check_text_health.py --strict # 外国語文字の混入も検査

問題があれば終了コード 1 で終了します。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 検査する対象
PATTERNS = [
    "src/**/*.py",
    "tests/*.py",
    "scripts/*.py",
    "examples/*.py",
    "*.md",
    "docs/*.md",
    ".github/**/*.md",
    ".github/**/*.yml",
    "pyproject.toml",
]

REPLACEMENT = "\ufffd"

# 日本語文書に混ざると不自然な文字の範囲
FOREIGN_RANGES = [
    ("ハングル", 0x1100, 0x11FF),
    ("ハングル", 0xAC00, 0xD7AF),
    ("キリル", 0x0400, 0x04FF),
    ("アラビア", 0x0600, 0x06FF),
    ("ヘブライ", 0x0590, 0x05FF),
    ("タイ", 0x0E00, 0x0E7F),
    ("デーヴァナーガリー", 0x0900, 0x097F),
    ("アルメニア", 0x0530, 0x058F),
    ("ジョージア", 0x10A0, 0x10FF),
    ("ベンガル", 0x0980, 0x09FF),
]

# 簡体字中国語だけに使われ、日本語では使われない文字。
# 日本語話者が書いた文章にこれらが現れたら、ほぼ確実に混入です。
# （日本語の新字体と字形が同じものは含めていません）
SIMPLIFIED_CHINESE = set(
    "这说时对开门问间关无华语书车见长应让认讲谢许请谁词试该为产亲从传军农决况减击则刚创"
    "别剧务动势协单卖卫压县发变员义习乡买亿仅优伟伤养兽冈册冲净凉凤凭凯划刘剂剑劝办劲劳"
    "勋历厉厌严丧丽举齐过还进远连违运选适隐韩题颜风飞马验驾骑龙"
)


def _targets() -> list[Path]:
    files: list[Path] = []
    for pattern in PATTERNS:
        files.extend(sorted(ROOT.glob(pattern)))
    return sorted({f for f in files if f.is_file()})


# 自動生成ファイルは外国語の技術名を含みうるため、文字混入の検査から除く
# （チェックスクリプト自身は、判定用の文字集合を定義しているため除外）
STRICT_EXCLUDE = {
    "src/miharun/rules_web.py",
    "scripts/check_text_health.py",
}


def _foreign_name(char: str) -> str | None:
    code = ord(char)
    for name, start, end in FOREIGN_RANGES:
        if start <= code <= end:
            return name
    if char in SIMPLIFIED_CHINESE:
        return "簡体字"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="テキストの健全性を検査する")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="日本語以外の文字（ハングル等）の混入もエラーにする",
    )
    args = parser.parse_args()

    problems = 0
    checked = 0

    for path in _targets():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            print(f"[NG] {path.relative_to(ROOT)}: 読み込めません: {exc}")
            problems += 1
            continue

        checked += 1
        rel = path.relative_to(ROOT)

        for number, line in enumerate(text.splitlines(), start=1):
            if REPLACEMENT in line:
                print(f"[NG] {rel}:{number}: 文字化け（U+FFFD）")
                problems += 1

            if args.strict and rel.as_posix() not in STRICT_EXCLUDE:
                found = {name for char in line if (name := _foreign_name(char))}
                if found:
                    names = "・".join(sorted(found))
                    print(f"[NG] {rel}:{number}: 不自然な文字（{names}）")
                    problems += 1

    if problems:
        print(f"\n{problems} 件の問題を検出しました（{checked} ファイルを検査）。")
        return 1

    print(f"OK: {checked} ファイルに問題はありません。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
