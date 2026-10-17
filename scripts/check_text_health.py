"""テキストの健全性を検査する（文字化け・文字混入の検出）.

CI で実行し、レポートやコードに文字化け（U+FFFD）や
日本語に混ざるはずのない文字（ハングル・キリル・アラビア文字、
簡体字中国語だけに使われる漢字など）が紛れ込んでいないかを確認します。

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

# 簡体字中国語だけに使われ、日本語では使われない「部首ブロック」。
# 日本語の新字体とは別の Unicode 領域を占めるため、範囲でまとめて判定できます。
SIMPLIFIED_RANGES = [
    ("言べん（簡体字）", 0x8BA0, 0x8C36),  # 讠 计 认 说 请 ……
    ("貝（簡体字）", 0x8D1D, 0x8D63),  # 贝 财 贡 贵 贴 ……
    ("車（簡体字）", 0x8F66, 0x8F9A),  # 车 轮 转 轻 输 ……
    ("糸へん（簡体字）", 0x7E9F, 0x7F35),  # 纟 红 纪 织 编 ……
    ("金へん（簡体字）", 0x9485, 0x9576),  # 钅 针 银 铁 键 ……
    ("見（簡体字）", 0x89C1, 0x89D1),  # 见 观 视 觉 ……
    ("食へん（簡体字）", 0x9963, 0x9995),  # 饣 饭 馆 ……
    ("馬（簡体字）", 0x9A6C, 0x9AA7),  # 马 骑 验 ……
    ("魚（簡体字）", 0x9C7C, 0x9CE4),  # 鱼 鲜 鲸 ……
    ("鳥（簡体字）", 0x9E1F, 0x9E74),  # 鸟 鸡 鹰 ……
    ("頁（簡体字）", 0x9875, 0x98A7),  # 页 顶 题 颜 ……
    ("風（簡体字）", 0x98CE, 0x98DA),  # 风 飘 飙 ……
    ("龍（簡体字）", 0x9F99, 0x9F9B),  # 龙 龚 龛
    ("門（簡体字）", 0x95E8, 0x961B),  # 门 问 闭 间 闻 ……
    ("韋（簡体字）", 0x97E6, 0x97EC),  # 韦 韧 韩
]

# 部首ブロックに含まれない、よく使われる簡体字だけの文字。
# 日本語の新字体と字形が同じもの（内・画・称・窃・茎・蛮・万・状・条・走・晒 など）は
# 入れていません。入れると日本語の本文を誤検知するためです。
SIMPLIFIED_CHINESE = set(
    "这说时对开无华语书长应让该为产亲从军农况减击则刚创别剧务动势协单卖卫压县发变员义习乡"
    "买亿仅优伟伤养兽冈册冲净凉凤凭凯划刘剂剑劝办劲劳勋历厉厌严丧丽举齐过还进远连违运选适"
    "隐飞显结报测处备录标样类业质图签权网据库个临两复够头夹夺奋奖妇妈妆娱婴娇宁宝实审宪宫"
    "宽宾寻导尔尘尝尧层岁岂岗岛岭崭嵘巅巩币帅师帐帜带帮幂并广庆庐废庙异弃张弯弹强归彻忆忧"
    "怀态总恶恼恳惬惭惮惯惫惩愿慑懒戏战户扎扑执扩扫扬扰抚抟抠抡抢护拟拢拣拥拦拧拨择挂挚挛"
    "挣挤挥捞损捡换捣掳掷掸掺揽搀搁搂搅摄摆摇摊擞攒敌敛斋斩旷昙晓晕晖暂杀杂杨极构枢枣枪枫"
    "柜柠栈栏树桥桦档桢楼榄榈榇槛歼殡毁毕毙毡气氢汇汉汤沟沥沦泽洁洼泼浏济浑浓涛涝涡涨涩渊"
    "渐渔渗湿溃溅滚满滤滥滩滨灭灵灾烂烛烦烧烫热焕爱爷犹狈狞独狱狮猎猬獭玑玛环现玮珑琐"
    "瓒电畅疗疟疡疮疯痪痈痉痒痫瘪瘫瘾癞皑皱监盖盘睁睐瞒矫矶矾矿码砖砚确碛碱祷祸离秃秆积秽"
    "稳穷窍窑窜窝窥竖竞笃笔笼筛简箩箪篓篮粤粪粮紧罗罚罢羡翘耻聂聋职联聪肃肠肤肮肾肿胀胁胜"
    "胶脉脏脐脑脓脸腊腻腾舆舰舱舻艰艳艺节芜苇苍苏苹茧荐荚荡荣荤药莲获莹莺萝萧萨蒋蓝蓟蓦蔷"
    "蔼蕴藓虏虑蚀蚂蛰蝼蝾螨衅衔补衬袄袜袭裆褛"
    # 部首ブロックに属さない「独立した」簡体字。
    # 増（日本語）と增（簡体字）のように字形だけが違うものは、
    # 範囲では拾えないため個別に列挙する。
    "增产单关图对济发变长开实卖买农军处备复听员响团园围场块报显检权极构标样"
    "欢积稳类联职萝药获营览观规觉达运还这进远连迟适选递逻遗邮郑释隐险队际"
    "陆陈阳阴阵阶飞齐齿龟"
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
    for name, start, end in SIMPLIFIED_RANGES:
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
