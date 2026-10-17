"""日本語の出力が Windows（英語環境）でも落ちないことのテスト.

Windows の既定の文字コードは、英語環境では cp1252 です。CI の
windows-latest で `examples/make_example.py` が日本語の print で
UnicodeEncodeError になり落ちたため、その再発防止が目的です。

標準出力を cp1252 に固定した子プロセスを起動し、日本語が出力できるかを
実際に確かめます（ネットワークは使いません）。
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from miharun.console import setup_console

ROOT = Path(__file__).resolve().parent.parent

# Windows（英語環境）の既定の文字コード。日本語を表せない。
HOSTILE_ENCODING = "cp1252"


def run_python(args: list[str]) -> subprocess.CompletedProcess[str]:
    """標準出力を cp1252 に固定して Python を起動する.

    子プロセスの出力は UTF-8（入口が整えた後）なので、
    受け取るときも UTF-8 として読む。
    """
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = HOSTILE_ENCODING
    env.pop("PYTHONUTF8", None)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )


class TestSetupConsole(unittest.TestCase):
    """`setup_console` が日本語を出力できる状態にすること."""

    def test_japanese_survives_cp1252_stdout(self):
        code = (
            "from miharun.console import setup_console\n"
            "setup_console()\n"
            "print('日本語のテスト')\n"
        )
        proc = run_python(["-c", code])

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("日本語のテスト", proc.stdout)

    def test_stream_without_reconfigure_is_ignored(self):
        class FakeStream:
            def isatty(self) -> bool:
                return False

        with mock.patch.object(sys, "stdout", FakeStream()), mock.patch.object(
            sys, "stderr", FakeStream()
        ):
            setup_console()  # 例外を出さないこと


class TestEntryPoints(unittest.TestCase):
    """日本語を出力する入口が、実際に落ちずに動くこと."""

    def test_text_health_checker_survives_cp1252_stdout(self):
        proc = run_python(["scripts/check_text_health.py"])

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("問題はありません", proc.stdout)

    def test_rule_builder_survives_cp1252_stdout(self):
        """外部通信は差し替えて失敗させ、文字コードで落ちていないことだけを見る.

        取得の失敗はスクリプト内で握り潰されて処理が続くため、
        握り潰されない例外を投げて最初の取得で止める。
        生成物（`rules_web.py`）を書き換えないことも確かめる。
        """
        target = ROOT / "src" / "miharun" / "rules_web.py"
        before = target.read_bytes()

        code = (
            "import runpy, urllib.request\n"
            "class Stop(BaseException):\n"
            "    pass\n"
            "def stub(*args, **kwargs):\n"
            "    raise Stop('stub-network')\n"
            "urllib.request.urlopen = stub\n"
            "runpy.run_path('scripts/build_web_rules.py', run_name='__main__')\n"
        )
        proc = run_python(["-c", code])

        self.assertNotIn("UnicodeEncodeError", proc.stderr)
        self.assertIn("署名データを取得しています", proc.stdout)
        self.assertIn("stub-network", proc.stderr)
        self.assertEqual(target.read_bytes(), before, "生成物を書き換えています")


if __name__ == "__main__":
    unittest.main()
