"""CLI の流れのテスト（ネットワークを使わない）.

`build_report` を差し替えて、ファイル出力と変化検知の順序だけを検証します。
実機確認で見つかった次の 2 件の不具合の再発防止が目的です。

* `--json --diff` を同時に指定しても変化を検出できること
  （以前は「今回の JSON」で「前回の JSON」を上書きしてから比較していたため、
  常に自分自身と比べて「変化なし」になっていました）
* 企業名からドメインを決められなかったとき、中身の無いレポートを
  出力しないこと（以前は `miharun-report-report.md` を作り、
  別の企業を調べるたびに上書きしていました）
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import miharun.cli as cli
from miharun.models import HostResult, SurfaceReport


def sample_report(
    hosts: list[str],
    domain: str | None = "example.com",
    target: str = "example.com",
    input_kind: str = "domain",
) -> SurfaceReport:
    report = SurfaceReport(target=target, input_kind=input_kind)
    report.domain = domain
    for host in hosts:
        report.hosts.append(HostResult(host=host, addresses=["203.0.113.10"]))
    return report


class TestDiffOrdering(unittest.TestCase):
    """変化検知が「前回の JSON」と正しく比べられること."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name)
        self.out.mkdir(parents=True, exist_ok=True)

    def _baseline(self, hosts: list[str]) -> None:
        (self.out / "miharun-example.com-report.json").write_text(
            json.dumps(
                {
                    "tool": "miharun",
                    "target": "example.com",
                    "domain": "example.com",
                    "hosts": [{"host": host} for host in hosts],
                    "technologies": [],
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )

    def _run(self, report: SurfaceReport, user_args: list[str]) -> tuple[int, str]:
        buffer = io.StringIO()
        with mock.patch.object(cli, "build_report", return_value=report):
            with contextlib.redirect_stdout(buffer):
                code = cli.main([*user_args, "--out", str(self.out)])
        return code, buffer.getvalue()

    def test_diff_detects_change_even_with_json(self):
        self._baseline(["old.example.com"])
        code, printed = self._run(
            sample_report(["old.example.com", "new.example.com"]),
            ["example.com", "--no-subdomains", "--json", "--diff"],
        )
        self.assertEqual(code, 0)
        self.assertIn("前回との比較", printed)
        self.assertIn("新規ホスト: 1", printed)
        self.assertIn("new.example.com", printed)

    def test_baseline_is_updated_after_comparing(self):
        self._baseline(["old.example.com"])
        self._run(
            sample_report(["old.example.com", "new.example.com"]),
            ["example.com", "--no-subdomains", "--json", "--diff"],
        )
        data = json.loads(
            (self.out / "miharun-example.com-report.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {host["host"] for host in data["hosts"]},
            {"old.example.com", "new.example.com"},
        )

    def test_diff_report_uses_japanese_labels(self):
        self._baseline(["old.example.com"])
        self._run(
            sample_report(["old.example.com", "new.example.com"]),
            ["example.com", "--no-subdomains", "--json", "--diff"],
        )
        text = (self.out / "miharun-example.com-diff.md").read_text(encoding="utf-8")
        self.assertIn("新たに現れたホスト", text)
        # 中国語の字形（新 + U+589E）が混ざっていないこと
        self.assertNotIn("\u65b0\u589e", text)


class TestNoReportWithoutDomain(unittest.TestCase):
    """調べる対象のドメインが決まらないときは何も出力しないこと."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name)
        self.out.mkdir(parents=True, exist_ok=True)

    def test_unknown_domain_writes_nothing(self):
        report = sample_report(
            [], domain=None, target="株式会社サンプル", input_kind="organization"
        )
        buffer = io.StringIO()
        with mock.patch.object(cli, "build_report", return_value=report):
            with contextlib.redirect_stdout(buffer):
                code = cli.main(["株式会社サンプル", "--out", str(self.out)])

        self.assertEqual(code, 2)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), [])
        self.assertIn("レポートは出力しません", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
