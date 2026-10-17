"""miharun で使うデータ構造.

標準ライブラリの dataclass だけで表現しています。
外部ライブラリに依存しないため、どの環境でもそのまま動きます。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

# 日本標準時（UTC+9・夏時間なし）
JST = timezone(timedelta(hours=9), "JST")


def now_jst() -> datetime:
    """日本標準時の現在時刻を返す。"""
    return datetime.now(JST)


@dataclass
class HostResult:
    """サブドメイン 1 つについて分かったこと。"""

    host: str
    addresses: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    reverse: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    http_status: Optional[int] = None
    http_server: Optional[str] = None
    http_title: Optional[str] = None
    http_markers: list[str] = field(default_factory=list)
    note: Optional[str] = None

    # --- 証明書透明性ログから分かる「露出期間」 ---
    # 最初に証明書が発行された日 = そのホストが少なくともその時点から公開されている
    first_seen: Optional[str] = None  # ISO8601（not_before の最早値）
    last_seen: Optional[str] = None  # ISO8601（not_before の最新値）
    issuers: list[str] = field(default_factory=list)  # 発行認証局

    @property
    def is_live(self) -> bool:
        """名前解決できた、または HTTP 応答があったホストか。"""
        return bool(self.addresses or self.http_status is not None)

    @property
    def exposure_days(self) -> Optional[int]:
        """このホストが外部公開されている日数（証明書透明性ログ基準）.

        まだ無い（証明書の記録がない）場合は None。
        """
        if not self.first_seen:
            return None
        try:
            start = datetime.fromisoformat(self.first_seen)
        except ValueError:
            return None
        # crt.sh の時刻はタイムゾーン無し（UTC）なので aware にそろえる
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        delta = now_jst() - start
        return max(0, delta.days)

    @property
    def exposure_years(self) -> Optional[float]:
        days = self.exposure_days
        return None if days is None else round(days / 365.25, 1)


@dataclass
class Finding:
    """レポートに載せる気づき（所見）。"""

    level: str  # "info" | "notice" | "warn"
    title: str
    detail: str = ""
    score: int = 0  # 危険度スコア（0 = 問題なし、100 = 重大）
    host: str = ""  # 関連ホスト（あれば）


def risk_level(score: int) -> str:
    """スコアからレベル名を返す（表示用）."""
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    return "low"


@dataclass
class Organization:
    """入力が企業名だった場合に埋まる法人情報。"""

    name: Optional[str] = None
    corporate_number: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    source: Optional[str] = None


@dataclass
class SurfaceReport:
    """miharun の最終的な出力。JSON にも Markdown にも変換できる。"""

    target: str
    input_kind: str  # "domain" | "organization"
    generated_at: datetime = field(default_factory=now_jst)
    domain: Optional[str] = None
    organization: Optional[Organization] = None

    # 頂点ドメインの DNS レコード（"MX" -> ["..."], "NS" -> ["..."] など）
    apex: dict[str, list[str]] = field(default_factory=dict)

    # 見つかったサブドメイン
    hosts: list[HostResult] = field(default_factory=list)

    # (カテゴリ, 技術名) の組。例: ("メール", "Google Workspace")
    technologies: list[tuple[str, str]] = field(default_factory=list)

    findings: list[Finding] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_technology(self, category: str, name: str) -> None:
        """重複を避けて技術を追加する。"""
        item = (category, name)
        if item not in self.technologies:
            self.technologies.append(item)

    def add_finding(
        self, level: str, title: str, detail: str = "", score: int = 0, host: str = ""
    ) -> None:
        """重複を避けて所見を追加する。"""
        for existing in self.findings:
            if existing.level == level and existing.title == title:
                return
        self.findings.append(
            Finding(
                level=level, title=title, detail=detail, score=score, host=host
            )
        )

    @property
    def overall_risk(self) -> int:
        """全体の危険度スコア（最も高い所見のスコア）。"""
        return max((f.score for f in self.findings), default=0)

    @property
    def live_hosts(self) -> list[HostResult]:
        return [h for h in self.hosts if h.is_live]
