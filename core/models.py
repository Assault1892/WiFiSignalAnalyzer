"""Data models for WiFi Signal & Stability Analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class WiFiInfo:
    """Represents collected Wi-Fi interface and signal metadata."""

    connected: bool
    interface: str = ""
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    rssi_dbm: Optional[int] = None
    noise_dbm: Optional[int] = None
    snr_db: Optional[int] = None
    signal_percent: Optional[int] = None
    tx_rate_mbps: Optional[float] = None
    channel: Optional[str] = None
    band: Optional[str] = None
    phy_mode: Optional[str] = None
    security_raw: str = ""
    mcs_index: Optional[int] = None
    platform_source: str = ""
    notes: List[str] = field(default_factory=list)

    def finalize(self) -> "WiFiInfo":
        """Compute derived fields (SNR, signal percentage, band) if missing."""
        if self.rssi_dbm is not None and self.noise_dbm is not None and self.snr_db is None:
            self.snr_db = self.rssi_dbm - self.noise_dbm
        if self.signal_percent is None and self.rssi_dbm is not None:
            pct = 2 * (self.rssi_dbm + 100)
            self.signal_percent = max(0, min(100, int(pct)))
        if self.rssi_dbm is None and self.signal_percent is not None:
            self.rssi_dbm = int(round((self.signal_percent / 2.0) - 100))
        if self.ssid and self.ssid.strip().lower() in {"<redacted>", "redacted"}:
            self.ssid = "接続中Wi-Fi (SSID非公開設定)"
        if self.bssid and self.bssid.strip().lower() in {"<redacted>", "redacted"}:
            self.bssid = "非公開 (<redacted>)"
        if not self.band and self.channel:
            ch_lower = self.channel.lower()
            if "6ghz" in ch_lower or "6 ghz" in ch_lower:
                self.band = "6GHz"
            elif "5ghz" in ch_lower or "5 ghz" in ch_lower:
                self.band = "5GHz"
            elif "2.4ghz" in ch_lower or "2.4 ghz" in ch_lower:
                self.band = "2.4GHz"
        if not self.band:
            self.band = "不明"
        return self

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PingTargetResult:
    """Ping / reachability statistics for a single host."""

    target: str
    transmitted: int
    received: int
    packet_loss_pct: float
    min_ms: Optional[float] = None
    avg_ms: Optional[float] = None
    max_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    method: str = "ICMP"
    raw_rtts: List[float] = field(default_factory=list)
    label: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PingSummary:
    """Aggregated Ping RTT and packet loss summary across targets."""

    targets: List[PingTargetResult] = field(default_factory=list)
    avg_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    avg_jitter_ms: Optional[float] = None
    total_loss_pct: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SpeedTestResult:
    """Results from Cloudflare Speedtest measurement."""

    skipped: bool = False
    download_mbps: Optional[float] = None
    upload_mbps: Optional[float] = None
    unloaded_latency_ms: Optional[float] = None
    loaded_latency_ms: Optional[float] = None
    colo: Optional[str] = None
    isp: Optional[str] = None
    client_ip: Optional[str] = None
    bytes_downloaded: int = 0
    bytes_uploaded: int = 0
    engine: str = "cloudflare-speed-cli"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAssessment:
    """Wi-Fi authentication and public network security evaluation."""

    auth_type: str
    is_encrypted: bool
    is_public_suspected: bool
    captive_portal_detected: bool
    risk_level: str
    score: int
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UseCaseEvaluation:
    """Suitability verdict for a specific network usage scenario."""

    id: str
    name: str
    icon: str
    rating: str
    score: int
    summary: str
    details: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiagnosticReport:
    """Complete Wi-Fi diagnostic report including scores and use-case verdicts."""

    timestamp: str
    mode: str
    wifi: WiFiInfo
    ping: PingSummary
    speed: SpeedTestResult
    security: SecurityAssessment
    pillar_scores: Dict[str, int]
    overall_score: int
    overall_grade: str
    overall_verdict: str
    use_cases: List[UseCaseEvaluation]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RealtimeEvent:
    """Represents a detected anomaly (packet loss, jitter swing, RTT spike, or RF drop)."""

    seq: int
    timestamp: str
    kind: str
    severity: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


REALTIME_CSV_HEADERS: Tuple[str, ...] = (
    "日時",
    "SSID",
    "RF",
    "ping ms",
    "jitter",
    "パケットロスしたかどうか",
    "パケットロス率",
    "最大ping ms",
    "ノイズ(dBm)",
    "SNR(dB)",
    "周波数帯",
    "チャネル",
    "リンク速度(Mbps)",
    "BSSID",
    "信号スコア",
    "安定性スコア",
    "セッション評価スコア",
    "セッション評価ランク",
    "単発スコア",
    "単発ランク",
    "検知イベント",
)


@dataclass
class RealtimeSample:
    """Single measurement tick during continuous real-time Wi-Fi evaluation."""

    seq: int
    timestamp: str
    datetime_str: str = ""
    epoch_sec: float = 0.0
    ssid: str = ""
    bssid: str = ""
    band: str = ""
    channel: str = ""
    rssi_dbm: Optional[int] = None
    noise_dbm: Optional[int] = None
    snr_db: Optional[int] = None
    tx_rate_mbps: Optional[float] = None
    avg_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    packet_loss_pct: float = 0.0
    per_target_rtt: Dict[str, Optional[float]] = field(default_factory=dict)
    per_target_loss: Dict[str, float] = field(default_factory=dict)
    signal_score: int = 0
    stability_score: int = 0
    overall_score: int = 0
    overall_grade: str = "-"
    instant_score: int = 0
    instant_grade: str = "-"
    window_sample_count: int = 1
    window_seconds: int = 0
    events: List[str] = field(default_factory=list)

    def to_csv_row(self) -> List[Any]:
        """Return fields aligned with REALTIME_CSV_HEADERS."""
        has_loss = "あり" if (self.packet_loss_pct or 0.0) > 0.0 else "なし"
        return [
            self.datetime_str or self.timestamp,
            self.ssid,
            self.rssi_dbm if self.rssi_dbm is not None else "",
            self.avg_rtt_ms if self.avg_rtt_ms is not None else "",
            self.jitter_ms if self.jitter_ms is not None else "",
            has_loss,
            self.packet_loss_pct,
            self.max_rtt_ms if self.max_rtt_ms is not None else "",
            self.noise_dbm if self.noise_dbm is not None else "",
            self.snr_db if self.snr_db is not None else "",
            self.band,
            self.channel,
            self.tx_rate_mbps if self.tx_rate_mbps is not None else "",
            self.bssid,
            self.signal_score,
            self.stability_score,
            self.overall_score,
            self.overall_grade,
            self.instant_score,
            self.instant_grade,
            " / ".join(self.events) if self.events else "",
        ]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
