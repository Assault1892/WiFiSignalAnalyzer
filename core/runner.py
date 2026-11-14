"""Shared diagnostic runner and report formatting helpers."""

from __future__ import annotations

import csv
import datetime
import io
import os
import re
import unicodedata
from typing import Callable, Dict, List, Optional, Tuple

from .evaluator import build_diagnostic_report
from .models import (
    REALTIME_CSV_HEADERS,
    DiagnosticReport,
    PingSummary,
    PingTargetResult,
    RealtimeEvent,
    RealtimeSample,
    SpeedTestResult,
    WiFiInfo,
)
from .network_tester import (
    check_captive_portal,
    run_cloudflare_speedtest,
    run_ping_tests,
    run_realtime_ping_tick,
)
from .wifi_scanner import collect_wifi_info

ProgressCallback = Callable[[int, int, str], None]


def run_diagnostics(
    mode: str = "light",
    progress_cb: Optional[ProgressCallback] = None,
    targets: Optional[Tuple[str, ...]] = None,
) -> DiagnosticReport:
    """Execute the 4-step Wi-Fi diagnostic pipeline and return a DiagnosticReport."""
    total_steps = 4

    def _emit(step: int, msg: str) -> None:
        if progress_cb is not None:
            progress_cb(step, total_steps, msg)

    _emit(1, "1/4 Wi-Fi信号品質・接続情報を取得中...")
    wifi = collect_wifi_info()

    _emit(2, "2/4 セキュリティリスク・キャプティブポータルを診断中...")
    captive = check_captive_portal()

    _emit(3, "3/4 Ping RTT・ジッター・パケットロスを測定中...")
    ping = run_ping_tests(
        targets=targets or (),
        mode=mode,
        progress_cb=lambda m: _emit(3, f"3/4 {m}"),
    )

    if mode == "ping-only":
        _emit(4, "4/4 速度テストはスキップされました (Ping・信号のみモード)")
    else:
        _emit(4, "4/4 Cloudflare Speedtestを実行中...")
    speed = run_cloudflare_speedtest(
        mode=mode,
        progress_cb=lambda m: _emit(4, f"4/4 {m}"),
    )

    return build_diagnostic_report(
        wifi=wifi,
        ping=ping,
        speed=speed,
        captive_portal_detected=captive,
        mode=mode,
    )


def detect_realtime_anomalies(
    seq: int,
    timestamp: str,
    wifi: WiFiInfo,
    ping: PingSummary,
    history: List[RealtimeSample],
) -> List[RealtimeEvent]:
    """Detect packet loss, jitter/RTT swings, RTT spikes, and RF signal drops."""
    events: List[RealtimeEvent] = []
    recent = history[-10:]
    prev = recent[-1] if recent else None

    # 1. Packet loss detection
    losing = [t for t in ping.targets if t.packet_loss_pct > 0.0]
    if ping.total_loss_pct > 0.0 or losing:
        loss_details = ", ".join(f"{t.target}({t.packet_loss_pct}%)" for t in losing[:4])
        detail_suffix = f" ({loss_details})" if loss_details else ""
        events.append(
            RealtimeEvent(
                seq=seq,
                timestamp=timestamp,
                kind="loss",
                severity="danger" if ping.total_loss_pct >= 10.0 else "warn",
                message=f"パケットロス発生: 全体 {ping.total_loss_pct}%{detail_suffix}",
            )
        )

    # 2. Jitter spike / RTT fluctuation detection
    hist_jitters = [s.jitter_ms for s in recent if s.jitter_ms is not None]
    baseline_jitter = (sum(hist_jitters) / len(hist_jitters)) if hist_jitters else None

    signed_delta: Optional[float] = None
    rtt_delta: Optional[float] = None
    if prev is not None and prev.avg_rtt_ms is not None and ping.avg_rtt_ms is not None:
        signed_delta = ping.avg_rtt_ms - prev.avg_rtt_ms
        rtt_delta = abs(signed_delta)

    cur_jitter = ping.avg_jitter_ms
    jitter_spike = (
        cur_jitter is not None
        and (
            cur_jitter >= 12.0
            or (baseline_jitter is not None and cur_jitter >= max(8.0, baseline_jitter * 2.0 + 4.0))
        )
    )
    rtt_swing = rtt_delta is not None and rtt_delta >= 15.0

    if jitter_spike or rtt_swing:
        parts: List[str] = []
        if cur_jitter is not None:
            parts.append(f"ジッター {cur_jitter} ms")
        if signed_delta is not None and rtt_swing:
            parts.append(f"平均RTT 前回比 {signed_delta:+.1f} ms")
        events.append(
            RealtimeEvent(
                seq=seq,
                timestamp=timestamp,
                kind="jitter",
                severity="danger" if ((cur_jitter or 0.0) >= 25.0 or (rtt_delta or 0.0) >= 35.0) else "warn",
                message=f"ジッター・遅延のブレ検知: {' / '.join(parts)}",
            )
        )

    # 3. High RTT spike
    if ping.max_rtt_ms is not None and ping.max_rtt_ms >= 100.0:
        avg_disp = ping.avg_rtt_ms if ping.avg_rtt_ms is not None else "-"
        events.append(
            RealtimeEvent(
                seq=seq,
                timestamp=timestamp,
                kind="rtt_spike",
                severity="danger" if ping.max_rtt_ms >= 150.0 else "warn",
                message=f"高遅延スパイク: 最大RTT {ping.max_rtt_ms} ms (平均 {avg_disp} ms)",
            )
        )

    # 4. RF signal drop detection
    if wifi.rssi_dbm is not None:
        prev_rssi = prev.rssi_dbm if prev is not None else None
        sharp_drop = prev_rssi is not None and (prev_rssi - wifi.rssi_dbm) >= 6
        crossed_weak = wifi.rssi_dbm <= -75 and (prev is None or (prev_rssi is not None and prev_rssi > -75))
        if sharp_drop or crossed_weak:
            snr_disp = wifi.snr_db if wifi.snr_db is not None else "-"
            events.append(
                RealtimeEvent(
                    seq=seq,
                    timestamp=timestamp,
                    kind="rf_drop",
                    severity="danger" if wifi.rssi_dbm <= -80 else "warn",
                    message=f"信号強度(RF)低下・変動: {wifi.rssi_dbm} dBm (SNR {snr_disp} dB)",
                )
            )

    return events


REALTIME_EVAL_WINDOW_SEC: float = 180.0


def filter_rolling_window(
    samples: List[RealtimeSample],
    window_sec: float = REALTIME_EVAL_WINDOW_SEC,
) -> List[RealtimeSample]:
    """Return samples belonging to the trailing `window_sec` seconds."""
    if not samples:
        return []
    now_ep = samples[-1].epoch_sec
    if now_ep <= 0:
        return samples[-60:]
    cutoff = now_ep - window_sec
    return [s for s in samples if s.epoch_sec <= 0 or s.epoch_sec >= cutoff]


def build_rolling_realtime_report(
    current_wifi: WiFiInfo,
    current_ping: PingSummary,
    window_samples: List[RealtimeSample],
    captive_portal_detected: bool = False,
    window_sec: float = REALTIME_EVAL_WINDOW_SEC,
) -> DiagnosticReport:
    """Evaluate Wi-Fi suitability using averaged RF & Ping metrics over `window_sec`."""
    win = filter_rolling_window(window_samples, window_sec)
    if not win:
        return build_diagnostic_report(
            wifi=current_wifi,
            ping=current_ping,
            speed=SpeedTestResult(skipped=True),
            captive_portal_detected=captive_portal_detected,
            mode="realtime",
        )

    rssis = [s.rssi_dbm for s in win if s.rssi_dbm is not None]
    noises = [s.noise_dbm for s in win if s.noise_dbm is not None]
    snrs = [s.snr_db for s in win if s.snr_db is not None]
    txs = [s.tx_rate_mbps for s in win if s.tx_rate_mbps is not None]

    rolling_wifi = WiFiInfo(
        connected=current_wifi.connected,
        interface=current_wifi.interface,
        ssid=current_wifi.ssid,
        bssid=current_wifi.bssid,
        rssi_dbm=int(round(sum(rssis) / len(rssis))) if rssis else current_wifi.rssi_dbm,
        noise_dbm=int(round(sum(noises) / len(noises))) if noises else current_wifi.noise_dbm,
        snr_db=int(round(sum(snrs) / len(snrs))) if snrs else current_wifi.snr_db,
        tx_rate_mbps=round(sum(txs) / len(txs), 1) if txs else current_wifi.tx_rate_mbps,
        channel=current_wifi.channel,
        band=current_wifi.band,
        phy_mode=current_wifi.phy_mode,
        security_raw=current_wifi.security_raw,
        mcs_index=current_wifi.mcs_index,
        platform_source=current_wifi.platform_source,
        notes=list(current_wifi.notes),
    ).finalize()

    avgs = [s.avg_rtt_ms for s in win if s.avg_rtt_ms is not None]
    maxs = [s.max_rtt_ms for s in win if s.max_rtt_ms is not None]
    jitters = [s.jitter_ms for s in win if s.jitter_ms is not None]
    inter_diffs = [abs(avgs[i] - avgs[i - 1]) for i in range(1, len(avgs))]

    mean_rtt = round(sum(avgs) / len(avgs), 2) if avgs else None
    max_rtt = round(max(maxs), 2) if maxs else None
    if jitters:
        mean_jit = sum(jitters) / len(jitters)
        mean_inter = (sum(inter_diffs) / len(inter_diffs)) if inter_diffs else 0.0
        rolling_jitter: Optional[float] = round(max(mean_jit, mean_jit * 0.65 + mean_inter * 0.35), 2)
    else:
        rolling_jitter = None
    rolling_loss = round(sum(s.packet_loss_pct for s in win) / len(win), 1)

    rolling_targets: List[PingTargetResult] = []
    for t in current_ping.targets:
        t_rtts = [
            s.per_target_rtt[t.target]
            for s in win
            if t.target in s.per_target_rtt and s.per_target_rtt[t.target] is not None
        ]
        t_losses = [s.per_target_loss[t.target] for s in win if t.target in s.per_target_loss]
        rolling_targets.append(
            PingTargetResult(
                target=t.target,
                transmitted=t.transmitted,
                received=t.received,
                packet_loss_pct=round(sum(t_losses) / len(t_losses), 1) if t_losses else t.packet_loss_pct,
                min_ms=t.min_ms,
                avg_ms=round(sum(t_rtts) / len(t_rtts), 2) if t_rtts else t.avg_ms,
                max_ms=t.max_ms,
                jitter_ms=t.jitter_ms,
                method=t.method,
                raw_rtts=list(t.raw_rtts),
                label=t.label,
                error=t.error,
            )
        )

    rolling_ping = PingSummary(
        targets=rolling_targets,
        avg_rtt_ms=mean_rtt,
        max_rtt_ms=max_rtt,
        avg_jitter_ms=rolling_jitter,
        total_loss_pct=rolling_loss,
    )

    report = build_diagnostic_report(
        wifi=rolling_wifi,
        ping=rolling_ping,
        speed=SpeedTestResult(skipped=True),
        captive_portal_detected=captive_portal_detected,
        mode="realtime",
    )
    span_sec = (
        max(0, int(round(win[-1].epoch_sec - win[0].epoch_sec)))
        if len(win) > 1 and win[0].epoch_sec > 0 and win[-1].epoch_sec > 0
        else 0
    )
    prefix = f"[過去{span_sec}秒・{len(win)}回平均] " if span_sec > 0 else f"[セッション{len(win)}回平均] "
    report.overall_verdict = prefix + report.overall_verdict
    return report


def run_realtime_tick(
    seq: int,
    targets: Optional[Tuple[str, ...]],
    history: List[RealtimeSample],
    captive_portal_detected: bool = False,
    prev_wifi: Optional[WiFiInfo] = None,
) -> Tuple[DiagnosticReport, RealtimeSample, List[RealtimeEvent]]:
    """Run one real-time evaluation cycle (RF polling + concurrent Ping + rolling evaluation)."""
    wifi = collect_wifi_info(fast=True)
    if prev_wifi is not None and wifi.connected:
        if not wifi.security_raw and prev_wifi.security_raw:
            wifi.security_raw = prev_wifi.security_raw
        if (not wifi.ssid or "非公開" in wifi.ssid) and prev_wifi.ssid and "非公開" not in prev_wifi.ssid:
            wifi.ssid = prev_wifi.ssid
        if not wifi.bssid and prev_wifi.bssid:
            wifi.bssid = prev_wifi.bssid
        wifi.finalize()

    ping = run_realtime_ping_tick(
        targets=targets or (),
        count_per_target=2,
        interval=0.2,
    )
    inst_report = build_diagnostic_report(
        wifi=wifi,
        ping=ping,
        speed=SpeedTestResult(skipped=True),
        captive_portal_detected=captive_portal_detected,
        mode="realtime",
    )

    now = datetime.datetime.now()
    ts_short = now.strftime("%H:%M:%S")
    dt_full = now.strftime("%Y-%m-%d %H:%M:%S")
    epoch_sec = now.timestamp()

    events = detect_realtime_anomalies(seq, ts_short, wifi, ping, history)
    per_target_rtt: Dict[str, Optional[float]] = {t.target: t.avg_ms for t in ping.targets}
    per_target_loss: Dict[str, float] = {t.target: t.packet_loss_pct for t in ping.targets}

    sample = RealtimeSample(
        seq=seq,
        timestamp=ts_short,
        datetime_str=dt_full,
        epoch_sec=epoch_sec,
        ssid=wifi.ssid or ("未接続" if not wifi.connected else ""),
        bssid=wifi.bssid or "",
        band=wifi.band or "",
        channel=wifi.channel or "",
        rssi_dbm=wifi.rssi_dbm,
        noise_dbm=wifi.noise_dbm,
        snr_db=wifi.snr_db,
        tx_rate_mbps=wifi.tx_rate_mbps,
        avg_rtt_ms=ping.avg_rtt_ms,
        max_rtt_ms=ping.max_rtt_ms,
        jitter_ms=ping.avg_jitter_ms,
        packet_loss_pct=ping.total_loss_pct,
        per_target_rtt=per_target_rtt,
        per_target_loss=per_target_loss,
        signal_score=inst_report.pillar_scores["signal"],
        stability_score=inst_report.pillar_scores["stability"],
        overall_score=inst_report.overall_score,
        overall_grade=inst_report.overall_grade,
        instant_score=inst_report.overall_score,
        instant_grade=inst_report.overall_grade,
        events=[e.message for e in events],
    )

    win = filter_rolling_window(history + [sample], REALTIME_EVAL_WINDOW_SEC)
    rolling_report = build_rolling_realtime_report(
        wifi,
        ping,
        win,
        captive_portal_detected=captive_portal_detected,
    )
    span_sec = (
        max(0, int(round(win[-1].epoch_sec - win[0].epoch_sec)))
        if len(win) > 1 and win[0].epoch_sec > 0 and win[-1].epoch_sec > 0
        else 0
    )
    sample.signal_score = rolling_report.pillar_scores["signal"]
    sample.stability_score = rolling_report.pillar_scores["stability"]
    sample.overall_score = rolling_report.overall_score
    sample.overall_grade = rolling_report.overall_grade
    sample.window_sample_count = len(win)
    sample.window_seconds = span_sec

    return rolling_report, sample, events


def _sanitize_filename_part(text: Optional[str]) -> str:
    cleaned = re.sub(r'[\\/:*?"<>|\s()（）]+', "_", (text or "").strip()).strip("_")
    return cleaned[:48] or "unknown"


def create_realtime_csv_path(
    ssid: Optional[str] = None,
    reports_dir: Optional[str] = None,
    now: Optional[datetime.datetime] = None,
) -> str:
    """Create a session CSV file path inside reports/ with timestamp and SSID."""
    target_dir = reports_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports",
    )
    os.makedirs(target_dir, exist_ok=True)
    ts = (now or datetime.datetime.now()).strftime("%Y%m%d_%H%M%S")
    safe_ssid = _sanitize_filename_part(ssid)
    return os.path.join(target_dir, f"realtime_{ts}_{safe_ssid}.csv")


def append_realtime_sample_csv(csv_path: str, sample: RealtimeSample) -> None:
    """Append one RealtimeSample row to `csv_path`, writing UTF-8 BOM + header if new."""
    parent = os.path.dirname(os.path.abspath(csv_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    need_header = (not os.path.exists(csv_path)) or os.path.getsize(csv_path) == 0
    if need_header:
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(list(REALTIME_CSV_HEADERS))
            writer.writerow(sample.to_csv_row())
    else:
        with open(csv_path, "a", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(sample.to_csv_row())


def write_realtime_samples_csv(csv_path: str, samples: List[RealtimeSample]) -> str:
    """Write all `samples` to `csv_path` with UTF-8 BOM headers."""
    parent = os.path.dirname(os.path.abspath(csv_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(list(REALTIME_CSV_HEADERS))
        for sample in samples:
            writer.writerow(sample.to_csv_row())
    return csv_path


def format_realtime_samples_csv(samples: List[RealtimeSample]) -> str:
    """Format `samples` as a UTF-8 BOM CSV string."""
    buf = io.StringIO()
    buf.write("\ufeff")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(list(REALTIME_CSV_HEADERS))
    for sample in samples:
        writer.writerow(sample.to_csv_row())
    return buf.getvalue()


def format_report_markdown(report: DiagnosticReport) -> str:
    """Format a DiagnosticReport as readable Markdown."""
    w = report.wifi
    p = report.ping
    sp = report.speed
    sec = report.security

    lines = [
        "# Wi-Fi信号品質・安定性 診断レポート",
        "",
        f"- **診断日時**: {report.timestamp}",
        f"- **測定モード**: {report.mode}",
        f"- **総合評価**: **ランク {report.overall_grade} ({report.overall_score} / 100点)**",
        f"- **総評**: {report.overall_verdict}",
        "",
        "## 1. Wi-Fi接続・信号品質",
        f"- **接続状態**: {'接続中' if w.connected else '未接続'} (`{w.interface or '-'}`)",
        f"- **SSID**: {w.ssid or '取得不可'}",
        f"- **BSSID**: {w.bssid or '取得不可'}",
        f"- **信号強度 (RSSI)**: {f'{w.rssi_dbm} dBm' if w.rssi_dbm is not None else '取得不可'}"
        + (f" ({w.signal_percent}%)" if w.signal_percent is not None else ""),
        f"- **ノイズ / SNR**: {f'{w.noise_dbm} dBm' if w.noise_dbm is not None else '取得不可'} / {f'{w.snr_db} dB' if w.snr_db is not None else '取得不可'}",
        f"- **周波数帯 / チャネル**: {w.band} / {w.channel or '取得不可'}",
        f"- **PHY / リンク速度**: {w.phy_mode or '取得不可'} / {f'{w.tx_rate_mbps} Mbps' if w.tx_rate_mbps is not None else '取得不可'}",
        f"- **信号スコア**: {report.pillar_scores['signal']} / 100",
        "",
        "## 2. 安定性 (Ping RTT・パケットロス)",
    ]
    if not p.targets:
        lines.append("- **状態**: スキップ (Ping宛先未指定)")
    else:
        lines.extend([
            f"- **平均RTT**: {f'{p.avg_rtt_ms} ms' if p.avg_rtt_ms is not None else '取得不可'} (最大: {f'{p.max_rtt_ms} ms' if p.max_rtt_ms is not None else '-'})",
            f"- **平均ジッター**: {f'{p.avg_jitter_ms} ms' if p.avg_jitter_ms is not None else '取得不可'}",
            f"- **パケットロス率**: {p.total_loss_pct}%",
            f"- **安定性スコア**: {report.pillar_scores['stability']} / 100",
            "",
            "| ターゲット | 方式 | 送信/受信 | ロス率 | 最小 / 平均 / 最大 (ms) | ジッター |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for t in p.targets:
            rtt_col = (
                f"{t.min_ms} / {t.avg_ms} / {t.max_ms}"
                if t.avg_ms is not None
                else (t.error or "応答なし")
            )
            target_disp = f"{t.target} ({t.label})" if t.label else t.target
            lines.append(
                f"| {target_disp} | {t.method} | {t.transmitted}/{t.received} | {t.packet_loss_pct}% | {rtt_col} | {f'{t.jitter_ms} ms' if t.jitter_ms is not None else '-'} |"
            )

    lines.extend(["", f"## 3. 通信速度 ({sp.engine})"])
    if sp.skipped:
        lines.append(f"- **状態**: スキップ (`{report.mode}` モード)")
    elif sp.error and sp.download_mbps is None:
        lines.append(f"- **エラー**: {sp.error}")
    else:
        lat_str = f"{sp.unloaded_latency_ms} ms" if sp.unloaded_latency_ms is not None else "取得不可"
        if sp.loaded_latency_ms is not None:
            lat_str += f" (負荷時: {sp.loaded_latency_ms} ms)"
        lines.extend([
            f"- **ダウンロード**: {f'{sp.download_mbps} Mbps' if sp.download_mbps is not None else '取得不可'}",
            f"- **アップロード**: {f'{sp.upload_mbps} Mbps' if sp.upload_mbps is not None else '取得不可'}",
            f"- **待機/負荷遅延**: {lat_str}",
            f"- **接続先Colo / ISP**: {sp.colo or '-'} / {sp.isp or '-'}",
            f"- **計測エンジン**: {sp.engine}",
            f"- **速度スコア**: {report.pillar_scores['speed']} / 100",
        ])

    lines.extend([
        "",
        "## 4. セキュリティリスク評価",
        f"- **認証方式**: {sec.auth_type} ({w.security_raw or '取得不可'})",
        f"- **公開Wi-Fiの疑い**: {'あり' if sec.is_public_suspected else 'なし'}",
        f"- **キャプティブポータル**: {'検出' if sec.captive_portal_detected else '未検出'}",
        f"- **リスクレベル**: **{sec.risk_level}** (スコア: {sec.score} / 100)",
    ])
    for f in sec.findings:
        lines.append(f"  - 所見: {f}")
    for r in sec.recommendations:
        lines.append(f"  - 推奨: {r}")

    lines.extend([
        "",
        "## 5. 用途別 適性評価",
        "",
        "| 用途 | 判定 | スコア | 評価サマリー | 詳細 |",
        "| --- | --- | --- | --- | --- |",
    ])
    for uc in report.use_cases:
        lines.append(f"| {uc.icon} {uc.name} | **{uc.rating}** | {uc.score}/100 | {uc.summary} | {uc.details} |")

    return "\n".join(lines) + "\n"


def _display_width(text: str) -> int:
    """Compute monospace terminal display width for mixed CJK/ASCII text."""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def _pad_right(text: str, target_width: int) -> str:
    pad = max(0, target_width - _display_width(text))
    return text + (" " * pad)


def format_report_cli(report: DiagnosticReport) -> str:
    """Format a DiagnosticReport as a concise, terminal-friendly summary."""
    w = report.wifi
    p = report.ping
    sp = report.speed
    sec = report.security

    sep = "=" * 72
    conn_desc = (
        f"{w.ssid or '接続中Wi-Fi'} ({w.interface or '-'} / {w.band}"
        + (f" / {w.phy_mode}" if w.phy_mode else "")
        + ")"
        if w.connected
        else "未接続"
    )

    # 1. Signal summary
    rssi_str = f"{w.rssi_dbm} dBm" if w.rssi_dbm is not None else "取得不可"
    snr_str = f"SNR {w.snr_db} dB" if w.snr_db is not None else "SNR -"
    tx_str = f"リンク {w.tx_rate_mbps} Mbps" if w.tx_rate_mbps is not None else "リンク -"
    sig_line = f"{report.pillar_scores['signal']:3d}/100点 | {rssi_str} ({snr_str}) / {w.band} / {tx_str}"

    # 2. Ping summary
    if not p.targets:
        ping_line = " スキップ | Ping宛先未指定"
    else:
        rtt_str = f"{p.avg_rtt_ms} ms" if p.avg_rtt_ms is not None else "応答なし"
        jit_str = f"{p.avg_jitter_ms} ms" if p.avg_jitter_ms is not None else "-"
        per_target = ", ".join(
            f"{t.target}: {f'{t.avg_ms}ms' if t.avg_ms is not None else '×'}"
            + (f"({t.packet_loss_pct}%ロス)" if t.packet_loss_pct > 0 else "")
            for t in p.targets
        )
        ping_line = (
            f"{report.pillar_scores['stability']:3d}/100点 | "
            f"平均 {rtt_str} / ジッター {jit_str} / ロス {p.total_loss_pct}% ({per_target})"
        )

    # 3. Speed summary
    if sp.skipped:
        spd_line = f" スキップ | 速度計測なし ({report.mode} モード)"
    elif sp.error and sp.download_mbps is None:
        spd_line = f"{report.pillar_scores['speed']:3d}/100点 | 計測エラー: {sp.error}"
    else:
        down_s = f"{sp.download_mbps} Mbps" if sp.download_mbps is not None else "-"
        up_s = f"{sp.upload_mbps} Mbps" if sp.upload_mbps is not None else "-"
        lat_parts: List[str] = []
        if sp.unloaded_latency_ms is not None:
            lat_parts.append(f"待機 {sp.unloaded_latency_ms}ms")
        if sp.loaded_latency_ms is not None:
            lat_parts.append(f"負荷時 {sp.loaded_latency_ms}ms")
        if sp.colo:
            lat_parts.append(sp.colo.split(" ")[0])
        extra = f" ({' / '.join(lat_parts)})" if lat_parts else ""
        spd_line = f"{report.pillar_scores['speed']:3d}/100点 | 下り {down_s} / 上り {up_s}{extra}"

    # 4. Security summary
    sec_line = (
        f"{report.pillar_scores['security']:3d}/100点 | "
        f"{sec.auth_type} / リスク: {sec.risk_level} / "
        f"公開Wi-Fi疑い: {'あり' if sec.is_public_suspected else 'なし'}"
    )
    if sec.captive_portal_detected:
        sec_line += " / キャプティブポータル検出"

    lines: List[str] = [
        sep,
        f" Wi-Fi 診断結果 | 総合評価: ランク {report.overall_grade} ({report.overall_score}/100点) | {report.timestamp}",
        sep,
        f" 接続先 : {conn_desc}",
        f" 総評   : {report.overall_verdict}",
        "",
        "[評価基準の要点]",
        f"  信号品質   : {sig_line}",
        f"  Ping安定性 : {ping_line}",
        f"  通信速度   : {spd_line}",
        f"  安全性     : {sec_line}",
        "",
        "[用途別の適性]",
    ]

    max_name_w = max((_display_width(uc.name) for uc in report.use_cases), default=28)
    for uc in report.use_cases:
        lines.append(f"  {uc.rating} ({uc.score:3d}点)  {_pad_right(uc.name, max_name_w)} : {uc.summary}")

    # Concise actionable highlights (only genuine issues / notes, max 3)
    points: List[str] = []
    if not w.connected:
        points.append("Wi-Fiに接続されていません。アクセスポイントへ接続してから再診断してください。")
    else:
        if w.rssi_dbm is not None and w.rssi_dbm <= -72:
            points.append(f"電波強度が弱めです ({w.rssi_dbm} dBm)。ルーターに近づくか障害物を減らすと改善が見込めます。")
        if p.total_loss_pct > 0.0:
            points.append(f"パケットロスが {p.total_loss_pct}% 発生しています。会議・ゲームで途切れの原因になります。")
        elif p.avg_jitter_ms is not None and p.avg_jitter_ms > 10.0:
            points.append(f"遅延のゆらぎ (ジッター {p.avg_jitter_ms} ms) がやや大きめです。")
        if not sec.is_encrypted or sec.is_public_suspected or sec.captive_portal_detected:
            points.extend(sec.recommendations[:2])

    if points:
        lines.extend(["", "[診断のポイント]"])
        for pt in points[:3]:
            lines.append(f"  ・{pt}")

    return "\n".join(lines) + "\n"
