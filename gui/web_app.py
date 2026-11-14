"""Local Web Dashboard GUI powered by Python's built-in ThreadingHTTPServer."""

from __future__ import annotations

import datetime
import json
import os
import platform
import subprocess
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.models import DiagnosticReport, RealtimeEvent, RealtimeSample
from core.network_tester import (
    DEFAULT_PING_TARGETS,
    PING_TARGET_LABELS,
    check_captive_portal,
)
from core.runner import (
    append_realtime_sample_csv,
    create_realtime_csv_path,
    detect_realtime_anomalies,
    format_realtime_samples_csv,
    format_report_markdown,
    run_diagnostics,
    run_realtime_tick,
    write_realtime_samples_csv,
)
from core.wifi_scanner import collect_wifi_info

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ensure_macos_webview_binary() -> Optional[str]:
    """Return path to compiled macOS WKWebView launcher binary, building if needed."""
    if platform.system() != "Darwin":
        return None
    bin_path = os.path.join(_PROJECT_ROOT, "bin", "macos_webview")
    src_path = os.path.join(_PROJECT_ROOT, "gui", "macos_webview.m")
    if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        if not os.path.isfile(src_path) or os.path.getmtime(bin_path) >= os.path.getmtime(src_path):
            return bin_path
    if not os.path.isfile(src_path):
        return None
    clang = "/usr/bin/clang"
    if not os.path.isfile(clang):
        return None
    try:
        os.makedirs(os.path.dirname(bin_path), exist_ok=True)
        proc = subprocess.run(
            [
                clang,
                "-O2",
                "-fobjc-arc",
                "-ObjC",
                "-framework",
                "Cocoa",
                "-framework",
                "WebKit",
                src_path,
                "-o",
                bin_path,
            ],
            capture_output=True,
            timeout=20.0,
            check=False,
        )
        if proc.returncode == 0 and os.path.isfile(bin_path):
            os.chmod(bin_path, 0o755)
            return bin_path
    except Exception:
        pass
    return bin_path if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK) else None


class _WebState:
    """Thread-safe shared diagnostic state for the local Web server."""

    def __init__(
        self,
        initial_report: Optional[DiagnosticReport] = None,
        initial_targets: Optional[Tuple[str, ...]] = None,
    ) -> None:
        self._lock = threading.Lock()
        self.running: bool = False
        self.realtime_active: bool = False
        self.stop_event: threading.Event = threading.Event()
        self.step: int = 4 if initial_report else 0
        self.total_steps: int = 4
        self.status_message: str = (
            "診断完了" if initial_report else "待機中: 「診断を実行」を押すと測定を開始します"
        )
        self.mode: str = initial_report.mode if initial_report else "light"
        self.targets: Tuple[str, ...] = initial_targets or DEFAULT_PING_TARGETS
        self.error: Optional[str] = None
        self.report: Optional[DiagnosticReport] = initial_report
        self.realtime_samples: List[RealtimeSample] = []
        self.session_samples: List[RealtimeSample] = []
        self.realtime_events: List[RealtimeEvent] = []
        self.realtime_tick: int = 0
        self.realtime_csv_path: Optional[str] = None
        self.requests_served: int = 0

    def record_request(self) -> None:
        with self._lock:
            self.requests_served += 1

    def _clear_records_locked(self) -> None:
        self.report = None
        self.error = None
        self.realtime_samples = []
        self.session_samples = []
        self.realtime_events = []
        self.realtime_tick = 0
        self.realtime_csv_path = None
        self.step = 0

    def start_run(self, mode: str, targets: Optional[Tuple[str, ...]] = None) -> bool:
        with self._lock:
            if self.running:
                return False
            self._clear_records_locked()
            self.stop_event.clear()
            self.running = True
            self.realtime_active = mode == "realtime"
            self.mode = mode
            if targets:
                self.targets = targets
            run_targets = self.targets
            self.total_steps = 4
            self.status_message = (
                "リアルタイム連続監視を開始しています..."
                if mode == "realtime"
                else "診断を開始しています..."
            )

        target_fn = self._realtime_worker if mode == "realtime" else self._worker
        args = (run_targets,) if mode == "realtime" else (mode, run_targets)
        thread = threading.Thread(target=target_fn, args=args, daemon=True)
        thread.start()
        return True

    def stop_run(self) -> bool:
        self.stop_event.set()
        with self._lock:
            if self.running and self.realtime_active:
                self.status_message = "リアルタイム監視を停止しています..."
            return self.running

    def _worker(self, mode: str, targets: Tuple[str, ...]) -> None:
        def on_progress(step: int, total: int, msg: str) -> None:
            with self._lock:
                self.step = step
                self.total_steps = total
                self.status_message = msg

        try:
            report = run_diagnostics(mode=mode, progress_cb=on_progress, targets=targets)
            now = datetime.datetime.now()
            ts_short = now.strftime("%H:%M:%S")
            dt_full = now.strftime("%Y-%m-%d %H:%M:%S")
            events = detect_realtime_anomalies(1, ts_short, report.wifi, report.ping, [])
            sample = RealtimeSample(
                seq=1,
                timestamp=ts_short,
                datetime_str=dt_full,
                epoch_sec=now.timestamp(),
                ssid=report.wifi.ssid or "",
                bssid=report.wifi.bssid or "",
                band=report.wifi.band or "",
                channel=report.wifi.channel or "",
                rssi_dbm=report.wifi.rssi_dbm,
                noise_dbm=report.wifi.noise_dbm,
                snr_db=report.wifi.snr_db,
                tx_rate_mbps=report.wifi.tx_rate_mbps,
                avg_rtt_ms=report.ping.avg_rtt_ms,
                max_rtt_ms=report.ping.max_rtt_ms,
                jitter_ms=report.ping.avg_jitter_ms,
                packet_loss_pct=report.ping.total_loss_pct,
                per_target_rtt={t.target: t.avg_ms for t in report.ping.targets},
                per_target_loss={t.target: t.packet_loss_pct for t in report.ping.targets},
                signal_score=report.pillar_scores["signal"],
                stability_score=report.pillar_scores["stability"],
                overall_score=report.overall_score,
                overall_grade=report.overall_grade,
                instant_score=report.overall_score,
                instant_grade=report.overall_grade,
                events=[e.message for e in events],
            )
            with self._lock:
                self.report = report
                self.realtime_samples = [sample]
                self.session_samples = [sample]
                self.realtime_events = list(reversed(events))
                self.realtime_tick = 1
                self.step = self.total_steps
                self.status_message = "診断完了"
        except Exception as exc:
            with self._lock:
                self.error = str(exc)
                self.status_message = f"診断エラー: {exc}"
        finally:
            with self._lock:
                self.running = False
                self.realtime_active = False

    def _realtime_worker(self, targets: Tuple[str, ...]) -> None:
        try:
            captive = check_captive_portal(timeout=2.0)
            prev_wifi = collect_wifi_info(fast=False)
            csv_path = create_realtime_csv_path(ssid=prev_wifi.ssid)
            with self._lock:
                self.realtime_csv_path = csv_path
            seq = 0
            while not self.stop_event.is_set():
                seq += 1
                with self._lock:
                    history_copy = list(self.session_samples[-240:])
                report, sample, events = run_realtime_tick(
                    seq=seq,
                    targets=targets,
                    history=history_copy,
                    captive_portal_detected=captive,
                    prev_wifi=prev_wifi,
                )
                if report.wifi.connected and report.wifi.ssid and "非公開" not in report.wifi.ssid:
                    prev_wifi = report.wifi
                try:
                    append_realtime_sample_csv(csv_path, sample)
                except OSError:
                    pass

                with self._lock:
                    self.report = report
                    self.realtime_tick = seq
                    self.step = self.total_steps
                    self.session_samples = (self.session_samples + [sample])[-3600:]
                    self.realtime_samples = (self.realtime_samples + [sample])[-60:]
                    if events:
                        self.realtime_events = (list(reversed(events)) + self.realtime_events)[:60]
                        self.status_message = f"リアルタイム監視中 (#{seq}) [⚠ {events[0].message}]"
                    else:
                        rtt_s = f"{sample.avg_rtt_ms} ms" if sample.avg_rtt_ms is not None else "-"
                        rssi_s = f"{sample.rssi_dbm} dBm" if sample.rssi_dbm is not None else "-"
                        self.status_message = (
                            f"リアルタイム監視中 (#{seq}) | セッション評価 {report.overall_grade}({report.overall_score}点) | "
                            f"RTT {rtt_s} / ロス {sample.packet_loss_pct}% / RF {rssi_s}"
                        )
                if self.stop_event.wait(0.8):
                    break
        except Exception as exc:
            with self._lock:
                self.error = str(exc)
                self.status_message = f"リアルタイム監視エラー: {exc}"
        finally:
            with self._lock:
                self.running = False
                self.realtime_active = False
                if not self.error:
                    csv_note = f" / CSV: {os.path.basename(self.realtime_csv_path)}" if self.realtime_csv_path else ""
                    self.status_message = f"リアルタイム監視を停止しました (計 {self.realtime_tick} 回測定{csv_note})"

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            loss_cnt = sum(1 for e in self.realtime_events if e.kind == "loss")
            jitter_cnt = sum(1 for e in self.realtime_events if e.kind in ("jitter", "rtt_spike"))
            rf_cnt = sum(1 for e in self.realtime_events if e.kind == "rf_drop")
            return {
                "running": self.running,
                "realtime_active": self.realtime_active,
                "step": self.step,
                "total_steps": self.total_steps,
                "status_message": self.status_message,
                "mode": self.mode,
                "targets": [
                    {"target": t, "label": PING_TARGET_LABELS.get(t, "カスタムターゲット")}
                    for t in self.targets
                ],
                "error": self.error,
                "report": self.report.to_dict() if self.report else None,
                "realtime": {
                    "tick_count": self.realtime_tick,
                    "samples": [s.to_dict() for s in self.realtime_samples],
                    "events": [e.to_dict() for e in self.realtime_events],
                    "loss_events": loss_cnt,
                    "jitter_events": jitter_cnt,
                    "rf_events": rf_cnt,
                    "csv_path": self.realtime_csv_path,
                },
            }

    def get_report(self) -> Optional[DiagnosticReport]:
        with self._lock:
            return self.report

    def get_session_samples(self) -> List[RealtimeSample]:
        with self._lock:
            return list(self.session_samples)

    def get_realtime_csv_path(self) -> Optional[str]:
        with self._lock:
            return self.realtime_csv_path


_HTML_PAGE = r"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFi Signal &amp; Stability Analyzer</title>
<style>
  :root {
    --bg: #0b1120;
    --panel: #111827;
    --panel-2: #1e293b;
    --border: #334155;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --green: #22c55e;
    --blue: #3b82f6;
    --amber: #f59e0b;
    --red: #ef4444;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Hiragino Sans", "Yu Gothic UI", sans-serif;
    background: radial-gradient(circle at top right, #172554 0%, var(--bg) 45%);
    color: var(--text);
    line-height: 1.5;
  }
  .container { max-width: 1180px; margin: 0 auto; padding: 24px 18px 48px; }
  header {
    display: flex; flex-wrap: wrap; gap: 16px;
    align-items: center; justify-content: space-between;
    background: rgba(17, 24, 39, 0.85);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 18px 22px;
    backdrop-filter: blur(8px);
  }
  .title-block h1 { margin: 0; font-size: 1.35rem; letter-spacing: 0.02em; }
  .title-block p { margin: 4px 0 0; color: var(--muted); font-size: 0.88rem; }
  .controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
  select, button {
    border-radius: 10px;
    border: 1px solid var(--border);
    background: var(--panel-2);
    color: var(--text);
    padding: 9px 14px;
    font-size: 0.9rem;
    cursor: pointer;
  }
  button.primary {
    background: linear-gradient(135deg, #0284c7, #2563eb);
    border-color: #38bdf8;
    font-weight: 600;
  }
  button.realtime {
    background: linear-gradient(135deg, #0f766e, #0284c7);
    border-color: #2dd4bf;
    font-weight: 600;
  }
  button.danger {
    background: linear-gradient(135deg, #b91c1c, #dc2626);
    border-color: #f87171;
    font-weight: 600;
  }
  button:disabled { opacity: 0.55; cursor: not-allowed; }
  .progress-bar-wrap {
    margin-top: 14px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 12px 16px;
    display: flex; align-items: center; gap: 14px;
  }
  .progress-track {
    flex: 1; height: 8px; background: #0f172a; border-radius: 999px; overflow: hidden;
  }
  .progress-fill {
    height: 100%; width: 0%; background: linear-gradient(90deg, #38bdf8, #22c55e);
    transition: width 0.3s ease;
  }
  .hero {
    margin-top: 18px;
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: 16px;
  }
  @media (max-width: 820px) { .hero { grid-template-columns: 1fr; } }
  .card {
    background: rgba(17, 24, 39, 0.9);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 18px;
  }
  .grade-box {
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    text-align: center;
  }
  .gauge-ring {
    width: 132px; height: 132px; border-radius: 50%;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    background: conic-gradient(var(--accent) 0deg, #1e293b 0deg);
    position: relative;
  }
  .gauge-inner {
    width: 106px; height: 106px; border-radius: 50%;
    background: var(--panel);
    display: flex; flex-direction: column; align-items: center; justify-content: center;
  }
  .grade-letter { font-size: 2.3rem; font-weight: 800; line-height: 1; }
  .grade-score { font-size: 0.86rem; color: var(--muted); margin-top: 4px; }
  .verdict { margin-top: 12px; font-size: 0.9rem; color: #cbd5e1; }
  .pillars-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 14px;
  }
  @media (max-width: 600px) { .pillars-grid { grid-template-columns: 1fr; } }
  .pillar {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px;
  }
  .pillar-head { display: flex; justify-content: space-between; align-items: baseline; }
  .pillar-title { font-weight: 600; font-size: 0.95rem; }
  .pillar-score { font-weight: 700; font-size: 1.1rem; color: var(--accent); }
  .bar-bg { height: 7px; background: #0f172a; border-radius: 999px; margin: 8px 0 10px; overflow: hidden; }
  .bar-fg { height: 100%; border-radius: 999px; transition: width 0.35s ease; }
  .kv-list { font-size: 0.84rem; color: #cbd5e1; }
  .kv-row { display: flex; justify-content: space-between; gap: 8px; padding: 2px 0; border-bottom: 1px dashed rgba(148,163,184,0.15); }
  .kv-row span:first-child { color: var(--muted); }
  h2.section-title { margin: 26px 0 12px; font-size: 1.08rem; color: #e2e8f0; }
  .usecase-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
  }
  @media (max-width: 960px) { .usecase-grid { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 600px) { .usecase-grid { grid-template-columns: 1fr; } }
  .uc-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 15px;
    display: flex; flex-direction: column; gap: 8px;
  }
  .uc-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; }
  .uc-name { font-weight: 600; font-size: 0.95rem; }
  .badge {
    padding: 3px 10px; border-radius: 999px; font-size: 0.78rem; font-weight: 700; white-space: nowrap;
  }
  .badge-best { background: rgba(34,197,94,0.18); color: #4ade80; border: 1px solid rgba(34,197,94,0.45); }
  .badge-good { background: rgba(59,130,246,0.18); color: #60a5fa; border: 1px solid rgba(59,130,246,0.45); }
  .badge-warn { background: rgba(245,158,11,0.18); color: #fbbf24; border: 1px solid rgba(245,158,11,0.45); }
  .badge-bad  { background: rgba(239,68,68,0.18); color: #f87171; border: 1px solid rgba(239,68,68,0.45); }
  .uc-summary { font-size: 0.86rem; color: #e2e8f0; }
  .uc-details { font-size: 0.78rem; color: var(--muted); }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }
  @media (max-width: 820px) { .two-col { grid-template-columns: 1fr; } }
  table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
  th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; }
  ul.sec-list { margin: 8px 0 0; padding-left: 18px; font-size: 0.86rem; color: #cbd5e1; }
  .muted { color: var(--muted); font-size: 0.85rem; }
  .rt-header {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
    gap: 12px; margin: 24px 0 10px;
  }
  .rt-stats { display: flex; flex-wrap: wrap; gap: 8px; }
  .stat-pill {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 999px; padding: 4px 11px; font-size: 0.8rem; color: #cbd5e1;
  }
  .anomaly-banner {
    border-radius: 12px; padding: 10px 14px; font-size: 0.88rem;
    border: 1px solid var(--border); background: var(--panel); color: var(--muted);
    margin-bottom: 12px;
  }
  .anomaly-banner.ok {
    background: rgba(34,197,94,0.12); border-color: rgba(34,197,94,0.4); color: #86efac;
  }
  .anomaly-banner.warn {
    background: rgba(245,158,11,0.16); border-color: rgba(245,158,11,0.5); color: #fcd34d;
  }
  .anomaly-banner.danger {
    background: rgba(239,68,68,0.18); border-color: rgba(239,68,68,0.55); color: #fca5a5;
  }
  .chart-head {
    display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin-bottom: 6px;
  }
  .chart-title { font-weight: 600; font-size: 0.95rem; }
  .chart-meta { font-size: 0.8rem; color: var(--muted); }
  .chart-svg { width: 100%; height: 185px; display: block; background: #0f172a; border-radius: 10px; }
  .chart-legend { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 8px; font-size: 0.78rem; color: var(--muted); }
  .legend-item { display: inline-flex; align-items: center; gap: 6px; }
  .legend-dot { width: 10px; height: 10px; border-radius: 999px; display: inline-block; }
  .event-log {
    max-height: 150px; overflow-y: auto; margin-top: 10px; padding: 8px 10px;
    background: #0f172a; border: 1px solid var(--border); border-radius: 10px;
    font-size: 0.82rem;
  }
  .event-item { padding: 4px 0; border-bottom: 1px dashed rgba(148,163,184,0.15); display: flex; gap: 8px; align-items: baseline; }
  .event-item:last-child { border-bottom: none; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="title-block">
      <h1>WiFi Signal &amp; Stability Analyzer</h1>
      <p>信号品質・Ping RTT/パケットロス・Cloudflare速度・セキュリティから用途別適性を総合評価</p>
    </div>
    <div class="controls">
      <select id="modeSelect">
        <option value="light" selected>軽量モード (低負荷・推奨)</option>
        <option value="standard">標準モード (詳細計測)</option>
        <option value="ping-only">Ping・信号・セキュリティのみ</option>
        <option value="realtime">リアルタイム連続監視 (常時Ping・RF・グラフ)</option>
      </select>
      <button id="runBtn" class="primary" onclick="startScan()">診断を実行</button>
      <button id="rtBtn" class="realtime" onclick="toggleRealtime()">リアルタイム監視</button>
      <button id="saveBtn" onclick="saveReport()" disabled>レポート保存</button>
      <button id="browserBtn" onclick="openInBrowser()">標準ブラウザで開く</button>
    </div>
  </header>

  <div class="progress-bar-wrap" style="flex-wrap:wrap;">
    <div id="statusText" style="min-width: 240px; font-size: 0.9rem;">待機中: 「診断を実行」を押すと測定を開始します</div>
    <div class="progress-track"><div id="progressFill" class="progress-fill"></div></div>
    <div id="metaStamp" class="muted"></div>
  </div>
  <div class="progress-bar-wrap" style="margin-top:8px; padding:9px 16px; gap:10px;">
    <label for="targetsInput" class="muted" style="white-space:nowrap;">Ping宛先 (カンマ区切り):</label>
    <input id="targetsInput" type="text" value="1.1.1.1, 8.8.8.8, 9.9.9.9, google.co.jp"
      style="flex:1; min-width:220px; border-radius:8px; border:1px solid var(--border); background:var(--panel-2); color:var(--text); padding:6px 10px; font-size:0.85rem;">
  </div>

  <div class="hero">
    <div class="card grade-box">
      <div id="gaugeRing" class="gauge-ring">
        <div class="gauge-inner">
          <div id="gradeLetter" class="grade-letter">-</div>
          <div id="gradeScore" class="grade-score">-- / 100</div>
        </div>
      </div>
      <div id="overallVerdict" class="verdict">診断を実行すると総合判定が表示されます。</div>
      <div id="wifiIdentity" class="muted" style="margin-top: 8px;"></div>
    </div>

    <div class="card">
      <div class="pillars-grid" id="pillarsGrid"></div>
    </div>
  </div>

  <div class="rt-header" id="realtimeSection">
    <h2 class="section-title" style="margin:0;">リアルタイム推移グラフ・異常検知 (Ping / パケットロス / RF)</h2>
    <div class="rt-stats">
      <span class="stat-pill" id="statTicks">測定: 0回</span>
      <span class="stat-pill" id="statLoss">ロス検知: 0件</span>
      <span class="stat-pill" id="statJitter">ジッター/RTTブレ: 0件</span>
      <span class="stat-pill" id="statRf">RF低下: 0件</span>
      <span class="stat-pill" id="statCsv" style="display:none; color:#38bdf8;"></span>
    </div>
  </div>
  <div id="anomalyBanner" class="anomaly-banner">
    診断または「リアルタイム監視」を開始すると、Ping RTT・ジッター・パケットロス・RF信号の推移グラフと異常検知が表示されます。
  </div>
  <div class="two-col" style="margin-top:0;">
    <div class="card">
      <div class="chart-head">
        <span class="chart-title">Ping RTT &amp; ジッター推移 (ms)</span>
        <span class="chart-meta" id="pingChartMeta">待機中</span>
      </div>
      <svg id="pingChartSvg" class="chart-svg" viewBox="0 0 540 185" preserveAspectRatio="none"></svg>
      <div class="chart-legend">
        <span class="legend-item"><span class="legend-dot" style="background:#38bdf8;"></span>平均RTT</span>
        <span class="legend-item"><span class="legend-dot" style="background:#94a3b8;"></span>最大RTT</span>
        <span class="legend-item"><span class="legend-dot" style="background:#f59e0b;"></span>ジッター</span>
        <span class="legend-item"><span class="legend-dot" style="background:#ef4444;"></span>異常検知位置</span>
      </div>
    </div>
    <div class="card">
      <div class="chart-head">
        <span class="chart-title">パケットロス率 (%) &amp; 信号強度 RSSI (dBm)</span>
        <span class="chart-meta" id="lossChartMeta">待機中</span>
      </div>
      <svg id="lossChartSvg" class="chart-svg" viewBox="0 0 540 185" preserveAspectRatio="none"></svg>
      <div class="chart-legend">
        <span class="legend-item"><span class="legend-dot" style="background:#ef4444;"></span>パケットロス率 (%)</span>
        <span class="legend-item"><span class="legend-dot" style="background:#22c55e;"></span>RSSI (dBm)</span>
      </div>
    </div>
  </div>
  <div class="card" style="margin-top:14px;">
    <div class="chart-head" style="margin-bottom:4px;">
      <span class="chart-title">パケットロス・ジッターブレ・RF変動検知ログ</span>
      <span class="chart-meta" id="eventLogCount">0件</span>
    </div>
    <div id="eventLogList" class="event-log muted">検知された変動イベントがここに表示されます。</div>
  </div>

  <h2 class="section-title">用途別の適性判定</h2>
  <div class="usecase-grid" id="useCaseGrid"></div>

  <div class="two-col">
    <div class="card">
      <h2 class="section-title" style="margin-top:0;">Ping RTT・パケットロス詳細</h2>
      <table>
        <thead>
          <tr><th>ターゲット</th><th>方式</th><th>送/受</th><th>ロス</th><th>平均RTT</th><th>ジッター</th></tr>
        </thead>
        <tbody id="pingTableBody"></tbody>
      </table>
    </div>
    <div class="card">
      <h2 class="section-title" style="margin-top:0;">セキュリティ所見・推奨対策</h2>
      <div id="secSummary" class="muted"></div>
      <ul id="secFindings" class="sec-list"></ul>
    </div>
  </div>
</div>

<script>
let pollTimer = null;
let isRealtimeActive = false;

function scoreColor(score) {
  if (score >= 80) return '#22c55e';
  if (score >= 60) return '#38bdf8';
  if (score >= 40) return '#f59e0b';
  return '#ef4444';
}

function badgeClass(rating) {
  if (rating.includes('最適')) return 'badge badge-best';
  if (rating.includes('快適')) return 'badge badge-good';
  if (rating.includes('注意')) return 'badge badge-warn';
  return 'badge badge-bad';
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

function clearDisplayedRecords(targetItems, statusMsg) {
  if (pollTimer) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
  document.getElementById('gaugeRing').style.background = 'conic-gradient(var(--accent) 0deg, #1e293b 0deg)';
  const gradeEl = document.getElementById('gradeLetter');
  gradeEl.textContent = '-';
  gradeEl.style.color = 'var(--text)';
  document.getElementById('gradeScore').textContent = '-- / 100';
  document.getElementById('overallVerdict').textContent = statusMsg || '診断を開始しています...';
  document.getElementById('wifiIdentity').textContent = '';
  document.getElementById('metaStamp').textContent = '';
  document.getElementById('progressFill').style.width = '0%';
  document.getElementById('saveBtn').disabled = true;
  if (statusMsg) {
    document.getElementById('statusText').textContent = statusMsg;
  }
  renderStandby(targetItems, true);
  renderRealtime({tick_count: 0, samples: [], events: [], loss_events: 0, jitter_events: 0, rf_events: 0}, true);
}

async function startScan() {
  const mode = document.getElementById('modeSelect').value;
  const rawTargets = document.getElementById('targetsInput').value;
  const targets = rawTargets.split(',').map(s => s.trim()).filter(Boolean);
  const startItems = targets.map(t => ({target: t, label: '計測準備中'}));
  const initMsg = mode === 'realtime'
    ? 'リアルタイム監視を開始しています（既存の記録をクリアしました）...'
    : '診断を開始しています（既存の記録をクリアしました）...';

  clearDisplayedRecords(startItems, initMsg);
  document.getElementById('runBtn').disabled = true;
  document.getElementById('modeSelect').disabled = true;
  if (mode === 'realtime') {
    isRealtimeActive = true;
    const rtBtn = document.getElementById('rtBtn');
    rtBtn.textContent = '監視を停止';
    rtBtn.className = 'danger';
    rtBtn.disabled = false;
  } else {
    document.getElementById('rtBtn').disabled = true;
  }

  await fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({mode, targets})
  });
  pollStatus();
}

async function toggleRealtime() {
  if (isRealtimeActive) {
    const rtBtn = document.getElementById('rtBtn');
    rtBtn.disabled = true;
    document.getElementById('statusText').textContent = 'リアルタイム監視を停止しています...';
    await fetch('/api/stop', {method: 'POST'});
    pollStatus();
    return;
  }
  document.getElementById('modeSelect').value = 'realtime';
  await startScan();
}

function renderStandby(targetItems, isMeasuring = false) {
  const cellLabel = isMeasuring ? '計測中...' : '未計測';
  const badgeLabel = isMeasuring ? '計測中' : '待機中';
  const placeholders = [
    {title: '信号品質 (RF)', rows: [['RSSI', cellLabel], ['ノイズ / SNR', cellLabel], ['帯域 / CH', cellLabel], ['PHY / リンク', cellLabel]]},
    {title: '安定性 (Ping)', rows: [['平均RTT', cellLabel], ['最大RTT', cellLabel], ['平均ジッター', cellLabel], ['パケットロス', cellLabel]]},
    {title: '通信速度 (Cloudflare)', rows: [['ダウンロード', cellLabel], ['アップロード', cellLabel], ['遅延 (待機/負荷)', cellLabel], ['Colo / Engine', 'cloudflare-speed-cli']]},
    {title: 'セキュリティ', rows: [['認証方式', cellLabel], ['暗号化', cellLabel], ['公開Wi-Fi疑い', cellLabel], ['リスクレベル', cellLabel]]},
  ];
  document.getElementById('pillarsGrid').innerHTML = placeholders.map(pl => `
    <div class="pillar">
      <div class="pillar-head">
        <span class="pillar-title">${escapeHtml(pl.title)}</span>
        <span class="pillar-score" style="color:var(--muted)">${badgeLabel}</span>
      </div>
      <div class="bar-bg"><div class="bar-fg" style="width:0%"></div></div>
      <div class="kv-list">${pl.rows.map(([k, v]) => `<div class="kv-row"><span>${escapeHtml(k)}</span><span>${escapeHtml(v)}</span></div>`).join('')}</div>
    </div>
  `).join('');

  const ucPlaceholders = [
    ['🌐', 'Webブラウジング・SNS・メール'],
    ['🎬', '高画質動画視聴 (YouTube / 4K配信)'],
    ['📹', 'Web会議・音声通話 (Zoom / Teams)'],
    ['🎮', 'オンラインゲーム (FPS・対人対戦)'],
    ['☁️', '大容量ファイル送受信・クラウド作業'],
    ['🔒', '機密業務・ネットバンキング・決済'],
  ];
  const ucDesc = isMeasuring ? '測定完了後に適性を判定します...' : '「診断を実行」を押すと適性を判定します。';
  document.getElementById('useCaseGrid').innerHTML = ucPlaceholders.map(([icon, name]) => `
    <div class="uc-card">
      <div class="uc-top">
        <div class="uc-name">${icon} ${escapeHtml(name)}</div>
        <span class="badge" style="background:var(--panel-2);color:var(--muted);border:1px solid var(--border);">${escapeHtml(cellLabel)}</span>
      </div>
      <div class="uc-summary muted">${ucDesc}</div>
    </div>
  `).join('');

  const items = (targetItems && targetItems.length) ? targetItems : [
    {target: '1.1.1.1', label: 'Cloudflare DNS (Anycast)'},
    {target: '8.8.8.8', label: 'Google Public DNS (Anycast)'},
    {target: '9.9.9.9', label: 'Quad9 DNS (Anycast)'},
    {target: 'google.co.jp', label: 'Google JP (DNS解決+国内Web)'},
  ];
  document.getElementById('pingTableBody').innerHTML = items.map(it => `
    <tr>
      <td>${escapeHtml(it.target)} <span class="muted">(${escapeHtml(it.label || 'カスタム')})</span></td>
      <td>-</td><td>-</td><td>-</td><td>${badgeLabel}</td><td>-</td>
    </tr>
  `).join('');
  document.getElementById('secSummary').textContent = isMeasuring ? 'セキュリティ診断中...' : '診断待機中';
  document.getElementById('secFindings').innerHTML = isMeasuring
    ? '<li>診断を実行中です...</li>'
    : '<li>「診断を実行」ボタンを押すと診断を開始します。</li>';
}

function _chartX(idx, n, padL, pw) {
  if (n <= 1) return padL + pw / 2;
  return padL + (idx / (n - 1)) * pw;
}

function _buildPolyline(points) {
  if (points.length < 2) return '';
  return points.map(p => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
}

function renderPingChart(samples) {
  const svg = document.getElementById('pingChartSvg');
  const meta = document.getElementById('pingChartMeta');
  if (!samples || samples.length === 0) {
    meta.textContent = '待機中';
    svg.innerHTML = `<text x="270" y="96" text-anchor="middle" fill="#64748b" font-size="13">測定データ待機中...</text>`;
    return;
  }
  const last = samples[samples.length - 1];
  meta.textContent = `平均: ${last.avg_rtt_ms ?? '-'} ms / 最大: ${last.max_rtt_ms ?? '-'} ms / ジッター: ${last.jitter_ms ?? '-'} ms`;

  const W = 540, H = 185, padL = 42, padR = 16, padT = 14, padB = 24;
  const pw = W - padL - padR, ph = H - padT - padB;
  const vals = [];
  samples.forEach(s => {
    if (s.avg_rtt_ms !== null && s.avg_rtt_ms !== undefined) vals.push(s.avg_rtt_ms);
    if (s.max_rtt_ms !== null && s.max_rtt_ms !== undefined) vals.push(s.max_rtt_ms);
    if (s.jitter_ms !== null && s.jitter_ms !== undefined) vals.push(s.jitter_ms);
  });
  const rawMax = Math.max(30, ...(vals.length ? vals : [30]));
  const maxY = Math.ceil((rawMax * 1.15) / 10) * 10;
  const yOf = v => padT + ph - (Math.max(0, v) / maxY) * ph;
  const n = samples.length;

  let out = '';
  for (let i = 0; i <= 3; i++) {
    const val = Math.round((maxY * i) / 3);
    const y = yOf(val);
    out += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}" stroke="#1e293b" stroke-width="1"/>`;
    out += `<text x="${padL - 6}" y="${(y + 4).toFixed(1)}" text-anchor="end" fill="#64748b" font-size="10">${val}</text>`;
  }

  samples.forEach((s, idx) => {
    if (Array.isArray(s.events) && s.events.length > 0) {
      const x = _chartX(idx, n, padL, pw);
      out += `<line x1="${x.toFixed(1)}" y1="${padT}" x2="${x.toFixed(1)}" y2="${padT + ph}" stroke="rgba(239,68,68,0.45)" stroke-width="4"/>`;
    }
  });

  const maxPts = [], avgPts = [], jitPts = [];
  samples.forEach((s, idx) => {
    const x = _chartX(idx, n, padL, pw);
    if (s.max_rtt_ms !== null && s.max_rtt_ms !== undefined) maxPts.push([x, yOf(s.max_rtt_ms)]);
    if (s.avg_rtt_ms !== null && s.avg_rtt_ms !== undefined) avgPts.push([x, yOf(s.avg_rtt_ms)]);
    if (s.jitter_ms !== null && s.jitter_ms !== undefined) jitPts.push([x, yOf(s.jitter_ms)]);
  });

  if (maxPts.length >= 2) out += `<polyline fill="none" stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="4 3" points="${_buildPolyline(maxPts)}"/>`;
  if (avgPts.length >= 2) out += `<polyline fill="none" stroke="#38bdf8" stroke-width="2.4" points="${_buildPolyline(avgPts)}"/>`;
  if (jitPts.length >= 2) out += `<polyline fill="none" stroke="#f59e0b" stroke-width="2" points="${_buildPolyline(jitPts)}"/>`;

  maxPts.forEach(([x, y]) => { out += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2.2" fill="#94a3b8"/>`; });
  avgPts.forEach(([x, y]) => { out += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.1" fill="#38bdf8"/>`; });
  jitPts.forEach(([x, y]) => { out += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2.6" fill="#f59e0b"/>`; });

  out += `<text x="${padL}" y="${H - 6}" fill="#64748b" font-size="10">${escapeHtml(samples[0].timestamp)}</text>`;
  if (n > 1) {
    out += `<text x="${W - padR}" y="${H - 6}" text-anchor="end" fill="#64748b" font-size="10">${escapeHtml(last.timestamp)} (#${last.seq})</text>`;
  }
  svg.innerHTML = out;
}

function renderLossRfChart(samples) {
  const svg = document.getElementById('lossChartSvg');
  const meta = document.getElementById('lossChartMeta');
  if (!samples || samples.length === 0) {
    meta.textContent = '待機中';
    svg.innerHTML = `<text x="270" y="96" text-anchor="middle" fill="#64748b" font-size="13">測定データ待機中...</text>`;
    return;
  }
  const last = samples[samples.length - 1];
  meta.textContent = `ロス: ${last.packet_loss_pct ?? 0}% / RSSI: ${last.rssi_dbm !== null && last.rssi_dbm !== undefined ? last.rssi_dbm + ' dBm' : '-'} / SNR: ${last.snr_db !== null && last.snr_db !== undefined ? last.snr_db + ' dB' : '-'}`;

  const W = 540, H = 185, padL = 38, padR = 44, padT = 14, padB = 24;
  const pw = W - padL - padR, ph = H - padT - padB;
  const yLoss = pct => padT + ph - (Math.min(100, Math.max(0, pct)) / 100) * ph;
  const yRssi = dbm => {
    const clamped = Math.min(-30, Math.max(-95, dbm));
    return padT + ph - ((clamped - (-95)) / 65) * ph;
  };
  const n = samples.length;
  const barW = Math.max(5, Math.min(22, (pw / Math.max(n, 1)) * 0.55));

  let out = '';
  [0, 50, 100].forEach(pct => {
    const y = yLoss(pct);
    out += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}" stroke="#1e293b" stroke-width="1"/>`;
    out += `<text x="${padL - 6}" y="${(y + 4).toFixed(1)}" text-anchor="end" fill="#f87171" font-size="10">${pct}%</text>`;
  });
  [-95, -62, -30].forEach(dbm => {
    const y = yRssi(dbm);
    out += `<text x="${W - padR + 6}" y="${(y + 4).toFixed(1)}" text-anchor="start" fill="#4ade80" font-size="10">${dbm}</text>`;
  });

  const lossPts = [], rssiPts = [];
  samples.forEach((s, idx) => {
    const x = _chartX(idx, n, padL, pw);
    const lp = Number(s.packet_loss_pct || 0);
    const yl = yLoss(lp);
    lossPts.push([x, yl]);
    if (lp > 0) {
      const h = (padT + ph) - yl;
      out += `<rect x="${(x - barW / 2).toFixed(1)}" y="${yl.toFixed(1)}" width="${barW.toFixed(1)}" height="${Math.max(2, h).toFixed(1)}" fill="rgba(239,68,68,0.6)" rx="2"/>`;
    }
    if (s.rssi_dbm !== null && s.rssi_dbm !== undefined) {
      rssiPts.push([x, yRssi(s.rssi_dbm)]);
    }
  });

  if (lossPts.length >= 2) out += `<polyline fill="none" stroke="#ef4444" stroke-width="1.8" points="${_buildPolyline(lossPts)}"/>`;
  if (rssiPts.length >= 2) out += `<polyline fill="none" stroke="#22c55e" stroke-width="2.4" points="${_buildPolyline(rssiPts)}"/>`;
  lossPts.forEach(([x, y], idx) => {
    if ((samples[idx].packet_loss_pct || 0) > 0) {
      out += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.4" fill="#ef4444"/>`;
    }
  });
  rssiPts.forEach(([x, y]) => { out += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3" fill="#22c55e"/>`; });

  out += `<text x="${padL}" y="${H - 6}" fill="#64748b" font-size="10">${escapeHtml(samples[0].timestamp)}</text>`;
  if (n > 1) {
    out += `<text x="${W - padR}" y="${H - 6}" text-anchor="end" fill="#64748b" font-size="10">${escapeHtml(last.timestamp)} (dBm)</text>`;
  }
  svg.innerHTML = out;
}

function renderRealtime(rt, isStarting = false) {
  const safeRt = rt || {tick_count: 0, samples: [], events: [], loss_events: 0, jitter_events: 0, rf_events: 0};
  const samples = safeRt.samples || [];
  const events = safeRt.events || [];

  document.getElementById('statTicks').textContent = `測定: ${safeRt.tick_count || 0}回`;
  document.getElementById('statLoss').textContent = `ロス検知: ${safeRt.loss_events || 0}件`;
  document.getElementById('statJitter').textContent = `ジッター/RTTブレ: ${safeRt.jitter_events || 0}件`;
  document.getElementById('statRf').textContent = `RF低下: ${safeRt.rf_events || 0}件`;
  const csvPill = document.getElementById('statCsv');
  if (safeRt.csv_path) {
    const base = safeRt.csv_path.split(/[\\/]/).pop();
    csvPill.textContent = `CSV記録: ${base}`;
    csvPill.title = safeRt.csv_path;
    csvPill.style.display = 'inline-block';
  } else {
    csvPill.textContent = '';
    csvPill.style.display = 'none';
  }
  document.getElementById('eventLogCount').textContent = `${events.length}件`;

  const banner = document.getElementById('anomalyBanner');
  if (samples.length === 0) {
    banner.className = 'anomaly-banner';
    banner.textContent = isStarting
      ? '記録をリセットしました。初回の測定結果を待機しています...'
      : '診断または「リアルタイム監視」を開始すると、Ping RTT・ジッター・パケットロス・RF信号の推移グラフと異常検知が表示されます。';
  } else {
    const last = samples[samples.length - 1];
    if (last.events && last.events.length > 0) {
      const hasLoss = (last.packet_loss_pct || 0) > 0;
      banner.className = hasLoss ? 'anomaly-banner danger' : 'anomaly-banner warn';
      banner.textContent = `⚠ 最新異常検知 (#${last.seq} ${last.timestamp}): ${last.events.join(' ／ ')}`;
    } else if (events.length > 0) {
      banner.className = 'anomaly-banner warn';
      banner.textContent = `現在の測定 (#${last.seq}) は安定 ／ 直近検知 (${events[0].timestamp}): ${events[0].message}`;
    } else {
      banner.className = 'anomaly-banner ok';
      banner.textContent = `✔ 安定稼働中 (#${last.seq}): パケットロス・大きなジッターやRFのブレは検知されていません`;
    }
  }

  renderPingChart(samples);
  renderLossRfChart(samples);

  const logEl = document.getElementById('eventLogList');
  if (events.length === 0) {
    logEl.className = 'event-log muted';
    logEl.textContent = samples.length === 0
      ? (isStarting ? '測定開始中（イベントログをクリアしました）...' : '検知された変動イベントがここに表示されます。')
      : '現在までにパケットロスや大きなジッター・RFのブレは検知されていません。';
  } else {
    logEl.className = 'event-log';
    logEl.innerHTML = events.map(ev => {
      const badgeCls = ev.severity === 'danger' ? 'badge badge-bad' : 'badge badge-warn';
      const kindLabel = ev.kind === 'loss' ? 'パケットロス'
        : ev.kind === 'jitter' ? 'ジッター/ブレ'
        : ev.kind === 'rtt_spike' ? '高遅延スパイク'
        : 'RF低下';
      return `<div class="event-item">
        <span class="muted">[${escapeHtml(ev.timestamp)} #${ev.seq}]</span>
        <span class="${badgeCls}">${escapeHtml(kindLabel)}</span>
        <span>${escapeHtml(ev.message)}</span>
      </div>`;
    }).join('');
  }
}

async function saveReport() {
  const btn = document.getElementById('saveBtn');
  btn.disabled = true;
  try {
    const res = await fetch('/api/save', {method: 'POST'});
    const data = await res.json();
    if (data.saved) {
      const csvNote = data.csv_path ? ` / CSV: ${data.csv_path}` : '';
      document.getElementById('statusText').textContent = `保存完了: ${data.md_path}${csvNote}`;
    } else {
      document.getElementById('statusText').textContent = `保存失敗: ${data.error || 'unknown'}`;
    }
  } finally {
    btn.disabled = false;
  }
}

async function openInBrowser() {
  await fetch('/api/open_browser', {method: 'POST'});
}

function renderReport(r) {
  const col = scoreColor(r.overall_score);
  const deg = Math.round((r.overall_score / 100) * 360);
  document.getElementById('gaugeRing').style.background = `conic-gradient(${col} ${deg}deg, #1e293b ${deg}deg)`;
  document.getElementById('gradeLetter').textContent = r.overall_grade;
  document.getElementById('gradeLetter').style.color = col;
  document.getElementById('gradeScore').textContent = `${r.overall_score} / 100`;
  document.getElementById('overallVerdict').textContent = r.overall_verdict;
  document.getElementById('metaStamp').textContent = `${r.timestamp} (${r.mode})`;

  const w = r.wifi;
  const p = r.ping;
  const sp = r.speed;
  const sec = r.security;

  document.getElementById('wifiIdentity').textContent =
    w.connected ? `${w.ssid || 'Wi-Fi接続中'} [${w.interface || 'iface'} / ${w.band}]` : 'Wi-Fi未接続';

  const pillars = [
    {
      title: '信号品質 (RF)',
      score: r.pillar_scores.signal,
      rows: [
        ['RSSI', w.rssi_dbm !== null ? `${w.rssi_dbm} dBm (${w.signal_percent ?? '-'}%)` : '取得不可'],
        ['ノイズ / SNR', `${w.noise_dbm !== null ? w.noise_dbm + ' dBm' : '-'} / ${w.snr_db !== null ? w.snr_db + ' dB' : '-'}`],
        ['帯域 / CH', `${w.band} / ${w.channel || '-'}`],
        ['PHY / リンク', `${w.phy_mode || '-'} / ${w.tx_rate_mbps !== null ? w.tx_rate_mbps + ' Mbps' : '-'}`],
      ]
    },
    {
      title: '安定性 (Ping)',
      score: r.pillar_scores.stability,
      rows: [
        ['平均RTT', p.avg_rtt_ms !== null ? `${p.avg_rtt_ms} ms` : '取得不可'],
        ['最大RTT', p.max_rtt_ms !== null ? `${p.max_rtt_ms} ms` : '-'],
        ['平均ジッター', p.avg_jitter_ms !== null ? `${p.avg_jitter_ms} ms` : '-'],
        ['パケットロス', `${p.total_loss_pct}%`],
      ]
    },
    {
      title: '通信速度 (Cloudflare)',
      score: r.pillar_scores.speed,
      scoreLabel: sp.skipped ? 'スキップ' : `${r.pillar_scores.speed}点`,
      rows: [
        ['ダウンロード', sp.download_mbps !== null ? `${sp.download_mbps} Mbps` : (sp.skipped ? 'スキップ' : '失敗')],
        ['アップロード', sp.upload_mbps !== null ? `${sp.upload_mbps} Mbps` : (sp.skipped ? 'スキップ' : '失敗')],
        ['遅延 (待機/負荷)', sp.unloaded_latency_ms !== null ? (sp.loaded_latency_ms !== null ? `${sp.unloaded_latency_ms} ms (負荷: ${sp.loaded_latency_ms} ms)` : `${sp.unloaded_latency_ms} ms`) : '-'],
        ['Colo / Engine', `${sp.colo || '-'} / ${sp.engine || 'cloudflare-speed-cli'}`],
      ]
    },
    {
      title: 'セキュリティ',
      score: r.pillar_scores.security,
      rows: [
        ['認証方式', sec.auth_type],
        ['暗号化', sec.is_encrypted ? '有効' : 'なし/脆弱'],
        ['公開Wi-Fi疑い', sec.is_public_suspected ? 'あり' : 'なし'],
        ['リスクレベル', sec.risk_level],
      ]
    }
  ];

  document.getElementById('pillarsGrid').innerHTML = pillars.map(pl => {
    const c = scoreColor(pl.score);
    const label = pl.scoreLabel || `${pl.score}点`;
    return `<div class="pillar">
      <div class="pillar-head">
        <span class="pillar-title">${escapeHtml(pl.title)}</span>
        <span class="pillar-score" style="color:${c}">${escapeHtml(label)}</span>
      </div>
      <div class="bar-bg"><div class="bar-fg" style="width:${pl.score}%;background:${c}"></div></div>
      <div class="kv-list">${pl.rows.map(([k, v]) => `<div class="kv-row"><span>${escapeHtml(k)}</span><span>${escapeHtml(v)}</span></div>`).join('')}</div>
    </div>`;
  }).join('');

  document.getElementById('useCaseGrid').innerHTML = r.use_cases.map(uc => `
    <div class="uc-card">
      <div class="uc-top">
        <div class="uc-name">${escapeHtml(uc.icon)} ${escapeHtml(uc.name)}</div>
        <span class="${badgeClass(uc.rating)}">${escapeHtml(uc.rating)} (${uc.score})</span>
      </div>
      <div class="uc-summary">${escapeHtml(uc.summary)}</div>
      <div class="uc-details">${escapeHtml(uc.details)}</div>
    </div>
  `).join('');

  document.getElementById('pingTableBody').innerHTML = p.targets.map(t => `
    <tr>
      <td>${escapeHtml(t.target)}${t.label ? ` <span class="muted">(${escapeHtml(t.label)})</span>` : ''}</td>
      <td>${escapeHtml(t.method)}</td>
      <td>${t.transmitted}/${t.received}</td>
      <td>${t.packet_loss_pct}%</td>
      <td>${t.avg_ms !== null ? t.avg_ms + ' ms' : escapeHtml(t.error || '応答なし')}</td>
      <td>${t.jitter_ms !== null ? t.jitter_ms + ' ms' : '-'}</td>
    </tr>
  `).join('');

  document.getElementById('secSummary').textContent =
    `認証: ${sec.auth_type} / リスク: ${sec.risk_level} / キャプティブポータル: ${sec.captive_portal_detected ? '検出' : '未検出'}`;
  const notes = [...sec.findings.map(x => '所見: ' + x), ...sec.recommendations.map(x => '推奨: ' + x), ...(w.notes || []).map(x => '補足: ' + x)];
  document.getElementById('secFindings').innerHTML = notes.map(n => `<li>${escapeHtml(n)}</li>`).join('');

  document.getElementById('saveBtn').disabled = false;
}

async function pollStatus() {
  if (pollTimer) clearTimeout(pollTimer);
  try {
    const res = await fetch('/api/status');
    const st = await res.json();
    isRealtimeActive = Boolean(st.realtime_active);
    document.getElementById('statusText').textContent = st.status_message;
    const pct = st.total_steps > 0 ? Math.round((st.step / st.total_steps) * 100) : 0;
    document.getElementById('progressFill').style.width = pct + '%';
    document.getElementById('runBtn').disabled = st.running;
    document.getElementById('modeSelect').disabled = st.running;

    const rtBtn = document.getElementById('rtBtn');
    if (st.realtime_active) {
      rtBtn.textContent = '監視を停止';
      rtBtn.className = 'danger';
      rtBtn.disabled = false;
    } else {
      rtBtn.textContent = 'リアルタイム監視';
      rtBtn.className = 'realtime';
      rtBtn.disabled = st.running;
    }

    if (st.report) renderReport(st.report);
    if (st.realtime) renderRealtime(st.realtime, st.running && !st.report);
    if (st.running) {
      pollTimer = setTimeout(pollStatus, st.realtime_active ? 800 : 450);
    }
  } catch (e) {
    document.getElementById('statusText').textContent = 'ステータス取得待機中...';
    pollTimer = setTimeout(pollStatus, 1000);
  }
}

window.addEventListener('DOMContentLoaded', async () => {
  const params = new URLSearchParams(window.location.search);
  const reqMode = params.get('mode');
  if (reqMode && ['light', 'standard', 'ping-only', 'realtime'].includes(reqMode)) {
    document.getElementById('modeSelect').value = reqMode;
  }
  const res = await fetch('/api/status');
  const st = await res.json();
  if (Array.isArray(st.targets) && st.targets.length > 0) {
    document.getElementById('targetsInput').value = st.targets.map(t => t.target).join(', ');
  }
  if (st.report || st.running) {
    pollStatus();
  } else {
    document.getElementById('statusText').textContent = st.status_message;
    renderStandby(st.targets, false);
    renderRealtime(st.realtime || {tick_count: 0, samples: [], events: [], loss_events: 0, jitter_events: 0, rf_events: 0}, false);
  }
});
</script>
</body>
</html>
"""


def _make_handler(state: _WebState):
    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            # Silence default stderr HTTP request logs
            return

        def _send_json(self, code: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                state.record_request()
                body = _HTML_PAGE.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed.path == "/api/status":
                state.record_request()
                self._send_json(HTTPStatus.OK, state.snapshot())
                return

            if parsed.path == "/api/report":
                fmt = "json"
                if "format=md" in parsed.query:
                    fmt = "md"
                elif "format=csv" in parsed.query:
                    fmt = "csv"

                if fmt == "csv":
                    samples = state.get_session_samples()
                    if not samples:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": "No session samples yet"})
                        return
                    csv_bytes = format_realtime_samples_csv(samples).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/csv; charset=utf-8")
                    self.send_header("Content-Disposition", 'attachment; filename="wifi_realtime_session.csv"')
                    self.send_header("Content-Length", str(len(csv_bytes)))
                    self.end_headers()
                    self.wfile.write(csv_bytes)
                    return

                report = state.get_report()
                if report is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "No report yet"})
                    return
                if fmt == "md":
                    md = format_report_markdown(report).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/markdown; charset=utf-8")
                    self.send_header("Content-Disposition", 'attachment; filename="wifi_report.md"')
                    self.send_header("Content-Length", str(len(md)))
                    self.end_headers()
                    self.wfile.write(md)
                else:
                    raw = json.dumps(report.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Disposition", 'attachment; filename="wifi_report.json"')
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                return

            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/start":
                length = int(self.headers.get("Content-Length", "0") or 0)
                mode = "light"
                req_targets: Optional[Tuple[str, ...]] = None
                if length > 0:
                    try:
                        data = json.loads(self.rfile.read(length).decode("utf-8"))
                        if data.get("mode") in {"light", "standard", "ping-only", "realtime"}:
                            mode = data["mode"]
                        raw_t = data.get("targets")
                        if isinstance(raw_t, list):
                            cleaned = tuple(str(x).strip() for x in raw_t if str(x).strip())
                            if cleaned:
                                req_targets = cleaned
                    except Exception:
                        pass
                started = state.start_run(mode, targets=req_targets)
                self._send_json(HTTPStatus.OK, {"started": started, "mode": mode})
                return

            if parsed.path == "/api/stop":
                stopped = state.stop_run()
                self._send_json(HTTPStatus.OK, {"stopped": stopped})
                return

            if parsed.path == "/api/save":
                report = state.get_report()
                if report is None:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"saved": False, "error": "診断結果がまだありません"})
                    return
                try:
                    reports_dir = os.path.join(_PROJECT_ROOT, "reports")
                    os.makedirs(reports_dir, exist_ok=True)
                    stamp = report.timestamp.replace(":", "").replace("-", "").replace(" ", "_")
                    md_path = os.path.join(reports_dir, f"wifi_report_{stamp}.md")
                    json_path = os.path.join(reports_dir, f"wifi_report_{stamp}.json")
                    with open(md_path, "w", encoding="utf-8") as f:
                        f.write(format_report_markdown(report))
                    with open(json_path, "w", encoding="utf-8") as f:
                        json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
                    existing_csv = state.get_realtime_csv_path()
                    samples = state.get_session_samples()
                    csv_path: Optional[str] = None
                    if existing_csv and os.path.isfile(existing_csv):
                        csv_path = existing_csv
                    elif samples:
                        csv_path = os.path.join(reports_dir, f"wifi_report_{stamp}.csv")
                        write_realtime_samples_csv(csv_path, samples)
                    self._send_json(
                        HTTPStatus.OK,
                        {"saved": True, "md_path": md_path, "json_path": json_path, "csv_path": csv_path},
                    )
                except OSError as exc:
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"saved": False, "error": str(exc)})
                return

            if parsed.path == "/api/open_browser":
                host = self.headers.get("Host") or "127.0.0.1"
                webbrowser.open(f"http://{host}/")
                self._send_json(HTTPStatus.OK, {"opened": True})
                return

            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    return DashboardHandler


def start_web_server(
    initial_report: Optional[DiagnosticReport] = None,
    port: int = 0,
    open_browser: bool = True,
    daemon: bool = False,
    initial_mode: str = "light",
    initial_targets: Optional[Tuple[str, ...]] = None,
) -> Tuple[ThreadingHTTPServer, str, _WebState]:
    """Start the local web GUI server and optionally open the browser."""
    state = _WebState(initial_report=initial_report, initial_targets=initial_targets)
    server = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(state))
    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}/"
    launch_url = f"{url}?mode={initial_mode}" if initial_mode != "light" else url

    if daemon:
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

    if open_browser:
        webbrowser.open(launch_url)

    return server, url, state


def run_macos_webview_gui(
    initial_mode: str = "light",
    port: int = 0,
    initial_targets: Optional[Tuple[str, ...]] = None,
) -> bool:
    """Launch native macOS WKWebView desktop window; returns False if binary unavailable."""
    bin_path = ensure_macos_webview_binary()
    if not bin_path:
        return False

    server, url, _ = start_web_server(
        initial_report=None,
        port=port,
        open_browser=False,
        daemon=True,
        initial_mode=initial_mode,
        initial_targets=initial_targets,
    )
    launch_url = f"{url}?mode={initial_mode}" if initial_mode != "light" else url
    try:
        proc = subprocess.Popen([bin_path, launch_url, "WiFi Signal & Stability Analyzer"])
        proc.wait()
        return True
    except KeyboardInterrupt:
        return True
    finally:
        server.shutdown()
        server.server_close()


def run_web_gui(
    initial_report: Optional[DiagnosticReport] = None,
    port: int = 0,
    open_browser: bool = True,
    initial_mode: str = "light",
    initial_targets: Optional[Tuple[str, ...]] = None,
) -> None:
    """Launch the Web Dashboard GUI and block until Ctrl+C."""
    server, url, _ = start_web_server(
        initial_report=initial_report,
        port=port,
        open_browser=open_browser,
        daemon=False,
        initial_mode=initial_mode,
        initial_targets=initial_targets,
    )
    launch_url = f"{url}?mode={initial_mode}" if initial_mode != "light" else url
    print(f"Web Dashboard running at: {launch_url}")
    print("終了するには Ctrl+C を押してください。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
