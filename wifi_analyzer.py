#!/usr/bin/env python3
"""WiFi Signal & Stability Analyzer — Main CLI & Cross-Platform GUI Entry Point."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from typing import List, Optional, Tuple

# Ensure project root is importable regardless of current working directory
_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from core.models import RealtimeSample
from core.network_tester import check_captive_portal
from core.runner import (
    append_realtime_sample_csv,
    create_realtime_csv_path,
    format_report_cli,
    format_report_markdown,
    run_diagnostics,
    run_realtime_tick,
)
from core.wifi_scanner import collect_wifi_info


def _has_tkinter() -> bool:
    try:
        import tkinter
        return float(tkinter.TkVersion) >= 8.6
    except Exception:
        return False


def _run_cli_realtime(
    targets: Optional[Tuple[str, ...]],
    ticks: int = 0,
    output_json: bool = False,
    csv_file: Optional[str] = None,
) -> int:
    """Run continuous real-time Ping + RF evaluation in CLI mode."""
    captive = check_captive_portal(timeout=2.0)
    prev_wifi = collect_wifi_info(fast=False)
    csv_path = csv_file or create_realtime_csv_path(ssid=prev_wifi.ssid)
    history: List[RealtimeSample] = []
    seq = 0
    loss_cnt = 0
    jitter_cnt = 0

    if not output_json:
        target_disp = ", ".join(targets) if targets else "1.1.1.1, 8.8.8.8, 9.9.9.9, google.co.jp"
        print(f"リアルタイム連続監視を開始しました (Ping宛先: {target_disp} / 停止: Ctrl+C)")
        print(f"CSV記録先: {csv_path}")

    try:
        while True:
            seq += 1
            report, sample, events = run_realtime_tick(
                seq=seq,
                targets=targets,
                history=history[-240:],
                captive_portal_detected=captive,
                prev_wifi=prev_wifi,
            )
            if report.wifi.connected and report.wifi.ssid and "非公開" not in report.wifi.ssid:
                prev_wifi = report.wifi
            append_realtime_sample_csv(csv_path, sample)
            history = (history + [sample])[-240:]
            loss_cnt += sum(1 for e in events if e.kind == "loss")
            jitter_cnt += sum(1 for e in events if e.kind in ("jitter", "rtt_spike"))

            if output_json:
                payload = {
                    "seq": seq,
                    "csv_path": csv_path,
                    "sample": sample.to_dict(),
                    "events": [e.to_dict() for e in events],
                    "overall_grade": report.overall_grade,
                    "overall_score": report.overall_score,
                }
                print(json.dumps(payload, ensure_ascii=False), flush=True)
            else:
                rssi_s = f"{sample.rssi_dbm} dBm" if sample.rssi_dbm is not None else "- dBm"
                snr_s = f"SNR {sample.snr_db} dB" if sample.snr_db is not None else "SNR -"
                rtt_s = f"{sample.avg_rtt_ms} ms" if sample.avg_rtt_ms is not None else "-"
                max_s = f"{sample.max_rtt_ms} ms" if sample.max_rtt_ms is not None else "-"
                jit_s = f"{sample.jitter_ms} ms" if sample.jitter_ms is not None else "-"
                print(
                    f"[{sample.timestamp} #{seq:03d}] セッション評価: ランク {report.overall_grade} ({report.overall_score:3d}点 / "
                    f"直近{sample.window_sample_count}回平均) [単発: {sample.instant_score}点] | "
                    f"RF {rssi_s} ({snr_s}) | RTT {rtt_s} (max {max_s}) / ジッター {jit_s} / ロス {sample.packet_loss_pct}%",
                    flush=True,
                )
                for ev in events:
                    print(f"  [検知:{ev.kind}] {ev.message}", flush=True)

            if ticks > 0 and seq >= ticks:
                break
            time.sleep(0.8)
    except KeyboardInterrupt:
        if not output_json:
            print(
                f"\n監視停止: 計 {seq} 回測定 (ロス検知 {loss_cnt} 件 / ジッター・遅延ブレ検知 {jitter_cnt} 件) / CSV保存済: {csv_path}"
            )
    return 0


def _print_cli_report(
    mode: str,
    output_json: bool,
    output_md: bool,
    targets: Optional[Tuple[str, ...]] = None,
    ticks: int = 0,
    csv_file: Optional[str] = None,
) -> int:
    if mode == "realtime":
        return _run_cli_realtime(
            targets=targets,
            ticks=ticks,
            output_json=output_json,
            csv_file=csv_file,
        )

    def on_progress(_step: int, _total: int, msg: str) -> None:
        if not output_json:
            print(f"  -> {msg}", file=sys.stderr)

    report = run_diagnostics(mode=mode, progress_cb=on_progress, targets=targets)
    if output_json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    elif output_md:
        print(format_report_markdown(report))
    else:
        print(format_report_cli(report))
    return 0


def _parse_targets(raw: Optional[str]) -> Optional[Tuple[str, ...]]:
    if not raw:
        return None
    items = tuple(part.strip() for part in raw.split(",") if part.strip())
    return items or None


def main(argv: Optional[List[str]] = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        description="接続中のWi-Fi信号品質・安定性・速度・セキュリティを診断し、用途別適性を評価するツール"
    )
    parser.add_argument(
        "--gui",
        choices=["auto", "tk", "web"],
        default="auto",
        help="GUIバックエンド選択 (default: auto)",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="GUIを起動せず要点を絞った診断結果をコンソール出力",
    )
    parser.add_argument(
        "--md",
        action="store_true",
        help="--cli 時に詳細Markdownレポートを出力",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="GUIを起動せずJSON形式で診断結果を出力",
    )
    parser.add_argument(
        "--mode",
        choices=["light", "standard", "ping-only", "realtime"],
        default="light",
        help="診断モード: light (低負荷・推奨), standard (詳細), ping-only (速度計測なし), realtime (リアルタイム連続監視)",
    )
    parser.add_argument(
        "--ticks",
        type=int,
        default=0,
        help="realtime CLIモード時の最大測定回数 (default: 0 = Ctrl+Cまで継続)",
    )
    parser.add_argument(
        "--csv",
        type=str,
        default=None,
        help="realtime CLIモード時のCSV保存先ファイルパス (既定: reports/realtime_<日時>_<SSID>.csv)",
    )
    parser.add_argument(
        "--targets",
        type=str,
        default=None,
        help="Ping測定先 (カンマ区切り; 既定: 1.1.1.1,8.8.8.8,9.9.9.9,google.co.jp)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="Web UIモード時の待受ポート番号 (default: 自動割り当て)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Web UIモード時にブラウザを自動起動しない",
    )

    args = parser.parse_args(raw_argv)
    targets = _parse_targets(args.targets)

    if args.cli or args.md or args.json:
        return _print_cli_report(
            mode=args.mode,
            output_json=args.json,
            output_md=args.md,
            targets=targets,
            ticks=args.ticks,
            csv_file=args.csv,
        )

    if args.gui == "web":
        from gui.web_app import run_web_gui
        run_web_gui(
            port=args.port,
            open_browser=not args.no_browser,
            initial_mode=args.mode,
            initial_targets=targets,
        )
        return 0

    if args.gui == "tk":
        if _has_tkinter():
            from gui.tk_app import run_tk_gui
            run_tk_gui(initial_mode=args.mode, auto_start=False, initial_targets=targets)
            return 0
        print(
            "エラー: Tcl/Tk 8.6以上のTkinterが利用できません。`--gui auto` または `--gui web` を使用してください。",
            file=sys.stderr,
        )
        return 1

    # auto mode: on macOS prefer native WKWebView desktop window (avoids Apple Tk 8.5 blank window bug)
    if platform.system() == "Darwin":
        from gui.web_app import run_macos_webview_gui
        if run_macos_webview_gui(
            initial_mode=args.mode,
            port=args.port,
            initial_targets=targets,
        ):
            return 0

    if _has_tkinter():
        from gui.tk_app import run_tk_gui
        run_tk_gui(initial_mode=args.mode, auto_start=False, initial_targets=targets)
        return 0

    from gui.web_app import run_web_gui
    run_web_gui(
        port=args.port,
        open_browser=not args.no_browser,
        initial_mode=args.mode,
        initial_targets=targets,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
