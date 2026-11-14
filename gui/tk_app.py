"""Native cross-platform Desktop GUI using Tkinter / ttk."""

from __future__ import annotations

import datetime
import json
import os
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional, Tuple

from core.models import DiagnosticReport, RealtimeEvent, RealtimeSample
from core.network_tester import check_captive_portal
from core.runner import (
    append_realtime_sample_csv,
    create_realtime_csv_path,
    detect_realtime_anomalies,
    format_report_markdown,
    run_diagnostics,
    run_realtime_tick,
    write_realtime_samples_csv,
)
from core.wifi_scanner import collect_wifi_info

# Color palette (high-contrast dark dashboard for cards + native ttk controls)
BG_ROOT = "#0b1120"
BG_CARD = "#111827"
BG_CARD_ALT = "#1e293b"
BORDER_COLOR = "#334155"
FG_PRIMARY = "#f1f5f9"
FG_MUTED = "#94a3b8"
COLOR_ACCENT = "#38bdf8"
COLOR_GREEN = "#22c55e"
COLOR_BLUE = "#3b82f6"
COLOR_AMBER = "#f59e0b"
COLOR_RED = "#ef4444"

_BMP_ICON_MAP: Dict[str, str] = {
    "🌐": "[WEB]",
    "🎬": "[MOVIE]",
    "📹": "[MEET]",
    "🎮": "[GAME]",
    "☁️": "[CLOUD]",
    "☁": "[CLOUD]",
    "🔒": "[LOCK]",
    "💾": "",
}

_MODE_LABELS: List[Tuple[str, str]] = [
    ("軽量 (低負荷・推奨)", "light"),
    ("標準 (詳細計測)", "standard"),
    ("Ping・信号のみ", "ping-only"),
    ("リアルタイム連続監視", "realtime"),
]


def _tk_safe(text: Any) -> str:
    """Ensure strings only contain BMP characters (required by Tcl/Tk 8.5 on macOS)."""
    s = str(text or "")
    for src, dst in _BMP_ICON_MAP.items():
        s = s.replace(src, dst)
    if tk.TkVersion < 8.6:
        s = "".join(ch if ord(ch) <= 0xFFFF else "" for ch in s)
    return s.strip()


def _score_color(score: int) -> str:
    if score >= 80:
        return COLOR_GREEN
    if score >= 60:
        return COLOR_ACCENT
    if score >= 40:
        return COLOR_AMBER
    return COLOR_RED


def _rating_colors(rating: str) -> Tuple[str, str]:
    if "最適" in rating:
        return "#14532d", "#4ade80"
    if "快適" in rating:
        return "#1e3a8a", "#60a5fa"
    if "注意" in rating:
        return "#78350f", "#fbbf24"
    return "#7f1d1d", "#f87171"


class WiFiAnalyzerTkApp:
    """Tkinter GUI controller for WiFi Signal & Stability Analyzer."""

    def __init__(
        self,
        root: tk.Tk,
        initial_mode: str = "light",
        auto_start: bool = False,
        initial_targets: Optional[Tuple[str, ...]] = None,
    ) -> None:
        self.root = root
        self.root.title("WiFi Signal & Stability Analyzer")
        self.root.geometry("1120x820")
        self.root.minsize(900, 680)
        self.root.configure(bg=BG_ROOT)

        self._queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self._running = False
        self._stop_event = threading.Event()
        self._report: Optional[DiagnosticReport] = None
        self._rt_samples: List[RealtimeSample] = []
        self._session_samples: List[RealtimeSample] = []
        self._rt_events: List[RealtimeEvent] = []
        self._rt_tick_count: int = 0
        self._realtime_csv_path: Optional[str] = None
        self._targets: Tuple[str, ...] = tuple(initial_targets) if initial_targets else ()
        self._web_server = None
        self._web_url: Optional[str] = None
        self._web_state = None

        self._mode_label_to_key = {label: key for label, key in _MODE_LABELS}
        self._mode_key_to_label = {key: label for label, key in _MODE_LABELS}
        initial_label = self._mode_key_to_label.get(initial_mode, _MODE_LABELS[0][0])
        self.mode_var = tk.StringVar(value=initial_label)
        self.targets_var = tk.StringVar(value=", ".join(self._targets))
        self.status_var = tk.StringVar(value="待機中: 「診断を実行」を押してください")
        self.progress_var = tk.DoubleVar(value=0.0)

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._poll_queue)
        if auto_start:
            self.root.after(250, self.start_scan)

    def _font(self, size: int, bold: bool = False) -> Tuple[str, int, str] | Tuple[str, int]:
        family = "Helvetica" if sys.platform == "darwin" else "Segoe UI" if sys.platform == "win32" else "Sans"
        return (family, size, "bold") if bold else (family, size)

    def _build_ui(self) -> None:
        # Header bar
        header = tk.Frame(self.root, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
        header.pack(fill=tk.X, padx=14, pady=(12, 6))

        title_col = tk.Frame(header, bg=BG_CARD)
        title_col.pack(side=tk.LEFT, padx=14, pady=10)
        tk.Label(
            title_col,
            text="WiFi Signal & Stability Analyzer",
            font=self._font(16, True),
            bg=BG_CARD,
            fg=FG_PRIMARY,
        ).pack(anchor="w")
        tk.Label(
            title_col,
            text="信号品質 / Ping RTT・パケットロス / Cloudflare速度 / セキュリティの総合診断",
            font=self._font(10),
            bg=BG_CARD,
            fg=FG_MUTED,
        ).pack(anchor="w", pady=(2, 0))

        ctrl_col = tk.Frame(header, bg=BG_CARD)
        ctrl_col.pack(side=tk.RIGHT, padx=14, pady=10)

        self.mode_combo = ttk.Combobox(
            ctrl_col,
            textvariable=self.mode_var,
            values=[label for label, _ in _MODE_LABELS],
            state="readonly",
            width=22,
        )
        self.mode_combo.pack(side=tk.LEFT, padx=(0, 8))

        self.run_btn = ttk.Button(ctrl_col, text="診断を実行", command=self.start_scan)
        self.run_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.stop_btn = ttk.Button(ctrl_col, text="監視停止", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.web_btn = ttk.Button(ctrl_col, text="ブラウザUIで開く", command=self.open_web_ui)
        self.web_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.save_btn = ttk.Button(ctrl_col, text="レポート保存", command=self.save_report, state="disabled")
        self.save_btn.pack(side=tk.LEFT)

        # Progress bar strip
        prog_frame = tk.Frame(self.root, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
        prog_frame.pack(fill=tk.X, padx=14, pady=(0, 8))

        tk.Label(
            prog_frame,
            textvariable=self.status_var,
            font=self._font(10),
            bg=BG_CARD,
            fg=FG_PRIMARY,
            anchor="w",
        ).pack(side=tk.LEFT, padx=12, pady=7)

        self.progress_bar = ttk.Progressbar(
            prog_frame,
            variable=self.progress_var,
            maximum=100.0,
            length=260,
            mode="determinate",
        )
        self.progress_bar.pack(side=tk.RIGHT, padx=12, pady=7)

        # Ping target input strip (empty by default; no preset targets)
        target_frame = tk.Frame(self.root, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
        target_frame.pack(fill=tk.X, padx=14, pady=(0, 8))
        tk.Label(
            target_frame,
            text="Ping宛先 (カンマ区切り・未入力時はスキップ):",
            font=self._font(9),
            bg=BG_CARD,
            fg=FG_MUTED,
            anchor="w",
        ).pack(side=tk.LEFT, padx=(12, 8), pady=6)
        self.targets_entry = ttk.Entry(target_frame, textvariable=self.targets_var)
        self.targets_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12), pady=6)

        # Scrollable body canvas
        body_wrap = tk.Frame(self.root, bg=BG_ROOT)
        body_wrap.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 12))

        self._canvas = tk.Canvas(body_wrap, bg=BG_ROOT, highlightthickness=0)
        scrollbar = ttk.Scrollbar(body_wrap, orient=tk.VERTICAL, command=self._canvas.yview)
        self._content = tk.Frame(self._canvas, bg=BG_ROOT)

        self._content_window = self._canvas.create_window((0, 0), window=self._content, anchor="nw")
        self._canvas.configure(yscrollcommand=scrollbar.set)

        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._content.bind("<Configure>", lambda _e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>", lambda e: self._canvas.itemconfigure(self._content_window, width=e.width))
        self._canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Top Hero Section (Grade Gauge + 4 Pillars)
        hero = tk.Frame(self._content, bg=BG_ROOT)
        hero.pack(fill=tk.X, pady=(0, 10))
        hero.columnconfigure(0, weight=0)
        hero.columnconfigure(1, weight=1)

        # Left Grade Card
        grade_card = tk.Frame(hero, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1, width=270)
        grade_card.grid(row=0, column=0, sticky="nsw", padx=(0, 10))
        grade_card.pack_propagate(False)

        self.gauge_canvas = tk.Canvas(grade_card, width=148, height=148, bg=BG_CARD, highlightthickness=0)
        self.gauge_canvas.pack(pady=(14, 4))

        self.wifi_id_lbl = tk.Label(
            grade_card,
            text="Wi-Fi情報待機中",
            font=self._font(10, True),
            bg=BG_CARD,
            fg=COLOR_ACCENT,
            wraplength=240,
            justify=tk.CENTER,
        )
        self.wifi_id_lbl.pack(padx=10, pady=(2, 4))

        self.verdict_lbl = tk.Label(
            grade_card,
            text="診断を実行すると総合判定が表示されます。",
            font=self._font(9),
            bg=BG_CARD,
            fg=FG_MUTED,
            wraplength=240,
            justify=tk.CENTER,
        )
        self.verdict_lbl.pack(padx=10, pady=(2, 12))

        # Right 2x2 Pillars
        pillars_wrap = tk.Frame(hero, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
        pillars_wrap.grid(row=0, column=1, sticky="nsew")
        pillars_wrap.columnconfigure(0, weight=1)
        pillars_wrap.columnconfigure(1, weight=1)

        self._pillar_widgets: Dict[str, Dict[str, Any]] = {}
        pillar_specs = [
            ("signal", "信号品質 (RF)", 0, 0),
            ("stability", "安定性 (Ping)", 0, 1),
            ("speed", "通信速度 (Cloudflare)", 1, 0),
            ("security", "セキュリティ", 1, 1),
        ]
        for key, title, r, c in pillar_specs:
            card = tk.Frame(pillars_wrap, bg=BG_CARD_ALT, highlightbackground=BORDER_COLOR, highlightthickness=1)
            card.grid(row=r, column=c, sticky="nsew", padx=8, pady=8)

            top = tk.Frame(card, bg=BG_CARD_ALT)
            top.pack(fill=tk.X, padx=10, pady=(8, 4))
            tk.Label(top, text=title, font=self._font(11, True), bg=BG_CARD_ALT, fg=FG_PRIMARY).pack(side=tk.LEFT)
            score_lbl = tk.Label(top, text="--", font=self._font(11, True), bg=BG_CARD_ALT, fg=COLOR_ACCENT)
            score_lbl.pack(side=tk.RIGHT)

            bar = tk.Canvas(card, height=8, bg="#0f172a", highlightthickness=0)
            bar.pack(fill=tk.X, padx=10, pady=(0, 6))

            kv_labels: List[Tuple[tk.Label, tk.Label]] = []
            for _ in range(4):
                row_f = tk.Frame(card, bg=BG_CARD_ALT)
                row_f.pack(fill=tk.X, padx=10, pady=1)
                kl = tk.Label(row_f, text="-", font=self._font(9), bg=BG_CARD_ALT, fg=FG_MUTED, anchor="w")
                kl.pack(side=tk.LEFT)
                vl = tk.Label(row_f, text="-", font=self._font(9), bg=BG_CARD_ALT, fg=FG_PRIMARY, anchor="e")
                vl.pack(side=tk.RIGHT)
                kv_labels.append((kl, vl))
            tk.Frame(card, height=6, bg=BG_CARD_ALT).pack()

            self._pillar_widgets[key] = {
                "score_lbl": score_lbl,
                "bar": bar,
                "kvs": kv_labels,
            }

        # Real-time Graphs & Anomaly Log Section
        rt_wrap = tk.Frame(self._content, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
        rt_wrap.pack(fill=tk.X, pady=(0, 10))

        rt_head = tk.Frame(rt_wrap, bg=BG_CARD)
        rt_head.pack(fill=tk.X, padx=12, pady=(10, 4))
        tk.Label(
            rt_head,
            text="リアルタイム推移グラフ・異常検知 (Ping / パケットロス / RF)",
            font=self._font(11, True),
            bg=BG_CARD,
            fg=FG_PRIMARY,
        ).pack(side=tk.LEFT)
        self.anomaly_lbl = tk.Label(
            rt_head,
            text="待機中: 測定開始後にグラフとブレ検知を表示します",
            font=self._font(9, True),
            bg=BG_CARD_ALT,
            fg=FG_MUTED,
            padx=8,
            pady=3,
        )
        self.anomaly_lbl.pack(side=tk.RIGHT)

        charts_row = tk.Frame(rt_wrap, bg=BG_CARD)
        charts_row.pack(fill=tk.X, padx=10, pady=(2, 6))
        charts_row.columnconfigure(0, weight=1)
        charts_row.columnconfigure(1, weight=1)

        ping_chart_box = tk.Frame(charts_row, bg=BG_CARD_ALT, highlightbackground=BORDER_COLOR, highlightthickness=1)
        ping_chart_box.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        tk.Label(
            ping_chart_box,
            text="Ping RTT & ジッター推移 (ms) [青:平均 / 灰:最大 / 橙:ジッター / 赤帯:異常]",
            font=self._font(9, True),
            bg=BG_CARD_ALT,
            fg=FG_PRIMARY,
        ).pack(anchor="w", padx=8, pady=(6, 2))
        self.ping_chart_canvas = tk.Canvas(ping_chart_box, height=140, bg="#0f172a", highlightthickness=0)
        self.ping_chart_canvas.pack(fill=tk.X, padx=8, pady=(0, 8))
        self.ping_chart_canvas.bind("<Configure>", lambda _e: self._draw_rt_charts())

        loss_chart_box = tk.Frame(charts_row, bg=BG_CARD_ALT, highlightbackground=BORDER_COLOR, highlightthickness=1)
        loss_chart_box.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        tk.Label(
            loss_chart_box,
            text="パケットロス率 (%) & 信号強度 RSSI (dBm) [赤棒:ロス% / 緑線:RSSI]",
            font=self._font(9, True),
            bg=BG_CARD_ALT,
            fg=FG_PRIMARY,
        ).pack(anchor="w", padx=8, pady=(6, 2))
        self.loss_chart_canvas = tk.Canvas(loss_chart_box, height=140, bg="#0f172a", highlightthickness=0)
        self.loss_chart_canvas.pack(fill=tk.X, padx=8, pady=(0, 8))
        self.loss_chart_canvas.bind("<Configure>", lambda _e: self._draw_rt_charts())

        tk.Label(
            rt_wrap,
            text="パケットロス・ジッターブレ・RF変動検知ログ",
            font=self._font(9, True),
            bg=BG_CARD,
            fg=FG_MUTED,
        ).pack(anchor="w", padx=12, pady=(0, 2))
        self.event_text = tk.Text(
            rt_wrap,
            height=4,
            bg=BG_CARD_ALT,
            fg=FG_PRIMARY,
            relief=tk.FLAT,
            font=self._font(9),
            padx=8,
            pady=4,
            wrap=tk.WORD,
            state="disabled",
        )
        self.event_text.pack(fill=tk.X, padx=12, pady=(0, 10))

        # Use-Case Suitability Section
        tk.Label(
            self._content,
            text="用途別の適性評価",
            font=self._font(12, True),
            bg=BG_ROOT,
            fg=FG_PRIMARY,
        ).pack(anchor="w", pady=(4, 6))

        self.uc_frame = tk.Frame(self._content, bg=BG_ROOT)
        self.uc_frame.pack(fill=tk.X, pady=(0, 10))
        for col in range(3):
            self.uc_frame.columnconfigure(col, weight=1)

        self._uc_cards: List[Dict[str, tk.Label]] = []
        for idx in range(6):
            card = tk.Frame(self.uc_frame, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
            card.grid(row=idx // 3, column=idx % 3, sticky="nsew", padx=5, pady=5)

            top = tk.Frame(card, bg=BG_CARD)
            top.pack(fill=tk.X, padx=10, pady=(10, 4))
            name_lbl = tk.Label(
                top,
                text="用途",
                font=self._font(10, True),
                bg=BG_CARD,
                fg=FG_PRIMARY,
                anchor="w",
                wraplength=200,
                justify=tk.LEFT,
            )
            name_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

            badge_lbl = tk.Label(
                top,
                text=" - ",
                font=self._font(9, True),
                bg=BG_CARD_ALT,
                fg=FG_PRIMARY,
                padx=8,
                pady=2,
            )
            badge_lbl.pack(side=tk.RIGHT)

            sum_lbl = tk.Label(
                card,
                text="",
                font=self._font(9),
                bg=BG_CARD,
                fg="#cbd5e1",
                anchor="w",
                wraplength=310,
                justify=tk.LEFT,
            )
            sum_lbl.pack(fill=tk.X, padx=10, pady=(2, 4))

            det_lbl = tk.Label(
                card,
                text="",
                font=self._font(8),
                bg=BG_CARD,
                fg=FG_MUTED,
                anchor="w",
                wraplength=310,
                justify=tk.LEFT,
            )
            det_lbl.pack(fill=tk.X, padx=10, pady=(0, 10))

            self._uc_cards.append(
                {"name": name_lbl, "badge": badge_lbl, "summary": sum_lbl, "details": det_lbl}
            )

        # Bottom Section: Ping & Security Findings
        bottom = tk.Frame(self._content, bg=BG_ROOT)
        bottom.pack(fill=tk.X, pady=(2, 8))
        bottom.columnconfigure(0, weight=1)
        bottom.columnconfigure(1, weight=1)

        ping_card = tk.Frame(bottom, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
        ping_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        tk.Label(
            ping_card,
            text="Ping RTT・パケットロス詳細",
            font=self._font(11, True),
            bg=BG_CARD,
            fg=FG_PRIMARY,
        ).pack(anchor="w", padx=12, pady=(10, 4))
        self.ping_text = tk.Text(
            ping_card,
            height=6,
            bg=BG_CARD_ALT,
            fg=FG_PRIMARY,
            relief=tk.FLAT,
            font=self._font(9),
            padx=8,
            pady=6,
            state="disabled",
        )
        self.ping_text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 10))

        sec_card = tk.Frame(bottom, bg=BG_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
        sec_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        tk.Label(
            sec_card,
            text="セキュリティ所見・推奨対策",
            font=self._font(11, True),
            bg=BG_CARD,
            fg=FG_PRIMARY,
        ).pack(anchor="w", padx=12, pady=(10, 4))
        self.sec_text = tk.Text(
            sec_card,
            height=6,
            bg=BG_CARD_ALT,
            fg=FG_PRIMARY,
            relief=tk.FLAT,
            font=self._font(9),
            padx=8,
            pady=6,
            wrap=tk.WORD,
            state="disabled",
        )
        self.sec_text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 10))

        self._draw_gauge(0, "-", COLOR_ACCENT)
        self._draw_rt_charts()

    def _on_mousewheel(self, event: Any) -> None:
        if sys.platform == "darwin":
            self._canvas.yview_scroll(int(-1 * event.delta), "units")
        else:
            self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _draw_gauge(self, score: int, grade: str, color: str) -> None:
        c = self.gauge_canvas
        c.delete("all")
        c.create_oval(14, 14, 134, 134, outline="#1e293b", width=12)
        if score > 0:
            extent = -359.9 * (score / 100.0)
            c.create_arc(14, 14, 134, 134, start=90, extent=extent, style=tk.ARC, outline=color, width=12)
        c.create_text(74, 64, text=_tk_safe(grade), fill=color, font=self._font(28, True))
        c.create_text(74, 98, text=f"{score} / 100" if grade != "-" else "-- / 100", fill=FG_MUTED, font=self._font(10))

    def _draw_bar(self, bar: tk.Canvas, score: int, color: str) -> None:
        bar.update_idletasks()
        w = max(bar.winfo_width(), 180)
        bar.delete("all")
        bar.create_rectangle(0, 0, w, 8, fill="#0f172a", outline="")
        fill_w = max(0, int(w * (score / 100.0)))
        if fill_w > 0:
            bar.create_rectangle(0, 0, fill_w, 8, fill=color, outline="")

    def _draw_rt_charts(self) -> None:
        samples = self._rt_samples
        self._draw_ping_chart(samples)
        self._draw_loss_chart(samples)

    def _draw_ping_chart(self, samples: List[RealtimeSample]) -> None:
        c = self.ping_chart_canvas
        c.update_idletasks()
        w = max(c.winfo_width(), 320)
        h = max(c.winfo_height(), 140)
        c.delete("all")

        if not samples:
            c.create_text(w // 2, h // 2, text="測定データ待機中...", fill=FG_MUTED, font=self._font(9))
            return

        pad_l, pad_r, pad_t, pad_b = 36, 12, 10, 18
        pw = max(20, w - pad_l - pad_r)
        ph = max(20, h - pad_t - pad_b)
        vals = [
            v
            for s in samples
            for v in (s.avg_rtt_ms, s.max_rtt_ms, s.jitter_ms)
            if v is not None
        ]
        max_y = max(30.0, max(vals) * 1.15) if vals else 30.0
        max_y = ((int(max_y) + 9) // 10) * 10 or 30

        def x_of(idx: int) -> float:
            if len(samples) <= 1:
                return pad_l + pw / 2.0
            return pad_l + (idx / (len(samples) - 1)) * pw

        def y_of(val: float) -> float:
            return pad_t + ph - (max(0.0, val) / max_y) * ph

        for i in range(4):
            val = (max_y * i) / 3.0
            y = y_of(val)
            c.create_line(pad_l, y, w - pad_r, y, fill="#1e293b")
            c.create_text(pad_l - 4, y, text=str(int(round(val))), anchor="e", fill=FG_MUTED, font=self._font(8))

        for idx, s in enumerate(samples):
            if s.events:
                x = x_of(idx)
                c.create_line(x, pad_t, x, pad_t + ph, fill="#7f1d1d", width=4)

        def _plot(attr: str, color: str, width: float = 2.0, dashed: bool = False) -> None:
            pts: List[float] = []
            for idx, s in enumerate(samples):
                v = getattr(s, attr)
                if v is not None:
                    pts.extend((x_of(idx), y_of(v)))
            if len(pts) >= 4:
                kw: Dict[str, Any] = {"fill": color, "width": width}
                if dashed:
                    kw["dash"] = (4, 3)
                c.create_line(*pts, **kw)
            for j in range(0, len(pts), 2):
                px, py = pts[j], pts[j + 1]
                c.create_oval(px - 2.5, py - 2.5, px + 2.5, py + 2.5, fill=color, outline="")

        _plot("max_rtt_ms", FG_MUTED, width=1.4, dashed=True)
        _plot("avg_rtt_ms", COLOR_ACCENT, width=2.2)
        _plot("jitter_ms", COLOR_AMBER, width=1.8)

        c.create_text(pad_l, h - 4, text=samples[0].timestamp, anchor="sw", fill=FG_MUTED, font=self._font(8))
        if len(samples) > 1:
            last = samples[-1]
            c.create_text(
                w - pad_r,
                h - 4,
                text=f"{last.timestamp} (#{last.seq})",
                anchor="se",
                fill=FG_MUTED,
                font=self._font(8),
            )

    def _draw_loss_chart(self, samples: List[RealtimeSample]) -> None:
        c = self.loss_chart_canvas
        c.update_idletasks()
        w = max(c.winfo_width(), 320)
        h = max(c.winfo_height(), 140)
        c.delete("all")

        if not samples:
            c.create_text(w // 2, h // 2, text="測定データ待機中...", fill=FG_MUTED, font=self._font(9))
            return

        pad_l, pad_r, pad_t, pad_b = 34, 36, 10, 18
        pw = max(20, w - pad_l - pad_r)
        ph = max(20, h - pad_t - pad_b)

        def x_of(idx: int) -> float:
            if len(samples) <= 1:
                return pad_l + pw / 2.0
            return pad_l + (idx / (len(samples) - 1)) * pw

        def y_loss(pct: float) -> float:
            return pad_t + ph - (min(100.0, max(0.0, pct)) / 100.0) * ph

        def y_rssi(dbm: int) -> float:
            clamped = max(-95, min(-30, dbm))
            return pad_t + ph - ((clamped - (-95)) / 65.0) * ph

        for pct in (0, 50, 100):
            y = y_loss(float(pct))
            c.create_line(pad_l, y, w - pad_r, y, fill="#1e293b")
            c.create_text(pad_l - 4, y, text=f"{pct}%", anchor="e", fill="#f87171", font=self._font(8))

        for dbm in (-95, -62, -30):
            y = y_rssi(dbm)
            c.create_text(w - pad_r + 4, y, text=str(dbm), anchor="w", fill="#4ade80", font=self._font(8))

        bar_w = max(4.0, min(18.0, (pw / max(len(samples), 1)) * 0.5))
        loss_pts: List[float] = []
        rssi_pts: List[float] = []
        for idx, s in enumerate(samples):
            x = x_of(idx)
            yl = y_loss(s.packet_loss_pct)
            loss_pts.extend((x, yl))
            if s.packet_loss_pct > 0:
                c.create_rectangle(x - bar_w / 2.0, yl, x + bar_w / 2.0, pad_t + ph, fill=COLOR_RED, outline="")
            if s.rssi_dbm is not None:
                rssi_pts.extend((x, y_rssi(s.rssi_dbm)))

        if len(loss_pts) >= 4:
            c.create_line(*loss_pts, fill=COLOR_RED, width=1.6)
        if len(rssi_pts) >= 4:
            c.create_line(*rssi_pts, fill=COLOR_GREEN, width=2.2)
        for j in range(0, len(rssi_pts), 2):
            px, py = rssi_pts[j], rssi_pts[j + 1]
            c.create_oval(px - 2.5, py - 2.5, px + 2.5, py + 2.5, fill=COLOR_GREEN, outline="")

        c.create_text(pad_l, h - 4, text=samples[0].timestamp, anchor="sw", fill=FG_MUTED, font=self._font(8))
        if len(samples) > 1:
            c.create_text(w - pad_r, h - 4, text=f"{samples[-1].timestamp} (dBm)", anchor="se", fill=FG_MUTED, font=self._font(8))

    def _clear_displayed_records(self, status_msg: str = "新しい測定を開始するため記録をクリアしました") -> None:
        self._report = None
        self._rt_samples = []
        self._session_samples = []
        self._rt_events = []
        self._rt_tick_count = 0
        self._realtime_csv_path = None
        self.save_btn.configure(state="disabled")
        self._draw_gauge(0, "-", COLOR_ACCENT)
        self.wifi_id_lbl.configure(text="Wi-Fi情報計測中...")
        self.verdict_lbl.configure(text=_tk_safe(status_msg))

        for key, pw in self._pillar_widgets.items():
            pw["score_lbl"].configure(text="--", fg=FG_MUTED)
            self._draw_bar(pw["bar"], 0, COLOR_ACCENT)
            for kl, vl in pw["kvs"]:
                kl.configure(text="-")
                vl.configure(text="未計測")

        for card_w in self._uc_cards:
            card_w["badge"].configure(text=" 計測中 ", bg=BG_CARD_ALT, fg=FG_MUTED)
            card_w["summary"].configure(text="測定中...")
            card_w["details"].configure(text="")

        self._set_textbox(self.ping_text, "測定中...")
        self._set_textbox(self.sec_text, "測定中...")
        self._set_textbox(self.event_text, "測定開始中（イベントログをクリアしました）...")
        self.anomaly_lbl.configure(text="記録クリア済み・測定中", bg=BG_CARD_ALT, fg=FG_MUTED)
        self._draw_rt_charts()

    def start_scan(self) -> None:
        if self._running:
            return
        mode_key = self._mode_label_to_key.get(self.mode_var.get(), "light")
        self._targets = tuple(part.strip() for part in self.targets_var.get().split(",") if part.strip())
        init_msg = (
            "リアルタイム連続監視を開始しています..."
            if mode_key == "realtime"
            else "診断を開始しています..."
        )
        self._clear_displayed_records(init_msg)
        self._stop_event.clear()
        self._running = True
        self.run_btn.configure(state="disabled")
        self.mode_combo.configure(state="disabled")
        self.targets_entry.configure(state="disabled")
        self.stop_btn.configure(state="normal" if mode_key == "realtime" else "disabled")
        self.progress_var.set(5.0)
        self.status_var.set(init_msg)

        if mode_key == "realtime":
            worker = threading.Thread(target=self._run_realtime_worker, daemon=True)
        else:
            worker = threading.Thread(target=self._run_worker, args=(mode_key,), daemon=True)
        worker.start()

    def stop_scan(self) -> None:
        self._stop_event.set()
        self.stop_btn.configure(state="disabled")
        self.status_var.set("リアルタイム監視を停止しています...")

    def _run_worker(self, mode_key: str) -> None:
        def on_progress(step: int, total: int, msg: str) -> None:
            pct = (step / float(total)) * 92.0
            self._queue.put(("progress", (pct, msg)))

        try:
            report = run_diagnostics(mode=mode_key, progress_cb=on_progress, targets=self._targets)
            now = datetime.datetime.now()
            ts_short = now.strftime("%H:%M:%S")
            events = detect_realtime_anomalies(1, ts_short, report.wifi, report.ping, [])
            sample = RealtimeSample(
                seq=1,
                timestamp=ts_short,
                datetime_str=now.strftime("%Y-%m-%d %H:%M:%S"),
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
            self._queue.put(("done", (report, sample, events)))
        except Exception as exc:
            self._queue.put(("error", str(exc)))

    def _run_realtime_worker(self) -> None:
        seq = 0
        history: List[RealtimeSample] = []
        try:
            captive = check_captive_portal(timeout=2.0)
            prev_wifi = collect_wifi_info(fast=False)
            csv_path = create_realtime_csv_path(ssid=prev_wifi.ssid)
            self._queue.put(("rt_started", csv_path))
            while not self._stop_event.is_set():
                seq += 1
                report, sample, events = run_realtime_tick(
                    seq=seq,
                    targets=self._targets,
                    history=history[-240:],
                    captive_portal_detected=captive,
                    prev_wifi=prev_wifi,
                )
                if report.wifi.connected and report.wifi.ssid and "非公開" not in report.wifi.ssid:
                    prev_wifi = report.wifi
                try:
                    append_realtime_sample_csv(csv_path, sample)
                except OSError:
                    pass
                history = (history + [sample])[-240:]
                self._queue.put(("rt_tick", (report, sample, events)))
                if self._stop_event.wait(0.8):
                    break
        except Exception as exc:
            self._queue.put(("error", str(exc)))
        finally:
            self._queue.put(("rt_stopped", seq))

    def _update_anomaly_ui(self) -> None:
        if not self._rt_samples:
            self._draw_rt_charts()
            return
        last = self._rt_samples[-1]
        if last.events:
            bg = "#7f1d1d" if last.packet_loss_pct > 0 else "#78350f"
            fg = "#fca5a5" if last.packet_loss_pct > 0 else "#fcd34d"
            self.anomaly_lbl.configure(
                text=_tk_safe(f"[異常検知 #{last.seq}] {last.events[0]}"),
                bg=bg,
                fg=fg,
            )
        elif self._rt_events:
            ev0 = self._rt_events[0]
            self.anomaly_lbl.configure(
                text=_tk_safe(f"現在安定 (#{last.seq}) / 直近検知: {ev0.message}"),
                bg="#78350f",
                fg="#fcd34d",
            )
        else:
            self.anomaly_lbl.configure(
                text=_tk_safe(f"安定稼働中 (#{last.seq}): ロス・大きなブレ未検知"),
                bg="#14532d",
                fg="#4ade80",
            )

        if self._rt_events:
            ev_lines = [
                f"[{ev.timestamp} #{ev.seq}] ({ev.kind}) {ev.message}"
                for ev in self._rt_events[:40]
            ]
            self._set_textbox(self.event_text, "\n".join(ev_lines))
        else:
            self._set_textbox(self.event_text, "現在までにパケットロスや大きなジッター・RFのブレは検知されていません。")
        self._draw_rt_charts()

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    pct, msg = payload
                    self.progress_var.set(pct)
                    self.status_var.set(_tk_safe(msg))
                elif kind == "done":
                    report, sample, events = payload
                    self._running = False
                    self.run_btn.configure(state="normal")
                    self.mode_combo.configure(state="readonly")
                    self.targets_entry.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self.save_btn.configure(state="normal")
                    self.progress_var.set(100.0)
                    self._report = report
                    self._rt_samples = [sample]
                    self._session_samples = [sample]
                    self._rt_events = list(reversed(events))
                    self._rt_tick_count = 1
                    self.status_var.set(_tk_safe(f"診断完了 ({report.timestamp} / モード: {report.mode})"))
                    self._render_report(report)
                    self._update_anomaly_ui()
                    if self._web_state is not None:
                        with self._web_state._lock:
                            self._web_state.report = report
                            self._web_state.realtime_samples = [sample]
                            self._web_state.session_samples = [sample]
                            self._web_state.realtime_events = list(reversed(events))
                            self._web_state.realtime_tick = 1
                            self._web_state.status_message = "診断完了"
                elif kind == "rt_started":
                    self._realtime_csv_path = payload
                elif kind == "rt_tick":
                    report, sample, events = payload
                    self._report = report
                    self._rt_tick_count = sample.seq
                    self._session_samples = (self._session_samples + [sample])[-3600:]
                    self._rt_samples = (self._rt_samples + [sample])[-60:]
                    if events:
                        self._rt_events = (list(reversed(events)) + self._rt_events)[:60]
                    self.save_btn.configure(state="normal")
                    self.progress_var.set(100.0)
                    rtt_s = f"{sample.avg_rtt_ms} ms" if sample.avg_rtt_ms is not None else "-"
                    rssi_s = f"{sample.rssi_dbm} dBm" if sample.rssi_dbm is not None else "-"
                    msg = (
                        f"リアルタイム監視中 (#{sample.seq}) | セッション評価 {report.overall_grade}({report.overall_score}点) | "
                        f"RTT {rtt_s} / ロス {sample.packet_loss_pct}% / RF {rssi_s}"
                    )
                    if events:
                        msg = f"リアルタイム監視中 (#{sample.seq}) [! {events[0].message}]"
                    self.status_var.set(_tk_safe(msg))
                    self._render_report(report)
                    self._update_anomaly_ui()
                elif kind == "rt_stopped":
                    self._running = False
                    self.run_btn.configure(state="normal")
                    self.mode_combo.configure(state="readonly")
                    self.targets_entry.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    if "エラー" not in self.status_var.get():
                        csv_note = f" / CSV: {os.path.basename(self._realtime_csv_path)}" if self._realtime_csv_path else ""
                        self.status_var.set(_tk_safe(f"リアルタイム監視を停止しました (計 {payload} 回測定{csv_note})"))
                elif kind == "error":
                    self._running = False
                    self.run_btn.configure(state="normal")
                    self.mode_combo.configure(state="readonly")
                    self.targets_entry.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self.status_var.set(_tk_safe(f"エラー: {payload}"))
                    messagebox.showerror("診断エラー", str(payload))
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _render_report(self, r: DiagnosticReport) -> None:
        col = _score_color(r.overall_score)
        self._draw_gauge(r.overall_score, r.overall_grade, col)

        w = r.wifi
        p = r.ping
        sp = r.speed
        sec = r.security

        if w.connected:
            id_txt = f"{w.ssid or '接続中Wi-Fi'}\n[{w.interface or 'iface'} / {w.band}]"
        else:
            id_txt = "Wi-Fi未接続"
        self.wifi_id_lbl.configure(text=_tk_safe(id_txt))
        self.verdict_lbl.configure(text=_tk_safe(r.overall_verdict))

        pillar_rows = {
            "signal": (
                f"{r.pillar_scores['signal']}点",
                r.pillar_scores["signal"],
                [
                    ("RSSI", f"{w.rssi_dbm} dBm ({w.signal_percent}%)" if w.rssi_dbm is not None else "取得不可"),
                    ("ノイズ / SNR", f"{w.noise_dbm if w.noise_dbm is not None else '-'} dBm / {w.snr_db if w.snr_db is not None else '-'} dB"),
                    ("帯域 / CH", f"{w.band} / {w.channel or '-'}"),
                    ("PHY / リンク", f"{w.phy_mode or '-'} / {f'{w.tx_rate_mbps} Mbps' if w.tx_rate_mbps is not None else '-'}"),
                ],
            ),
            "stability": (
                "スキップ" if not p.targets else f"{r.pillar_scores['stability']}点",
                r.pillar_scores["stability"],
                [
                    ("状態", "スキップ (宛先未指定)"),
                    ("平均RTT", "-"),
                    ("平均ジッター", "-"),
                    ("パケットロス", "-"),
                ]
                if not p.targets
                else [
                    ("平均RTT", f"{p.avg_rtt_ms} ms" if p.avg_rtt_ms is not None else "取得不可"),
                    ("最大RTT", f"{p.max_rtt_ms} ms" if p.max_rtt_ms is not None else "-"),
                    ("平均ジッター", f"{p.avg_jitter_ms} ms" if p.avg_jitter_ms is not None else "-"),
                    ("パケットロス", f"{p.total_loss_pct}%"),
                ],
            ),
            "speed": (
                "スキップ" if sp.skipped else f"{r.pillar_scores['speed']}点",
                r.pillar_scores["speed"],
                [
                    ("ダウンロード", "スキップ" if sp.skipped else (f"{sp.download_mbps} Mbps" if sp.download_mbps is not None else "失敗")),
                    ("アップロード", "スキップ" if sp.skipped else (f"{sp.upload_mbps} Mbps" if sp.upload_mbps is not None else "失敗")),
                    (
                        "遅延 (待機/負荷)",
                        (
                            f"{sp.unloaded_latency_ms} ms (負荷: {sp.loaded_latency_ms} ms)"
                            if sp.unloaded_latency_ms is not None and sp.loaded_latency_ms is not None
                            else (f"{sp.unloaded_latency_ms} ms" if sp.unloaded_latency_ms is not None else "-")
                        ),
                    ),
                    ("Colo / Engine", f"{sp.colo or '-'} / {sp.engine}"),
                ],
            ),
            "security": (
                f"{r.pillar_scores['security']}点",
                r.pillar_scores["security"],
                [
                    ("認証方式", sec.auth_type),
                    ("暗号化", "有効" if sec.is_encrypted else "なし/脆弱"),
                    ("公開Wi-Fi疑い", "あり" if sec.is_public_suspected else "なし"),
                    ("リスクレベル", sec.risk_level),
                ],
            ),
        }

        for key, (label_text, score_val, kvs) in pillar_rows.items():
            pw = self._pillar_widgets[key]
            c = _score_color(score_val)
            pw["score_lbl"].configure(text=_tk_safe(label_text), fg=c)
            self._draw_bar(pw["bar"], score_val, c)
            for (kl, vl), (k_str, v_str) in zip(pw["kvs"], kvs):
                kl.configure(text=_tk_safe(k_str))
                vl.configure(text=_tk_safe(v_str))

        for card_w, uc in zip(self._uc_cards, r.use_cases):
            bg_b, fg_b = _rating_colors(uc.rating)
            card_w["name"].configure(text=_tk_safe(f"{uc.icon} {uc.name}"))
            card_w["badge"].configure(text=_tk_safe(f"{uc.rating} ({uc.score})"), bg=bg_b, fg=fg_b)
            card_w["summary"].configure(text=_tk_safe(uc.summary))
            card_w["details"].configure(text=_tk_safe(uc.details))

        # Ping details box
        if not p.targets:
            self._set_textbox(
                self.ping_text,
                "Ping宛先が未指定のためPing測定はスキップされました。\n安定性を測定したい場合は上の入力欄にPing先を入力してください。",
            )
        else:
            ping_lines = []
            for t in p.targets:
                if t.avg_ms is not None:
                    ping_lines.append(
                        f"{t.target:<14} [{t.method}] 送/受 {t.transmitted}/{t.received}  ロス {t.packet_loss_pct}%  "
                        f"最小/平均/最大 {t.min_ms}/{t.avg_ms}/{t.max_ms} ms  ジッター {t.jitter_ms} ms"
                    )
                else:
                    ping_lines.append(
                        f"{t.target:<14} [{t.method}] 送/受 {t.transmitted}/{t.received}  ロス {t.packet_loss_pct}%  ({t.error or '応答なし'})"
                    )
            self._set_textbox(self.ping_text, "\n".join(ping_lines))

        # Security findings box
        sec_lines = [
            f"認証方式: {sec.auth_type} / リスク: {sec.risk_level} / キャプティブポータル: {'検出' if sec.captive_portal_detected else '未検出'}",
            "",
        ]
        for f in sec.findings:
            sec_lines.append(f"・所見: {f}")
        for rec in sec.recommendations:
            sec_lines.append(f"・推奨: {rec}")
        for note in w.notes:
            sec_lines.append(f"・補足: {note}")
        self._set_textbox(self.sec_text, "\n".join(sec_lines))

    def _set_textbox(self, box: tk.Text, content: str) -> None:
        box.configure(state="normal")
        box.delete("1.0", tk.END)
        box.insert("1.0", _tk_safe(content))
        box.configure(state="disabled")

    def open_web_ui(self) -> None:
        from gui.web_app import start_web_server

        if self._web_server is None:
            server, url, state = start_web_server(
                initial_report=self._report,
                port=0,
                open_browser=True,
                daemon=True,
            )
            self._web_server = server
            self._web_url = url
            self._web_state = state
        else:
            if self._web_state is not None and self._report is not None:
                with self._web_state._lock:
                    self._web_state.report = self._report
                    self._web_state.status_message = "診断完了"
            if self._web_url:
                webbrowser.open(self._web_url)

    def save_report(self) -> None:
        if self._report is None:
            return
        path = filedialog.asksaveasfilename(
            title="診断レポートを保存",
            defaultextension=".md",
            filetypes=[
                ("Markdownファイル (*.md)", "*.md"),
                ("JSONファイル (*.json)", "*.json"),
                ("CSV履歴ファイル (*.csv)", "*.csv"),
            ],
            initialfile="wifi_diagnostic_report.md",
        )
        if not path:
            return
        try:
            if path.lower().endswith(".csv"):
                write_realtime_samples_csv(path, self._session_samples)
            elif path.lower().endswith(".json"):
                content = json.dumps(self._report.to_dict(), ensure_ascii=False, indent=2)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            else:
                content = format_report_markdown(self._report)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            extra = (
                f"\n\n自動記録中のセッションCSV:\n{os.path.abspath(self._realtime_csv_path)}"
                if self._realtime_csv_path and not path.lower().endswith(".csv")
                else ""
            )
            messagebox.showinfo("保存完了", f"レポートを保存しました:\n{os.path.abspath(path)}{extra}")
        except OSError as exc:
            messagebox.showerror("保存エラー", f"保存に失敗しました:\n{exc}")

    def _on_close(self) -> None:
        self._stop_event.set()
        if self._web_server is not None:
            try:
                self._web_server.shutdown()
                self._web_server.server_close()
            except Exception:
                pass
        self.root.destroy()


def run_tk_gui(
    initial_mode: str = "light",
    auto_start: bool = False,
    initial_targets: Optional[Tuple[str, ...]] = None,
) -> None:
    """Launch the Tkinter desktop GUI."""
    root = tk.Tk()
    WiFiAnalyzerTkApp(
        root,
        initial_mode=initial_mode,
        auto_start=auto_start,
        initial_targets=initial_targets,
    )
    root.mainloop()
