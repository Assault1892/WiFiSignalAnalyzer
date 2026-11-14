"""Security, signal/stability/speed scoring, and use-case suitability evaluation."""

from __future__ import annotations

import datetime
import re
from typing import Dict, List, Optional, Tuple

from .models import (
    DiagnosticReport,
    PingSummary,
    SecurityAssessment,
    SpeedTestResult,
    UseCaseEvaluation,
    WiFiInfo,
)

PUBLIC_SSID_KEYWORDS: Tuple[str, ...] = (
    "free",
    "public",
    "guest",
    "wi2",
    "docomo",
    "au_wi-fi",
    "au-wifi",
    "softbank",
    "starbucks",
    "tullys",
    "komeda",
    "hotel",
    "airport",
    "shinkansen",
    "0000",
    "0001",
    "7spot",
    "lawson",
    "famima",
    "cafe",
    "lobby",
    "spot",
    "visitor",
    "hotspot",
    "metro",
    "station",
)


def _clamp(val: float, lo: float = 0.0, hi: float = 100.0) -> int:
    return int(round(max(lo, min(hi, val))))


def _normalize_auth_type(security_raw: str) -> str:
    s = (security_raw or "").strip().lower()
    if not s or "不明" in s:
        return "不明"
    if "wpa3" in s and ("wpa2" in s or "transition" in s):
        return "WPA2/WPA3"
    if "wpa3" in s or "sae" in s:
        return "WPA3"
    if "wpa2" in s:
        return "WPA2"
    if "wpa" in s:
        return "WPA (TKIP)"
    if "wep" in s:
        return "WEP"
    if "owe" in s:
        return "OWE"
    if any(tok in s for tok in ("none", "open", "オープン", "なし", "暗号化なし")):
        return "Open (暗号化なし)"
    return security_raw.strip()


def evaluate_security(wifi: WiFiInfo, captive_portal_detected: bool = False) -> SecurityAssessment:
    """Assess authentication strength and public/untrusted Wi-Fi risk."""
    if not wifi.connected:
        return SecurityAssessment(
            auth_type="不明",
            is_encrypted=False,
            is_public_suspected=False,
            captive_portal_detected=captive_portal_detected,
            risk_level="高 (危険)",
            score=0,
            findings=["Wi-Fiに接続されていないためセキュリティ評価ができません。"],
            recommendations=["Wi-Fiアクセスポイントへ接続してから再診断してください。"],
        )

    auth_type = _normalize_auth_type(wifi.security_raw)
    findings: List[str] = []
    recommendations: List[str] = []

    is_encrypted = auth_type not in {"Open (暗号化なし)", "WEP", "不明"}
    if auth_type == "WPA3":
        score = 100
        findings.append("最新の強固な暗号化方式 (WPA3) で保護されています。")
    elif auth_type == "WPA2/WPA3":
        score = 92
        findings.append("WPA2/WPA3移行モードで暗号化されています。")
    elif auth_type == "WPA2":
        score = 84
        findings.append("標準的なWPA2 (AES) で暗号化されています。")
    elif auth_type == "OWE":
        score = 62
        findings.append("OWE (Enhanced Open) により無線区間は暗号化されていますが、認証なしネットワークです。")
        recommendations.append("不特定多数が接続できる可能性があるため、重要なログイン時はVPN併用を推奨します。")
    elif auth_type == "WPA (TKIP)":
        score = 40
        findings.append("旧式のWPA (TKIP) が使用されており、暗号化強度が低下しています。")
        recommendations.append("ルーター側でWPA2またはWPA3への変更を推奨します。")
    elif auth_type == "WEP":
        score = 15
        is_encrypted = False
        findings.append("脆弱なWEP暗号化が使用されており、第三者に解読される恐れがあります。")
        recommendations.append("機密情報の送信は避け、WPA2/WPA3対応ネットワークへ切り替えてください。")
    elif auth_type == "Open (暗号化なし)":
        score = 10
        is_encrypted = False
        findings.append("無線の暗号化が行われていないオープンWi-Fiです（通信傍受のリスク大）。")
        recommendations.append("決済・ログイン・機密作業には使用せず、必ずVPNまたはモバイル回線を利用してください。")
    else:
        score = 55
        findings.append(f"認証方式を正確に判別できませんでした ({wifi.security_raw or '取得不可'})。")

    # Public Wi-Fi heuristics
    ssid_lower = (wifi.ssid or "").lower()
    matched_kw = [kw for kw in PUBLIC_SSID_KEYWORDS if kw in ssid_lower]
    is_public_suspected = (
        auth_type in {"Open (暗号化なし)", "OWE"}
        or bool(matched_kw)
        or captive_portal_detected
    )

    if matched_kw:
        score = min(score, 65) if is_encrypted else min(score, 15)
        findings.append(f"SSID名に公開Wi-Fiの特徴 ({', '.join(matched_kw[:3])}) が含まれています。")
    if captive_portal_detected:
        score = min(score, 55) if is_encrypted else min(score, 10)
        findings.append("キャプティブポータル（ログイン画面やHTTPリダイレクト）が検出されました。")

    if is_public_suspected and is_encrypted:
        recommendations.append("共有ネットワークの可能性があるため、機密作業時はVPN利用とHTTPS確認を徹底してください。")
    if not recommendations:
        recommendations.append("現在の暗号化設定は良好です。OS・ルーターのファームウェアも最新に保つとさらに安全です。")

    if score >= 75:
        risk_level = "低 (安全)"
    elif score >= 45:
        risk_level = "中 (注意)"
    else:
        risk_level = "高 (危険)"

    return SecurityAssessment(
        auth_type=auth_type,
        is_encrypted=is_encrypted,
        is_public_suspected=is_public_suspected,
        captive_portal_detected=captive_portal_detected,
        risk_level=risk_level,
        score=_clamp(score),
        findings=findings,
        recommendations=recommendations,
    )


def score_signal(wifi: WiFiInfo) -> int:
    """Compute 0-100 score for RF signal quality."""
    if not wifi.connected:
        return 0

    rssi = wifi.rssi_dbm
    if rssi is not None:
        if rssi >= -50:
            base = 100.0
        elif rssi >= -60:
            base = 82.0 + (rssi + 60) * 1.8
        elif rssi >= -67:
            base = 70.0 + (rssi + 67) * (12.0 / 7.0)
        elif rssi >= -75:
            base = 42.0 + (rssi + 75) * (28.0 / 8.0)
        elif rssi >= -85:
            base = 15.0 + (rssi + 85) * 2.7
        else:
            base = 10.0
    elif wifi.signal_percent is not None:
        base = float(wifi.signal_percent)
    else:
        base = 60.0

    # SNR adjustment when noise floor is available
    if wifi.snr_db is not None:
        if wifi.snr_db >= 35:
            base += 4
        elif wifi.snr_db < 15:
            base -= 18
        elif wifi.snr_db < 22:
            base -= 8

    # Band & link rate adjustment
    if wifi.band == "2.4GHz":
        base -= 6  # More prone to neighbor interference
    elif wifi.band in {"5GHz", "6GHz"}:
        base += 2

    if wifi.tx_rate_mbps is not None:
        if wifi.tx_rate_mbps < 30:
            base -= 15
        elif wifi.tx_rate_mbps < 72:
            base -= 7

    return _clamp(base)


def score_stability(ping: PingSummary) -> int:
    """Compute 0-100 score for Ping RTT, jitter, and packet loss stability."""
    if ping.avg_rtt_ms is None:
        return 0

    rtt = ping.avg_rtt_ms
    if rtt <= 15:
        rtt_score = 100.0
    elif rtt <= 30:
        rtt_score = 88.0 + (30.0 - rtt) * (12.0 / 15.0)
    elif rtt <= 50:
        rtt_score = 72.0 + (50.0 - rtt) * (16.0 / 20.0)
    elif rtt <= 80:
        rtt_score = 52.0 + (80.0 - rtt) * (20.0 / 30.0)
    elif rtt <= 150:
        rtt_score = 25.0 + (150.0 - rtt) * (27.0 / 70.0)
    else:
        rtt_score = max(5.0, 25.0 - (rtt - 150.0) * 0.1)

    jitter = ping.avg_jitter_ms or 0.0
    if jitter > 30:
        rtt_score -= 30
    elif jitter > 15:
        rtt_score -= 18
    elif jitter > 7:
        rtt_score -= 8
    elif jitter > 3:
        rtt_score -= 3

    # Packet loss is heavily penalized
    loss = ping.total_loss_pct
    if loss > 0:
        rtt_score -= min(85.0, loss * 12.0)

    return _clamp(rtt_score)


def score_speed(speed: SpeedTestResult) -> int:
    """Compute 0-100 score from Cloudflare download and upload speeds."""
    if speed.skipped:
        return 0
    if speed.download_mbps is None and speed.upload_mbps is None:
        return 0

    down = speed.download_mbps or 0.0
    up = speed.upload_mbps or 0.0

    def _curve(mbps: float, milestones: Tuple[Tuple[float, float], ...]) -> float:
        prev_x, prev_y = 0.0, 0.0
        for x, y in milestones:
            if mbps <= x:
                return prev_y + ((mbps - prev_x) / (x - prev_x)) * (y - prev_y)
            prev_x, prev_y = x, y
        return 100.0

    down_score = _curve(down, ((5.0, 35.0), (15.0, 58.0), (35.0, 75.0), (80.0, 88.0), (200.0, 97.0), (400.0, 100.0)))
    up_score = _curve(up, ((2.0, 30.0), (8.0, 58.0), (20.0, 78.0), (50.0, 90.0), (150.0, 100.0)))

    return _clamp(down_score * 0.65 + up_score * 0.35)


def _rating_from_score(score: int, max_cap: Optional[str] = None) -> str:
    order = ["× 不向き", "△ 注意", "○ 快適", "◎ 最適"]
    if score >= 82:
        raw = "◎ 最適"
    elif score >= 65:
        raw = "○ 快適"
    elif score >= 42:
        raw = "△ 注意"
    else:
        raw = "× 不向き"
    if max_cap and max_cap in order:
        return order[min(order.index(raw), order.index(max_cap))]
    return raw


def _cap_score_for_rating(score: int, rating: str) -> int:
    if rating == "× 不向き":
        return min(score, 39)
    if rating == "△ 注意":
        return min(score, 62)
    if rating == "○ 快適":
        return min(score, 81)
    return score


def evaluate_use_cases(
    wifi: WiFiInfo,
    ping: PingSummary,
    speed: SpeedTestResult,
    security: SecurityAssessment,
    pillar_scores: Dict[str, int],
) -> List[UseCaseEvaluation]:
    """Evaluate suitability of the current Wi-Fi AP across 6 real-world use cases."""
    sig_s = pillar_scores["signal"]
    stb_s = pillar_scores["stability"]
    spd_s = pillar_scores["speed"]
    sec_s = pillar_scores["security"]

    down = speed.download_mbps
    up = speed.upload_mbps
    rtt = ping.avg_rtt_ms
    jitter = ping.avg_jitter_ms or 0.0
    loss = ping.total_loss_pct
    speed_unmeasured = speed.skipped

    # Effective speed estimate if speedtest was skipped (ping-only mode)
    eff_spd_s = spd_s if not speed_unmeasured else max(35, min(75, sig_s))

    cases: List[UseCaseEvaluation] = []

    # 1. Web browsing / SNS / Email
    s_web = _clamp(sig_s * 0.25 + stb_s * 0.30 + eff_spd_s * 0.25 + sec_s * 0.20)
    cap_web: Optional[str] = None
    if ping.avg_rtt_ms is None or loss >= 30.0:
        cap_web = "× 不向き"
    elif down is not None and down < 1.5:
        cap_web = "× 不向き"
    elif (down is not None and down < 5.0) or not security.is_encrypted or loss > 3.0:
        cap_web = "△ 注意"
    r_web = _rating_from_score(s_web, cap_web)
    s_web = _cap_score_for_rating(s_web, r_web)
    if not wifi.connected:
        web_summary = "Wi-Fi未接続のため通信・安全性評価不可"
    elif not security.is_encrypted:
        web_summary = "暗号化なしネットワークのため機密ログインに注意"
    elif s_web >= 65:
        web_summary = "日常の検索・SNS・メールはストレスなく利用可能"
    else:
        web_summary = "表示遅延や通信途切れが起きやすい状態"
    cases.append(
        UseCaseEvaluation(
            id="web_browsing",
            name="Webブラウジング・SNS・メール",
            icon="🌐",
            rating=r_web,
            score=s_web,
            summary=web_summary,
            details=f"下り {down if down is not None else '未計測'} Mbps / Ping {rtt if rtt is not None else '未計測'} ms / パケットロス {loss}%",
        )
    )

    # 2. High-res Video Streaming (4K / FHD)
    s_vid = _clamp(sig_s * 0.25 + stb_s * 0.20 + eff_spd_s * 0.50 + sec_s * 0.05)
    cap_vid: Optional[str] = None
    if ping.avg_rtt_ms is None or (down is not None and down < 3.0) or loss >= 10.0:
        cap_vid = "× 不向き"
    elif (down is not None and down < 18.0) or loss > 2.0 or speed_unmeasured:
        cap_vid = "△ 注意"
    elif down is not None and down < 25.0:
        cap_vid = "○ 快適"
    r_vid = _rating_from_score(s_vid, cap_vid)
    s_vid = _cap_score_for_rating(s_vid, r_vid)
    if speed_unmeasured:
        vid_summary = "速度未計測のため暫定判定（FHD/4K判定には速度テスト実行を推奨）"
    elif r_vid == "× 不向き":
        vid_summary = "帯域不足またはパケットロスにより動画が停止しやすい状態"
    elif down is not None and down >= 35.0 and loss <= 1.0:
        vid_summary = "4K HDRストリーミングもバッファリングなしで快適再生可能"
    elif down is not None and down >= 10.0:
        vid_summary = "フルHD (1080p) 再生は十分快適、4Kでは混雑時に画質低下の可能性"
    else:
        vid_summary = "帯域不足またはロスにより動画が停止しやすい状態"
    cases.append(
        UseCaseEvaluation(
            id="video_streaming",
            name="高画質動画視聴 (YouTube / 4K配信)",
            icon="🎬",
            rating=r_vid,
            score=s_vid,
            summary=vid_summary,
            details=f"必要目安: FHD 5Mbps / 4K 25Mbps以上 (実測: {down if down is not None else '未計測'} Mbps)",
        )
    )

    # 3. Video Conferencing (Zoom / Teams / Meet)
    s_conf = _clamp(sig_s * 0.25 + stb_s * 0.40 + eff_spd_s * 0.25 + sec_s * 0.10)
    cap_conf: Optional[str] = None
    if ping.avg_rtt_ms is None or loss > 2.0 or (rtt is not None and rtt > 150) or (up is not None and up < 1.5) or (down is not None and down < 2.0):
        cap_conf = "× 不向き"
    elif loss > 0.5 or jitter > 18.0 or (rtt is not None and rtt > 75) or (up is not None and up < 4.0) or (wifi.rssi_dbm is not None and wifi.rssi_dbm < -72):
        cap_conf = "△ 注意"
    r_conf = _rating_from_score(s_conf, cap_conf)
    s_conf = _cap_score_for_rating(s_conf, r_conf)
    if r_conf in {"◎ 最適", "○ 快適"}:
        conf_summary = "遅延・ロスが少なく、カメラONのWeb会議や画面共有も安定"
    elif r_conf == "△ 注意":
        conf_summary = "音声途切れや画質低下の恐れあり（カメラOFFやルーター接近を推奨）"
    else:
        conf_summary = "パケットロス・遅延または上り速度不足によりWeb会議は不安定"
    cases.append(
        UseCaseEvaluation(
            id="video_conference",
            name="Web会議・音声通話 (Zoom / Teams)",
            icon="📹",
            rating=r_conf,
            score=s_conf,
            summary=conf_summary,
            details=f"Ping {rtt if rtt is not None else '未計測'} ms / ジッター {jitter} ms / 上り {up if up is not None else '未計測'} Mbps / ロス {loss}%",
        )
    )

    # 4. Online Gaming (FPS / Competitive)
    s_game = _clamp(sig_s * 0.20 + stb_s * 0.60 + eff_spd_s * 0.15 + sec_s * 0.05)
    cap_game: Optional[str] = None
    if ping.avg_rtt_ms is None or loss > 1.5 or jitter > 22.0 or (rtt is not None and rtt > 90):
        cap_game = "× 不向き"
    elif loss > 0.0 or jitter > 10.0 or (rtt is not None and rtt > 45) or (wifi.band == "2.4GHz" and rtt is not None and rtt > 25):
        cap_game = "△ 注意"
    elif wifi.band == "2.4GHz":
        cap_game = "○ 快適"
    r_game = _rating_from_score(s_game, cap_game)
    s_game = _cap_score_for_rating(s_game, r_game)
    if r_game == "◎ 最適":
        game_summary = "低Ping・低ジッター・ロス0%でFPSや対人ゲームにも十分対応可能"
    elif r_game == "○ 快適":
        if wifi.band == "2.4GHz":
            game_summary = "概ね快適（5GHz/6GHz帯または有線接続に切り替えるとさらに安定）"
        else:
            game_summary = "低遅延で快適ですが、電波強度がやや弱いためルーターに近づくとさらに安定"
    elif r_game == "△ 注意":
        game_summary = "ラグスパイクや応答遅延が発生する可能性（RPG向け、FPSは注意）"
    else:
        game_summary = "遅延・ジッター・パケットロスが大きく対戦ゲームには不向き"
    cases.append(
        UseCaseEvaluation(
            id="online_gaming",
            name="オンラインゲーム (FPS・対人対戦)",
            icon="🎮",
            rating=r_game,
            score=s_game,
            summary=game_summary,
            details=f"Ping {rtt if rtt is not None else '未計測'} ms / ジッター {jitter} ms / ロス {loss}% / 帯域 {wifi.band}",
        )
    )

    # 5. Large File Transfers / Cloud Sync / Dev Work
    s_cloud = _clamp(sig_s * 0.20 + stb_s * 0.20 + eff_spd_s * 0.50 + sec_s * 0.10)
    cap_cloud: Optional[str] = None
    if ping.avg_rtt_ms is None or (down is not None and down < 5.0) or (up is not None and up < 3.0) or loss >= 10.0:
        cap_cloud = "× 不向き"
    elif (down is not None and down < 25.0) or (up is not None and up < 12.0) or speed_unmeasured:
        cap_cloud = "△ 注意"
    r_cloud = _rating_from_score(s_cloud, cap_cloud)
    s_cloud = _cap_score_for_rating(s_cloud, r_cloud)
    if speed_unmeasured:
        cloud_summary = "速度未計測のため暫定評価（速度テスト実行で正確な転送時間を見積もり可能）"
    elif r_cloud in {"◎ 最適", "○ 快適"}:
        cloud_summary = "上下ともに十分な速度があり、クラウド同期や大容量アップロードも高速"
    elif r_cloud == "△ 注意":
        cloud_summary = "大容量ファイルのアップロードやバックアップに時間がかかりやすい状態"
    else:
        cloud_summary = "転送速度不足またはパケットロスにより大容量データのやり取りには不向き"
    cases.append(
        UseCaseEvaluation(
            id="cloud_large_files",
            name="大容量ファイル送受信・クラウド作業",
            icon="☁️",
            rating=r_cloud,
            score=s_cloud,
            summary=cloud_summary,
            details=f"下り {down if down is not None else '未計測'} Mbps / 上り {up if up is not None else '未計測'} Mbps",
        )
    )

    # 6. Confidential Work / Banking / Payments
    s_bank = _clamp(sec_s * 0.65 + stb_s * 0.20 + sig_s * 0.15)
    cap_bank: Optional[str] = None
    if not security.is_encrypted or not wifi.connected:
        cap_bank = "× 不向き"
    elif security.is_public_suspected or security.captive_portal_detected or security.auth_type == "WPA (TKIP)":
        cap_bank = "△ 注意"
    r_bank = _rating_from_score(s_bank, cap_bank)
    s_bank = _cap_score_for_rating(s_bank, r_bank)
    if not security.is_encrypted:
        bank_summary = "暗号化されていない危険なWi-Fiのため決済・機密業務は厳禁"
    elif security.is_public_suspected:
        bank_summary = "公開/共有Wi-Fiの疑いあり。機密業務・決済時はVPN利用を推奨"
    elif r_bank == "△ 注意":
        bank_summary = f"{security.auth_type}で暗号化は良好ですが、電波・回線が不安定なため決済操作の途切れに注意"
    else:
        bank_summary = f"{security.auth_type}で適切に暗号化されており安全に利用可能"
    cases.append(
        UseCaseEvaluation(
            id="banking_confidential",
            name="機密業務・ネットバンキング・決済",
            icon="🔒",
            rating=r_bank,
            score=s_bank,
            summary=bank_summary,
            details=f"認証方式: {security.auth_type} / 公開Wi-Fi疑い: {'あり' if security.is_public_suspected else 'なし'} / リスク: {security.risk_level}",
        )
    )

    return cases


def build_diagnostic_report(
    wifi: WiFiInfo,
    ping: PingSummary,
    speed: SpeedTestResult,
    captive_portal_detected: bool = False,
    mode: str = "light",
) -> DiagnosticReport:
    """Compute all scores, overall grade, and use-case verdicts into a DiagnosticReport."""
    security = evaluate_security(wifi, captive_portal_detected=captive_portal_detected)

    sig_s = score_signal(wifi)
    stb_s = score_stability(ping)
    spd_s = score_speed(speed)
    sec_s = security.score

    pillar_scores = {
        "signal": sig_s,
        "stability": stb_s,
        "speed": spd_s,
        "security": sec_s,
    }

    if speed.skipped:
        overall = _clamp(sig_s * 0.30 + stb_s * 0.40 + sec_s * 0.30)
    else:
        overall = _clamp(sig_s * 0.22 + stb_s * 0.30 + spd_s * 0.28 + sec_s * 0.20)

    if overall >= 88:
        grade = "S"
        verdict = "非常に高品質・安全で、あらゆる用途に安心して使える優秀なWi-Fi環境です。"
    elif overall >= 75:
        grade = "A"
        verdict = "安定性・速度・安全性ともに良好で、Web会議や動画視聴を含め快適に利用できます。"
    elif overall >= 58:
        grade = "B"
        verdict = "日常利用には十分ですが、一部ボトルネック（速度・遅延・セキュリティ等）があります。"
    elif overall >= 40:
        grade = "C"
        verdict = "通信の不安定さまたはセキュリティ上の注意点が目立ちます。用途を選んで利用してください。"
    else:
        grade = "D"
        verdict = "信号・回線品質またはセキュリティリスクに重大な課題があります。回線やAPの変更を推奨します。"

    use_cases = evaluate_use_cases(wifi, ping, speed, security, pillar_scores)

    return DiagnosticReport(
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        mode=mode,
        wifi=wifi,
        ping=ping,
        speed=speed,
        security=security,
        pillar_scores=pillar_scores,
        overall_score=overall,
        overall_grade=grade,
        overall_verdict=verdict,
        use_cases=use_cases,
    )
