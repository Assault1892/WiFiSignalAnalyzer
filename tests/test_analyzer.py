"""Unit and integration tests for WiFi Signal & Stability Analyzer."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.evaluator import build_diagnostic_report, evaluate_security
from core.models import (
    REALTIME_CSV_HEADERS,
    PingSummary,
    PingTargetResult,
    RealtimeEvent,
    RealtimeSample,
    SpeedTestResult,
    WiFiInfo,
)
from core.network_tester import (
    DEFAULT_PING_TARGETS,
    PING_TARGET_LABELS,
    parse_cloudflare_speed_cli_json,
    parse_ping_output,
)
from core.runner import (
    append_realtime_sample_csv,
    build_rolling_realtime_report,
    detect_realtime_anomalies,
    format_realtime_samples_csv,
    format_report_cli,
    format_report_markdown,
)
from core.wifi_scanner import (
    parse_linux_iw_link,
    parse_linux_nmcli_wifi,
    parse_linux_proc_wireless,
    parse_macos_ipconfig_summary,
    parse_macos_preferred_wireless_networks,
    parse_macos_system_profiler_json,
    parse_windows_netsh_interfaces,
)
from gui.web_app import _WebState, _make_handler


class TestWiFiParsers(unittest.TestCase):
    def test_macos_system_profiler_json(self) -> None:
        sample = json.dumps({
            "SPAirPortDataType": [
                {
                    "spairport_airport_interfaces": [
                        {
                            "_name": "en0",
                            "spairport_status_information": "spairport_status_connected",
                            "spairport_current_network_information": {
                                "_name": "<redacted>",
                                "spairport_network_channel": "36 (5GHz, 80MHz)",
                                "spairport_network_phymode": "802.11ax",
                                "spairport_network_rate": 864,
                                "spairport_network_mcs": 9,
                                "spairport_security_mode": "spairport_security_mode_wpa3_transition",
                                "spairport_signal_noise": "-54 dBm / -92 dBm",
                            },
                        }
                    ]
                }
            ]
        })
        info = parse_macos_system_profiler_json(sample)
        self.assertIsNotNone(info)
        assert info is not None
        self.assertTrue(info.connected)
        self.assertEqual(info.interface, "en0")
        self.assertEqual(info.ssid, "接続中Wi-Fi (SSID非公開設定)")
        self.assertEqual(info.rssi_dbm, -54)
        self.assertEqual(info.noise_dbm, -92)
        self.assertEqual(info.snr_db, 38)
        self.assertEqual(info.band, "5GHz")
        self.assertEqual(info.tx_rate_mbps, 864.0)
        self.assertEqual(info.mcs_index, 9)
        self.assertIn("WPA2/WPA3", info.security_raw)

    def test_macos_ipconfig_summary(self) -> None:
        sample = """
        InterfaceName : en0
        SSID : MyHomeWiFi_5G
        BSSID : aa:bb:cc:dd:ee:ff
        Security : WPA3_SAE
        LinkStatusActive : TRUE
        """
        info = parse_macos_ipconfig_summary(sample)
        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual(info.ssid, "MyHomeWiFi_5G")
        self.assertEqual(info.bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(info.security_raw, "WPA3 Personal")

        inactive = "LinkStatusActive : FALSE\n"
        self.assertIsNone(parse_macos_ipconfig_summary(inactive))

    def test_macos_preferred_wireless_networks(self) -> None:
        sample = "Preferred networks on en0:\n\tMyHomeWiFi\n\tOfficeWiFi\n"
        self.assertEqual(parse_macos_preferred_wireless_networks(sample), "MyHomeWiFi")

        empty_sample = "Preferred networks on en0:\n"
        self.assertIsNone(parse_macos_preferred_wireless_networks(empty_sample))

        err_sample = "Error: en9 is not a Wi-Fi interface.\n"
        self.assertIsNone(parse_macos_preferred_wireless_networks(err_sample))

    def test_windows_netsh_en_and_ja(self) -> None:
        win_en = """
        There is 1 interface on the system:
            Name                   : Wi-Fi
            State                  : connected
            SSID                   : Office_AP
            BSSID                  : 11:22:33:44:55:66
            Radio type             : 802.11ax
            Authentication         : WPA2-Personal
            Cipher                 : CCMP
            Band                   : 5 GHz
            Channel                : 44
            Transmit rate (Mbps)   : 1201
            Signal                 : 84%
        """
        info = parse_windows_netsh_interfaces(win_en)
        self.assertIsNotNone(info)
        assert info is not None
        self.assertTrue(info.connected)
        self.assertEqual(info.ssid, "Office_AP")
        self.assertEqual(info.signal_percent, 84)
        self.assertEqual(info.rssi_dbm, -58)
        self.assertEqual(info.band, "5GHz")
        self.assertEqual(info.tx_rate_mbps, 1201.0)
        self.assertIn("WPA2-Personal", info.security_raw)

        win_ja = """
            名前                   : Wi-Fi
            状態                   : 接続
            SSID                   : Home_24G
            BSSID                  : 10:20:30:40:50:60
            無線の種類             : 802.11n
            認証                   : WPA3-パーソナル
            暗号                   : GCMP
            チャネル               : 6
            送信速度 (Mbps)        : 144.4
            シグナル               : 70%
        """
        info_ja = parse_windows_netsh_interfaces(win_ja)
        self.assertIsNotNone(info_ja)
        assert info_ja is not None
        self.assertEqual(info_ja.band, "2.4GHz")
        self.assertEqual(info_ja.signal_percent, 70)
        self.assertIn("WPA3", info_ja.security_raw)

    def test_linux_parsers(self) -> None:
        nm_out = "no:OtherNet:AA\\:BB\\:CC\\:DD\\:EE\\:00:1:2412 MHz:130 Mbit/s:40:WPA2\n" \
                 "yes:Lab5G:11\\:22\\:33\\:44\\:55\\:66:36:5180 MHz:866 Mbit/s:88:WPA2 WPA3\n"
        nm = parse_linux_nmcli_wifi(nm_out)
        self.assertIsNotNone(nm)
        assert nm is not None
        self.assertEqual(nm.ssid, "Lab5G")
        self.assertEqual(nm.bssid, "11:22:33:44:55:66")
        self.assertEqual(nm.band, "5GHz")
        self.assertEqual(nm.signal_percent, 88)

        proc_out = (
            "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n"
            " face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n"
            " wlan0: 0000   62.  -55.  -95.        0      0      0      0      0        0\n"
        )
        iface, rssi, noise = parse_linux_proc_wireless(proc_out)
        self.assertEqual(iface, "wlan0")
        self.assertEqual(rssi, -55)
        self.assertEqual(noise, -95)

        iw_out = (
            "Connected to 11:22:33:44:55:66 (on wlan0)\n"
            "\tSSID: Lab5G\n"
            "\tfreq: 5180\n"
            "\tsignal: -53 dBm\n"
            "\ttx bitrate: 780.0 MBit/s HE-MCS 9\n"
        )
        iw = parse_linux_iw_link(iw_out, "wlan0")
        self.assertIsNotNone(iw)
        assert iw is not None
        self.assertEqual(iw.rssi_dbm, -53)
        self.assertEqual(iw.band, "5GHz")
        self.assertEqual(iw.tx_rate_mbps, 780.0)


class TestPingParser(unittest.TestCase):
    def test_macos_ping_output(self) -> None:
        raw = """
        PING 1.1.1.1 (1.1.1.1): 56 data bytes
        64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=10.2 ms
        64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.2 ms
        64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=11.2 ms
        64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=14.2 ms

        --- 1.1.1.1 ping statistics ---
        5 packets transmitted, 4 packets received, 20.0% packet loss
        round-trip min/avg/max/stddev = 10.200/11.950/14.200/1.479 ms
        """
        res = parse_ping_output("1.1.1.1", raw, 5)
        self.assertEqual(res.transmitted, 5)
        self.assertEqual(res.received, 4)
        self.assertEqual(res.packet_loss_pct, 20.0)
        self.assertEqual(res.min_ms, 10.2)
        self.assertEqual(res.avg_ms, 11.95)
        self.assertEqual(res.max_ms, 14.2)
        self.assertAlmostEqual(res.jitter_ms or 0.0, 2.0, places=2)

    def test_windows_ja_ping_output(self) -> None:
        raw = """
        1.1.1.1 に ping を送信しています 32 バイトのデータ:
        1.1.1.1 からの応答: バイト数 =32 時間 =8ms TTL=57
        1.1.1.1 からの応答: バイト数 =32 時間 <1ms TTL=57
        1.1.1.1 からの応答: バイト数 =32 時間 =10ms TTL=57

        1.1.1.1 の ping 統計:
            パケット数: 送信 = 3、受信 = 3、損失 = 0 (0% の損失)、
        """
        res = parse_ping_output("1.1.1.1", raw, 3)
        self.assertEqual(res.transmitted, 3)
        self.assertEqual(res.received, 3)
        self.assertEqual(res.packet_loss_pct, 0.0)
        self.assertEqual(len(res.raw_rtts), 3)


class TestCloudflareCliParser(unittest.TestCase):
    def test_parse_cloudflare_speed_cli_json(self) -> None:
        sample = json.dumps({
            "version": "1.0.12",
            "timestamp_utc": "2026-11-14T08:50:00Z",
            "base_url": "https://speed.cloudflare.com",
            "meas_id": "abc123",
            "colo": "NRT",
            "as_org": "Example ISP",
            "ip": "203.0.113.10",
            "idle_latency": {
                "sent": 5,
                "received": 5,
                "loss": 0.0,
                "min_ms": 8.4,
                "mean_ms": 9.8,
                "median_ms": 9.5,
                "max_ms": 11.2,
                "jitter_ms": 1.1,
            },
            "download": {
                "bytes": 18000000,
                "duration_ms": 3000,
                "mbps": 148.62,
            },
            "upload": {
                "bytes": 6000000,
                "duration_ms": 3000,
                "mbps": 52.34,
            },
            "loaded_latency_download": {
                "sent": 10,
                "received": 10,
                "loss": 0.0,
                "median_ms": 24.15,
                "mean_ms": 25.0,
            },
            "loaded_latency_upload": {
                "sent": 10,
                "received": 10,
                "loss": 0.0,
                "median_ms": 19.8,
            },
        })
        res = parse_cloudflare_speed_cli_json(sample)
        self.assertIsNotNone(res)
        assert res is not None
        self.assertFalse(res.skipped)
        self.assertEqual(res.engine, "cloudflare-speed-cli")
        self.assertEqual(res.download_mbps, 148.62)
        self.assertEqual(res.upload_mbps, 52.34)
        self.assertEqual(res.unloaded_latency_ms, 9.5)
        self.assertEqual(res.loaded_latency_ms, 24.15)
        self.assertEqual(res.colo, "NRT")
        self.assertEqual(res.isp, "Example ISP")
        self.assertEqual(res.client_ip, "203.0.113.10")
        self.assertEqual(res.bytes_downloaded, 18000000)
        self.assertEqual(res.bytes_uploaded, 6000000)

        self.assertIsNone(parse_cloudflare_speed_cli_json(""))
        self.assertIsNone(parse_cloudflare_speed_cli_json("not json"))

        dict_colo_sample = json.dumps({
            "colo": {"iata": "NRT", "city": "Tokyo", "cca2": "JP"},
            "as_org": "So-net Service",
            "download": {"bytes": 1000, "mbps": 55.5},
            "upload": {"bytes": 500, "mbps": 22.2},
            "idle_latency": {"median_ms": 14.0},
        })
        res2 = parse_cloudflare_speed_cli_json(dict_colo_sample)
        self.assertIsNotNone(res2)
        assert res2 is not None
        self.assertEqual(res2.colo, "NRT (Tokyo, JP)")


class TestEvaluatorAndUseCases(unittest.TestCase):
    def _make_ping(self, avg: float, jitter: float, loss: float) -> PingSummary:
        t = PingTargetResult(
            target="1.1.1.1",
            transmitted=5,
            received=5 if loss == 0 else 4,
            packet_loss_pct=loss,
            min_ms=avg,
            avg_ms=avg,
            max_ms=avg + jitter,
            jitter_ms=jitter,
            method="ICMP",
            raw_rtts=[avg],
        )
        return PingSummary(
            targets=[t],
            avg_rtt_ms=avg,
            max_rtt_ms=avg + jitter,
            avg_jitter_ms=jitter,
            total_loss_pct=loss,
        )

    def test_excellent_fiber_wifi(self) -> None:
        wifi = WiFiInfo(
            connected=True,
            interface="en0",
            ssid="Home_5G_Mesh",
            rssi_dbm=-48,
            noise_dbm=-92,
            tx_rate_mbps=1200.0,
            band="5GHz",
            phy_mode="802.11ax (Wi-Fi 6)",
            security_raw="WPA3 Personal",
        ).finalize()
        ping = self._make_ping(avg=11.0, jitter=1.2, loss=0.0)
        speed = SpeedTestResult(
            skipped=False,
            download_mbps=240.0,
            upload_mbps=110.0,
            unloaded_latency_ms=10.5,
            colo="NRT",
            isp="Sample Fiber",
        )
        report = build_diagnostic_report(wifi, ping, speed, captive_portal_detected=False)
        self.assertIn(report.overall_grade, {"S", "A"})
        self.assertGreaterEqual(report.overall_score, 88)
        by_id = {u.id: u for u in report.use_cases}
        self.assertEqual(by_id["online_gaming"].rating, "◎ 最適")
        self.assertEqual(by_id["banking_confidential"].rating, "◎ 最適")
        self.assertEqual(by_id["video_conference"].rating, "◎ 最適")
        self.assertEqual(by_id["video_streaming"].rating, "◎ 最適")

    def test_high_jitter_packet_loss_caps_gaming_and_conf(self) -> None:
        wifi = WiFiInfo(
            connected=True,
            interface="en0",
            ssid="Congested_24G",
            rssi_dbm=-68,
            noise_dbm=-86,
            tx_rate_mbps=72.0,
            band="2.4GHz",
            security_raw="WPA2 Personal",
        ).finalize()
        ping = self._make_ping(avg=45.0, jitter=26.0, loss=3.5)
        speed = SpeedTestResult(skipped=False, download_mbps=60.0, upload_mbps=15.0)
        report = build_diagnostic_report(wifi, ping, speed)
        by_id = {u.id: u for u in report.use_cases}
        self.assertEqual(by_id["online_gaming"].rating, "× 不向き")
        self.assertEqual(by_id["video_conference"].rating, "× 不向き")

    def test_open_public_wifi_security_risk(self) -> None:
        wifi = WiFiInfo(
            connected=True,
            interface="en0",
            ssid="Starbucks_Free_WiFi",
            rssi_dbm=-55,
            band="5GHz",
            security_raw="Open (None)",
        ).finalize()
        sec = evaluate_security(wifi, captive_portal_detected=True)
        self.assertFalse(sec.is_encrypted)
        self.assertTrue(sec.is_public_suspected)
        self.assertTrue(sec.captive_portal_detected)
        self.assertEqual(sec.risk_level, "高 (危険)")

        ping = self._make_ping(avg=22.0, jitter=3.0, loss=0.0)
        speed = SpeedTestResult(skipped=False, download_mbps=80.0, upload_mbps=30.0)
        report = build_diagnostic_report(wifi, ping, speed, captive_portal_detected=True)
        by_id = {u.id: u for u in report.use_cases}
        self.assertEqual(by_id["banking_confidential"].rating, "× 不向き")
        self.assertEqual(by_id["web_browsing"].rating, "△ 注意")

    def test_ping_only_mode(self) -> None:
        wifi = WiFiInfo(
            connected=True,
            interface="en0",
            ssid="TestNet",
            rssi_dbm=-56,
            band="5GHz",
            security_raw="WPA2 Personal",
        ).finalize()
        ping = self._make_ping(avg=18.0, jitter=2.0, loss=0.0)
        speed = SpeedTestResult(skipped=True)
        report = build_diagnostic_report(wifi, ping, speed, mode="ping-only")
        self.assertGreaterEqual(report.overall_score, 75)
        md = format_report_markdown(report)
        self.assertIn("ping-only", md)
        self.assertIn("TestNet", md)

        cli_text = format_report_cli(report)
        self.assertIn("[評価基準の要点]", cli_text)
        self.assertIn("[用途別の適性]", cli_text)
        self.assertNotIn("| --- |", cli_text)
        self.assertNotIn("**", cli_text)

    def test_detect_realtime_anomalies(self) -> None:
        base_wifi = WiFiInfo(
            connected=True,
            interface="en0",
            ssid="RTTestAP",
            rssi_dbm=-54,
            noise_dbm=-92,
            band="5GHz",
            security_raw="WPA3 Personal",
        ).finalize()
        stable_ping = self._make_ping(avg=12.0, jitter=1.8, loss=0.0)
        history = [
            RealtimeSample(
                seq=1,
                timestamp="18:40:00",
                rssi_dbm=-54,
                noise_dbm=-92,
                snr_db=38,
                avg_rtt_ms=12.0,
                max_rtt_ms=14.0,
                jitter_ms=1.8,
                packet_loss_pct=0.0,
            )
        ]
        self.assertEqual(
            detect_realtime_anomalies(2, "18:40:02", base_wifi, stable_ping, history),
            [],
        )

        noisy_wifi = WiFiInfo(
            connected=True,
            interface="en0",
            ssid="RTTestAP",
            rssi_dbm=-76,
            noise_dbm=-92,
            band="5GHz",
            security_raw="WPA3 Personal",
        ).finalize()
        noisy_ping = PingSummary(
            targets=[
                PingTargetResult("1.1.1.1", 2, 1, 50.0, 12.0, 32.0, 120.0, 22.0, "ICMP", [12.0])
            ],
            avg_rtt_ms=32.0,
            max_rtt_ms=120.0,
            avg_jitter_ms=22.0,
            total_loss_pct=50.0,
        )
        events = detect_realtime_anomalies(3, "18:40:04", noisy_wifi, noisy_ping, history)
        kinds = {e.kind for e in events}
        self.assertIn("loss", kinds)
        self.assertIn("jitter", kinds)
        self.assertIn("rtt_spike", kinds)
        self.assertIn("rf_drop", kinds)

    def test_rolling_realtime_evaluation_and_csv(self) -> None:
        wifi = WiFiInfo(
            connected=True,
            interface="en0",
            ssid="HomeMesh_5G",
            bssid="aa:bb:cc:11:22:33",
            rssi_dbm=-56,
            noise_dbm=-92,
            tx_rate_mbps=864.0,
            channel="36 (5GHz, 80MHz)",
            band="5GHz",
            security_raw="WPA3 Personal",
        ).finalize()
        cur_ping = PingSummary(
            targets=[PingTargetResult("1.1.1.1", 2, 2, 0.0, 12.0, 14.0, 16.0, 2.0, "ICMP", [12.0, 16.0])],
            avg_rtt_ms=14.0,
            max_rtt_ms=16.0,
            avg_jitter_ms=2.0,
            total_loss_pct=0.0,
        )
        base_epoch = 1794650000.0
        samples = [
            # Expired sample (>180s ago): should be excluded from 3-min rolling window
            RealtimeSample(
                seq=1,
                timestamp="19:10:00",
                datetime_str="2026-11-14 19:10:00",
                epoch_sec=base_epoch - 220.0,
                ssid="HomeMesh_5G",
                rssi_dbm=-85,
                noise_dbm=-92,
                snr_db=7,
                avg_rtt_ms=180.0,
                max_rtt_ms=250.0,
                jitter_ms=40.0,
                packet_loss_pct=50.0,
            ),
            RealtimeSample(
                seq=2,
                timestamp="19:12:30",
                datetime_str="2026-11-14 19:12:30",
                epoch_sec=base_epoch - 60.0,
                ssid="HomeMesh_5G",
                rssi_dbm=-54,
                noise_dbm=-92,
                snr_db=38,
                tx_rate_mbps=864.0,
                avg_rtt_ms=10.0,
                max_rtt_ms=12.0,
                jitter_ms=1.0,
                packet_loss_pct=0.0,
                per_target_rtt={"1.1.1.1": 10.0},
                per_target_loss={"1.1.1.1": 0.0},
            ),
            RealtimeSample(
                seq=3,
                timestamp="19:13:30",
                datetime_str="2026-11-14 19:13:30",
                epoch_sec=base_epoch,
                ssid="HomeMesh_5G",
                rssi_dbm=-58,
                noise_dbm=-92,
                snr_db=34,
                tx_rate_mbps=864.0,
                avg_rtt_ms=20.0,
                max_rtt_ms=24.0,
                jitter_ms=3.0,
                packet_loss_pct=25.0,
                per_target_rtt={"1.1.1.1": 20.0},
                per_target_loss={"1.1.1.1": 25.0},
                events=["パケットロス発生"],
            ),
        ]

        report = build_rolling_realtime_report(wifi, cur_ping, samples, captive_portal_detected=False)
        self.assertIn("[過去60秒・2回平均]", report.overall_verdict)
        self.assertEqual(report.wifi.rssi_dbm, -56)
        self.assertEqual(report.ping.avg_rtt_ms, 15.0)
        self.assertEqual(report.ping.max_rtt_ms, 24.0)
        self.assertEqual(report.ping.total_loss_pct, 12.5)
        self.assertEqual(report.ping.targets[0].avg_ms, 15.0)
        self.assertEqual(report.ping.targets[0].packet_loss_pct, 12.5)

        csv_str = format_realtime_samples_csv(samples[1:])
        self.assertIn("日時,SSID,RF,ping ms,jitter,パケットロスしたかどうか,パケットロス率", csv_str)

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "session.csv")
            append_realtime_sample_csv(csv_path, samples[1])
            append_realtime_sample_csv(csv_path, samples[2])
            with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
                rows = list(csv.reader(f))
            self.assertEqual(tuple(rows[0]), REALTIME_CSV_HEADERS)
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[1][0], "2026-11-14 19:12:30")
            self.assertEqual(rows[1][1], "HomeMesh_5G")
            self.assertEqual(rows[1][2], "-54")
            self.assertEqual(rows[1][5], "なし")
            self.assertEqual(rows[2][5], "あり")
            self.assertEqual(rows[2][6], "25.0")


class _FakeSocket:
    """In-memory socket wrapper for testing BaseHTTPRequestHandler without network."""

    def __init__(self, raw_request: bytes) -> None:
        self._rfile = io.BytesIO(raw_request)
        self.wfile = io.BytesIO()

    def makefile(self, mode: str, *_args, **_kwargs):
        return self._rfile if "r" in mode else self.wfile

    def sendall(self, data: bytes) -> None:
        self.wfile.write(data)

    def close(self) -> None:
        return


class TestWebDashboardServer(unittest.TestCase):
    def _sample_report(self):
        wifi = WiFiInfo(
            connected=True,
            interface="en0",
            ssid="WebTestAP",
            rssi_dbm=-52,
            noise_dbm=-90,
            band="5GHz",
            security_raw="WPA3 Personal",
        ).finalize()
        ping = PingSummary(
            targets=[
                PingTargetResult("1.1.1.1", 5, 5, 0.0, 9.0, 10.0, 11.0, 1.0, "ICMP", [10.0])
            ],
            avg_rtt_ms=10.0,
            max_rtt_ms=11.0,
            avg_jitter_ms=1.0,
            total_loss_pct=0.0,
        )
        speed = SpeedTestResult(skipped=False, download_mbps=120.0, upload_mbps=50.0)
        return build_diagnostic_report(wifi, ping, speed)

    def _dispatch(self, handler_cls, raw_req: bytes) -> str:
        sock = _FakeSocket(raw_req)
        handler_cls(sock, ("127.0.0.1", 12345), None)
        return sock.wfile.getvalue().decode("utf-8", errors="replace")

    def test_web_handler_endpoints(self) -> None:
        standby_state = _WebState()
        self.assertFalse(standby_state.running)
        self.assertIsNone(standby_state.report)
        snap = standby_state.snapshot()
        self.assertEqual(
            [t["target"] for t in snap["targets"]],
            ["1.1.1.1", "8.8.8.8", "9.9.9.9", "google.co.jp"],
        )
        self.assertEqual(DEFAULT_PING_TARGETS, ("1.1.1.1", "8.8.8.8", "9.9.9.9", "google.co.jp"))
        self.assertIn("8.8.8.8", PING_TARGET_LABELS)

        report = self._sample_report()
        state = _WebState(initial_report=report)
        handler_cls = _make_handler(state)

        html_resp = self._dispatch(handler_cls, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn("200 OK", html_resp)
        self.assertIn("WiFi Signal &amp; Stability Analyzer", html_resp)
        self.assertIn("renderStandby(st.targets, false)", html_resp)

        status_resp = self._dispatch(handler_cls, b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn("200 OK", status_resp)
        _, _, body = status_resp.partition("\r\n\r\n")
        st = json.loads(body)
        self.assertFalse(st["running"])
        self.assertEqual(st["report"]["wifi"]["ssid"], "WebTestAP")

        md_resp = self._dispatch(handler_cls, b"GET /api/report?format=md HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn("200 OK", md_resp)
        self.assertIn("WebTestAP", md_resp)

        json_resp = self._dispatch(handler_cls, b"GET /api/report?format=json HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn("200 OK", json_resp)
        self.assertIn('"WebTestAP"', json_resp)

        save_resp = self._dispatch(handler_cls, b"POST /api/save HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        self.assertIn("200 OK", save_resp)
        _, _, save_body = save_resp.partition("\r\n\r\n")
        save_data = json.loads(save_body)
        self.assertTrue(save_data["saved"])
        try:
            self.assertTrue(os.path.isfile(save_data["md_path"]))
            self.assertTrue(os.path.isfile(save_data["json_path"]))
        finally:
            for p in (save_data.get("md_path"), save_data.get("json_path")):
                if p and os.path.isfile(p):
                    os.remove(p)
            reports_dir = os.path.dirname(save_data["md_path"])
            if os.path.isdir(reports_dir) and not os.listdir(reports_dir):
                os.rmdir(reports_dir)

    def test_web_state_clear_on_start_and_stop(self) -> None:
        report = self._sample_report()
        state = _WebState(initial_report=report)
        state.realtime_tick = 3
        sample = RealtimeSample(
            seq=3,
            timestamp="18:42:00",
            datetime_str="2026-11-14 18:42:00",
            ssid="WebTestAP",
            rssi_dbm=-55,
            avg_rtt_ms=14.0,
            max_rtt_ms=20.0,
            jitter_ms=2.5,
            packet_loss_pct=0.0,
        )
        state.realtime_samples = [sample]
        state.session_samples = [sample]
        state.realtime_csv_path = "/tmp/dummy.csv"
        state.realtime_events = [
            RealtimeEvent(seq=3, timestamp="18:42:00", kind="jitter", severity="warn", message="test")
        ]

        handler_cls = _make_handler(state)
        html_resp = self._dispatch(handler_cls, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn("clearDisplayedRecords", html_resp)
        self.assertIn("pingChartSvg", html_resp)
        self.assertIn("lossChartSvg", html_resp)
        self.assertIn("eventLogList", html_resp)

        csv_resp = self._dispatch(handler_cls, b"GET /api/report?format=csv HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn("200 OK", csv_resp)
        self.assertIn("日時,SSID,RF,ping ms,jitter,パケットロスしたかどうか,パケットロス率", csv_resp)
        self.assertIn("WebTestAP", csv_resp)

        with mock.patch("gui.web_app.threading.Thread") as mock_thread:
            started = state.start_run("realtime", targets=("1.1.1.1", "8.8.8.8"))
            self.assertTrue(started)
            self.assertTrue(mock_thread.called)

        self.assertIsNone(state.report)
        self.assertEqual(state.realtime_samples, [])
        self.assertEqual(state.session_samples, [])
        self.assertEqual(state.realtime_events, [])
        self.assertEqual(state.realtime_tick, 0)
        self.assertIsNone(state.realtime_csv_path)
        self.assertTrue(state.realtime_active)

        stop_resp = self._dispatch(handler_cls, b"POST /api/stop HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        self.assertIn("200 OK", stop_resp)
        self.assertIn('"stopped": true', stop_resp)
        self.assertTrue(state.stop_event.is_set())


class TestTkinterApp(unittest.TestCase):
    def test_tk_gui_render_if_available(self) -> None:
        try:
            import tkinter as tk
        except ImportError:
            self.skipTest("tkinter not installed in this Python interpreter")
            return

        from gui.tk_app import WiFiAnalyzerTkApp

        root = tk.Tk()
        root.withdraw()
        try:
            app = WiFiAnalyzerTkApp(root, initial_mode="light", auto_start=False)
            wifi = WiFiInfo(
                connected=True,
                interface="en0",
                ssid="TkTestAP",
                rssi_dbm=-55,
                noise_dbm=-91,
                band="5GHz",
                tx_rate_mbps=866.0,
                security_raw="WPA3 Personal",
            ).finalize()
            ping = PingSummary(
                targets=[PingTargetResult("1.1.1.1", 5, 5, 0.0, 10.0, 12.0, 14.0, 1.5, "ICMP", [10.0])],
                avg_rtt_ms=12.0,
                max_rtt_ms=14.0,
                avg_jitter_ms=1.5,
                total_loss_pct=0.0,
            )
            speed = SpeedTestResult(skipped=False, download_mbps=140.0, upload_mbps=60.0)
            report = build_diagnostic_report(wifi, ping, speed)
            app._render_report(report)
            app._rt_samples = [
                RealtimeSample(
                    seq=1,
                    timestamp="18:45:00",
                    rssi_dbm=-55,
                    avg_rtt_ms=12.0,
                    max_rtt_ms=14.0,
                    jitter_ms=1.5,
                    packet_loss_pct=20.0,
                    events=["パケットロス発生"],
                )
            ]
            app._rt_events = [
                RealtimeEvent(seq=1, timestamp="18:45:00", kind="loss", severity="danger", message="パケットロス発生")
            ]
            app._update_anomaly_ui()
            root.update_idletasks()
            self.assertIn("TkTestAP", app.wifi_id_lbl.cget("text"))
            self.assertGreater(len(app.ping_chart_canvas.find_all()), 0)
            self.assertGreater(len(app.loss_chart_canvas.find_all()), 0)

            app._clear_displayed_records("クリアテスト")
            root.update_idletasks()
            self.assertIsNone(app._report)
            self.assertEqual(app._rt_samples, [])
            self.assertEqual(app._rt_events, [])
            self.assertIn("Wi-Fi情報計測中", app.wifi_id_lbl.cget("text"))
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
