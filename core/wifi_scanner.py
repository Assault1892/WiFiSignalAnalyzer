"""Cross-platform Wi-Fi interface and signal quality collector."""

from __future__ import annotations

import ctypes
import json
import os
import platform
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .models import WiFiInfo

_CW_SECURITY_MAP: Dict[int, str] = {
    0: "Open (None)",
    1: "WEP",
    2: "WPA Personal",
    3: "WPA/WPA2 Personal",
    4: "WPA2 Personal",
    5: "Personal",
    6: "Dynamic WEP",
    7: "WPA Enterprise",
    8: "WPA/WPA2 Enterprise",
    9: "WPA2 Enterprise",
    10: "Enterprise",
    11: "WPA3 Personal",
    12: "WPA3 Enterprise",
    13: "WPA2/WPA3 Personal (Transition)",
    14: "OWE (Enhanced Open)",
    15: "OWE Transition",
}

_CW_PHY_MODE_MAP: Dict[int, str] = {
    1: "802.11a",
    2: "802.11b",
    3: "802.11g",
    4: "802.11n (Wi-Fi 4)",
    5: "802.11ac (Wi-Fi 5)",
    6: "802.11ax (Wi-Fi 6)",
    7: "802.11be (Wi-Fi 7)",
}

_CW_BAND_MAP: Dict[int, str] = {
    1: "2.4GHz",
    2: "5GHz",
    3: "6GHz",
}

_CW_WIDTH_MAP: Dict[int, str] = {
    1: "20MHz",
    2: "40MHz",
    3: "80MHz",
    4: "160MHz",
    5: "320MHz",
}

_SPAIRPORT_SECURITY_MAP: Dict[str, str] = {
    "spairport_security_mode_none": "Open (None)",
    "spairport_security_mode_wep": "WEP",
    "spairport_security_mode_wpa_personal": "WPA Personal",
    "spairport_security_mode_wpa_enterprise": "WPA Enterprise",
    "spairport_security_mode_wpa2_personal": "WPA2 Personal",
    "spairport_security_mode_wpa2_enterprise": "WPA2 Enterprise",
    "spairport_security_mode_wpa3_personal": "WPA3 Personal",
    "spairport_security_mode_wpa3_enterprise": "WPA3 Enterprise",
    "spairport_security_mode_wpa3_transition": "WPA2/WPA3 Personal (Transition)",
    "spairport_security_mode_owe": "OWE (Enhanced Open)",
    "spairport_security_mode_owe_transition": "OWE Transition",
}


def _run_cmd(args: List[str], timeout: float = 8.0) -> Tuple[int, str]:
    """Run a subprocess safely and decode stdout with fallbacks."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        raw = proc.stdout or b""
        for enc in ("utf-8", "cp932", "latin-1"):
            try:
                return proc.returncode, raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return proc.returncode, raw.decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


def _normalize_phy_mode(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    text = raw.strip()
    lower = text.lower()
    if "be" in lower:
        return "802.11be (Wi-Fi 7)"
    if "ax" in lower or "wi-fi 6" in lower or "wifi 6" in lower:
        return "802.11ax (Wi-Fi 6)"
    if "ac" in lower or "wi-fi 5" in lower:
        return "802.11ac (Wi-Fi 5)"
    if "n" in lower and "802.11" in lower:
        return "802.11n (Wi-Fi 4)"
    return text


def _infer_band_from_channel(channel_str: Optional[str], freq_mhz: Optional[int] = None) -> Optional[str]:
    if freq_mhz is not None:
        if freq_mhz >= 5925:
            return "6GHz"
        if freq_mhz >= 4900:
            return "5GHz"
        if 2400 <= freq_mhz <= 2500:
            return "2.4GHz"
    if not channel_str:
        return None
    lower = channel_str.lower()
    if "6ghz" in lower or "6 ghz" in lower:
        return "6GHz"
    if "5ghz" in lower or "5 ghz" in lower:
        return "5GHz"
    if "2.4ghz" in lower or "2.4 ghz" in lower:
        return "2.4GHz"
    m = re.search(r"\b(\d+)\b", channel_str)
    if m:
        ch = int(m.group(1))
        if 1 <= ch <= 14:
            return "2.4GHz"
        if 32 <= ch <= 177:
            return "5GHz"
    return None


def _merge_wifi_info(base: WiFiInfo, supplement: Optional[WiFiInfo]) -> WiFiInfo:
    """Fill missing fields in `base` using values from `supplement`."""
    if supplement is None:
        return base
    if not base.connected and supplement.connected:
        base.connected = True
    if not base.interface and supplement.interface:
        base.interface = supplement.interface
    if (not base.ssid or "非公開" in base.ssid or "<redacted>" in base.ssid.lower()) and supplement.ssid:
        if "<redacted>" not in supplement.ssid.lower():
            base.ssid = supplement.ssid
        elif not base.ssid:
            base.ssid = supplement.ssid
    for attr in (
        "bssid",
        "rssi_dbm",
        "noise_dbm",
        "snr_db",
        "signal_percent",
        "tx_rate_mbps",
        "channel",
        "phy_mode",
        "mcs_index",
    ):
        if getattr(base, attr) is None and getattr(supplement, attr) is not None:
            setattr(base, attr, getattr(supplement, attr))
    if (not base.band or base.band == "不明") and supplement.band and supplement.band != "不明":
        base.band = supplement.band
    if not base.security_raw and supplement.security_raw:
        base.security_raw = supplement.security_raw
    if supplement.platform_source and supplement.platform_source not in base.platform_source:
        base.platform_source = (
            f"{base.platform_source} + {supplement.platform_source}"
            if base.platform_source
            else supplement.platform_source
        )
    for note in supplement.notes:
        if note not in base.notes:
            base.notes.append(note)
    return base


# ---------------------------------------------------------------------------
# macOS Parsers and Collectors
# ---------------------------------------------------------------------------

def parse_macos_system_profiler_json(raw_json: str) -> Optional[WiFiInfo]:
    """Parse output from `system_profiler SPAirPortDataType -json`."""
    if not raw_json.strip():
        return None
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return None

    entries = data.get("SPAirPortDataType") or []
    for entry in entries:
        interfaces = entry.get("spairport_airport_interfaces") or []
        for iface in interfaces:
            iface_name = iface.get("_name") or "en0"
            status = str(iface.get("spairport_status_information") or "")
            current = iface.get("spairport_current_network_information")
            if not current and "connected" not in status.lower():
                continue
            current = current or {}
            ssid = current.get("_name")
            sec_raw = str(current.get("spairport_security_mode") or "")
            security = _SPAIRPORT_SECURITY_MAP.get(sec_raw, sec_raw.replace("spairport_security_mode_", "").replace("_", " ").strip())

            rssi_dbm: Optional[int] = None
            noise_dbm: Optional[int] = None
            sig_noise = str(current.get("spairport_signal_noise") or "")
            m_sn = re.search(r"(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm", sig_noise)
            if m_sn:
                rssi_dbm = int(m_sn.group(1))
                noise_dbm = int(m_sn.group(2))

            tx_rate: Optional[float] = None
            rate_val = current.get("spairport_network_rate")
            if rate_val is not None:
                m_rate = re.search(r"(\d+(?:\.\d+)?)", str(rate_val))
                if m_rate:
                    tx_rate = float(m_rate.group(1))

            mcs_index: Optional[int] = None
            if current.get("spairport_network_mcs") is not None:
                try:
                    mcs_index = int(current["spairport_network_mcs"])
                except (ValueError, TypeError):
                    pass

            channel = current.get("spairport_network_channel")
            if channel is not None:
                channel = str(channel)

            phy_mode = _normalize_phy_mode(current.get("spairport_network_phymode"))
            bssid = current.get("spairport_network_bssid")

            info = WiFiInfo(
                connected=True,
                interface=iface_name,
                ssid=ssid,
                bssid=bssid,
                rssi_dbm=rssi_dbm,
                noise_dbm=noise_dbm,
                tx_rate_mbps=tx_rate,
                channel=channel,
                band=_infer_band_from_channel(channel),
                phy_mode=phy_mode,
                security_raw=security,
                mcs_index=mcs_index,
                platform_source="macOS system_profiler",
            )
            return info.finalize()
    return None


def parse_macos_ipconfig_summary(raw_text: str, interface: str = "en0") -> Optional[WiFiInfo]:
    """Parse output from `ipconfig getsummary <iface>`."""
    if not raw_text.strip():
        return None
    fields: Dict[str, str] = {}
    for line in raw_text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip()] = v.strip()

    link_active = fields.get("LinkStatusActive", "").upper()
    if link_active == "FALSE":
        return None
    if not fields.get("SSID") and not fields.get("BSSID") and link_active != "TRUE":
        return None

    sec_raw = fields.get("Security", "")
    sec_upper = sec_raw.upper()
    if "WPA3" in sec_upper and "WPA2" in sec_upper:
        security = "WPA2/WPA3 Personal"
    elif "WPA3" in sec_upper or "SAE" in sec_upper:
        security = "WPA3 Personal"
    elif "WPA2" in sec_upper:
        security = "WPA2 Enterprise" if "8021X" in sec_upper or "EAP" in sec_upper else "WPA2 Personal"
    elif "WPA" in sec_upper:
        security = "WPA Personal"
    elif "WEP" in sec_upper:
        security = "WEP"
    elif sec_upper in {"NONE", "OPEN"}:
        security = "Open (None)"
    else:
        security = sec_raw

    return WiFiInfo(
        connected=True,
        interface=fields.get("InterfaceName", interface),
        ssid=fields.get("SSID"),
        bssid=fields.get("BSSID"),
        security_raw=security,
        platform_source="macOS ipconfig",
    ).finalize()


def _collect_macos_corewlan() -> Optional[WiFiInfo]:
    """Query Apple CoreWLAN framework directly via ctypes."""
    try:
        objc = ctypes.cdll.LoadLibrary("/usr/lib/libobjc.A.dylib")
        ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreWLAN.framework/CoreWLAN")
    except OSError:
        return None

    objc.objc_getClass.restype = ctypes.c_void_p
    objc.objc_getClass.argtypes = [ctypes.c_char_p]
    objc.sel_registerName.restype = ctypes.c_void_p
    objc.sel_registerName.argtypes = [ctypes.c_char_p]

    msg_ptr = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(("objc_msgSend", objc))
    msg_long = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)(("objc_msgSend", objc))
    msg_bool = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)(("objc_msgSend", objc))
    if platform.machine() == "x86_64" and hasattr(objc, "objc_msgSend_fpret"):
        msg_double = ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_void_p, ctypes.c_void_p)(("objc_msgSend_fpret", objc))
    else:
        msg_double = ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_void_p, ctypes.c_void_p)(("objc_msgSend", objc))
    msg_cstr = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p)(("objc_msgSend", objc))

    def sel(name: str) -> Any:
        return objc.sel_registerName(name.encode("ascii"))

    def ns_to_str(nsstr: Any) -> Optional[str]:
        if not nsstr:
            return None
        raw = msg_cstr(nsstr, sel("UTF8String"))
        return raw.decode("utf-8", errors="replace") if raw else None

    cls_client = objc.objc_getClass(b"CWWiFiClient")
    if not cls_client:
        return None
    client = msg_ptr(cls_client, sel("sharedWiFiClient"))
    if not client:
        return None
    iface = msg_ptr(client, sel("interface"))
    if not iface:
        return None

    power_on = bool(msg_bool(iface, sel("powerOn")))
    if not power_on:
        return None

    rssi = int(msg_long(iface, sel("rssiValue")))
    noise = int(msg_long(iface, sel("noiseMeasurement")))
    tx_rate = float(msg_double(iface, sel("transmitRate")))
    sec_code = int(msg_long(iface, sel("security")))
    phy_code = int(msg_long(iface, sel("activePHYMode")))

    iface_name = ns_to_str(msg_ptr(iface, sel("interfaceName"))) or "en0"
    ssid = ns_to_str(msg_ptr(iface, sel("ssid")))
    bssid = ns_to_str(msg_ptr(iface, sel("bssid")))

    if rssi == 0 and tx_rate == 0.0 and not ssid and not bssid:
        return None

    channel_str: Optional[str] = None
    band_str: Optional[str] = None
    wlan_ch = msg_ptr(iface, sel("wlanChannel"))
    if wlan_ch:
        ch_num = int(msg_long(wlan_ch, sel("channelNumber")))
        band_code = int(msg_long(wlan_ch, sel("channelBand")))
        width_code = int(msg_long(wlan_ch, sel("channelWidth")))
        band_str = _CW_BAND_MAP.get(band_code)
        width_str = _CW_WIDTH_MAP.get(width_code)
        parts = [p for p in (band_str, width_str) if p]
        channel_str = f"{ch_num} ({', '.join(parts)})" if parts else str(ch_num)

    info = WiFiInfo(
        connected=True,
        interface=iface_name,
        ssid=ssid,
        bssid=bssid,
        rssi_dbm=rssi if rssi < 0 else None,
        noise_dbm=noise if noise < 0 else None,
        tx_rate_mbps=round(tx_rate, 1) if tx_rate > 0 else None,
        channel=channel_str,
        band=band_str,
        phy_mode=_CW_PHY_MODE_MAP.get(phy_code),
        security_raw=_CW_SECURITY_MAP.get(sec_code, f"Unknown ({sec_code})"),
        platform_source="macOS CoreWLAN",
    )
    return info.finalize()


def parse_macos_preferred_wireless_networks(raw_text: str) -> Optional[str]:
    """Extract the most recently connected SSID from `networksetup -listpreferredwirelessnetworks`."""
    if not raw_text:
        return None
    found_header = False
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not found_header:
            if stripped.lower().startswith("preferred networks on"):
                found_header = True
            else:
                return None
            continue
        if "<redacted>" in stripped.lower():
            return None
        return stripped
    return None


def _collect_macos_wifi(fast: bool = False) -> WiFiInfo:
    result = WiFiInfo(connected=False, platform_source="macOS")

    cw_info = _collect_macos_corewlan()
    if cw_info is not None:
        result = _merge_wifi_info(result, cw_info)

    if not (fast and result.connected and result.rssi_dbm is not None):
        rc, sp_out = _run_cmd(["system_profiler", "SPAirPortDataType", "-json"], timeout=10.0)
        if rc == 0 and sp_out:
            sp_info = parse_macos_system_profiler_json(sp_out)
            result = _merge_wifi_info(result, sp_info)

    if not fast or not result.ssid or "非公開" in result.ssid or "<redacted>" in result.ssid.lower():
        candidate_iface = result.interface or "en0"
        rc_ip, ip_out = _run_cmd(["ipconfig", "getsummary", candidate_iface], timeout=4.0)
        if rc_ip == 0 and ip_out:
            ip_info = parse_macos_ipconfig_summary(ip_out, candidate_iface)
            result = _merge_wifi_info(result, ip_info)

    if result.connected and (
        not result.ssid or "非公開" in result.ssid or "<redacted>" in result.ssid.lower()
    ):
        candidate_iface = result.interface or "en0"
        rc_ns, ns_out = _run_cmd(
            ["networksetup", "-listpreferredwirelessnetworks", candidate_iface], timeout=4.0
        )
        if rc_ns == 0 and ns_out:
            pref_ssid = parse_macos_preferred_wireless_networks(ns_out)
            if pref_ssid:
                result.ssid = pref_ssid
                if "networksetup" not in (result.platform_source or ""):
                    if result.platform_source:
                        result.platform_source = f"{result.platform_source} + macOS networksetup"
                    else:
                        result.platform_source = "macOS networksetup"

    if not result.connected:
        result.notes.append(
            "Wi-Fi接続情報が取得できませんでした（Wi-Fiがオフ、有線接続中、またはOS権限・実行環境による制限の可能性があります）。"
        )
    elif result.ssid and "非公開" in result.ssid:
        result.notes.append(
            "macOSのプライバシー仕様によりSSIDが<redacted>として非公開化されています（信号品質・速度・セキュリティ評価には影響しません）。"
        )

    return result.finalize()


# ---------------------------------------------------------------------------
# Windows Parsers and Collectors
# ---------------------------------------------------------------------------

def parse_windows_netsh_interfaces(raw_text: str) -> Optional[WiFiInfo]:
    """Parse `netsh wlan show interfaces` output (English & Japanese Windows)."""
    if not raw_text.strip():
        return None

    kv: Dict[str, str] = {}
    for line in raw_text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        k = key.strip().lower()
        v = val.strip()
        if k and v:
            kv[k] = v

    state = kv.get("state", kv.get("状態", "")).lower()
    if state and not any(w in state for w in ("connected", "接続")):
        if "disconnected" in state or "切断" in state:
            return None

    ssid = kv.get("ssid")
    bssid = kv.get("bssid", kv.get("ap bssid"))
    if not ssid and not bssid and not state:
        return None

    iface = kv.get("name", kv.get("名前", "Wi-Fi"))
    sig_str = kv.get("signal", kv.get("シグナル", ""))
    sig_pct: Optional[int] = None
    m_sig = re.search(r"(\d+)\s*%", sig_str)
    if m_sig:
        sig_pct = int(m_sig.group(1))

    rssi_dbm: Optional[int] = None
    rssi_str = kv.get("rssi", "")
    m_rssi = re.search(r"(-?\d+)", rssi_str)
    if m_rssi:
        rssi_dbm = int(m_rssi.group(1))

    tx_rate: Optional[float] = None
    for rk in ("transmit rate (mbps)", "送信速度 (mbps)", "receive rate (mbps)", "受信速度 (mbps)"):
        if rk in kv:
            m_r = re.search(r"(\d+(?:\.\d+)?)", kv[rk])
            if m_r:
                tx_rate = float(m_r.group(1))
                break

    channel = kv.get("channel", kv.get("チャネル"))
    band = kv.get("band", kv.get("バンド"))
    if not band:
        band = _infer_band_from_channel(channel)
    else:
        band = band.replace(" ", "")

    radio = _normalize_phy_mode(kv.get("radio type", kv.get("無線の種類")))
    auth = kv.get("authentication", kv.get("認証", ""))
    cipher = kv.get("cipher", kv.get("暗号", ""))
    security = f"{auth} ({cipher})".strip() if auth and cipher else (auth or cipher)

    return WiFiInfo(
        connected=True,
        interface=iface,
        ssid=ssid,
        bssid=bssid,
        rssi_dbm=rssi_dbm,
        signal_percent=sig_pct,
        tx_rate_mbps=tx_rate,
        channel=channel,
        band=band,
        phy_mode=radio,
        security_raw=security,
        platform_source="Windows netsh",
    ).finalize()


def _collect_windows_wifi() -> WiFiInfo:
    rc, out = _run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=6.0)
    if rc == 0 and out:
        parsed = parse_windows_netsh_interfaces(out)
        if parsed is not None:
            return parsed
    return WiFiInfo(
        connected=False,
        platform_source="Windows netsh",
        notes=["WindowsのWi-Fi接続が検出されませんでした（Wi-Fi無効または有線接続中）。"],
    ).finalize()


# ---------------------------------------------------------------------------
# Linux Parsers and Collectors
# ---------------------------------------------------------------------------

def parse_linux_nmcli_wifi(raw_text: str) -> Optional[WiFiInfo]:
    """Parse `nmcli -t -f ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY dev wifi`."""
    for line in raw_text.splitlines():
        if not line.strip():
            continue
        # nmcli -t escapes literal ':' inside BSSID as '\:'
        parts = re.split(r"(?<!\\):", line)
        parts = [p.replace("\\:", ":") for p in parts]
        if len(parts) < 8:
            continue
        active = parts[0].strip().lower()
        if active not in {"yes", "true", "*"}:
            continue
        ssid = parts[1].strip() or None
        bssid = parts[2].strip() or None
        chan = parts[3].strip() or None
        freq_str = parts[4].strip()
        rate_str = parts[5].strip()
        sig_str = parts[6].strip()
        security = parts[7].strip()

        freq_mhz: Optional[int] = None
        m_f = re.search(r"(\d+)", freq_str)
        if m_f:
            freq_mhz = int(m_f.group(1))

        tx_rate: Optional[float] = None
        m_r = re.search(r"(\d+(?:\.\d+)?)", rate_str)
        if m_r:
            tx_rate = float(m_r.group(1))

        sig_pct: Optional[int] = None
        m_s = re.search(r"(\d+)", sig_str)
        if m_s:
            sig_pct = int(m_s.group(1))

        band = _infer_band_from_channel(chan, freq_mhz)
        ch_display = f"{chan} ({band})" if chan and band else chan

        return WiFiInfo(
            connected=True,
            ssid=ssid,
            bssid=bssid,
            signal_percent=sig_pct,
            tx_rate_mbps=tx_rate,
            channel=ch_display,
            band=band,
            security_raw=security or "Open (None)",
            platform_source="Linux nmcli",
        ).finalize()
    return None


def parse_linux_proc_wireless(raw_text: str) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    """Parse `/proc/net/wireless` returning (interface, rssi_dbm, noise_dbm)."""
    for line in raw_text.splitlines()[2:]:
        if ":" not in line:
            continue
        iface_part, _, rest = line.partition(":")
        iface = iface_part.strip()
        cols = rest.split()
        if len(cols) >= 4:
            try:
                level = int(float(cols[2].rstrip(".")))
                noise = int(float(cols[3].rstrip(".")))
                rssi = level if level < 0 else None
                noise_dbm = noise if noise < 0 else None
                return iface, rssi, noise_dbm
            except ValueError:
                continue
    return None, None, None


def parse_linux_iw_link(raw_text: str, interface: str = "wlan0") -> Optional[WiFiInfo]:
    """Parse `iw dev <iface> link` output."""
    if not raw_text.strip() or "not connected" in raw_text.lower():
        return None
    bssid_m = re.search(r"Connected to\s+([0-9a-fA-F:]{17})", raw_text)
    ssid_m = re.search(r"SSID:\s*(.+)", raw_text)
    freq_m = re.search(r"freq:\s*(\d+)", raw_text)
    sig_m = re.search(r"signal:\s*(-?\d+)\s*dBm", raw_text)
    tx_m = re.search(r"tx bitrate:\s*(\d+(?:\.\d+)?)\s*MBit/s", raw_text)

    freq_mhz = int(freq_m.group(1)) if freq_m else None
    band = _infer_band_from_channel(None, freq_mhz)

    return WiFiInfo(
        connected=True,
        interface=interface,
        ssid=ssid_m.group(1).strip() if ssid_m else None,
        bssid=bssid_m.group(1).strip() if bssid_m else None,
        rssi_dbm=int(sig_m.group(1)) if sig_m else None,
        tx_rate_mbps=float(tx_m.group(1)) if tx_m else None,
        band=band,
        platform_source="Linux iw",
    ).finalize()


def _collect_linux_wifi() -> WiFiInfo:
    result = WiFiInfo(connected=False, platform_source="Linux")

    rc, nm_out = _run_cmd(
        ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY", "dev", "wifi"],
        timeout=6.0,
    )
    if rc == 0 and nm_out:
        nm_info = parse_linux_nmcli_wifi(nm_out)
        result = _merge_wifi_info(result, nm_info)

    iface_proc: Optional[str] = None
    if os.path.exists("/proc/net/wireless"):
        try:
            with open("/proc/net/wireless", "r", encoding="utf-8", errors="replace") as f:
                iface_proc, rssi_proc, noise_proc = parse_linux_proc_wireless(f.read())
            if iface_proc:
                proc_info = WiFiInfo(
                    connected=rssi_proc is not None,
                    interface=iface_proc,
                    rssi_dbm=rssi_proc,
                    noise_dbm=noise_proc,
                    platform_source="Linux /proc/net/wireless",
                )
                result = _merge_wifi_info(result, proc_info)
        except OSError:
            pass

    target_iface = result.interface or iface_proc or "wlan0"
    rc_iw, iw_out = _run_cmd(["iw", "dev", target_iface, "link"], timeout=4.0)
    if rc_iw == 0 and iw_out:
        iw_info = parse_linux_iw_link(iw_out, target_iface)
        result = _merge_wifi_info(result, iw_info)

    if not result.connected:
        result.notes.append("Linux上でアクティブなWi-Fi接続が見つかりませんでした。")
    return result.finalize()


def collect_wifi_info(fast: bool = False) -> WiFiInfo:
    """Detect current OS and collect connected Wi-Fi signal and security metadata."""
    system = platform.system()
    if system == "Darwin":
        return _collect_macos_wifi(fast=fast)
    if system == "Windows":
        return _collect_windows_wifi()
    if system == "Linux":
        return _collect_linux_wifi()
    return WiFiInfo(
        connected=False,
        platform_source=system,
        notes=[f"未対応のOSプラットフォームです: {system}"],
    ).finalize()
