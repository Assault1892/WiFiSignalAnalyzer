"""Network testers: low-load Ping RTT/packet loss and Cloudflare Speedtest."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import PingSummary, PingTargetResult, SpeedTestResult

DEFAULT_PING_TARGETS: Tuple[str, ...] = ("1.1.1.1", "8.8.8.8", "9.9.9.9", "google.co.jp")
PING_TARGET_LABELS: Dict[str, str] = {
    "1.1.1.1": "Cloudflare DNS (Anycast)",
    "8.8.8.8": "Google Public DNS (Anycast)",
    "9.9.9.9": "Quad9 DNS (Anycast)",
    "google.co.jp": "Google JP (DNS解決+国内Web)",
    "208.67.222.222": "Cisco OpenDNS (Anycast)",
    "cloudflare.com": "Cloudflare Web (DNS解決+CDN)",
}
USER_AGENT = "Mozilla/5.0 WiFiSignalAnalyzer/1.0"


def _compute_jitter(rtts: List[float]) -> Optional[float]:
    """Compute mean consecutive RTT jitter (RFC 3550-style IPDV mean)."""
    if not rtts:
        return None
    if len(rtts) == 1:
        return 0.0
    diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
    return round(sum(diffs) / len(diffs), 2)


def parse_ping_output(target: str, raw_text: str, requested_count: int) -> PingTargetResult:
    """Parse ping CLI output across macOS, Linux, and Windows (EN/JA)."""
    rtts: List[float] = []

    for line in raw_text.splitlines():
        # Match `time=12.3 ms`, `time=12ms`, `時間=12ms`, `time<1ms`, `時間 < 1 ms`
        m_lt = re.search(r"(?:time|時間)\s*<\s*(\d+(?:\.\d+)?)\s*ms", line, re.IGNORECASE)
        if m_lt:
            rtts.append(max(0.5, float(m_lt.group(1)) * 0.5))
            continue
        m_eq = re.search(r"(?:time|時間)\s*=\s*(\d+(?:\.\d+)?)\s*ms", line, re.IGNORECASE)
        if m_eq:
            rtts.append(float(m_eq.group(1)))

    transmitted = requested_count
    received = len(rtts)
    loss_pct: Optional[float] = None

    m_unix = re.search(
        r"(\d+)\s+packets?\s+transmitted,\s+(\d+)\s+(?:packets\s+)?received.*?(\d+(?:\.\d+)?)%\s+packet\s+loss",
        raw_text,
        re.IGNORECASE | re.DOTALL,
    )
    if m_unix:
        transmitted = int(m_unix.group(1))
        received = int(m_unix.group(2))
        loss_pct = float(m_unix.group(3))
    else:
        m_win_en = re.search(
            r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*\d+\s*\((\d+(?:\.\d+)?)%\s*loss\)",
            raw_text,
            re.IGNORECASE,
        )
        m_win_ja = re.search(
            r"送信\s*=\s*(\d+)、\s*受信\s*=\s*(\d+)、\s*損失\s*=\s*\d+\s*\((\d+(?:\.\d+)?)%\s*の損失\)",
            raw_text,
        )
        m_win = m_win_en or m_win_ja
        if m_win:
            transmitted = int(m_win.group(1))
            received = int(m_win.group(2))
            loss_pct = float(m_win.group(3))

    if loss_pct is None:
        m_loss_only = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s+loss|loss|の損失)", raw_text, re.IGNORECASE)
        if m_loss_only:
            loss_pct = float(m_loss_only.group(1))
        elif transmitted > 0:
            loss_pct = round(((transmitted - received) / transmitted) * 100.0, 1)
        else:
            loss_pct = 100.0

    min_ms = round(min(rtts), 2) if rtts else None
    avg_ms = round(sum(rtts) / len(rtts), 2) if rtts else None
    max_ms = round(max(rtts), 2) if rtts else None
    jitter_ms = _compute_jitter(rtts)

    # Also check summary stats if individual lines were missing (e.g. non-standard output)
    if avg_ms is None:
        m_rtt_unix = re.search(
            r"(?:round-trip|rtt)\s+min/avg/max/(?:stddev|mdev)\s*=\s*(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)",
            raw_text,
            re.IGNORECASE,
        )
        if m_rtt_unix:
            min_ms = round(float(m_rtt_unix.group(1)), 2)
            avg_ms = round(float(m_rtt_unix.group(2)), 2)
            max_ms = round(float(m_rtt_unix.group(3)), 2)
            jitter_ms = round(float(m_rtt_unix.group(4)), 2)

    return PingTargetResult(
        target=target,
        transmitted=transmitted,
        received=received,
        packet_loss_pct=round(loss_pct, 1),
        min_ms=min_ms,
        avg_ms=avg_ms,
        max_ms=max_ms,
        jitter_ms=jitter_ms,
        method="ICMP",
        raw_rtts=[round(x, 2) for x in rtts],
        label=PING_TARGET_LABELS.get(target, ""),
    )


def _tcp_ping_fallback(target: str, count: int, interval: float = 0.2) -> PingTargetResult:
    """Measure TCP handshake RTT to port 443 when ICMP is blocked."""
    rtts: List[float] = []
    last_err: Optional[str] = None
    for i in range(count):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((target, 443), timeout=2.0):
                dt_ms = (time.perf_counter() - t0) * 1000.0
                rtts.append(round(dt_ms, 2))
        except OSError as exc:
            last_err = str(exc)
        if i + 1 < count:
            time.sleep(interval)

    received = len(rtts)
    loss_pct = round(((count - received) / count) * 100.0, 1) if count > 0 else 100.0
    return PingTargetResult(
        target=target,
        transmitted=count,
        received=received,
        packet_loss_pct=loss_pct,
        min_ms=round(min(rtts), 2) if rtts else None,
        avg_ms=round(sum(rtts) / len(rtts), 2) if rtts else None,
        max_ms=round(max(rtts), 2) if rtts else None,
        jitter_ms=_compute_jitter(rtts),
        method="TCP-443",
        raw_rtts=rtts,
        label=PING_TARGET_LABELS.get(target, ""),
        error=last_err if received == 0 else None,
    )


def run_ping_target(target: str, count: int = 5, interval: float = 0.25) -> PingTargetResult:
    """Run low-load ping against a single target with TCP-443 fallback."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", str(count), "-w", "1500", target]
    elif system == "Darwin":
        cmd = ["ping", "-c", str(count), "-i", str(interval), "-W", "1500", target]
    else:
        # Linux: -W is in seconds
        cmd = ["ping", "-c", str(count), "-i", str(interval), "-W", "2", target]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=max(10.0, count * 2.5),
            check=False,
        )
        raw = proc.stdout or b""
        if not raw and proc.stderr:
            raw = proc.stderr
        text = raw.decode("utf-8", errors="replace")
        if not text and os.name == "nt":
            text = raw.decode("cp932", errors="replace")
        icmp_res = parse_ping_output(target, text, count)
        if icmp_res.received > 0:
            return icmp_res
    except (OSError, subprocess.TimeoutExpired) as exc:
        icmp_err = str(exc)
    else:
        icmp_err = "ICMP無応答または送信制限"

    # Fallback to TCP-443 if ICMP was blocked or timed out completely
    tcp_res = _tcp_ping_fallback(target, count, interval=min(0.25, interval))
    if tcp_res.received > 0:
        return tcp_res
    if not tcp_res.error:
        tcp_res.error = icmp_err
    return tcp_res


def _aggregate_ping_results(results: List[PingTargetResult]) -> PingSummary:
    """Aggregate per-target ping measurements into a PingSummary."""
    avgs = [r.avg_ms for r in results if r.avg_ms is not None]
    maxs = [r.max_ms for r in results if r.max_ms is not None]
    jitters = [r.jitter_ms for r in results if r.jitter_ms is not None]
    total_tx = sum(r.transmitted for r in results)
    total_rx = sum(r.received for r in results)
    total_loss = round(((total_tx - total_rx) / total_tx) * 100.0, 1) if total_tx > 0 else 100.0

    return PingSummary(
        targets=results,
        avg_rtt_ms=round(sum(avgs) / len(avgs), 2) if avgs else None,
        max_rtt_ms=round(max(maxs), 2) if maxs else None,
        avg_jitter_ms=round(sum(jitters) / len(jitters), 2) if jitters else None,
        total_loss_pct=total_loss,
    )


def _run_concurrent_pings(
    clean_targets: Tuple[str, ...],
    count: int,
    interval: float,
    stagger: float = 0.05,
) -> PingSummary:
    """Execute concurrent pings across targets and aggregate the summary."""
    results: List[Optional[PingTargetResult]] = [None] * len(clean_targets)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(clean_targets))) as pool:
        future_map = {}
        for idx, target in enumerate(clean_targets):
            if idx > 0 and stagger > 0:
                time.sleep(stagger)
            fut = pool.submit(run_ping_target, target, count, interval)
            future_map[fut] = idx

        for fut in concurrent.futures.as_completed(future_map):
            idx = future_map[fut]
            target = clean_targets[idx]
            try:
                results[idx] = fut.result()
            except Exception as exc:
                results[idx] = PingTargetResult(
                    target=target,
                    transmitted=count,
                    received=0,
                    packet_loss_pct=100.0,
                    method="ICMP",
                    label=PING_TARGET_LABELS.get(target, ""),
                    error=str(exc),
                )

    final_results: List[PingTargetResult] = [r for r in results if r is not None]
    return _aggregate_ping_results(final_results)


def run_ping_tests(
    targets: Tuple[str, ...] = DEFAULT_PING_TARGETS,
    mode: str = "light",
    progress_cb: Optional[Callable[[str], None]] = None,
) -> PingSummary:
    """Measure RTT and packet loss concurrently across multiple low-load targets."""
    clean_targets = tuple(t.strip() for t in targets if t and t.strip()) or DEFAULT_PING_TARGETS
    count = 6 if mode == "standard" else 4
    interval = 0.25

    if progress_cb:
        progress_cb(f"Ping測定中 ({len(clean_targets)}箇所へ各{count}回・低負荷): {', '.join(clean_targets)}")

    return _run_concurrent_pings(clean_targets, count=count, interval=interval, stagger=0.05)


def run_realtime_ping_tick(
    targets: Tuple[str, ...] = DEFAULT_PING_TARGETS,
    count_per_target: int = 2,
    interval: float = 0.2,
) -> PingSummary:
    """Run one lightweight concurrent Ping burst across targets for real-time monitoring."""
    clean_targets = tuple(t.strip() for t in targets if t and t.strip()) or DEFAULT_PING_TARGETS
    return _run_concurrent_pings(
        clean_targets,
        count=max(1, count_per_target),
        interval=interval,
        stagger=0.02,
    )


def check_captive_portal(timeout: float = 2.5) -> bool:
    """Check whether an HTTP captive portal intercepts cleartext traffic."""
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(
        "http://captive.apple.com/hotspot-detect.html",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            if resp.status != 200:
                return True
            body = resp.read(2048).decode("utf-8", errors="ignore")
            return "Success" not in body
    except urllib.error.HTTPError as exc:
        # 3xx redirects caught by _NoRedirect raise HTTPError
        if 300 <= exc.code < 400:
            return True
        return False
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    return ctx


def _timed_download(
    url: str,
    ctx: ssl.SSLContext,
    max_duration_sec: float = 5.0,
    timeout: float = 8.0,
) -> Tuple[int, float]:
    """Download from Cloudflare endpoint with wall-clock cap; returns (bytes, seconds)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    t0 = time.perf_counter()
    total_bytes = 0
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total_bytes += len(chunk)
            if (time.perf_counter() - t0) >= max_duration_sec:
                break
    elapsed = max(time.perf_counter() - t0, 0.001)
    return total_bytes, elapsed


def _timed_upload(
    url: str,
    payload_size: int,
    ctx: ssl.SSLContext,
    timeout: float = 8.0,
) -> Tuple[int, float]:
    """Upload payload to Cloudflare endpoint; returns (bytes, seconds)."""
    payload = b"0" * payload_size
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/octet-stream",
            "Content-Length": str(payload_size),
        },
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        resp.read(256)
    elapsed = max(time.perf_counter() - t0, 0.001)
    return payload_size, elapsed


_CF_CLI_RELEASE_BASE = (
    "https://github.com/kavehtehrani/cloudflare-speed-cli/releases/latest/download"
)


def _project_bin_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")


def _cloudflare_cli_asset_name() -> Optional[Tuple[str, str]]:
    """Return (archive_filename, binary_filename) for the current OS and CPU arch."""
    system = platform.system()
    machine = platform.machine().lower()
    is_arm = machine in {"arm64", "aarch64"}
    is_x64 = machine in {"x86_64", "amd64"}

    if system == "Darwin":
        if is_arm:
            return "cloudflare-speed-cli-aarch64-apple-darwin.tar.xz", "cloudflare-speed-cli"
        if is_x64:
            return "cloudflare-speed-cli-x86_64-apple-darwin.tar.xz", "cloudflare-speed-cli"
    elif system == "Linux":
        if is_arm:
            return "cloudflare-speed-cli-aarch64-unknown-linux-musl.tar.xz", "cloudflare-speed-cli"
        if is_x64:
            return "cloudflare-speed-cli-x86_64-unknown-linux-musl.tar.xz", "cloudflare-speed-cli"
    elif system == "Windows" and is_x64:
        return "cloudflare-speed-cli-x86_64-pc-windows-msvc.zip", "cloudflare-speed-cli.exe"
    return None


def find_or_install_cloudflare_speed_cli(
    progress_cb: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """Locate cloudflare-speed-cli binary or download & SHA256-verify it into ./bin/."""
    bin_name = "cloudflare-speed-cli.exe" if os.name == "nt" else "cloudflare-speed-cli"
    local_bin = os.path.join(_project_bin_dir(), bin_name)

    candidates = [
        local_bin,
        shutil.which(bin_name),
        os.path.expanduser(f"~/.local/bin/{bin_name}"),
        os.path.expanduser(f"~/.cargo/bin/{bin_name}"),
        f"/opt/homebrew/bin/{bin_name}",
        f"/usr/local/bin/{bin_name}",
    ]
    for cand in candidates:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand

    asset_info = _cloudflare_cli_asset_name()
    if asset_info is None:
        return None
    archive_name, inner_bin = asset_info

    if progress_cb:
        progress_cb("cloudflare-speed-cli を取得・検証中 (初回のみ)...")

    ctx = _ssl_context()
    archive_url = f"{_CF_CLI_RELEASE_BASE}/{archive_name}"
    sha_url = f"{archive_url}.sha256"

    try:
        sha_req = urllib.request.Request(sha_url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(sha_req, timeout=10.0, context=ctx) as resp:
            sha_text = resp.read(1024).decode("utf-8", errors="replace").strip()
        expected_sha = sha_text.split()[0].lower() if sha_text else ""
        if len(expected_sha) != 64:
            return None

        os.makedirs(_project_bin_dir(), exist_ok=True)
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, archive_name)
            dl_req = urllib.request.Request(archive_url, headers={"User-Agent": USER_AGENT})
            h = hashlib.sha256()
            with urllib.request.urlopen(dl_req, timeout=30.0, context=ctx) as resp, open(
                archive_path, "wb"
            ) as out_f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
                    out_f.write(chunk)

            if h.hexdigest().lower() != expected_sha:
                return None

            tmp_dest = local_bin + ".tmp"
            extracted = False
            if archive_name.endswith(".tar.xz"):
                with tarfile.open(archive_path, "r:xz") as tf:
                    for member in tf.getmembers():
                        if member.isfile() and os.path.basename(member.name) == inner_bin:
                            src_f = tf.extractfile(member)
                            if src_f is not None:
                                with src_f, open(tmp_dest, "wb") as dst_f:
                                    shutil.copyfileobj(src_f, dst_f)
                                extracted = True
                                break
            elif archive_name.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    for name in zf.namelist():
                        if os.path.basename(name) == inner_bin:
                            with zf.open(name, "r") as src_f, open(tmp_dest, "wb") as dst_f:
                                shutil.copyfileobj(src_f, dst_f)
                            extracted = True
                            break

            if not extracted or not os.path.isfile(tmp_dest):
                return None

            os.chmod(tmp_dest, 0o755)
            os.replace(tmp_dest, local_bin)
            return local_bin
    except Exception:
        return None


def _pick_latency_ms(block: Any) -> Optional[float]:
    if not isinstance(block, dict):
        return None
    for key in ("median_ms", "mean_ms", "min_ms"):
        val = block.get(key)
        if isinstance(val, (int, float)):
            return round(float(val), 2)
    return None


def parse_cloudflare_speed_cli_json(raw_json: str) -> Optional[SpeedTestResult]:
    """Parse JSON output produced by `cloudflare-speed-cli --json`."""
    text = (raw_json or "").strip()
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data: Dict[str, Any] = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None

    dl = data.get("download") or {}
    ul = data.get("upload") or {}
    if not isinstance(dl, dict) or not isinstance(ul, dict):
        return None

    down_mbps = dl.get("mbps")
    up_mbps = ul.get("mbps")
    if down_mbps is None and up_mbps is None:
        return None

    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    raw_colo = data.get("colo") or data.get("server") or meta.get("colo")
    colo_str: Optional[str] = None
    if isinstance(raw_colo, dict):
        iata = raw_colo.get("iata") or raw_colo.get("code")
        city = raw_colo.get("city")
        cca2 = raw_colo.get("cca2") or raw_colo.get("country")
        loc = ", ".join(str(x) for x in (city, cca2) if x)
        if iata and loc:
            colo_str = f"{iata} ({loc})"
        elif iata or loc:
            colo_str = str(iata or loc)
    elif raw_colo:
        colo_str = str(raw_colo)

    isp = data.get("as_org") or meta.get("asOrganization")
    client_ip = (
        data.get("ip")
        or data.get("external_ipv4")
        or data.get("external_ipv6")
        or meta.get("clientIp")
    )

    unloaded = _pick_latency_ms(data.get("idle_latency"))
    loaded = _pick_latency_ms(data.get("loaded_latency_download")) or _pick_latency_ms(
        data.get("loaded_latency_upload")
    )

    return SpeedTestResult(
        skipped=False,
        download_mbps=round(float(down_mbps), 2) if isinstance(down_mbps, (int, float)) else None,
        upload_mbps=round(float(up_mbps), 2) if isinstance(up_mbps, (int, float)) else None,
        unloaded_latency_ms=unloaded,
        loaded_latency_ms=loaded,
        colo=colo_str,
        isp=str(isp) if isp else None,
        client_ip=str(client_ip) if client_ip else None,
        bytes_downloaded=int(dl.get("bytes") or 0),
        bytes_uploaded=int(ul.get("bytes") or 0),
        engine="cloudflare-speed-cli",
    )


def _run_python_http_speedtest_fallback(
    mode: str = "light",
    progress_cb: Optional[Callable[[str], None]] = None,
) -> SpeedTestResult:
    """Fallback Python urllib Cloudflare Speedtest when cloudflare-speed-cli is unavailable."""

    ctx = _ssl_context()
    client_ip: Optional[str] = None
    isp: Optional[str] = None
    colo: Optional[str] = None

    # 1. Fetch Cloudflare meta
    if progress_cb:
        progress_cb("Cloudflare Speedtest: サーバー情報を取得中...")
    try:
        meta_req = urllib.request.Request(
            "https://speed.cloudflare.com/meta",
            headers={"User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(meta_req, timeout=4.0, context=ctx) as resp:
            meta = json.loads(resp.read(8192).decode("utf-8", errors="replace"))
            client_ip = meta.get("clientIp")
            isp = meta.get("asOrganization")
            colo = meta.get("colo")
    except Exception:
        # Meta is helpful but non-fatal
        pass

    # 2. Unloaded latency (3 small 0-byte probes)
    unloaded_samples: List[float] = []
    try:
        for _ in range(3):
            t0 = time.perf_counter()
            req = urllib.request.Request(
                "https://speed.cloudflare.com/__down?bytes=0",
                headers={"User-Agent": USER_AGENT},
            )
            with urllib.request.urlopen(req, timeout=4.0, context=ctx) as resp:
                resp.read(64)
            unloaded_samples.append((time.perf_counter() - t0) * 1000.0)
    except Exception as exc:
        return SpeedTestResult(
            skipped=False,
            colo=colo,
            isp=isp,
            client_ip=client_ip,
            error=f"Cloudflare Speedtest接続失敗: {exc}",
        )

    unloaded_ms = round(min(unloaded_samples), 2) if unloaded_samples else None

    # 3. Download throughput (adaptive payload sizes)
    total_down_bytes = 0
    down_speeds: List[float] = []
    try:
        if progress_cb:
            progress_cb("Cloudflare Speedtest: ダウンロード速度を測定中...")
        warmup_size = 200_000 if mode == "standard" else 100_000
        w_bytes, _ = _timed_download(
            f"https://speed.cloudflare.com/__down?bytes={warmup_size}",
            ctx,
            max_duration_sec=3.0,
        )
        total_down_bytes += w_bytes

        first_size = 5_000_000 if mode == "standard" else 2_000_000
        d1_bytes, d1_sec = _timed_download(
            f"https://speed.cloudflare.com/__down?bytes={first_size}",
            ctx,
            max_duration_sec=5.0,
        )
        total_down_bytes += d1_bytes
        if d1_bytes > 0:
            down_speeds.append((d1_bytes * 8.0) / (d1_sec * 1_000_000.0))

        # Run a second larger stage only if the line is fast enough to avoid extra load
        threshold_sec = 0.8 if mode == "standard" else 0.5
        if d1_sec < threshold_sec and d1_bytes >= first_size * 0.9:
            second_size = 15_000_000 if mode == "standard" else 5_000_000
            d2_bytes, d2_sec = _timed_download(
                f"https://speed.cloudflare.com/__down?bytes={second_size}",
                ctx,
                max_duration_sec=5.0,
            )
            total_down_bytes += d2_bytes
            if d2_bytes > 0:
                down_speeds.append((d2_bytes * 8.0) / (d2_sec * 1_000_000.0))
    except Exception as exc:
        return SpeedTestResult(
            skipped=False,
            unloaded_latency_ms=unloaded_ms,
            colo=colo,
            isp=isp,
            client_ip=client_ip,
            bytes_downloaded=total_down_bytes,
            error=f"ダウンロード測定エラー: {exc}",
        )

    download_mbps = round(down_speeds[-1], 2) if down_speeds else None

    # 4. Upload throughput
    total_up_bytes = 0
    up_speeds: List[float] = []
    try:
        if progress_cb:
            progress_cb("Cloudflare Speedtest: アップロード速度を測定中...")
        u1_size = 1_000_000 if mode == "standard" else 500_000
        u1_bytes, u1_sec = _timed_upload("https://speed.cloudflare.com/__up", u1_size, ctx)
        total_up_bytes += u1_bytes
        up_speeds.append((u1_bytes * 8.0) / (u1_sec * 1_000_000.0))

        up_threshold = 0.7 if mode == "standard" else 0.5
        if u1_sec < up_threshold:
            u2_size = 3_000_000 if mode == "standard" else 1_500_000
            u2_bytes, u2_sec = _timed_upload("https://speed.cloudflare.com/__up", u2_size, ctx)
            total_up_bytes += u2_bytes
            up_speeds.append((u2_bytes * 8.0) / (u2_sec * 1_000_000.0))
    except Exception as exc:
        return SpeedTestResult(
            skipped=False,
            download_mbps=download_mbps,
            upload_mbps=round(up_speeds[-1], 2) if up_speeds else None,
            unloaded_latency_ms=unloaded_ms,
            colo=colo,
            isp=isp,
            client_ip=client_ip,
            bytes_downloaded=total_down_bytes,
            bytes_uploaded=total_up_bytes,
            error=f"アップロード測定エラー: {exc}",
        )

    upload_mbps = round(up_speeds[-1], 2) if up_speeds else None

    return SpeedTestResult(
        skipped=False,
        download_mbps=download_mbps,
        upload_mbps=upload_mbps,
        unloaded_latency_ms=unloaded_ms,
        colo=colo,
        isp=isp,
        client_ip=client_ip,
        bytes_downloaded=total_down_bytes,
        bytes_uploaded=total_up_bytes,
        engine="python-urllib-fallback",
    )


def run_cloudflare_speedtest(
    mode: str = "light",
    progress_cb: Optional[Callable[[str], None]] = None,
) -> SpeedTestResult:
    """Run Cloudflare Speedtest via `cloudflare-speed-cli` (with urllib fallback)."""
    if mode == "ping-only":
        return SpeedTestResult(skipped=True)

    cli_path = find_or_install_cloudflare_speed_cli(progress_cb=progress_cb)
    if cli_path:
        if mode == "standard":
            flags = [
                "--json",
                "--auto-save",
                "false",
                "--download-duration",
                "6s",
                "--upload-duration",
                "6s",
                "--idle-latency-duration",
                "2s",
                "--concurrency",
                "6",
                "--udp-packets",
                "20",
            ]
        else:
            flags = [
                "--json",
                "--auto-save",
                "false",
                "--download-duration",
                "3s",
                "--upload-duration",
                "3s",
                "--idle-latency-duration",
                "1s",
                "--concurrency",
                "3",
                "--download-bytes-per-req",
                "2000000",
                "--upload-bytes-per-req",
                "1000000",
                "--udp-packets",
                "10",
                "--skip-diagnostics",
            ]

        if progress_cb:
            progress_cb("cloudflare-speed-cli で速度・遅延を測定中...")
        try:
            proc = subprocess.run(
                [cli_path, *flags],
                capture_output=True,
                timeout=45.0,
                check=False,
            )
            stdout_text = (proc.stdout or b"").decode("utf-8", errors="replace")
            if proc.returncode == 0 and stdout_text.strip():
                parsed = parse_cloudflare_speed_cli_json(stdout_text)
                if parsed is not None:
                    return parsed
        except (OSError, subprocess.TimeoutExpired):
            pass

    if progress_cb:
        progress_cb("内蔵PythonクライアントでCloudflare Speedtestを実行中...")
    return _run_python_http_speedtest_fallback(mode=mode, progress_cb=progress_cb)
