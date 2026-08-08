"""
capture.py - Packet Capture Engine using Scapy
NetPhantom v3.3.1 — Professional Network Packet Sniffer & Analyzer
Author: Lucky | Cybersecurity Project
"""

import os
import threading
import queue
import time
from collections import deque
from scapy.all import sniff, wrpcap, rdpcap, conf

from .analyzer import PacketAnalyzer
from .errors import (
    PrivilegeError, CaptureEngineError, ExportError, ValidationError, logger
)

# ─────────────────────────────────────────────
#  C Libpcap & PyWiFi Integration Helpers
# ─────────────────────────────────────────────
def init_c_libpcap():
    """Directly bind C wpcap.dll / Packet.dll Npcap engine via ctypes."""
    if os.name == 'nt':
        import ctypes
        for dll in ["wpcap.dll", "Packet.dll", r"C:\Windows\System32\Npcap\wpcap.dll"]:
            try:
                return ctypes.cdll.LoadLibrary(dll)
            except Exception:
                pass
    return None

C_WPCAP_LIB = init_c_libpcap()

def scan_wifi_networks() -> list[dict]:
    """Scan and return available wireless networks using PyWiFi."""
    results = []
    try:
        import pywifi
        wifi = pywifi.PyWiFi()
        ifaces = wifi.interfaces()
        if ifaces:
            iface = ifaces[0]
            iface.scan()
            time.sleep(0.5)
            bss = iface.scan_results()
            for b in bss:
                if getattr(b, 'ssid', ''):
                    results.append({
                        "ssid": b.ssid,
                        "bssid": getattr(b, 'bssid', ''),
                        "signal": getattr(b, 'signal', 0),
                    })
    except Exception as e:
        logger.debug(f"PyWiFi scan notice: {e}")
    return results


# ─────────────────────────────────────────────
#  Capture Engine
# ─────────────────────────────────────────────
class CaptureEngine:
    """
    Thread-safe packet capture engine.
    Sniffs packets on a given interface and pushes
    parsed results to a thread-safe Queue for GUI/CLI consumers.
    """

    # Maximum raw packets kept in memory — set very high to avoid data loss
    RAW_PACKET_MAXLEN = 500_000

    def __init__(self, interface: str = None, bpf_filter: str = "",
                 save_path: str = None, error_callback=None):
        self.interface = interface or conf.iface
        self.bpf_filter = bpf_filter.strip()
        self.save_path = save_path
        self.error_callback = error_callback  # Called with error string on failures

        self.analyzer = PacketAnalyzer()
        self.packet_queue: queue.Queue = queue.Queue(maxsize=100_000)

        # Use deque with maxlen to cap memory usage automatically
        self.raw_packets: deque = deque(maxlen=self.RAW_PACKET_MAXLEN)

        self._stop_event = threading.Event()
        self._capture_thread: threading.Thread | None = None
        self._running = False
        self._running_lock = threading.Lock()

        self.start_time: float | None = None
        self.pps_counter = 0            # Packets this second
        self.pps_value = 0              # Exported/read packets/sec
        self._pps_last_ts: float = 0
        self.bps_value = 0              # Bytes per second
        self._bps_counter = 0
        self._pps_history: list = []    # (timestamp, pps) for throughput graph

        # Filter validity flag — set False when BPF causes an error
        self.filter_error: str | None = None

    # ─────────────────────────────────────────
    #  Public API
    # ─────────────────────────────────────────
    def start(self):
        """Start packet capture in a background thread."""
        with self._running_lock:
            if self._running:
                return
            self._stop_event.clear()
            self.filter_error = None
            self.analyzer.reset()
            self.raw_packets.clear()
            self._pps_history.clear()
            # Drain any stale queue items
            while True:
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    break

            self.start_time = time.time()
            self._pps_last_ts = self.start_time
            self._running = True

        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="CaptureThread",
        )
        self._capture_thread.start()

    def stop(self):
        """Signal the capture thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=3.0)
        with self._running_lock:
            self._running = False
        self._capture_thread = None

    def is_running(self) -> bool:
        with self._running_lock:
            return self._running

    def get_stats(self) -> dict:
        """Return current capture stats including packets/sec and bytes/sec."""
        stats = self.analyzer.get_stats()
        now = time.time()
        elapsed = now - self._pps_last_ts
        if elapsed >= 1.0:
            self.pps_value = round(self.pps_counter / elapsed, 1)
            self.bps_value = round(self._bps_counter / elapsed, 1)
            self._pps_history.append((now, self.pps_value))
            if len(self._pps_history) > 120:
                self._pps_history = self._pps_history[-120:]
            self.pps_counter = 0
            self._bps_counter = 0
            self._pps_last_ts = now
        stats["pps"] = self.pps_value
        stats["bps"] = self.bps_value
        stats["pps_history"] = list(self._pps_history)
        if self.start_time:
            stats["elapsed"] = round(time.time() - self.start_time, 1)
        return stats

    # ─────────────────────────────────────────
    #  PCAP Import
    # ─────────────────────────────────────────
    def load_pcap(self, path: str) -> bool:
        """Load packets from a .pcap file and run them through the analyzer."""
        try:
            packets = rdpcap(path)
            self.analyzer.reset()
            self.raw_packets = deque(packets, maxlen=self.RAW_PACKET_MAXLEN)
            self.start_time = time.time()
            self._pps_last_ts = self.start_time

            for pkt in packets:
                try:
                    pkt_info = self.analyzer.parse(pkt)
                    try:
                        self.packet_queue.put_nowait(pkt_info)
                    except queue.Full:
                        pass
                except Exception as inner_e:
                    logger.warning(f"Failed to parse packet frame: {inner_e}")

            return True
        except Exception as e:
            err = CaptureEngineError(f"Failed to load PCAP file: {e}")
            if self.error_callback:
                self.error_callback(err.message)
            return False

    # ─────────────────────────────────────────
    #  Export
    # ─────────────────────────────────────────
    def export_pcap(self, path: str) -> bool:
        """Save captured packets to a .pcap file."""
        with self._running_lock:
            if not self.raw_packets:
                return False
            packets_snapshot = list(self.raw_packets)
        try:
            wrpcap(path, packets_snapshot)
            return True
        except Exception as e:
            err = ExportError(f"PCAP export failed: {e}")
            if self.error_callback:
                self.error_callback(err.message)
            return False

    def export_json(self, path: str) -> bool:
        """Save parsed packet summaries to a JSON file."""
        import json
        try:
            temp_analyzer = PacketAnalyzer()
            data = []
            with self._running_lock:
                packets_snapshot = list(self.raw_packets)
            for raw_pkt in packets_snapshot:
                try:
                    pkt_info = temp_analyzer.parse(raw_pkt)
                    safe = {k: v for k, v in pkt_info.items() if k != "raw_pkt"}
                    data.append(safe)
                except Exception:
                    pass
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            err = ExportError(f"JSON export failed: {e}")
            if self.error_callback:
                self.error_callback(err.message)
            return False

    def export_txt(self, path: str, stored_packets: list) -> bool:
        """Save a plain-text summary of displayed packets."""
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("NetPhantom — Captured Packet Log\n")
                f.write("=" * 70 + "\n\n")
                for pkt in stored_packets:
                    src = pkt.get("src", "?")
                    sport = pkt.get("sport", "")
                    dst = pkt.get("dst", "?")
                    dport = pkt.get("dport", "")
                    src_str = f"{src}:{sport}" if sport else src
                    dst_str = f"{dst}:{dport}" if dport else dst
                    info = (pkt.get("tls_info") or pkt.get("http_info") or
                            pkt.get("behavior", "") or pkt.get("flags", "") or "")
                    f.write(
                        f"[{pkt.get('time', '')}] #{pkt.get('index', '')}  "
                        f"{pkt.get('protocol', '?'):10}  "
                        f"{src_str:30} → {dst_str:30}  "
                        f"{pkt.get('length', 0):5}B  {info}\n"
                    )
            return True
        except Exception as e:
            err = ExportError(f"TXT export failed: {e}")
            if self.error_callback:
                self.error_callback(err.message)
            return False

    # ─────────────────────────────────────────
    #  Internal Loop
    # ─────────────────────────────────────────
    def _capture_loop(self):
        """Run Scapy sniff() in a loop until stop is signalled."""
        bpf = self.bpf_filter if self.bpf_filter else None
        target_iface = resolve_scapy_interface(self.interface)

        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=target_iface,
                    filter=bpf,
                    prn=self._packet_callback,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                    timeout=1,
                )
            except PermissionError:
                err = PrivilegeError("Permission denied. Run as Administrator / root.")
                if self.error_callback:
                    self.error_callback(err.message)
                with self._running_lock:
                    self._running = False
                break
            except OSError as e:
                err = CaptureEngineError(f"Network interface capture error: {e}")
                if self.error_callback:
                    self.error_callback(err.message)
                with self._running_lock:
                    self._running = False
                break
            except Exception as e:
                err_str = str(e).lower()
                if bpf and ("filter" in err_str or "bpf" in err_str or
                            "syntax" in err_str or "invalid" in err_str):
                    val_err = ValidationError(f"BPF filter '{bpf}' is invalid on this interface: {e}")
                    self.filter_error = f"{val_err.message}. Capturing without filter."
                    if self.error_callback:
                        self.error_callback(self.filter_error)
                    bpf = None
                else:
                    err = CaptureEngineError(f"Unexpected capture error: {e}")
                    if self.error_callback:
                        self.error_callback(err.message)
                    with self._running_lock:
                        self._running = False
                    break

    def _packet_callback(self, pkt):
        """Called by Scapy for every captured packet."""
        try:
            self.raw_packets.append(pkt)
            pkt_info = self.analyzer.parse(pkt)
            self.pps_counter += 1
            self._bps_counter += len(pkt)
            # Autosave is intentionally NOT triggered here — writing PCAP from the
            # Scapy callback thread while the deque is mutated is a race condition.
            # Periodic saves should be driven by a timer in the GUI poll loop.
            try:
                self.packet_queue.put_nowait(pkt_info)
            except queue.Full:
                pass  # Drop silently when the GUI consumer is lagging
        except Exception as e:
            logger.debug(f"Packet callback parsing error: {e}")


def resolve_scapy_interface(iface_input):
    """
    Safely resolve a human-readable interface string (e.g. 'Wi-Fi') or GUID
    to a valid Scapy NetworkInterface object or device name string.
    """
    if not iface_input:
        return conf.iface

    try:
        from scapy.all import conf, IFACES
        # 1. Exact match in IFACES (by devname, name, or description)
        for key, iface_obj in IFACES.items():
            if str(key) == str(iface_input):
                return iface_obj
            name = getattr(iface_obj, "name", "")
            desc = getattr(iface_obj, "description", "")
            dev = getattr(iface_obj, "devname", "")
            if iface_input in (name, desc, dev):
                return iface_obj

        # 2. Case-insensitive / substring match
        target_lower = str(iface_input).lower()
        for key, iface_obj in IFACES.items():
            name = getattr(iface_obj, "name", "").lower()
            desc = getattr(iface_obj, "description", "").lower()
            if target_lower in name or target_lower in desc or name in target_lower:
                return iface_obj

        # 3. Scapy dev_from_name
        try:
            return conf.ifaces.dev_from_name(str(iface_input))
        except Exception:
            pass
    except Exception as e:
        logger.warning(f"Interface resolution warning: {e}")

    return iface_input or conf.iface


# ─────────────────────────────────────────────
#  Utility: List available interfaces
# ─────────────────────────────────────────────
def list_interfaces() -> list[str]:
    """Return a list of available network interface names sorted by physical activity priority."""
    try:
        from scapy.all import get_working_ifaces, conf
        raw_ifaces = get_working_ifaces()

        def priority_score(iface_obj):
            name = getattr(iface_obj, "name", "").lower()
            ip = getattr(iface_obj, "ip", "")
            has_ip = 1 if (ip and ip != "127.0.0.1" and ip != "0.0.0.0") else 0

            # Prioritize Wi-Fi and Ethernet with valid IP addresses
            if "wi-fi" in name or "wifi" in name or "wlan" in name:
                return (100 + has_ip * 50)
            if "ethernet" in name or "eth" in name:
                return (90 + has_ip * 50)
            if "local area connection" in name and "*" not in name:
                return (70 + has_ip * 30)
            if "loopback" in name or name == "lo":
                return 1
            # Virtual / Direct adapters like Local Area Connection* 10
            return (10 + has_ip * 20)

        sorted_objs = sorted(raw_ifaces, key=priority_score, reverse=True)
        names = [o.name for o in sorted_objs if getattr(o, "name", None)]

        # Deduplicate while preserving order
        unique_names = list(dict.fromkeys(names))
        return unique_names if unique_names else [str(conf.iface)]
    except Exception as e:
        logger.warning(f"Failed to query working interfaces: {e}")
        return ["Wi-Fi", "Ethernet"]
