"""
analyzer.py - Deep Packet Inspection, Protocol Dissection & Threat Detection
NetPhantom v3.0 — Professional Network Packet Sniffer & Analyzer
Author: Lucky | Cybersecurity Project
"""

import time
import ipaddress
from datetime import datetime
from collections import defaultdict
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, Ether

# ─────────────────────────────────────────────
#  Optional Layer Loading
# ─────────────────────────────────────────────
try:
    from scapy.all import load_layer
    load_layer("tls")
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLS_Ext_ServerName
    HAS_TLS = True
except Exception:
    HAS_TLS = False

try:
    from scapy.all import load_layer
    load_layer("http")
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HAS_HTTP = True
except Exception:
    HAS_HTTP = False


# ─────────────────────────────────────────────
#  Color Rules for Packet Row Background
# ─────────────────────────────────────────────
# Returns a color category string used by the GUI to set row bg color
PACKET_COLOR_RULES = {
    "tcp_syn":     "#1a2744",   # TCP SYN — dark blue highlight
    "tcp_synack":  "#1a3340",   # TCP SYN-ACK
    "tcp_fin":     "#2a1a1a",   # TCP FIN/RST — dark red tint
    "tcp_rst":     "#3a1a1a",   # TCP RST — stronger red
    "tcp":         "#0f1e2e",   # Regular TCP — subtle blue
    "udp":         "#0f2318",   # UDP — subtle green
    "dns":         "#1a2a1f",   # DNS — teal tint
    "http":        "#1f2a15",   # HTTP — warm green
    "https":       "#151a2f",   # HTTPS/TLS — deep blue
    "tls":         "#151a2f",   # TLS
    "icmp":        "#2a2510",   # ICMP — amber tint
    "arp":         "#1a1530",   # ARP — purple tint
    "quic":        "#101a2f",   # QUIC — cyan tint
    "ipv6":        "#15151f",   # IPv6
    "alert":       "#3a0f0f",   # Threat/alert — red highlight
    "other":       "#111827",   # Default
}


def get_packet_color_rule(info: dict) -> str:
    """Determine the color rule for a packet based on protocol and flags."""
    proto = info.get("protocol", "").upper()
    flags = info.get("flags", "")

    if info.get("_threat"):
        return "alert"

    if "TLS" in proto:
        return "tls"
    if proto == "QUIC":
        return "quic"
    if proto in ("HTTPS",):
        return "https"
    if proto == "HTTP":
        return "http"
    if proto == "DNS":
        return "dns"
    if proto == "ARP":
        return "arp"
    if proto == "ICMP":
        return "icmp"
    if proto == "IPV6":
        return "ipv6"
    if proto == "UDP":
        return "udp"

    # TCP flag-based colors
    if proto == "TCP" and flags:
        if "R" in flags:
            return "tcp_rst"
        if "F" in flags:
            return "tcp_fin"
        if "S" in flags and "A" in flags:
            return "tcp_synack"
        if "S" in flags:
            return "tcp_syn"
        return "tcp"

    if proto == "TCP":
        return "tcp"

    return "other"


# ─────────────────────────────────────────────
#  Helper: IP Classification
# ─────────────────────────────────────────────
def categorize_ip(ip_str: str) -> str:
    """Classify an IP address as Local, Broadcast, Multicast, or External."""
    if not ip_str or ip_str == "N/A":
        return "Unknown"
    if ip_str in ("255.255.255.255", "ff:ff:ff:ff:ff:ff"):
        return "Broadcast"
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_multicast:   return "Multicast"
        if ip.is_loopback:    return "Loopback"
        if ip.is_private:     return "Local"
        return "External"
    except ValueError:
        return "Unknown"


# ─────────────────────────────────────────────
#  Stream Key Helper
# ─────────────────────────────────────────────
def make_stream_key(info: dict) -> str:
    """Return a canonical bi-directional flow key."""
    src = f"{info['src']}:{info.get('sport') or 0}"
    dst = f"{info['dst']}:{info.get('dport') or 0}"
    # Ensure same key regardless of direction
    return " ↔ ".join(sorted([src, dst]))


# ─────────────────────────────────────────────
#  Protocol Dissection Tree Builder
# ─────────────────────────────────────────────
def build_protocol_tree(pkt) -> list:
    """
    Build a Wireshark-style protocol dissection tree from a Scapy packet.
    Returns a list of dicts:
      [{"layer": "Ethernet II", "fields": [("Src MAC", "aa:bb:..."), ...]}, ...]
    """
    tree = []

    # Frame info
    frame_fields = [
        ("Frame Length", f"{len(pkt)} bytes"),
        ("Capture Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
    ]
    tree.append({"layer": f"Frame ({len(pkt)} bytes on wire)", "fields": frame_fields})

    # Ethernet
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        eth_fields = [
            ("Destination", eth.dst),
            ("Source", eth.src),
            ("Type", f"0x{eth.type:04x}" if eth.type else "N/A"),
        ]
        tree.append({"layer": "Ethernet II", "fields": eth_fields})

    # IPv4
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        ip_fields = [
            ("Version", "4"),
            ("Header Length", f"{ip_layer.ihl * 4} bytes"),
            ("Total Length", str(ip_layer.len)),
            ("Identification", f"0x{ip_layer.id:04x} ({ip_layer.id})"),
            ("Flags", str(ip_layer.flags)),
            ("Fragment Offset", str(ip_layer.frag)),
            ("TTL", str(ip_layer.ttl)),
            ("Protocol", str(ip_layer.proto)),
            ("Header Checksum", f"0x{ip_layer.chksum:04x}" if ip_layer.chksum else "N/A"),
            ("Source Address", ip_layer.src),
            ("Destination Address", ip_layer.dst),
        ]
        tree.append({"layer": f"Internet Protocol Version 4, Src: {ip_layer.src}, Dst: {ip_layer.dst}", "fields": ip_fields})

    # IPv6
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        ip6_fields = [
            ("Version", "6"),
            ("Traffic Class", str(ip6.tc)),
            ("Flow Label", f"0x{ip6.fl:05x}"),
            ("Payload Length", str(ip6.plen)),
            ("Next Header", str(ip6.nh)),
            ("Hop Limit", str(ip6.hlim)),
            ("Source Address", ip6.src),
            ("Destination Address", ip6.dst),
        ]
        tree.append({"layer": f"Internet Protocol Version 6, Src: {ip6.src}, Dst: {ip6.dst}", "fields": ip6_fields})

    # ARP
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op_str = "Request" if arp.op == 1 else "Reply" if arp.op == 2 else str(arp.op)
        arp_fields = [
            ("Hardware Type", str(arp.hwtype)),
            ("Protocol Type", f"0x{arp.ptype:04x}"),
            ("Operation", f"{op_str} ({arp.op})"),
            ("Sender MAC", arp.hwsrc),
            ("Sender IP", arp.psrc),
            ("Target MAC", arp.hwdst),
            ("Target IP", arp.pdst),
        ]
        tree.append({"layer": f"Address Resolution Protocol ({op_str})", "fields": arp_fields})

    # TCP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags_str = str(tcp.flags)
        tcp_fields = [
            ("Source Port", str(tcp.sport)),
            ("Destination Port", str(tcp.dport)),
            ("Sequence Number", str(tcp.seq)),
            ("Acknowledgment Number", str(tcp.ack)),
            ("Header Length", f"{tcp.dataofs * 4} bytes"),
            ("Flags", f"0x{int(tcp.flags):03x} ({flags_str})"),
            ("Window Size", str(tcp.window)),
            ("Checksum", f"0x{tcp.chksum:04x}" if tcp.chksum else "N/A"),
            ("Urgent Pointer", str(tcp.urgptr)),
        ]
        # TCP Options
        if tcp.options:
            for opt_name, opt_val in tcp.options:
                tcp_fields.append((f"Option: {opt_name}", str(opt_val)))
        tree.append({"layer": f"Transmission Control Protocol, Src Port: {tcp.sport}, Dst Port: {tcp.dport}, [{flags_str}]", "fields": tcp_fields})

    # UDP
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        udp_fields = [
            ("Source Port", str(udp.sport)),
            ("Destination Port", str(udp.dport)),
            ("Length", str(udp.len)),
            ("Checksum", f"0x{udp.chksum:04x}" if udp.chksum else "N/A"),
        ]
        tree.append({"layer": f"User Datagram Protocol, Src Port: {udp.sport}, Dst Port: {udp.dport}", "fields": udp_fields})

    # ICMP
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        type_names = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request",
                      11: "Time Exceeded", 5: "Redirect"}
        type_str = type_names.get(icmp.type, f"Type {icmp.type}")
        icmp_fields = [
            ("Type", f"{icmp.type} ({type_str})"),
            ("Code", str(icmp.code)),
            ("Checksum", f"0x{icmp.chksum:04x}" if icmp.chksum else "N/A"),
            ("Identifier", str(icmp.id) if hasattr(icmp, 'id') else "N/A"),
            ("Sequence", str(icmp.seq) if hasattr(icmp, 'seq') else "N/A"),
        ]
        tree.append({"layer": f"Internet Control Message Protocol ({type_str})", "fields": icmp_fields})

    # DNS
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        qr_str = "Response" if dns.qr else "Query"
        dns_fields = [
            ("Transaction ID", f"0x{dns.id:04x}"),
            ("Type", qr_str),
            ("Questions", str(dns.qdcount)),
            ("Answer RRs", str(dns.ancount)),
            ("Authority RRs", str(dns.nscount)),
            ("Additional RRs", str(dns.arcount)),
        ]
        # Query section
        if dns.qd and pkt.haslayer(DNSQR):
            try:
                qname = dns.qd.qname.decode("utf-8", "ignore")
                qtype_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT",
                             28: "AAAA", 33: "SRV", 255: "ANY"}
                qtype = qtype_map.get(dns.qd.qtype, str(dns.qd.qtype))
                dns_fields.append(("Query Name", qname))
                dns_fields.append(("Query Type", qtype))
            except Exception:
                pass
        # Answer section
        if dns.an and pkt.haslayer(DNSRR):
            try:
                for i in range(dns.ancount):
                    rr = dns.an[i] if hasattr(dns.an, '__getitem__') else dns.an
                    rname = rr.rrname.decode("utf-8", "ignore") if hasattr(rr.rrname, 'decode') else str(rr.rrname)
                    rdata = str(rr.rdata.decode("utf-8", "ignore") if hasattr(rr.rdata, 'decode') else rr.rdata)
                    dns_fields.append((f"Answer {i+1}", f"{rname} → {rdata}"))
                    if i >= 4:
                        break
            except Exception:
                pass
        tree.append({"layer": f"Domain Name System ({qr_str})", "fields": dns_fields})

    # HTTP
    if HAS_HTTP and pkt.haslayer(HTTPRequest):
        req = pkt[HTTPRequest]
        http_fields = []
        for field_name in ["Method", "Host", "Path", "Http_Version", "User_Agent", "Accept", "Content_Type"]:
            val = getattr(req, field_name, None)
            if val:
                val_str = val.decode("utf-8", "ignore") if isinstance(val, bytes) else str(val)
                http_fields.append((field_name.replace("_", " "), val_str))
        tree.append({"layer": "Hypertext Transfer Protocol (Request)", "fields": http_fields})

    elif HAS_HTTP and pkt.haslayer(HTTPResponse):
        resp = pkt[HTTPResponse]
        http_fields = []
        for field_name in ["Http_Version", "Status_Code", "Reason_Phrase", "Content_Type", "Server"]:
            val = getattr(resp, field_name, None)
            if val:
                val_str = val.decode("utf-8", "ignore") if isinstance(val, bytes) else str(val)
                http_fields.append((field_name.replace("_", " "), val_str))
        tree.append({"layer": "Hypertext Transfer Protocol (Response)", "fields": http_fields})

    # TLS
    if HAS_TLS and pkt.haslayer(TLS):
        tls_fields = []
        if pkt.haslayer(TLSClientHello):
            ch = pkt[TLSClientHello]
            tls_fields.append(("Handshake Type", "Client Hello"))
            if hasattr(ch, "version"):
                ver_map = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
                tls_fields.append(("Version", ver_map.get(ch.version, f"0x{ch.version:04x}")))
            # SNI
            if ch.ext:
                for ext in ch.ext:
                    if isinstance(ext, TLS_Ext_ServerName) and ext.servernames:
                        sni = ext.servernames[0].servername.decode("utf-8", "ignore")
                        tls_fields.append(("Server Name (SNI)", sni))
            tree.append({"layer": "Transport Layer Security (Client Hello)", "fields": tls_fields})
        elif pkt.haslayer(TLSServerHello):
            tls_fields.append(("Handshake Type", "Server Hello"))
            tree.append({"layer": "Transport Layer Security (Server Hello)", "fields": tls_fields})
        else:
            tls_fields.append(("Record", "Encrypted Application Data"))
            tree.append({"layer": "Transport Layer Security", "fields": tls_fields})

    # Raw Payload
    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        payload_fields = [
            ("Length", f"{len(raw)} bytes"),
        ]
        tree.append({"layer": f"Data ({len(raw)} bytes)", "fields": payload_fields})

    return tree


# ─────────────────────────────────────────────
#  Hex Dump Formatter
# ─────────────────────────────────────────────
def format_hex_dump(pkt) -> str:
    """Format packet bytes as a Wireshark-style hex dump with offset, hex, and ASCII columns."""
    raw_bytes = bytes(pkt)
    lines = []
    for offset in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Add spacing between groups of 8
        if len(chunk) > 8:
            hex_part = hex_part[:23] + "  " + hex_part[24:]
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04x}   {hex_part:<50s}  {ascii_part}")
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  Core Packet Analyzer
# ─────────────────────────────────────────────
class PacketAnalyzer:
    """Parses raw Scapy packets into structured dicts with DPI and stream tracking."""

    # Threat detection thresholds
    PORT_SCAN_THRESHOLD   = 15    # unique dst ports from one IP
    DOS_PPS_THRESHOLD     = 100   # packets/sec from one IP
    ICMP_FLOOD_THRESHOLD  = 50    # ICMP packets/sec from one IP
    DNS_FLOOD_THRESHOLD   = 30    # DNS queries/sec from one IP
    SYN_FLOOD_THRESHOLD   = 50    # SYN packets/sec from one IP

    def __init__(self):
        self.packet_count   = 0
        self.total_bytes    = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats       = defaultdict(int)
        # Stream tracking: key → {packets, bytes, proto, last_seen, first_seen}
        self.streams: dict[str, dict] = {}
        # Endpoint tracking: ip → {tx_pkts, rx_pkts, tx_bytes, rx_bytes}
        self.endpoints: dict[str, dict] = {}
        # Threat detection state
        self._threat_state = {
            "port_targets": defaultdict(set),        # src_ip → set of dst_ports
            "pps_counter": defaultdict(int),          # src_ip → packet count this window
            "icmp_counter": defaultdict(int),          # src_ip → icmp count this window
            "dns_counter": defaultdict(int),           # src_ip → dns count this window
            "syn_counter": defaultdict(int),           # src_ip → syn count this window
            "arp_table": {},                           # ip → mac (for ARP spoof detection)
            "window_start": time.time(),
        }
        self.alerts: list[dict] = []

    def parse(self, pkt) -> dict:
        self.packet_count += 1
        self.total_bytes += len(pkt)
        now = time.time()
        ts  = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        info = {
            "index":        self.packet_count,
            "time":         ts,
            "timestamp":    now,
            "src":          "N/A",
            "dst":          "N/A",
            "protocol":     "OTHER",
            "length":       len(pkt),
            "sport":        None,
            "dport":        None,
            "flags":        None,
            "ttl":          None,
            "payload_ascii":"",
            "payload_hex":  "",
            "summary":      pkt.summary(),
            "raw_pkt":      pkt,
            "classification":"Unknown",
            "is_encrypted": False,
            "tls_info":     None,
            "http_info":    None,
            "behavior":     "",
            "_threat":      None,
            "color_rule":   "other",
        }

        # ── L2 Ethernet ────────────────────────
        if pkt.haslayer(Ether):
            info["eth_src"] = pkt[Ether].src
            info["eth_dst"] = pkt[Ether].dst

        # ── L3 IP / IPv6 ───────────────────────
        if pkt.haslayer(IP):
            info["src"] = pkt[IP].src
            info["dst"] = pkt[IP].dst
            info["ttl"] = pkt[IP].ttl
            self.ip_stats[info["src"]] += 1

        elif pkt.haslayer(IPv6):
            info["src"]      = pkt[IPv6].src
            info["dst"]      = pkt[IPv6].dst
            info["protocol"] = "IPv6"

        # ── Boundary Classification ─────────────
        src_cat = categorize_ip(info["src"])
        dst_cat = categorize_ip(info["dst"])
        if dst_cat == "Broadcast":
            info["classification"] = f"{src_cat} → Broadcast"
        elif dst_cat == "Multicast":
            info["classification"] = f"{src_cat} → Multicast"
        else:
            info["classification"] = f"{src_cat} ↔ {dst_cat}"

        # ── L3 ARP ─────────────────────────────
        if pkt.haslayer(ARP):
            info["src"]      = pkt[ARP].psrc
            info["dst"]      = pkt[ARP].pdst
            info["protocol"] = "ARP"

        # ── L4 Transport ───────────────────────
        if pkt.haslayer(TCP):
            info["protocol"] = "TCP"
            info["sport"]    = pkt[TCP].sport
            info["dport"]    = pkt[TCP].dport
            info["flags"]    = str(pkt[TCP].flags)

        elif pkt.haslayer(UDP):
            info["protocol"] = "UDP"
            info["sport"]    = pkt[UDP].sport
            info["dport"]    = pkt[UDP].dport

        elif pkt.haslayer(ICMP):
            info["protocol"] = "ICMP"

        # ── DPI: Application Layer ──────────────
        app_proto = None

        if pkt.haslayer(DNS):
            app_proto = "DNS"
            try:
                qn = pkt[DNS].qd.qname.decode("utf-8", "ignore")
                info["tls_info"] = f"Query: {qn}"
            except Exception:
                pass

        elif info["protocol"] == "UDP" and (info["sport"] == 443 or info["dport"] == 443):
            app_proto = "QUIC"
            info["is_encrypted"] = True

        elif HAS_HTTP and (pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse)):
            app_proto = "HTTP"
            if pkt.haslayer(HTTPRequest):
                method = pkt[HTTPRequest].Method.decode("utf-8", "ignore") if pkt[HTTPRequest].Method else ""
                host   = pkt[HTTPRequest].Host.decode("utf-8", "ignore")   if pkt[HTTPRequest].Host   else ""
                path   = pkt[HTTPRequest].Path.decode("utf-8", "ignore")   if pkt[HTTPRequest].Path   else ""
                info["http_info"] = f"{method} {host}{path}"

        elif info["protocol"] == "TCP" and (info["sport"] in (80, 8080) or info["dport"] in (80, 8080)):
            app_proto = "HTTP"

        elif HAS_TLS and pkt.haslayer(TLS):
            app_proto            = "TLS"
            info["is_encrypted"] = True
            if pkt.haslayer(TLSClientHello):
                info["protocol"] = "TLS ClientHello"
                sni = "Unknown Domain"; version = "TLS"
                ch  = pkt[TLSClientHello]
                if hasattr(ch, "version"):
                    if ch.version == 0x0303: version = "TLS 1.2"
                    elif ch.version == 0x0304: version = "TLS 1.3"
                if ch.ext:
                    for ext in ch.ext:
                        if isinstance(ext, TLS_Ext_ServerName) and ext.servernames:
                            sni = ext.servernames[0].servername.decode("utf-8", "ignore")
                info["tls_info"] = f"SNI: {sni} | {version}"
            elif pkt.haslayer(TLSServerHello):
                info["protocol"] = "TLS ServerHello"
                info["tls_info"] = "Handshake Reply"

        elif info["protocol"] == "TCP" and (info["sport"] == 443 or info["dport"] == 443):
            app_proto            = "HTTPS"
            info["is_encrypted"] = True

        if app_proto and info["protocol"] not in ("TLS ClientHello", "TLS ServerHello"):
            info["protocol"] = app_proto

        # ── Payload ─────────────────────────────
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            info["payload_ascii"] = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)[:300]
            info["payload_hex"]   = " ".join(f"{b:02x}" for b in raw)[:500]

        # ── Behavior Tagging ────────────────────
        info["behavior"] = self._determine_behavior(info)

        # ── Protocol Stats ──────────────────────
        self.protocol_stats[info["protocol"].split()[0]] += 1

        # ── Endpoint Tracking ───────────────────
        self._track_endpoint(info)

        # ── Stream Tracking ─────────────────────
        if info["src"] != "N/A":
            key = make_stream_key(info)
            if key not in self.streams:
                self.streams[key] = {
                    "proto":      info["protocol"].split()[0],
                    "packets":    0,
                    "bytes":      0,
                    "key":        key,
                    "first_seen": ts,
                }
            s = self.streams[key]
            s["packets"]   += 1
            s["bytes"]     += info["length"]
            s["last_seen"]  = ts

        # ── Threat Detection ────────────────────
        threat = self._detect_threats(info, now)
        if threat:
            info["_threat"] = threat
            alert_entry = {
                "time": ts,
                "type": threat,
                "src":  info["src"],
                "dst":  info["dst"],
                "proto": info["protocol"],
                "pkt_index": info["index"],
            }
            self.alerts.append(alert_entry)

        # ── Color Rule ──────────────────────────
        info["color_rule"] = get_packet_color_rule(info)

        return info

    # ── Endpoint Tracking ─────────────────────
    def _track_endpoint(self, info: dict):
        """Track per-endpoint tx/rx packet and byte counts."""
        src = info["src"]
        dst = info["dst"]
        length = info["length"]

        if src != "N/A":
            if src not in self.endpoints:
                self.endpoints[src] = {"tx_pkts": 0, "rx_pkts": 0, "tx_bytes": 0, "rx_bytes": 0}
            self.endpoints[src]["tx_pkts"] += 1
            self.endpoints[src]["tx_bytes"] += length

        if dst != "N/A":
            if dst not in self.endpoints:
                self.endpoints[dst] = {"tx_pkts": 0, "rx_pkts": 0, "tx_bytes": 0, "rx_bytes": 0}
            self.endpoints[dst]["rx_pkts"] += 1
            self.endpoints[dst]["rx_bytes"] += length

    # ── Threat Detection ──────────────────────
    def _detect_threats(self, info: dict, now: float) -> str | None:
        """Enhanced threat detection with multiple attack vectors."""
        state = self._threat_state
        src = info["src"]
        if src == "N/A":
            return None

        # Reset window every second
        if now - state["window_start"] >= 1.0:
            state["pps_counter"].clear()
            state["icmp_counter"].clear()
            state["dns_counter"].clear()
            state["syn_counter"].clear()
            state["window_start"] = now

        # Count packets per source
        state["pps_counter"][src] += 1

        # Port scan detection
        dport = info.get("dport")
        if dport and info["protocol"] in ("TCP", "UDP"):
            state["port_targets"][src].add(dport)
            if len(state["port_targets"][src]) > self.PORT_SCAN_THRESHOLD:
                return f"⚠ PORT SCAN from {src} ({len(state['port_targets'][src])} ports)"

        # SYN flood detection
        flags = info.get("flags", "")
        if info["protocol"] == "TCP" and "S" in flags and "A" not in flags:
            state["syn_counter"][src] += 1
            if state["syn_counter"][src] > self.SYN_FLOOD_THRESHOLD:
                return f"⚠ SYN FLOOD from {src} ({state['syn_counter'][src]} SYNs/sec)"

        # DoS detection (high PPS)
        if state["pps_counter"][src] > self.DOS_PPS_THRESHOLD:
            return f"⚠ HIGH TRAFFIC from {src} ({state['pps_counter'][src]} pkt/sec)"

        # ICMP flood
        if info["protocol"] == "ICMP":
            state["icmp_counter"][src] += 1
            if state["icmp_counter"][src] > self.ICMP_FLOOD_THRESHOLD:
                return f"⚠ ICMP FLOOD from {src} ({state['icmp_counter'][src]}/sec)"

        # DNS flood
        if info["protocol"] == "DNS":
            state["dns_counter"][src] += 1
            if state["dns_counter"][src] > self.DNS_FLOOD_THRESHOLD:
                return f"⚠ DNS FLOOD from {src} ({state['dns_counter'][src]}/sec)"

        # ARP spoofing detection
        if info["protocol"] == "ARP":
            arp_ip = info["src"]
            arp_mac = info.get("eth_src", "")
            if arp_ip in state["arp_table"]:
                if state["arp_table"][arp_ip] != arp_mac and arp_mac:
                    return f"⚠ ARP SPOOF: {arp_ip} changed MAC {state['arp_table'][arp_ip]} → {arp_mac}"
            if arp_mac:
                state["arp_table"][arp_ip] = arp_mac

        return None

    # ── Behavior Tagger ────────────────────────
    def _determine_behavior(self, info: dict) -> str:
        proto  = info.get("protocol", "")
        sport  = info.get("sport")
        dport  = info.get("dport")
        payload = info.get("payload_ascii", "").lower()

        browser = ""
        if "brave"   in payload: browser = " (Brave)"
        elif "chrome" in payload: browser = " (Chrome)"
        elif "firefox" in payload: browser = " (Firefox)"
        elif "safari"  in payload: browser = " (Safari)"
        elif "edge"    in payload: browser = " (Edge)"

        if any(x in proto for x in ("HTTP", "TLS", "QUIC")) or sport in (80, 443) or dport in (80, 443):
            return f"Web Browsing{browser}"
        if proto == "DNS" or sport == 53 or dport == 53:
            return "DNS Resolution"
        if sport in (1900, 5353, 5355) or dport in (1900, 5353, 5355):
            return "Local Discovery"
        if proto == "ICMP":
            return "Network Ping"
        if sport == 22 or dport == 22:
            return "SSH Remote Shell"
        if sport in (20, 21) or dport in (20, 21):
            return "File Transfer (FTP)"
        if sport == 3389 or dport == 3389:
            return "Remote Desktop"
        if proto == "ARP":
            return "ARP Resolution"
        if sport == 25 or dport == 25 or sport == 587 or dport == 587:
            return "Email (SMTP)"
        if sport == 143 or dport == 143 or sport == 993 or dport == 993:
            return "Email (IMAP)"
        if sport == 110 or dport == 110 or sport == 995 or dport == 995:
            return "Email (POP3)"
        if sport == 3306 or dport == 3306:
            return "Database (MySQL)"
        if sport == 5432 or dport == 5432:
            return "Database (PostgreSQL)"
        if sport == 6379 or dport == 6379:
            return "Cache (Redis)"
        if sport == 27017 or dport == 27017:
            return "Database (MongoDB)"
        return f"Network Traffic ({proto})"

    def get_stats(self) -> dict:
        return {
            "total":      self.packet_count,
            "total_bytes": self.total_bytes,
            "protocols":  dict(self.protocol_stats),
            "top_ips":    sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10],
            "streams":    sorted(self.streams.values(), key=lambda s: s["bytes"], reverse=True)[:50],
            "endpoints":  self._get_top_endpoints(20),
            "alerts":     len(self.alerts),
        }

    def _get_top_endpoints(self, n: int = 20) -> list:
        """Return top endpoints by total traffic."""
        result = []
        for ip, data in self.endpoints.items():
            total = data["tx_bytes"] + data["rx_bytes"]
            result.append({
                "ip": ip,
                "tx_pkts": data["tx_pkts"],
                "rx_pkts": data["rx_pkts"],
                "tx_bytes": data["tx_bytes"],
                "rx_bytes": data["rx_bytes"],
                "total_bytes": total,
            })
        result.sort(key=lambda x: x["total_bytes"], reverse=True)
        return result[:n]

    def get_top_streams(self, n: int = 40) -> list:
        return sorted(self.streams.values(), key=lambda s: s["bytes"], reverse=True)[:n]

    def get_alerts(self, n: int = 100) -> list:
        """Return the most recent alerts."""
        return self.alerts[-n:]

    def reset(self):
        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_stats.clear()
        self.ip_stats.clear()
        self.streams.clear()
        self.endpoints.clear()
        self.alerts.clear()
        self._threat_state = {
            "port_targets": defaultdict(set),
            "pps_counter": defaultdict(int),
            "icmp_counter": defaultdict(int),
            "dns_counter": defaultdict(int),
            "syn_counter": defaultdict(int),
            "arp_table": {},
            "window_start": time.time(),
        }


# ─────────────────────────────────────────────
#  Packet Detail Formatter (legacy text format)
# ─────────────────────────────────────────────
def format_packet_details(pkt_info: dict) -> str:
    """Return a clean multi-line detailed packet report."""
    lines = [
        "╔═════════════════════════════════════════════════════════════╗",
        f"  PACKET #{pkt_info['index']}  ·  {pkt_info['time']}",
        "╚═════════════════════════════════════════════════════════════╝",
        "",
        f"  BEHAVIOR   : {pkt_info.get('behavior', 'Unknown')}",
        f"  PROTOCOL   : {pkt_info['protocol']}",
        f"  SRC        : {pkt_info['src']}" + (f":{pkt_info['sport']}" if pkt_info.get("sport") else ""),
        f"  DST        : {pkt_info['dst']}" + (f":{pkt_info['dport']}" if pkt_info.get("dport") else ""),
        f"  LENGTH     : {pkt_info['length']} bytes",
        f"  BOUNDARY   : {pkt_info['classification']}",
        f"  ENCRYPTED  : {'YES ✓' if pkt_info['is_encrypted'] else 'NO'}",
    ]

    if pkt_info.get("ttl") is not None:
        lines.append(f"  TTL        : {pkt_info['ttl']}")
    if pkt_info.get("flags") and pkt_info["flags"] != "None":
        lines.append(f"  TCP FLAGS  : {pkt_info['flags']}")
    if pkt_info.get("tls_info"):
        lines.append(f"  TLS INFO   : {pkt_info['tls_info']}")
    if pkt_info.get("http_info"):
        lines.append(f"  HTTP       : {pkt_info['http_info']}")

    if pkt_info.get("payload_ascii"):
        lines += ["", "  ── PAYLOAD · ASCII ───────────────────────────"]
        pl = pkt_info["payload_ascii"]
        for i in range(0, len(pl), 64):
            lines.append(f"  {pl[i:i+64]}")

    if pkt_info.get("payload_hex"):
        lines += ["", "  ── PAYLOAD · HEX ─────────────────────────────"]
        hx = pkt_info["payload_hex"]
        for i in range(0, len(hx), 48):
            lines.append(f"  {hx[i:i+48]}")

    lines += ["", "  ── RAW SUMMARY ───────────────────────────────"]
    lines.append(f"  {pkt_info['summary']}")
    return "\n".join(lines)
