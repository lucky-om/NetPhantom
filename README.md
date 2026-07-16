# ◆ NetPhantom v3.0 — Professional Network Packet Analyzer

---

```
  ███╗   ██╗███████╗████████╗    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██╔██╗ ██║█████╗     ██║       ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██║╚██╗██║██╔══╝     ██║       ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║ ╚████║███████╗   ██║       ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
                                                          NetPhantom v3.0
```

**A Wireshark-inspired network packet sniffer & analyzer built with Python, Scapy, and Tkinter.**

---

## 📁 Project Structure

```
NetPhantom/
├── main.py          ← Entry point: CLI launcher & GUI bootstrap
├── capture.py       ← Packet capture engine (Scapy + threading + PCAP import)
├── analyzer.py      ← Deep packet inspection, protocol dissection, threat detection
├── gui.py           ← Professional Tkinter GUI (Midnight Blue theme, 3-pane layout)
├── setup.py         ← Package config: enables `netphantom` CLI command
├── requirements.txt ← Python dependencies
├── SECURITY.md      ← Security policy
└── README.md        ← This file
```

---

## ⚙️ Installation

### 💻 Windows Setup Installer (Recommended)
You can install NetPhantom on Windows using the pre-compiled graphic setup installer:
1. Navigate to the `dist/` directory.
2. Double-click `NetPhantom_Setup.exe`.
3. Follow the wizard steps to install NetPhantom, create Desktop and Start Menu shortcuts, and launch the application.

### 🐍 Standard Python Installation (Cross-Platform)

### 1. Prerequisites
- Python 3.10+
- **Windows**: [Npcap](https://npcap.com/) installed (required by Scapy)
- **Linux/macOS**: `libpcap` (usually pre-installed)

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Install NetPhantom CLI Command

```bash
# From the project directory:
pip install -e .

# Now you can launch NetPhantom from anywhere:
netphantom
```

This registers the `netphantom` command system-wide. Works on **Windows**, **Linux**, and **macOS**.

### 4. Privileges (REQUIRED for full capture)

| Platform | How to Run |
|----------|------------|
| Windows  | Right-click terminal → **Run as Administrator** → `netphantom` |
| Linux    | `sudo netphantom` |
| macOS    | `sudo netphantom` |

---

## 🚀 Usage

### Launch GUI (Default)

```bash
netphantom
# or:
python main.py
```

### Open a PCAP File

```bash
netphantom --open capture.pcap
netphantom -o traffic.pcap
```

### List Network Interfaces

```bash
netphantom -l
```

### Check Version

```bash
netphantom --version
```

---

## 🎨 GUI Features — Wireshark-Inspired Layout

### Three-Pane Layout

```
┌──────────────────────────────────────────────────────────────┐
│ ◆ NetPhantom v3.0   [File│Capture│Analyze│View│Help]         │
├──────────────────────────────────────────────────────────────┤
│ [Interface ▼] [Capture Filter  ] [▶ Start] [■ Stop] [Proto ▼]│
│ 🔍 [Display Filter                              ] [Apply]    │
├──────────────────────────────────────────────────────────────┤
│                    PACKET LIST (color-coded rows)            │
│ No. │ Time │ Source │ Destination │ Protocol │ Length │ Info  │
├──────────────────────┬───────────────────────────────────────┤
│  PROTOCOL TREE       │  HEX DUMP                            │
│  ▸ Frame: 74 bytes   │  0000  45 00 00 4a 1b 3e  E..J.>    │
│  ▸ Ethernet II       │  0010  80 11 00 00 0a 00  ......    │
│  ▸ IPv4: 10.0→8.8    │  0020  08 08 08 08 d5 3e  .....>    │
│  ▸ UDP: 54590→53     │                                      │
├──────────────────────┴───────────────────────────────────────┤
│ ● CAPTURING on Wi-Fi │ 1,247 packets │ 38.2 pkt/s │ 14:32  │
└──────────────────────────────────────────────────────────────┘
```

### Panel Descriptions

| Panel | Description |
|-------|-------------|
| **Menu Bar** | File (Open/Save PCAP, Export JSON), Capture, Analyze, View, Help |
| **Toolbar** | Interface selector, BPF capture filter, Start/Stop buttons |
| **Display Filter** | Post-capture search & protocol filter |
| **Packet List** | Color-coded rows: click to inspect, double-click for detail popup |
| **Protocol Tree** | Wireshark-style expandable protocol dissection (Ethernet → IP → TCP → App) |
| **Hex Dump** | Raw packet bytes with offset, hex, and ASCII columns |
| **Side Panel** | Tabbed: 📊 Stats, 🔗 Streams, ⚠ Alerts, 🌐 Endpoints, 📈 Graph |

### ⌨️ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `F5` | Start capture |
| `F6` | Stop capture |
| `Ctrl+O` | Open PCAP file |
| `Ctrl+S` | Save as PCAP |
| `Ctrl+F` | Focus display filter |
| `Ctrl+L` | Clear all packets |
| `Ctrl+R` | Restart capture |
| `Ctrl++` | Zoom in |
| `Ctrl+-` | Zoom out |
| `Escape` | Stop capture |
| `Double-click` | Open packet detail popup |

### 🎨 Color Coding (Packet Rows)

| Color | Protocol |
|-------|----------|
| 🟢 Emerald | TCP |
| 🔵 Blue | UDP |
| 🟡 Amber | ICMP |
| 🟣 Violet | ARP |
| 🩵 Cyan | DNS / TLS |
| 🟠 Orange | HTTP |
| 🟢 Teal | HTTPS / QUIC |
| 💗 Pink | TLS Handshake |
| 🔴 Red BG | Threat / Alert packets |

---

## 🔐 Threat Detection

| Threat | Detection |
|--------|-----------|
| **Port Scan** | > 15 unique dst ports from one IP |
| **SYN Flood** | > 50 SYN packets/sec from one IP |
| **DoS / High Traffic** | > 100 packets/sec from one IP |
| **ICMP Flood** | > 50 ICMP packets/sec from one IP |
| **DNS Flood** | > 30 DNS queries/sec from one IP |
| **ARP Spoofing** | IP address changes MAC address |

Alerts appear in the ⚠ Alerts tab and as red-highlighted rows in the packet list.

---

## 📦 Export Formats

| Format | Description |
|--------|-------------|
| `.pcap` | Standard packet capture (open in Wireshark) |
| `.json` | Parsed packet summaries (for scripting/analysis) |

---

## 🧠 Architecture

```
main.py  (NetPhantom Entry Point)
  ├─ parse_arguments()   → argparse (--open, -l, --version)
  ├─ check_privileges()  → admin/root check
  └─ run_gui()           → gui.py → PacketSnifferGUI
                                    │
                              capture.py → CaptureEngine
                                    │        ├─ sniff() [background thread]
                                    │        ├─ load_pcap() [PCAP import]
                                    │        ├─ Queue<pkt_info> (10000)
                                    │        └─ export_pcap / export_json
                                    │
                              analyzer.py → PacketAnalyzer
                                             ├─ parse(pkt) → dict
                                             ├─ build_protocol_tree(pkt) → dissection
                                             ├─ format_hex_dump(pkt) → hex view
                                             ├─ get_stats() → dict
                                             ├─ _detect_threats() → alerts
                                             └─ endpoint/stream tracking
```

---

## 📋 Requirements

```
Python >= 3.10
scapy >= 2.5.0
colorama >= 0.4.6
psutil >= 5.9.0
tkinter (bundled with Python)
Npcap (Windows only) — https://npcap.com
```

---

## 🛡️ Security & Ethics

> **⚠ Warning: Only use this tool on networks you own or have explicit written permission to monitor.**

This tool is built for:
- ✅ Authorized penetration testing
- ✅ Network troubleshooting on your own network
- ✅ Cybersecurity education and learning
- ✅ CTF/lab environments
- ❌ NOT for unauthorized surveillance

---

## 🧪 Testing

```bash
# Generate test traffic
ping 8.8.8.8
curl http://example.com
nslookup google.com
```

---

## 🐛 Troubleshooting

| Issue | Fix |
|-------|-----|
| `Permission denied` | Run as Administrator (Windows) or `sudo` (Linux) |
| No packets captured | Install Npcap (Windows) or check interface name |
| `Interface not found` | Run `netphantom -l` to list available interfaces |
| Scapy import error | `pip install -r requirements.txt` |
| GUI doesn't open | Ensure `tkinter` is installed (`python -m tkinter`) |
| `netphantom` not found | Run `pip install -e .` from the project directory |

---

## 👨‍💻 Author

**Lucky** — Ethical Hacker

**Tool Name: NetPhantom v3.0**

## 📜 License

This project is licensed under the Apache License 2.0.
See the LICENSE file for details.

---

*"With great packet-sniffing power comes great responsibility."*
