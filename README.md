# ◆ NetPhantom v3.3.2 — Professional Network Packet Analyzer

---

```
 _  _     _   ___ _            _               
| \| |___| |_| _ \ |_  __ _ _ _| |_ ___ _ __   
|_|\_\___|\__|_| |_||_\__,_|_||_\__\___/_|_|_| v3.3.2
```

**A Wireshark-inspired network packet sniffer & analyzer built with Python, Scapy, and Tkinter.**

---

## ⚙️ Download & Installation

NetPhantom is available as a standalone executable for multiple platforms. You do not need Python installed to run it.

### 💻 Windows Setup Installer (Recommended)
1. Go to the **Releases** page on GitHub.
2. Download `NetPhantom_Setup.exe`.
3. Double-click the installer and follow the wizard steps to install NetPhantom.
4. Launch NetPhantom from your Desktop or Start Menu.
*(Note: Npcap will be installed automatically if not present.)*

### 🐧 Linux (AppImage / Debian)
1. Go to the **Releases** page on GitHub.
2. Download the `.AppImage` or `.deb` package.
3. For AppImage, make it executable: `chmod +x NetPhantom*.AppImage`
4. Run with root privileges to capture packets: `sudo ./NetPhantom*.AppImage`

### 🍏 macOS (DMG)
1. Go to the **Releases** page on GitHub.
2. Download the `.dmg` file.
3. Open the DMG and drag NetPhantom to your Applications folder.
4. Launch from Launchpad (may require granting permissions in System Settings).

---

## 🚀 Usage

Upon launching NetPhantom, the GUI will open. Note that **Administrator/root privileges are required** to capture live network traffic. 

- **Select Interface:** Choose your network interface from the top toolbar dropdown.
- **Start Capture:** Click the `▶ Start` button (or press `F5`).
- **Stop Capture:** Click the `■ Stop` button (or press `F6`).
- **Load PCAP:** Go to `File > Open PCAP` to analyze offline packet captures.
- **AI Analysis:** Right-click any packet row and select `🤖 Phantom AI Explain Packet` for AI-powered threat assessment.

---

## 🎨 GUI Features

### Three-Pane Layout

```
┌──────────────────────────────────────────────────────────────┐
│ ◆ NetPhantom v3.3.2   [File│Capture│Analyze│View│Help]         │
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
| `.txt`  | Plain text log export |

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

## 👨‍💻 Author

**Lucky** — Ethical Hacker

**Tool Name: NetPhantom v3.3.2**

## 📜 License

This project is licensed under the Apache License 2.0.
See the LICENSE file for details.

---

*"With great packet-sniffing power comes great responsibility."*
