# ◆ NetPhantom v3.3.2 — Professional Network Packet Analyzer

<div align="center">

![Version](https://img.shields.io/badge/version-v3.3.2-00f3ff?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/license-Apache%202.0-emerald?style=for-the-badge)

```text
 _  _     _   ___ _            _               
| \| |___| |_| _ \ |_  __ _ _ _| |_ ___ _ __   
|_|\_\___|\__|_| |_||_\__,_|_||_\__\___/_|_|_| v3.3.2
```

**A Wireshark-inspired, high-precision network packet sniffer & threat analyzer built with Python, Scapy, and Tkinter.**

[Website](https://lucky-om.github.io/NET-PHANTOM-WEBSITE/) • [Releases](https://github.com/lucky-om/NetPhantom/releases) • [Documentation](https://lucky-om.github.io/NET-PHANTOM-WEBSITE/docs.html)

</div>

---

## ✨ Features

- **Deep Packet Inspection:** Analyze TCP, UDP, ICMP, DNS, TLS, and ARP packets in real-time.
- **Threat Intelligence Heuristics:** Built-in detection for SYN Floods, Port Scans, ICMP Floods, and ARP Spoofing.
- **Phantom AI Integration:** AI-powered packet explanation and threat auditing directly from the UI.
- **Cross-Platform:** Runs seamlessly on Windows, Linux, and macOS.
- **Cyberpunk HUD UI:** A beautiful, terminal-inspired graphical interface.
- **Export Capabilities:** Export your captures to `.pcap`, `.json`, or plain text logs.

---

## ⚙️ Download & Installation

NetPhantom is available as a standalone executable for multiple platforms. **You do not need Python installed to run the pre-built binaries.**

### 💻 Windows Setup Installer (Recommended)
1. Go to the [Releases](https://github.com/lucky-om/NetPhantom/releases) page.
2. Download `NetPhantom_Setup.exe`.
3. Double-click the installer and follow the wizard steps.
4. Launch NetPhantom from your Desktop or Start Menu.
> *Note: Npcap will be installed automatically if not present on your system.*

### 🐧 Linux (AppImage / Debian)
1. Go to the [Releases](https://github.com/lucky-om/NetPhantom/releases) page.
2. Download the `.AppImage` or `.deb` package.
3. For AppImage, make it executable: `chmod +x NetPhantom*.AppImage`
4. Run with root privileges to capture packets: `sudo ./NetPhantom*.AppImage`

### 🐧 Linux (From Source)
1. Clone the repository: `git clone https://github.com/lucky-om/NetPhantom`
2. Change directory: `cd NetPhantom`
3. Run the installer script: `sudo bash ./installers/linux/install.sh`

### 🍏 macOS (DMG)
1. Go to the [Releases](https://github.com/lucky-om/NetPhantom/releases) page.
2. Download the `.dmg` file.
3. Open the DMG and drag NetPhantom to your Applications folder.
4. Launch from Launchpad (may require granting permissions in System Settings).

---

## 🚀 Usage

Upon launching NetPhantom, the GUI will open. Note that **Administrator/root privileges are required** to capture live network traffic on most operating systems. 

- **Select Interface:** Choose your network interface from the top toolbar dropdown.
- **Start Capture:** Click the `▶ Start` button (or press `F5`).
- **Stop Capture:** Click the `■ Stop` button (or press `F6`).
- **Load PCAP:** Go to `File > Open PCAP` to analyze offline packet captures.
- **AI Analysis:** Right-click any packet row and select `🤖 Phantom AI Explain Packet` for AI-powered threat assessment.

---

## 🎨 GUI Layout & Shortcuts

### Three-Pane Layout Structure

```text
┌──────────────────────────────────────────────────────────────┐
│ ◆ NetPhantom v3.3.2   [File│Capture│Analyze│View│Help]         │
├──────────────────────────────────────────────────────────────┤
│ [Interface ▼] [Capture Filter  ] [▶ Start] [■ Stop] [Proto ▼]│
│ 🔍 [Display Filter                              ] [Apply]    │
├──────────────────────────────────────────────────────────────┤
│                    PACKET LIST (color-coded rows)            │
│ No. │ Time │ Source │ Destination │ Protocol │ Length │ Info │
├──────────────────────┬───────────────────────────────────────┤
│  PROTOCOL TREE       │  HEX DUMP                             │
│  ▸ Frame: 74 bytes   │  0000  45 00 00 4a 1b 3e  E..J.>      │
│  ▸ Ethernet II       │  0010  80 11 00 00 0a 00  ......      │
│  ▸ IPv4: 10.0→8.8    │  0020  08 08 08 08 d5 3e  .....>      │
│  ▸ UDP: 54590→53     │                                       │
├──────────────────────┴───────────────────────────────────────┤
│ ● CAPTURING on Wi-Fi │ 1,247 packets │ 38.2 pkt/s │ 14:32    │
└──────────────────────────────────────────────────────────────┘
```

### ⌨️ Keyboard Shortcuts

| Key | Action | Key | Action |
|-----|--------|-----|--------|
| `F5` | Start capture | `Ctrl+R` | Restart capture |
| `F6` / `Esc` | Stop capture | `Ctrl++` | Zoom in UI |
| `Ctrl+O` | Open PCAP file | `Ctrl+-` | Zoom out UI |
| `Ctrl+S` | Save as PCAP | `Ctrl+F` | Focus display filter |
| `Ctrl+L` | Clear all packets | `Double-click` | Open packet detail popup |

### 🎨 Color Coding (Packet Rows)

| Color | Protocol / Type | Color | Protocol / Type |
|-------|-----------------|-------|-----------------|
| 🟢 **Emerald** | TCP | 🟠 **Orange** | HTTP |
| 🔵 **Blue** | UDP | 🟢 **Teal** | HTTPS / QUIC |
| 🟡 **Amber** | ICMP | 💗 **Pink** | TLS Handshake |
| 🟣 **Violet** | ARP | 🔴 **Red BG** | Threat / Alert packets |
| 🩵 **Cyan** | DNS / TLS | | |

---

## 🔐 Threat Detection Heuristics

NetPhantom runs live statistical heuristics to identify suspicious network behavior:

| Threat Signature | Trigger Condition |
|------------------|-------------------|
| **Port Scan** | `> 15` unique destination ports contacted from a single IP within 10 seconds. |
| **SYN Flood** | `> 50` SYN packets/sec originating from a single IP. |
| **DoS / High Traffic** | `> 100` total packets/sec originating from a single IP. |
| **ICMP Flood** | `> 50` ICMP packets/sec from a single IP. |
| **DNS Flood** | `> 30` DNS queries/sec from a single IP. |
| **ARP Spoofing** | IP address is detected shifting to a different MAC address on the local network. |

*Alerts appear in the `⚠ Alerts` tab and trigger red-highlighted rows in the live packet list.*

---

## 🛡️ Security & Ethics

> **⚠ Warning: Only use this tool on networks you own or have explicit written permission to monitor.**

This tool is built strictly for:
- ✅ Authorized penetration testing and auditing
- ✅ Network troubleshooting on your own hardware
- ✅ Cybersecurity education and protocol learning
- ✅ CTF/lab environments

It is **NOT** intended for unauthorized surveillance or malicious interception.

---

## 👨‍💻 Author

**Lucky** — Cybersecurity Developer

## 📜 License

This project is licensed under the Apache License 2.0.
See the `LICENSE` file for details.

<div align="center">
<i>"With great packet-sniffing power comes great responsibility."</i>
</div>
