#!/bin/bash
# install.sh - NetPhantom Linux Dependency & CLI/Desktop Installer
# NetPhantom v3.3.2 — Professional Network Packet Sniffer & Threat Analyzer
# Author: Luckyverse | Cybersecurity Project

set -e

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

VERSION="3.3.2"

# Clear terminal for clean installation UI
clear

# Initialization Animation
echo -e "${CYAN}Initializing NetPhantom Secure Installer...${NC}"
echo -ne "${BLUE}[ "
for i in {1..25}; do
    echo -ne "█"
    sleep 0.04
done
echo -e " ] 100%${NC}\n"
sleep 0.2
clear

echo -e "${RED}"
# Center ASCII art with sed
cat << "EOF" | sed 's/^/                    /'
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣾⣿⣿⣿⣿⣿⣿⣶⣄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⠿⢿⣿⣿⣿⣿⣆⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⠁⠀⠿⢿⣿⡿⣿⣿⡆⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣦⣤⣴⣿⠃⠀⠿⣿⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⡿⠋⠁⣿⠟⣿⣿⢿⣧⣤⣴⣿⡇⠀
⠀⠀⠀⠀⢀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠘⠁⢸⠟⢻⣿⡿⠀⠀
⠀⠀⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣴⣇⢀⣤⠀⠀⠀⠀⠘⣿⠃⠀⠀
⠀⠀⠀⠀⠀⢈⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣴⣿⢀⣴⣾⠇⠀⠀⠀
⠀⠀⣀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀
⠀⠀⠉⠉⠉⠉⣡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⡿⠟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀
⠀⠀⣴⡾⠿⠿⠿⠛⠋⠉⠀⢸⣿⣿⣿⣿⠿⠋⢸⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡿⠟⠋⠁⠀⠀⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
EOF
echo -e "${CYAN}"
echo -e "         ========================================================================="
echo -e "                              ◆  N E T P H A N T O M   v${VERSION}  ◆"
echo -e "                     Professional Network Packet Sniffer & Threat Analyzer"
echo -e "         ========================================================================="
echo -e "${NC}"
sleep 0.5

# Handle Uninstall Flag
if [ "$1" == "--uninstall" ] || [ "$1" == "-u" ]; then
    echo -e "${YELLOW}[*] Uninstalling NetPhantom v${VERSION}...${NC}"
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Error: Please run uninstall with sudo / as root.${NC}"
        echo "    sudo ./install.sh --uninstall"
        exit 1
    fi
    rm -f /usr/local/bin/netphantom
    rm -f /usr/share/applications/netphantom.desktop
    rm -f /usr/share/pixmaps/netphantom.png
    rm -f /usr/share/icons/hicolor/128x128/apps/netphantom.png
    if command -v gtk-update-icon-cache &> /dev/null; then
        gtk-update-icon-cache -f -t /usr/share/icons/hicolor &> /dev/null || true
    fi
    echo -e "${GREEN}[✓] NetPhantom has been completely uninstalled.${NC}"
    exit 0
fi

# Help Flag
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: sudo ./install.sh [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help         Show this help message"
    echo "  -u, --uninstall    Uninstall NetPhantom and remove shortcuts"
    echo "  -y, --yes          Non-interactive mode (auto-confirm all prompts)"
    exit 0
fi

# Check for root/sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Error: Please run this installer with sudo / as root.${NC}"
    echo "    sudo ./install.sh"
    exit 1
fi

# Determine script root directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"

# Detect Package Manager & Install System Dependencies
echo -e "${BLUE}[*] Detecting Linux distribution and package manager...${NC}"
if command -v apt-get &> /dev/null; then
    echo -e "${GREEN}[+] Debian / Ubuntu / Kali / Mint detected (apt)${NC}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-tk tcpdump libpcap-dev libcap2-bin desktop-file-utils
elif command -v dnf &> /dev/null; then
    echo -e "${GREEN}[+] Fedora / RHEL / Rocky Linux detected (dnf)${NC}"
    dnf install -y python3 python3-pip python3-tkinter tcpdump libpcap-devel libcap desktop-file-utils
elif command -v pacman &> /dev/null; then
    echo -e "${GREEN}[+] Arch Linux / Manjaro detected (pacman)${NC}"
    pacman -Sy --noconfirm python python-pip tk tcpdump libpcap libcap desktop-file-utils
elif command -v zypper &> /dev/null; then
    echo -e "${GREEN}[+] openSUSE detected (zypper)${NC}"
    zypper --non-interactive install python3 python3-pip python3-tk tcpdump libpcap-devel libcap-progs
else
    echo -e "${YELLOW}[!] Warning: Unknown package manager. Please ensure python3, tkinter, tcpdump, and libpcap are installed.${NC}"
fi

# Install Python Package
sleep 0.5
echo -e "${BLUE}[*] Bootstrapping Python Environment...${NC}"
sleep 0.3
echo -e "${BLUE}[*] Installing NetPhantom Python package & dependencies...${NC}"
cd "$PROJECT_ROOT"

# Use --break-system-packages if modern PEP 668 is active (Ubuntu 24.04+, Debian 12+, Arch)
PIP_FLAGS=""
if python3 -m pip install --help 2>&1 | grep -q "break-system-packages"; then
    PIP_FLAGS="--break-system-packages"
fi

python3 -m pip install -e . $PIP_FLAGS || python3 -m pip install . $PIP_FLAGS

# Create /usr/local/bin/netphantom Launcher Wrapper
echo -e "${BLUE}[*] Registering system command /usr/local/bin/netphantom...${NC}"
cat << 'EOF' > /usr/local/bin/netphantom
#!/bin/bash
PYTHON_BIN="$(which python3)"
if [ -f "$PYTHON_BIN" ]; then
    exec "$PYTHON_BIN" -m netphantom.main "$@"
else
    echo "[!] Error: python3 executable not found in PATH."
    exit 1
fi
EOF
chmod +x /usr/local/bin/netphantom

# Set capabilities so non-root users can capture raw packets
echo -e "${BLUE}[*] Granting raw packet capture capabilities (cap_net_raw, cap_net_admin)...${NC}"
PYTHON_PATH="$(readlink -f "$(which python3)")"
if command -v setcap &> /dev/null && [ -f "$PYTHON_PATH" ]; then
    setcap cap_net_raw,cap_net_admin=eip "$PYTHON_PATH" 2>/dev/null || \
        echo -e "${YELLOW}[!] Notice: setcap could not be applied to $PYTHON_PATH. Root privileges (sudo) will be required for packet capture.${NC}"
fi

# Install Application Icon & Desktop Entry
echo -e "${BLUE}[*] Installing Desktop Shortcut & Icon...${NC}"
LOGO_SRC="$PROJECT_ROOT/logo.png"
if [ -f "$LOGO_SRC" ]; then
    mkdir -p /usr/share/pixmaps
    mkdir -p /usr/share/icons/hicolor/128x128/apps
    cp "$LOGO_SRC" /usr/share/pixmaps/netphantom.png
    cp "$LOGO_SRC" /usr/share/icons/hicolor/128x128/apps/netphantom.png
fi

DESKTOP_SRC="$SCRIPT_DIR/netphantom.desktop"
if [ -f "$DESKTOP_SRC" ]; then
    cp "$DESKTOP_SRC" /usr/share/applications/netphantom.desktop
    chmod +x /usr/share/applications/netphantom.desktop
    if command -v desktop-file-validate &> /dev/null; then
        desktop-file-validate /usr/share/applications/netphantom.desktop 2>/dev/null || true
    fi
    if command -v update-desktop-database &> /dev/null; then
        update-desktop-database /usr/share/applications &>/dev/null || true
    fi
    if command -v gtk-update-icon-cache &> /dev/null; then
        gtk-update-icon-cache -f -t /usr/share/icons/hicolor &>/dev/null || true
    fi
    echo -e "${GREEN}[✓] Desktop shortcut installed to /usr/share/applications/netphantom.desktop${NC}"
fi

echo -e "${CYAN}         =========================================================================${NC}"
echo -e "${GREEN}         [✓] NetPhantom v${VERSION} Installation Complete!${NC}"
echo -e "             • Terminal Launch: ${CYAN}netphantom${NC} (or ${CYAN}sudo netphantom${NC})"
echo -e "             • Desktop Launch: Find ${CYAN}NetPhantom${NC} in Application Menu"
echo -e "             • Uninstall:       ${CYAN}sudo ./installers/linux/install.sh --uninstall${NC}"
echo -e "${CYAN}         =========================================================================${NC}"
echo ""
