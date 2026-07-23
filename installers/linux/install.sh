#!/bin/bash
# install.sh - NetPhantom Linux Dependency & CLI Installer
# Author: Luckyverse | Cybersecurity Project

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0;m' # No Color

echo -e "${BLUE}=== NetPhantom v3.0 — Linux Installer ===${NC}"

# Check for root/sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Error: Please run this script with sudo / as root.${NC}"
  echo "    sudo ./install.sh"
  exit 1
fi

# Detect Package Manager
echo -e "${BLUE}[*] Checking and installing system packages...${NC}"
if command -v apt-get &> /dev/null; then
  apt-get update -y
  # Install tcpdump and python3 dependencies (libpcap hooks require tcpdump/libpcap)
  apt-get install -y python3 python3-pip python3-tk tcpdump libpcap-dev
elif command -v dnf &> /dev/null; then
  dnf install -y python3 python3-pip python3-tkinter tcpdump libpcap-devel
elif command -v pacman &> /dev/null; then
  pacman -Sy --noconfirm python python-pip tk tcpdump libpcap
else
  echo -e "${RED}[!] Warning: Unknown package manager. Please ensure python3, tkinter, tcpdump, and libpcap are installed.${NC}"
fi

# Install Python requirements
echo -e "${BLUE}[*] Installing NetPhantom python library dependencies...${NC}"
# Use pip install -e . to register 'netphantom' CLI executable in developer mode
python3 -m pip install -e ..

# Register Desktop Entry
echo -e "${BLUE}[*] Copying desktop entry shortcut...${NC}"
DESKTOP_FILE="netphantom.desktop"
if [ -f "$DESKTOP_FILE" ]; then
  cp "$DESKTOP_FILE" /usr/share/applications/
  chmod +x /usr/share/applications/"$DESKTOP_FILE"
  echo -e "${GREEN}[✓] Desktop shortcut installed to /usr/share/applications/netphantom.desktop${NC}"
else
  echo -e "${RED}[!] Warning: netphantom.desktop file not found in current directory.${NC}"
fi

echo -e "${GREEN}[✓] NetPhantom installation complete!${NC}"
echo -e "    Launch it via terminal: ${BLUE}sudo netphantom${NC}"
