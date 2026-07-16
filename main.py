"""
main.py - Entry Point
NetPhantom v3.0 — Professional Network Packet Sniffer & Analyzer
Author: Luckyverse | Cybersecurity Portfolio Project

Usage:
    netphantom                  (launches GUI directly)
    netphantom -l               (list interfaces)
    netphantom --open file.pcap (open a PCAP file)
    sudo netphantom             (Linux: run with privileges)
"""

import argparse
import sys
import os


def check_privileges() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="netphantom",
        description="NetPhantom v3.0 — Professional Network Packet Analyzer\n  Usage: netphantom",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", "-V", action="version", version="NetPhantom v3.0")
    parser.add_argument("--list-interfaces", "-l", action="store_true",
                        help="Print available network interfaces and exit")
    parser.add_argument("--open", "-o", type=str, default=None, metavar="FILE",
                        help="Open a .pcap file directly in the GUI")
    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.list_interfaces:
        from capture import list_interfaces
        ifaces = list_interfaces()
        print("\nAvailable Network Interfaces:")
        for i, iface in enumerate(ifaces, 1):
            print(f"  {i}. {iface}")
        print()
        sys.exit(0)

    if not check_privileges():
        if os.name == "nt":
            import ctypes
            try:
                # Relaunch the program invoking UAC
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
                sys.exit(0)
            except Exception:
                from tkinter import messagebox
                import tkinter as tk
                root = tk.Tk()
                root.withdraw()
                messagebox.showerror(
                    "Privilege Error",
                    "NetPhantom requires Administrator privileges to monitor network adapters.\n\n"
                    "Please run this application as Administrator."
                )
                sys.exit(1)
        else:
            print(
                "\n[!] Privilege Error: NetPhantom must be run as root.\n"
                "    → Linux: sudo netphantom\n"
            )
            try:
                from tkinter import messagebox
                import tkinter as tk
                root = tk.Tk()
                root.withdraw()
                messagebox.showerror(
                    "Privilege Error",
                    "NetPhantom must be run as root (sudo) to capture raw sockets."
                )
            except Exception:
                pass
            sys.exit(1)

    try:
        from gui import run_gui
        run_gui(open_file=args.open)
    except ImportError as e:
        print(f"[!] GUI dependency missing: {e}")
        print("    Install: pip install -r requirements.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()
