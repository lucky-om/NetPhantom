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
import signal

# Ensure current package directory is on sys.path
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)



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
            import subprocess
            import ctypes
            try:
                # Relaunch the program invoking UAC, quoting arguments and preserving current directory
                params = subprocess.list2cmdline(sys.argv)
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, params, os.getcwd(), 1
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

    # ── Install SIGINT (Ctrl+C) handler ─────────────────────────────────────
    # On the terminal, Ctrl+C raises KeyboardInterrupt which tkinter does NOT
    # propagate cleanly — the process crashes with a traceback. Instead we
    # intercept the signal and schedule a graceful shutdown via the Tk event
    # loop so all cleanup (stop capture, join thread, save config) runs first.
    _sigint_received = [False]

    def _handle_sigint(signum, frame):
        if _sigint_received[0]:
            # Second Ctrl+C — force exit immediately
            print("\n[NetPhantom] Force quit.", file=sys.stderr)
            os._exit(1)
        _sigint_received[0] = True
        print("\n[NetPhantom] Ctrl+C detected — shutting down gracefully...",
              file=sys.stderr)
        # Schedule the graceful close in the main Tk thread
        try:
            _app_ref[0].root.after(0, _app_ref[0].on_close)
        except Exception:
            os._exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)
    # ────────────────────────────────────────────────────────────────────────

    _app_ref = [None]  # Mutable reference so the signal handler can reach the app

    try:
        from gui import run_gui
        run_gui(open_file=args.open, app_ref=_app_ref)
    except ImportError as e:
        print(f"[!] GUI dependency missing: {e}")
        print("    Install: pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        # Final safety net — should normally be handled by _handle_sigint above
        print("\n[NetPhantom] Interrupted. Exiting cleanly.", file=sys.stderr)
        if _app_ref[0]:
            try:
                _app_ref[0].on_close()
            except Exception:
                pass
        sys.exit(0)


if __name__ == "__main__":
    main()
