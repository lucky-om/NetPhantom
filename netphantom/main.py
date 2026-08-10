"""
main.py - Entry Point
NetPhantom v3.3.2 — Professional Network Packet Sniffer & Analyzer
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
import shutil
import threading
import traceback

# ── Crash Logger: write unhandled exceptions to log file ────────────────────
_LOG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "NetPhantom")
_LOG_FILE = os.path.join(_LOG_DIR, "crash.log")

def _install_crash_logger():
    """Redirect unhandled exceptions to a log file so crashes are never silent."""
    try:
        os.makedirs(_LOG_DIR, exist_ok=True)
    except Exception:
        pass
    _orig_excepthook = sys.excepthook
    def _log_excepthook(exc_type, exc_value, exc_tb):
        try:
            with open(_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"Crash: {exc_type.__name__}: {exc_value}\n")
                f.write(f"Traceback:\n")
                traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
                f.write(f"{'='*60}\n")
        except Exception:
            pass
        _orig_excepthook(exc_type, exc_value, exc_tb)
    sys.excepthook = _log_excepthook

    # Also hook threading exceptions (Python 3.8+) so background thread crashes are logged
    if hasattr(threading, "excepthook"):
        _orig_thread_hook = threading.excepthook
        def _log_thread_hook(args):
            try:
                with open(_LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"THREAD CRASH: {args.exc_type.__name__}: {args.exc_value}\n")
                    f.write(f"Thread: {args.thread}\n")
                    if args.exc_traceback:
                        traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback, file=f)
                    f.write(f"{'='*60}\n")
            except Exception:
                pass
            _orig_thread_hook(args)
        threading.excepthook = _log_thread_hook

_install_crash_logger()

if getattr(sys, 'frozen', False):
    _exe_dir = os.path.dirname(sys.executable)
    if _exe_dir not in sys.path:
        sys.path.insert(0, _exe_dir)
else:
    _pkg_dir = os.path.dirname(os.path.abspath(__file__))
    _parent_dir = os.path.dirname(_pkg_dir)
    if _parent_dir not in sys.path:
        sys.path.insert(0, _parent_dir)


def check_privileges() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        if os.geteuid() == 0:
            return True
        # Check if raw socket creation is allowed via Linux capabilities (cap_net_raw)
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            try:
                pass  # Socket opened successfully — capability is available
            finally:
                s.close()
            return True
        except Exception:
            return False


def parse_arguments() -> argparse.Namespace:
    # Handle direct double-click file arguments from Windows Explorer / Linux File Manager
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        candidate = sys.argv[1].strip('"\'')
        if any(candidate.lower().endswith(ext) for ext in [".pcap", ".pcapng", ".cap", ".pkt", ".snoop", ".trc"]):
            return argparse.Namespace(list_interfaces=False, open=candidate)

    parser = argparse.ArgumentParser(
        prog="netphantom",
        description="NetPhantom v3.3.2 — Professional Network Packet Analyzer\n  Usage: netphantom",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file_pos", nargs="?", default=None, help="PCAP file to open")
    parser.add_argument("--version", "-V", action="version", version="NetPhantom v3.3.2")
    parser.add_argument("--list-interfaces", "-l", action="store_true",
                        help="Print available network interfaces and exit")
    parser.add_argument("--open", "-o", type=str, default=None, metavar="FILE",
                        help="Open a .pcap file directly in the GUI")
    args = parser.parse_args()
    if not args.open and args.file_pos:
        args.open = args.file_pos
    return args


def main():
    args = parse_arguments()

    if args.list_interfaces:
        try:
            from .capture import list_interfaces
        except ImportError:
            from netphantom.capture import list_interfaces
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
                if getattr(sys, "frozen", False):
                    # Frozen exe: re-launch the exe itself with 'runas' verb.
                    # sys.executable IS the exe path in frozen mode.
                    exe_path = sys.executable
                    params = subprocess.list2cmdline(sys.argv[1:]) if len(sys.argv) > 1 else ""
                else:
                    exe_path = sys.executable
                    if __package__:
                        params = subprocess.list2cmdline(["-m", __package__] + sys.argv[1:])
                    else:
                        params = subprocess.list2cmdline(sys.argv[1:])

                # ShellExecuteW returns > 32 on success, <= 32 on failure/denial
                result = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", exe_path, params, os.path.dirname(exe_path), 1
                )
                if result <= 32:
                    try:
                        from tkinter import messagebox
                        import tkinter as tk
                        _r = tk.Tk()
                        _r.withdraw()
                        messagebox.showerror(
                            "Privilege Error",
                            "NetPhantom requires Administrator privileges to monitor network adapters.\n\n"
                            "UAC elevation was denied. Please right-click the application and select\n"
                            "'Run as administrator', or enable Npcap in WinPcap compatibility mode."
                        )
                        _r.destroy()
                    except Exception:
                        pass
                    sys.exit(1)
                sys.exit(0)  # Parent process exits; elevated child takes over
            except Exception:
                try:
                    from tkinter import messagebox
                    import tkinter as tk
                    _r = tk.Tk()
                    _r.withdraw()
                    messagebox.showerror(
                        "Privilege Error",
                        "NetPhantom requires Administrator privileges to monitor network adapters.\n\n"
                        "Please run this application as Administrator."
                    )
                    _r.destroy()
                except Exception:
                    pass
                sys.exit(1)
        else:
            # Try PolicyKit (pkexec) elevation for Linux desktop environments
            if shutil.which("pkexec"):
                try:
                    import subprocess
                    # Re-launch via PolicyKit; sys.executable already covers argv[0]
                    cmd = ["pkexec", sys.executable] + sys.argv[1:]
                    subprocess.Popen(cmd)
                    sys.exit(0)
                except Exception:
                    pass

            print(
                "\n[!] Privilege Error: NetPhantom requires root or raw socket capabilities.\n"
                "    → Linux CLI: sudo netphantom\n"
                "    → Or grant caps: sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)\n"
            )
            try:
                from tkinter import messagebox
                import tkinter as tk
                root = tk.Tk()
                root.withdraw()
                messagebox.showerror(
                    "Privilege Error",
                    "NetPhantom requires root privileges or raw socket capabilities to capture packets.\n\n"
                    "Please launch with 'sudo netphantom' or run 'sudo ./install.sh'."
                )
            except Exception:
                pass
            sys.exit(1)

    _sigint_received = [False]

    def _handle_sigint(_sig, _frame):
        if _sigint_received[0]:
            print("\n[NetPhantom] Force quit.", file=sys.stderr)
            os._exit(1)
        _sigint_received[0] = True
        print("\n[NetPhantom] Ctrl+C detected — shutting down gracefully...",
              file=sys.stderr)
        try:
            _app_ref[0].root.after(0, _app_ref[0].on_close)
        except Exception:
            os._exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)

    _app_ref = [None]

    try:
        try:
            from .gui import run_gui
        except ImportError:
            from netphantom.gui import run_gui
        run_gui(open_file=args.open, app_ref=_app_ref)
    except ImportError as e:
        try:
            from tkinter import messagebox
            import tkinter as tk
            _r = tk.Tk(); _r.withdraw()
            messagebox.showerror(
                "NetPhantom — Missing Dependency",
                f"A required module is missing:\n\n{e}\n\n"
                "Please reinstall NetPhantom or check the crash log at:\n"
                f"{_LOG_FILE}"
            )
            _r.destroy()
        except Exception:
            pass
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
    try:
        main()
    except Exception as e:
        # Last-resort crash handler — write to log and show error dialog
        try:
            os.makedirs(_LOG_DIR, exist_ok=True)
            with open(_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"FATAL: {type(e).__name__}: {e}\n")
                traceback.print_exception(type(e), e, e.__traceback__, file=f)
                f.write(f"{'='*60}\n")
        except Exception:
            pass
        try:
            from tkinter import messagebox
            import tkinter as tk
            _root = tk.Tk()
            _root.withdraw()
            messagebox.showerror(
                "NetPhantom — Fatal Error",
                f"A critical error prevented NetPhantom from starting:\n\n"
                f"{type(e).__name__}: {e}\n\n"
                f"Crash log saved to:\n{_LOG_FILE}"
            )
        except Exception:
            print(f"\n[FATAL] {type(e).__name__}: {e}", file=sys.stderr)
            print(f"Crash log: {_LOG_FILE}", file=sys.stderr)
        sys.exit(1)
