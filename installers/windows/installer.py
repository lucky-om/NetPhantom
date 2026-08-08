# -*- coding: utf-8 -*-
"""
installer.py - Graphical Setup Web-Installer for NetPhantom v3.3.1
Author: Luckyverse | Cybersecurity Project

Guides the user through EULA agreement, location selection, shortcut options,
downloads/configures application packages, and sets up desktop shortcuts.
"""

import os
import sys
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

try:
    if os.name == 'nt':
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

try:
    import winshell
except ImportError:
    winshell = None

try:
    from win32com.client import Dispatch
except ImportError:
    Dispatch = None

# ──────────────────────────────────────────────
#  Theme Constants
# ──────────────────────────────────────────────
BG_BASE      = "#0a0e1a"
BG_PANEL     = "#111827"
BG_HEADER    = "#1e293b"
BG_INPUT     = "#1a2332"
BG_HOVER     = "#243347"
BG_SELECTED  = "#1e3a5f"
BORDER       = "#1e3a5f"

ACCENT_BLUE  = "#3b82f6"
ACCENT_GREEN = "#10b981"
ACCENT_RED   = "#ef4444"
ACCENT_AMBER = "#f59e0b"
TEXT_PRIMARY = "#e2e8f0"
TEXT_SECONDARY = "#94a3b8"
TEXT_DIM     = "#64748b"

# EULA text
EULA_TEXT = """NetPhantom v3.3.1 End User License & Ethical Terms of Service
Publisher: Luckyverse

IMPORTANT: READ CAREFULLY BEFORE INSTALLING OR RUNNING NETPHANTOM. THIS SOFTWARE IS DISTRIBUTED WITH NO WARRANTIES AND ALL USAGE IS ENTIRELY AT YOUR OWN RISK.

1. END USER LICENSE AGREEMENT & DISCLAIMER (EULA)
By executing, installing, or modifying NetPhantom, you agree to assume all liability. Network monitoring, frame interception, and packet sniffing can violate wiretapping, computer fraud, and privacy laws globally. Under no circumstances shall the developer or publisher (Luckyverse) be held responsible or liable for any legal actions, regulatory penalties, data breaches, network crashes, or system damages resulting from the use or misuse of this tool.

2. "USE AT YOUR OWN RISK" WARRANTY DISCLAIMER
This software is provided by the copyright holders and contributors "AS IS" and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall Luckyverse or its contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.

3. NETWORK DISRUPTION & OS CRASH WARNING
Raw socket binding and hardware-level packet capture require interface driver hooks (Npcap/Libpcap). Under high network load or driver conflicts, this capture process can cause network card instability, connection drops, system lag, or operating system crashes (Kernel Panics / Blue Screens of Death). The publisher accepts zero responsibility for hardware failures, connection loss, or system instability caused by packet capturing.

4. COMPLIANCE WITH WIRE-TAPPING LAWS
In many jurisdictions, capturing or reading packet payloads containing data of third parties without their explicit consent constitutes a felony under wiretapping, electronic communications, and surveillance acts. It is the sole responsibility of the user to confirm that they possess explicit, written permission from the owner of the network before binding any adapter.

5. PRIVACY POLICY & ABSOLUTE LOCAL ISOLATION
NetPhantom is engineered to respect complete local data privacy:
- Volatile RAM Buffer: Captured frames and decrypted packet trees exist only in volatile system RAM. They are completely and permanently wiped from system memory when the application is terminated.
- Zero Telemetry: There are no backend tracking systems, telemetry pingbacks, crash-report transmitters, or database collection services.
- No Storage: The software does not log, save, or mirror your captured packet streams to any server. You are in complete control of any local PCAP exports.
"""

class SetupWizard:
    def __init__(self, root):
        self.root = root
        self.root.title("NetPhantom v3.3.1 Setup")
        
        # Auto-clear Windows Mark of the Web (Zone.Identifier) if present
        if os.name == 'nt':
            try:
                import subprocess
                _curr_exe = sys.executable
                _motw_stream = f"{_curr_exe}:Zone.Identifier"
                if os.path.exists(_motw_stream):
                    os.remove(_motw_stream)
                subprocess.run(["powershell", "-Command", "Unblock-File -Path '*' -ErrorAction SilentlyContinue"], creationflags=0x08000000)
            except Exception:
                pass

        # Set window icon from logo.png
        try:
            from PIL import Image, ImageTk
            _logo_candidates = [
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png"),
                os.path.join(getattr(sys, '_MEIPASS', '.'), "logo.png"),
                "logo.png",
            ]
            for _lp in _logo_candidates:
                if os.path.isfile(_lp):
                    _icon_img = Image.open(_lp).resize((64, 64), Image.LANCZOS)
                    self._icon_photo = ImageTk.PhotoImage(_icon_img)
                    self.root.iconphoto(True, self._icon_photo)
                    break
        except Exception:
            pass

        if os.name == 'nt':
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                try:
                    import ctypes
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass

        self.root.configure(bg=BG_BASE)
        self.root.geometry("620x560")
        self.root.minsize(560, 480)
        self.root.resizable(True, True)

        # Center window
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"620x560+{(sw-620)//2}+{(sh-560)//2}")

        # Default Install Path (Program Files if Admin, LOCALAPPDATA Programs if Standard User)
        def _is_admin():
            if os.name != 'nt':
                return True
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False

        if _is_admin():
            pf = os.environ.get("ProgramFiles", "C:\\Program Files")
            self.install_dir = os.path.join(pf, "NetPhantom")
        else:
            local_appdata = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
            self.install_dir = os.path.join(local_appdata, "Programs", "NetPhantom")

        self.step = 1
        self._build_ui()

    def _build_ui(self):
        # 1. Header Area (TOP)
        self.header_frame = tk.Frame(self.root, bg=BG_HEADER, height=70)
        self.header_frame.pack(fill=tk.X, side=tk.TOP)
        self.header_frame.pack_propagate(False)

        self.title_lbl = tk.Label(self.header_frame, text="NetPhantom v3.3.1 Installation",
                                  bg=BG_HEADER, fg=TEXT_PRIMARY, font=("Segoe UI", 12, "bold"))
        self.title_lbl.pack(anchor="w", padx=16, pady=(12, 2))

        self.subtitle_lbl = tk.Label(self.header_frame, text="Follow the steps to install the network analyzer.",
                                     bg=BG_HEADER, fg=TEXT_DIM, font=("Segoe UI", 9))
        self.subtitle_lbl.pack(anchor="w", padx=16)

        # 2. Footer Navigation Area (BOTTOM - Packed FIRST so it is ALWAYS visible!)
        self.footer_frame = tk.Frame(self.root, bg=BG_PANEL, height=54)
        self.footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.footer_frame.pack_propagate(False)

        # Separator line above footer
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill=tk.X, side=tk.BOTTOM)

        self.btn_next = tk.Button(self.footer_frame, text="Next >", command=self._next_step,
                                  bg=ACCENT_BLUE, fg="white", activebackground=BG_HOVER,
                                  activeforeground="white", font=("Segoe UI", 9, "bold"),
                                  relief="flat", bd=0, padx=20, pady=6, cursor="hand2")
        self.btn_next.pack(side=tk.RIGHT, padx=12, pady=10)

        self.btn_cancel = tk.Button(self.footer_frame, text="Cancel", command=self.root.destroy,
                                    bg=BG_INPUT, fg=TEXT_PRIMARY, activebackground=BG_HOVER,
                                    activeforeground=TEXT_PRIMARY, font=("Segoe UI", 9),
                                    relief="flat", bd=0, padx=16, pady=6, cursor="hand2")
        self.btn_cancel.pack(side=tk.RIGHT, padx=4, pady=10)

        self.btn_back = tk.Button(self.footer_frame, text="< Back", command=self._prev_step,
                                  bg=BG_INPUT, fg=TEXT_PRIMARY, activebackground=BG_HOVER,
                                  activeforeground=TEXT_PRIMARY, font=("Segoe UI", 9),
                                  relief="flat", bd=0, padx=16, pady=6, cursor="hand2")
        self.btn_back.pack(side=tk.RIGHT, padx=4, pady=10)

        # 3. Content Area (MIDDLE - Packed AFTER footer so it cannot push buttons off-screen)
        self.content_frame = tk.Frame(self.root, bg=BG_BASE)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)

        # Initialize step view
        self._show_step_1()

    def _show_step_1(self):
        # Clear content frame
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="NetPhantom v3.3.1 Setup")
        self.subtitle_lbl.config(text="Welcome to the NetPhantom Setup Wizard.")
        self.btn_next.config(state=tk.NORMAL, text="Next >")
        self.btn_back.config(state=tk.DISABLED)

        lbl_welcome = tk.Label(self.content_frame,
                               text="This wizard will install NetPhantom v3.3.1 on your computer.\n\n"
                                    "It is recommended that you close all other applications before continuing.\n\n"
                                    "Click Next to continue, or Cancel to exit Setup.",
                               bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 10),
                               justify="left", anchor="w")
        lbl_welcome.pack(fill=tk.BOTH, expand=True, pady=10)

    def _show_step_2(self):
        # Clear content frame
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="License Agreement")
        self.subtitle_lbl.config(text="Please review the license terms before installing.")
        self.btn_back.config(state=tk.NORMAL)

        lbl_instructions = tk.Label(self.content_frame,
                                    text="If you accept the terms of the agreement, select the option below.",
                                    bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 9),
                                    justify="left", anchor="w")
        lbl_instructions.pack(fill=tk.X, pady=(0, 6))

        # License text area
        self.license_box = scrolledtext.ScrolledText(self.content_frame, bg=BG_PANEL, fg=TEXT_PRIMARY,
                                                     font=("Consolas", 9), insertbackground=TEXT_PRIMARY,
                                                     relief="flat", height=10)
        self.license_box.pack(fill=tk.BOTH, expand=True, pady=4)
        self.license_box.insert(tk.END, EULA_TEXT)
        self.license_box.config(state=tk.DISABLED)

        # Acceptance checkbox
        self.accept_var = tk.BooleanVar(value=False)
        self.chk_accept = tk.Checkbutton(self.content_frame, text="I accept the agreement, terms, and privacy policy",
                                         variable=self.accept_var, command=self._toggle_next_by_agreement,
                                         bg=BG_BASE, fg=TEXT_PRIMARY, activebackground=BG_BASE,
                                         activeforeground=TEXT_PRIMARY, selectcolor=BG_INPUT,
                                         font=("Segoe UI", 9, "bold"))
        self.chk_accept.pack(anchor="w", pady=(8, 0))

        # Disable Next button by default on step 2 until EULA is accepted
        self.btn_next.config(state=tk.DISABLED)

    def _toggle_next_by_agreement(self):
        if self.accept_var.get():
            self.btn_next.config(state=tk.NORMAL)
        else:
            self.btn_next.config(state=tk.DISABLED)

    def _show_step_3(self):
        # Step 3: Choose Components 
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Choose Components")
        self.subtitle_lbl.config(text="Choose which features of NetPhantom v3.3.1 you want to install.")
        self.btn_next.config(state=tk.NORMAL, text="Next >")
        self.btn_back.config(state=tk.NORMAL)

        lbl_desc = tk.Label(self.content_frame, text="The following components are available for installation:",
                            bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 9))
        lbl_desc.pack(anchor="w", pady=(0, 6))

        # Scrollable Frame for Components Tree
        tree_frame = tk.Frame(self.content_frame, bg=BG_PANEL, bd=1, relief="solid")
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=4)

        self.comp_core = tk.BooleanVar(value=True)
        self.comp_gui = tk.BooleanVar(value=True)
        self.comp_cli = tk.BooleanVar(value=True)
        self.comp_extcap = tk.BooleanVar(value=True)
        self.comp_android = tk.BooleanVar(value=True)
        self.comp_etw = tk.BooleanVar(value=True)
        self.comp_randpkt = tk.BooleanVar(value=True)
        self.comp_ssh_wifidump = tk.BooleanVar(value=True)
        self.comp_udpdump = tk.BooleanVar(value=True)

        cb_style = {"bg": BG_PANEL, "fg": TEXT_PRIMARY, "activebackground": BG_PANEL,
                    "activeforeground": TEXT_PRIMARY, "selectcolor": BG_INPUT, "font": ("Segoe UI", 9)}

        tk.Checkbutton(tree_frame, text="NetPhantom Core Engine & Dissector", variable=self.comp_core, state=tk.DISABLED, **cb_style).pack(anchor="w", padx=12, pady=1)
        tk.Checkbutton(tree_frame, text="   NetPhantom GUI Dashboard HUD", variable=self.comp_gui, state=tk.DISABLED, **cb_style).pack(anchor="w", padx=32, pady=1)
        tk.Checkbutton(tree_frame, text="   Global CLI Command (netphantom)", variable=self.comp_cli, **cb_style).pack(anchor="w", padx=32, pady=1)
        
        tk.Checkbutton(tree_frame, text="External Capture Tools (extcap)", variable=self.comp_extcap, **cb_style).pack(anchor="w", padx=12, pady=(4, 1))
        tk.Checkbutton(tree_frame, text="   Androiddump (Android ADB Packet Sniffer)", variable=self.comp_android, **cb_style).pack(anchor="w", padx=32, pady=1)
        tk.Checkbutton(tree_frame, text="   Etwdump (Event Tracing for Windows Sniffer)", variable=self.comp_etw, **cb_style).pack(anchor="w", padx=32, pady=1)
        tk.Checkbutton(tree_frame, text="   Randpktdump (Random Packet Generator)", variable=self.comp_randpkt, **cb_style).pack(anchor="w", padx=32, pady=1)
        tk.Checkbutton(tree_frame, text="   Sshdump, Ciscodump & Wifidump (Remote/Wi-Fi Dissector)", variable=self.comp_ssh_wifidump, **cb_style).pack(anchor="w", padx=32, pady=1)
        tk.Checkbutton(tree_frame, text="   UDPdump (UDP Listener & Raw Capture Tool)", variable=self.comp_udpdump, **cb_style).pack(anchor="w", padx=32, pady=1)

        # Space Required Label
        tk.Label(self.content_frame, text="Space required: 35.0 MB", bg=BG_BASE, fg=TEXT_DIM, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(4, 0))

    def _show_step_4(self):
        # Step 4: Additional Tasks 
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Additional Tasks")
        self.subtitle_lbl.config(text="Create shortcuts and associate file extensions.")

        cb_style = {"bg": BG_BASE, "fg": TEXT_PRIMARY, "activebackground": BG_BASE,
                    "activeforeground": TEXT_PRIMARY, "selectcolor": BG_INPUT, "font": ("Segoe UI", 9)}

        tk.Label(self.content_frame, text="Create Shortcuts", bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        
        self.shortcut_start = tk.BooleanVar(value=True)
        self.shortcut_desktop = tk.BooleanVar(value=True)
        self.assoc_files_var = tk.BooleanVar(value=True)

        tk.Checkbutton(self.content_frame, text="NetPhantom Start Menu Item", variable=self.shortcut_start, **cb_style).pack(anchor="w", padx=12, pady=2)
        tk.Checkbutton(self.content_frame, text="NetPhantom Desktop Icon", variable=self.shortcut_desktop, **cb_style).pack(anchor="w", padx=12, pady=2)

        tk.Label(self.content_frame, text="Associate File Extensions", bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(16, 4))
        tk.Checkbutton(self.content_frame, text="Associate trace file extensions with NetPhantom", variable=self.assoc_files_var, **cb_style).pack(anchor="w", padx=12, pady=2)
        
        tk.Label(self.content_frame,
                 text="Extensions include: .pcap, .pcapng, .cap, .pkt, .snoop, .trc, .pcap.gz\n"
                      "Allows double-clicking packet captures in Windows Explorer to open directly in NetPhantom.",
                 bg=BG_BASE, fg=TEXT_DIM, font=("Segoe UI", 8), justify="left").pack(anchor="w", padx=32, pady=(2, 0))

    def _show_step_5(self):
        # Step 5: Choose Install Location 
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Choose Install Location")
        self.subtitle_lbl.config(text="Choose the folder in which to install NetPhantom v3.3.1.")

        tk.Label(self.content_frame, text="Destination Folder", bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))

        path_frame = tk.Frame(self.content_frame, bg=BG_BASE)
        path_frame.pack(fill=tk.X, pady=4)

        self.path_var = tk.StringVar(value=self.install_dir)
        self.entry_path = tk.Entry(path_frame, textvariable=self.path_var, bg=BG_INPUT,
                                   fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                                   font=("Segoe UI", 9), relief="flat", bd=6)
        self.entry_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        btn_browse = tk.Button(path_frame, text="Browse...", command=self._browse_dir,
                               bg=BG_INPUT, fg=TEXT_PRIMARY, activebackground=BG_HOVER,
                               activeforeground=TEXT_PRIMARY, font=("Segoe UI", 9),
                               relief="flat", bd=0, padx=12, pady=4, cursor="hand2")
        btn_browse.pack(side=tk.RIGHT)

        # Calculate space available on destination drive
        try:
            import shutil
            drive = os.path.splitdrive(self.install_dir)[0] or "C:"
            usage = shutil.disk_usage(drive + "\\")
            avail_gb = round(usage.free / (1024**3), 1)
        except Exception:
            avail_gb = 50.0

        space_frame = tk.Frame(self.content_frame, bg=BG_BASE)
        space_frame.pack(fill=tk.X, pady=16)
        tk.Label(space_frame, text="Space required: 35.0 MB", bg=BG_BASE, fg=TEXT_SECONDARY, font=("Segoe UI", 9)).pack(anchor="w")
        tk.Label(space_frame, text=f"Space available: {avail_gb} GB", bg=BG_BASE, fg=TEXT_SECONDARY, font=("Segoe UI", 9)).pack(anchor="w")

    def _show_step_6(self):
        # Step 6: Packet Capture Driver
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Packet Capture Driver")
        self.subtitle_lbl.config(text="NetPhantom requires Npcap to capture live network data.")

        # Check Npcap status
        npcap_installed = self._check_npcap_installed()
        status_text = "[OK] Npcap 1.88 Driver Detected" if npcap_installed else "[!] Npcap Driver Not Found"
        status_color = ACCENT_GREEN if npcap_installed else ACCENT_AMBER

        # Card 1: Currently installed status
        card1 = tk.Frame(self.content_frame, bg=BG_PANEL, highlightbackground=BORDER, highlightthickness=1)
        card1.pack(fill=tk.X, pady=(0, 8), padx=2, ipady=8)
        tk.Label(card1, text="CURRENTLY INSTALLED NPCAP VERSION", bg=BG_PANEL, fg=TEXT_SECONDARY, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=12, pady=(4, 2))
        tk.Label(card1, text=status_text, bg=BG_PANEL, fg=status_color, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12)

        # Card 2: Install / Update option
        card2 = tk.Frame(self.content_frame, bg=BG_PANEL, highlightbackground=BORDER, highlightthickness=1)
        card2.pack(fill=tk.X, pady=8, padx=2, ipady=8)
        
        self.install_npcap_var = tk.BooleanVar(value=not npcap_installed)
        cb = tk.Checkbutton(card2, text="Install / Update Npcap 1.88 Driver", variable=self.install_npcap_var,
                          bg=BG_PANEL, fg=TEXT_PRIMARY, activebackground=BG_PANEL, activeforeground=TEXT_PRIMARY,
                          selectcolor=BG_INPUT, font=("Segoe UI", 9, "bold"), cursor="hand2")
        cb.pack(anchor="w", padx=12, pady=(4, 2))
        
        tk.Label(card2, text="Allows NetPhantom to capture raw socket frames in promiscuous mode on Wi-Fi and Ethernet adapters.",
                 bg=BG_PANEL, fg=TEXT_DIM, font=("Segoe UI", 8), wraplength=520, justify="left").pack(anchor="w", padx=32)

        # Card 3: Important Notice
        card3 = tk.Frame(self.content_frame, bg=BG_PANEL, highlightbackground=ACCENT_AMBER, highlightthickness=1)
        card3.pack(fill=tk.X, pady=8, padx=2, ipady=8)
        tk.Label(card3, text="IMPORTANT NOTICE", bg=BG_PANEL, fg=ACCENT_AMBER, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=12, pady=(4, 2))
        tk.Label(card3, text="If your system previously experienced a packet driver error, ensure you close any existing network sniffers before installing. Npcap 1.88 will run in silent driver mode.",
                 bg=BG_PANEL, fg=TEXT_PRIMARY, font=("Segoe UI", 8), wraplength=520, justify="left").pack(anchor="w", padx=12)

    def _check_npcap_installed(self) -> bool:
        if os.name != 'nt':
            return True
        system32 = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
        npcap_dll = os.path.join(system32, "Npcap", "wpcap.dll")
        winpcap_dll = os.path.join(system32, "wpcap.dll")
        return os.path.exists(npcap_dll) or os.path.exists(winpcap_dll)

    def _show_step_7(self):
        # Step 7: Installing Progress
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Installing NetPhantom")
        self.subtitle_lbl.config(text="Please wait while Setup installs NetPhantom on your system.")

        self.btn_next.config(state=tk.DISABLED)
        self.btn_cancel.config(state=tk.DISABLED)

        self.lbl_status = tk.Label(self.content_frame, text="Configuring application components...",
                                   bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 9))
        self.lbl_status.pack(anchor="w", pady=(20, 4))

        self.progress = ttk.Progressbar(self.content_frame, mode="determinate", length=480)
        self.progress.pack(fill=tk.X, pady=8)

        # Trigger installation
        self.root.after(500, self._perform_installation)

    def _show_step_8(self):
        # Step 8: Installation Complete
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Installation Complete")
        self.subtitle_lbl.config(text="NetPhantom v3.3.1 has been successfully installed.")

        self.btn_next.config(text="Finish", state=tk.NORMAL)
        self.btn_cancel.pack_forget()

        self.run_app_var = tk.BooleanVar(value=True)

        lbl_finished = tk.Label(self.content_frame,
                                text="Setup has finished installing NetPhantom v3.3.1 on your computer.\n"
                                     "All components, CLI tools, and file associations have been configured.",
                                bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 10),
                                justify="left", anchor="w")
        lbl_finished.pack(fill=tk.X, pady=10)

        chk_run = tk.Checkbutton(self.content_frame, text="Launch NetPhantom v3.3.1 now", variable=self.run_app_var,
                                 bg=BG_BASE, fg=TEXT_PRIMARY, activebackground=BG_BASE,
                                 activeforeground=TEXT_PRIMARY, selectcolor=BG_INPUT,
                                 font=("Segoe UI", 9, "bold"))
        chk_run.pack(anchor="w", pady=20)

    def _browse_dir(self):
        from tkinter import filedialog
        chosen = filedialog.askdirectory(initialdir=self.path_var.get(), title="Select Install Folder")
        if chosen:
            self.path_var.set(os.path.normpath(chosen))

    def _prev_step(self):
        if self.step > 1 and self.step not in (7, 8):
            self.step -= 1
            show_method = getattr(self, f"_show_step_{self.step}", None)
            if show_method:
                show_method()

    def _next_step(self):
        if self.step == 1:
            self.step = 2
            self._show_step_2()
        elif self.step == 2:
            self.step = 3
            self._show_step_3()
        elif self.step == 3:
            self.step = 4
            self._show_step_4()
        elif self.step == 4:
            self.step = 5
            self._show_step_5()
        elif self.step == 5:
            chosen = self.path_var.get().strip()
            if os.path.basename(chosen.rstrip("\\/")) != "NetPhantom":
                chosen = os.path.join(chosen, "NetPhantom")
            self.install_dir = os.path.normpath(chosen)
            self.step = 6
            self._show_step_6()
        elif self.step == 6:
            self.step = 7
            self._show_step_7()
        elif self.step == 7:
            pass
        elif self.step == 8:
            if self.run_app_var.get():
                target_exe = os.path.join(self.install_dir, "NetPhantom.exe")
                if os.path.exists(target_exe):
                    try:
                        import ctypes
                        ctypes.windll.shell32.ShellExecuteW(
                            None, "runas", target_exe, None, self.install_dir, 1
                        )
                    except Exception as e:
                        messagebox.showerror("Launch Error", f"Could not launch NetPhantom:\n{e}")
                else:
                    messagebox.showwarning(
                        "Launch Error",
                        "NetPhantom.exe not found. Please reinstall NetPhantom.\n\n"
                        f"Expected at: {target_exe}"
                    )
            self.root.destroy()


    def _perform_installation(self):
        try:
            # Create installation directory with automatic user directory fallback if Access Denied
            try:
                os.makedirs(self.install_dir, exist_ok=True)
                test_file = os.path.join(self.install_dir, ".perm_test")
                with open(test_file, "w") as f:
                    f.write("ok")
                if os.path.exists(test_file):
                    os.remove(test_file)
            except (PermissionError, OSError):
                local_appdata = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
                self.install_dir = os.path.normpath(os.path.join(local_appdata, "Programs", "NetPhantom"))
                os.makedirs(self.install_dir, exist_ok=True)

            self.progress["value"] = 25
            self.lbl_status.config(text="Extracting NetPhantom application binary...")
            self.root.update()

            base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))

            # 1. Purge only web/repository clutter — preserve netphantom/ package (the actual app)
            unwanted_items = [
                ".github", "website", "docs", "docs.html", "index.html",
                "download.html", "privacy.html", "threats.html", "404.html", "style.css", "script.js",
                "CNAME", "sitemap.xml", "robots.txt", ".gitignore", "README.md", "SECURITY.md",
                "requirements.txt", "setup.py", "NetPhantom_Setup.zip", "NetPhantom_Setup.exe",
                "skills-lock.json"
            ]
            for item in unwanted_items:
                target_path = os.path.join(self.install_dir, item)
                if os.path.isfile(target_path):
                    try:
                        os.remove(target_path)
                    except Exception:
                        pass
                elif os.path.isdir(target_path):
                    try:
                        shutil.rmtree(target_path, ignore_errors=True)
                    except Exception:
                        pass

            # 2. Extract Wireshark-style enterprise directory bundle (NetPhantom.exe + _internal/ DLLs + assets)
            app_bundle_src = os.path.join(base_path, "app_files")
            if not os.path.exists(app_bundle_src):
                app_bundle_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "NetPhantom")

            if os.path.exists(app_bundle_src):
                for item in os.listdir(app_bundle_src):
                    src_item = os.path.join(app_bundle_src, item)
                    dst_item = os.path.join(self.install_dir, item)
                    try:
                        if os.path.isdir(src_item):
                            if os.path.exists(dst_item):
                                shutil.rmtree(dst_item, ignore_errors=True)
                            shutil.copytree(src_item, dst_item)
                        else:
                            shutil.copy2(src_item, dst_item)
                    except Exception as copy_err:
                        print(f"Bundle extract notice ({item}): {copy_err}")
            else:
                # Fallback standalone binary copy
                essential_files = ["NetPhantom.exe", "logo.png", "logo.ico"]
                for file_name in essential_files:
                    src_file = os.path.join(base_path, file_name)
                    if not os.path.exists(src_file):
                        src_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", file_name)
                    if os.path.exists(src_file):
                        try:
                            shutil.copy2(src_file, os.path.join(self.install_dir, file_name))
                        except Exception:
                            pass

            self.progress["value"] = 65
            self.lbl_status.config(text="Creating application shortcuts...")
            self.root.update()

            # Create Launcher CMD File with Python fallback and crash logging
            cmd_launcher = os.path.join(self.install_dir, "NetPhantom.cmd")
            try:
                with open(cmd_launcher, "w", encoding="utf-8") as f:
                    f.write('@echo off\n')
                    f.write('title NetPhantom v3.3.1\n')
                    f.write('cd /d "%~dp0"\n')
                    f.write('\n')
                    f.write('REM --- Try PyInstaller exe first ---\n')
                    f.write('if exist "NetPhantom.exe" (\n')
                    f.write('    start "" "NetPhantom.exe" %*\n')
                    f.write('    goto :eof\n')
                    f.write(')\n')
                    f.write('\n')
                    f.write('REM --- Fallback: run from Python source ---\n')
                    f.write('if exist "netphantom\\main.py" (\n')
                    f.write('    echo [NetPhantom] PyInstaller exe not found, launching from Python source...\n')
                    f.write('    pythonw -m netphantom %*\n')
                    f.write('    if errorlevel 1 (\n')
                    f.write('        python -m netphantom %*\n')
                    f.write('    )\n')
                    f.write('    goto :eof\n')
                    f.write(')\n')
                    f.write('\n')
                    f.write('echo [NetPhantom] ERROR: Neither NetPhantom.exe nor netphantom package found.\n')
                    f.write('echo Please reinstall NetPhantom.\n')
                    f.write('pause\n')
            except Exception:
                pass

            uninst_script = os.path.join(self.install_dir, "Uninstall.cmd")
            try:
                with open(uninst_script, "w", encoding="utf-8") as f:
                    f.write('@echo off\n')
                    f.write('setlocal enabledelayedexpansion\n')
                    f.write('title NetPhantom Uninstaller\n')
                    f.write('echo Uninstalling NetPhantom v3.3.1...\n')
                    f.write('taskkill /F /IM NetPhantom.exe >nul 2>&1\n')
                    f.write('timeout /t 1 >nul\n')
                    f.write('del /q "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\NetPhantom\\NetPhantom.lnk" >nul 2>&1\n')
                    f.write('rmdir "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\NetPhantom" >nul 2>&1\n')
                    f.write('del /q "%USERPROFILE%\\Desktop\\NetPhantom.lnk" >nul 2>&1\n')
                    f.write('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NetPhantom" /f >nul 2>&1\n')
                    f.write('reg delete "HKCU\\Software\\Classes\\NetPhantom.PacketCapture" /f >nul 2>&1\n')
                    f.write('echo Removing install directory...\n')
                    # Capture the install dir BEFORE changing directory
                    f.write('set "TARGET_DIR=%~dp0"\n')
                    f.write('REM Strip trailing backslash for rmdir compatibility\n')
                    f.write('if "!TARGET_DIR:~-1!"=="\\" set "TARGET_DIR=!TARGET_DIR:~0,-1!"\n')
                    f.write('cd /d "%TEMP%"\n')
                    f.write('echo Uninstall complete.\n')
                    # Use a delayed cmd process to delete the folder after Uninstall.cmd exits
                    f.write('start /b "" cmd /c "ping 127.0.0.1 -n 2 >nul & rmdir /s /q \"!TARGET_DIR!\""\n')
                    f.write('exit\n')
            except Exception:
                pass

            # Create crash log wrapper script
            debug_launcher = os.path.join(self.install_dir, "NetPhantom_Debug.cmd")
            try:
                with open(debug_launcher, "w", encoding="utf-8") as f:
                    f.write('@echo off\n')
                    f.write('title NetPhantom Debug Mode\n')
                    f.write('cd /d "%~dp0"\n')
                    f.write('echo ================================================\n')
                    f.write('echo  NetPhantom v3.3.1 - Debug Launch\n')
                    f.write('echo ================================================\n')
                    f.write('echo.\n')
                    f.write('if exist "NetPhantom.exe" (\n')
                    f.write('    echo [*] Launching NetPhantom.exe with console output...\n')
                    f.write('    "NetPhantom.exe" %*\n')
                    f.write(') else if exist "netphantom\\main.py" (\n')
                    f.write('    echo [*] Launching from Python source with console output...\n')
                    f.write('    python -m netphantom %*\n')
                    f.write(') else (\n')
                    f.write('    echo [!] ERROR: NetPhantom not found. Please reinstall.\n')
                    f.write(')\n')
                    f.write('echo.\n')
                    f.write('if errorlevel 1 echo [!] Process exited with error code %errorlevel%\n')
                    f.write('echo.\n')
                    f.write('pause\n')
            except Exception:
                pass

            dest_exe = os.path.join(self.install_dir, "NetPhantom.exe")
            cmd_launcher = os.path.join(self.install_dir, "NetPhantom.cmd")
            py_main = os.path.join(self.install_dir, "netphantom", "main.py")

            # Pick the best available target for shortcuts
            if os.path.exists(dest_exe):
                target_exe = dest_exe
            elif os.path.exists(cmd_launcher):
                target_exe = cmd_launcher
            elif os.path.exists(py_main):
                # Create a Python-based shortcut launcher
                py_launcher = os.path.join(self.install_dir, "NetPhantom_Python.cmd")
                try:
                    with open(py_launcher, "w", encoding="utf-8") as f:
                        f.write('@echo off\n')
                        f.write('cd /d "%~dp0"\n')
                        f.write('pythonw -m netphantom %*\n')
                except Exception:
                    pass
                target_exe = py_launcher if os.path.exists(py_launcher) else cmd_launcher
            else:
                target_exe = cmd_launcher

            if self.shortcut_desktop.get():
                desktop_path = winshell.desktop()
                shortcut_path = os.path.join(desktop_path, "NetPhantom.lnk")
                self._create_link(target_exe, shortcut_path, "NetPhantom Network Analyzer")

            if self.shortcut_start.get():
                start_menu_path = winshell.programs()
                group_dir = os.path.join(start_menu_path, "NetPhantom")
                os.makedirs(group_dir, exist_ok=True)
                shortcut_path = os.path.join(group_dir, "NetPhantom.lnk")
                self._create_link(target_exe, shortcut_path, "NetPhantom Network Analyzer")

            # 3. Associate File Extensions in Windows Registry if selected
            if getattr(self, "assoc_files_var", None) and self.assoc_files_var.get():
                try:
                    self._register_file_associations()
                except Exception:
                    pass

            # 5. Auto-Install Npcap 1.80 Driver if missing or requested
            if getattr(self, "install_npcap_var", None) and self.install_npcap_var.get():
                self.lbl_status.config(text="Auto-installing Npcap 1.88 Packet Capture Driver...")
                self.progress["value"] = 88
                self.root.update()
                
                npcap_exe = os.path.join(base_path, "npcap_installer.exe")
                if not os.path.exists(npcap_exe):
                    npcap_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "npcap_installer.exe")
                
                if os.path.exists(npcap_exe):
                    try:
                        if os.name == 'nt':
                            import ctypes
                            ctypes.windll.shell32.ShellExecuteW(None, "runas", npcap_exe, "/winpcap_mode=yes /loopback_support=yes /S", None, 1)
                        else:
                            import subprocess
                            subprocess.run([npcap_exe, "/S"], check=False)
                    except Exception as e:
                        print("Npcap driver install notice:", e)

            # Complete!
            self.progress["value"] = 100
            self.lbl_status.config(text="Setup complete!")
            self.root.update()
            
            self.step = 8
            self._show_step_8()

        except Exception as e:
            messagebox.showerror("Installation Failed", f"An error occurred: {e}")
            self.root.destroy()

    def _register_file_associations(self):
        if os.name != 'nt':
            return
        import winreg
        cmd_launcher = os.path.join(self.install_dir, "NetPhantom.cmd")
        py_main = os.path.join(self.install_dir, "netphantom", "main.py")
        
        python_exe = sys.executable
        if "python.exe" in python_exe.lower() or "pythonw.exe" in python_exe.lower():
            py_bin = python_exe.replace("python.exe", "pythonw.exe")
        else:
            py_bin = "pythonw"

        launch_cmd = f'"{cmd_launcher}" "%1"' if os.path.exists(cmd_launcher) else f'"{py_bin}" "{py_main}" "%1"'
        exts = [".pcap", ".pcapng", ".cap", ".pkt", ".snoop", ".trc"]
        app_prog_id = "NetPhantom.PacketCapture"

        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{app_prog_id}") as key:
                winreg.SetValue(key, "", winreg.REG_SZ, "NetPhantom Packet Capture File")
                with winreg.CreateKey(key, r"shell\open\command") as cmd_key:
                    winreg.SetValue(cmd_key, "", winreg.REG_SZ, launch_cmd)

            for ext in exts:
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{ext}") as ext_key:
                    winreg.SetValue(ext_key, "", winreg.REG_SZ, app_prog_id)

            self._register_uninstall_entry()
        except Exception as e:
            print("File association registry notice:", e)

    def _register_uninstall_entry(self):
        """Write Windows Add/Remove Programs registry entry (HKCU — no elevation needed)."""
        if os.name != 'nt':
            return
        import winreg
        uninst_key_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\NetPhantom"
        icon_path = os.path.join(self.install_dir, "logo.ico")
        uninst_cmd = f'"{os.path.join(self.install_dir, "Uninstall.cmd")}"'

        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, uninst_key_path) as ukey:
                winreg.SetValueEx(ukey, "DisplayName",    0, winreg.REG_SZ, "NetPhantom Network Analyzer v3.3.1")
                winreg.SetValueEx(ukey, "Publisher",      0, winreg.REG_SZ, "Luckyverse Security")
                winreg.SetValueEx(ukey, "DisplayVersion", 0, winreg.REG_SZ, "3.3.1")
                winreg.SetValueEx(ukey, "DisplayIcon",    0, winreg.REG_SZ,
                                  icon_path if os.path.exists(icon_path) else
                                  os.path.join(self.install_dir, "NetPhantom.exe"))
                winreg.SetValueEx(ukey, "InstallLocation", 0, winreg.REG_SZ, self.install_dir)
                winreg.SetValueEx(ukey, "UninstallString", 0, winreg.REG_SZ, uninst_cmd)
                winreg.SetValueEx(ukey, "NoModify",  0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(ukey, "NoRepair",  0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(ukey, "Comments",  0, winreg.REG_SZ,
                                  "NetPhantom Professional Network Packet Analyzer")
        except Exception as e:
            print("Uninstall registry notice:", e)

    def _create_link(self, target, link_path, description):
        icon_file = os.path.join(self.install_dir, "logo.ico")
        if not os.path.exists(icon_file):
            icon_file = os.path.join(self.install_dir, "logo.png")
        if Dispatch:
            try:
                shell = Dispatch('WScript.Shell')
                shortcut = shell.CreateShortCut(link_path)
                shortcut.Targetpath = target
                shortcut.WorkingDirectory = self.install_dir
                shortcut.Description = description
                if os.path.exists(icon_file):
                    shortcut.IconLocation = f"{icon_file},0"
                elif os.path.exists(target) and target.endswith(".exe"):
                    shortcut.IconLocation = f"{target},0"
                shortcut.save()
                return
            except Exception:
                pass
        if winshell:
            try:
                winshell.CreateShortcut(
                    Path=link_path,
                    Target=target,
                    WorkingDirectory=self.install_dir,
                    Icon=(icon_file if os.path.exists(icon_file) else target, 0),
                    Description=description
                )
            except Exception:
                pass

if __name__ == "__main__":
    # Apply High DPI to installer window
    try:
        if os.name == 'nt':
            import ctypes
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                try:
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass
    except Exception:
        pass

    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use("clam")
    
    # Custom progressbar style
    style.configure("Horizontal.TProgressbar",
                    troughcolor=BG_PANEL, background=ACCENT_BLUE,
                    bordercolor=BG_BASE)
    
    app = SetupWizard(root)
    root.mainloop()
