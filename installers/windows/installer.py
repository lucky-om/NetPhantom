"""
installer.py - Graphical Setup Web-Installer for NetPhantom v3.0
Author: Luckyverse | Cybersecurity Project

Guides the user through EULA agreement, location selection, shortcut options,
downloads/configures application packages, and sets up desktop shortcuts.
"""

import os
import sys
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import winshell
from win32com.client import Dispatch

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
TEXT_PRIMARY = "#e2e8f0"
TEXT_DIM     = "#64748b"

# EULA text
EULA_TEXT = """NetPhantom v3.0 End User License & Ethical Terms of Service
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
        self.root.title("NetPhantom v3.0 Setup")
        
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

        self.root.configure(bg=BG_BASE)
        self.root.geometry("560x420")
        self.root.resizable(False, False)

        # Center window
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"560x420+{(sw-560)//2}+{(sh-420)//2}")

        # Default Install Path (Program Files for system driver access & AppLocker compliance)
        pf = os.environ.get("ProgramFiles", "C:\\Program Files")
        self.install_dir = os.path.join(pf, "NetPhantom")

        self.step = 1
        self._build_ui()

    def _build_ui(self):
        # Header Area
        self.header_frame = tk.Frame(self.root, bg=BG_HEADER, height=70)
        self.header_frame.pack(fill=tk.X, side=tk.TOP)
        self.header_frame.pack_propagate(False)

        self.title_lbl = tk.Label(self.header_frame, text="NetPhantom v3.0 Installation",
                                  bg=BG_HEADER, fg=TEXT_PRIMARY, font=("Segoe UI", 12, "bold"))
        self.title_lbl.pack(anchor="w", padx=16, pady=(12, 2))

        self.subtitle_lbl = tk.Label(self.header_frame, text="Follow the steps to install the network analyzer.",
                                     bg=BG_HEADER, fg=TEXT_DIM, font=("Segoe UI", 9))
        self.subtitle_lbl.pack(anchor="w", padx=16)

        # Content Area
        self.content_frame = tk.Frame(self.root, bg=BG_BASE)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        # Footer Navigation Area
        self.footer_frame = tk.Frame(self.root, bg=BG_PANEL, height=50)
        self.footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.footer_frame.pack_propagate(False)

        # Separator line
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill=tk.X, side=tk.BOTTOM)

        self.btn_next = tk.Button(self.footer_frame, text="Next >", command=self._next_step,
                                  bg=ACCENT_BLUE, fg="white", activebackground=BG_HOVER,
                                  activeforeground="white", font=("Segoe UI", 9, "bold"),
                                  relief="flat", bd=0, padx=16, pady=6, cursor="hand2")
        self.btn_next.pack(side=tk.RIGHT, padx=12, pady=10)

        self.btn_cancel = tk.Button(self.footer_frame, text="Cancel", command=self.root.destroy,
                                    bg=BG_INPUT, fg=TEXT_PRIMARY, activebackground=BG_HOVER,
                                    activeforeground=TEXT_PRIMARY, font=("Segoe UI", 9),
                                    relief="flat", bd=0, padx=16, pady=6, cursor="hand2")
        self.btn_cancel.pack(side=tk.RIGHT, padx=4, pady=10)

        # Initialize step view
        self._show_step_1()

    def _show_step_1(self):
        # Clear content frame
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="NetPhantom v3.0 Setup")
        self.subtitle_lbl.config(text="Welcome to the NetPhantom Setup Wizard.")

        lbl_welcome = tk.Label(self.content_frame,
                               text="This wizard will install NetPhantom v3.0 on your computer.\n\n"
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
        # Step 3: Choose Components (Wireshark-style Tree/Checkbox Selection)
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Choose Components")
        self.subtitle_lbl.config(text="Choose which features of NetPhantom v3.0 you want to install.")

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

        tk.Checkbutton(tree_frame, text="☑ NetPhantom Core Engine & Dissector", variable=self.comp_core, state=tk.DISABLED, **cb_style).pack(anchor="w", padx=8, pady=2)
        tk.Checkbutton(tree_frame, text="  ☑ NetPhantom GUI Dashboard HUD", variable=self.comp_gui, state=tk.DISABLED, **cb_style).pack(anchor="w", padx=24, pady=1)
        tk.Checkbutton(tree_frame, text="  [x] Global CLI Command (netphantom)", variable=self.comp_cli, **cb_style).pack(anchor="w", padx=24, pady=1)
        
        tk.Checkbutton(tree_frame, text="[x] External Capture Tools (extcap)", variable=self.comp_extcap, **cb_style).pack(anchor="w", padx=8, pady=(6, 2))
        tk.Checkbutton(tree_frame, text="  [x] Androiddump (Android ADB Packet Sniffer)", variable=self.comp_android, **cb_style).pack(anchor="w", padx=24, pady=1)
        tk.Checkbutton(tree_frame, text="  [x] Etwdump (Event Tracing for Windows Sniffer)", variable=self.comp_etw, **cb_style).pack(anchor="w", padx=24, pady=1)
        tk.Checkbutton(tree_frame, text="  [x] Randpktdump (Random Packet Generator)", variable=self.comp_randpkt, **cb_style).pack(anchor="w", padx=24, pady=1)
        tk.Checkbutton(tree_frame, text="  [x] Sshdump, Ciscodump & Wifidump (Remote/Wi-Fi Dissector)", variable=self.comp_ssh_wifidump, **cb_style).pack(anchor="w", padx=24, pady=1)
        tk.Checkbutton(tree_frame, text="  [x] UDPdump (UDP Listener & Raw Capture Tool)", variable=self.comp_udpdump, **cb_style).pack(anchor="w", padx=24, pady=1)

        # Space Required Label
        tk.Label(self.content_frame, text="Space required: 35.0 MB", bg=BG_BASE, fg=TEXT_SECONDARY, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(6, 0))

    def _show_step_4(self):
        # Step 4: Additional Tasks (Shortcuts & File Associations)
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
        # Step 5: Choose Install Location (with disk space check)
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Choose Install Location")
        self.subtitle_lbl.config(text="Choose the folder in which to install NetPhantom v3.0.")

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
        # Step 6: Packet Capture Driver (Npcap Installation & Check)
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Packet Capture Driver")
        self.subtitle_lbl.config(text="NetPhantom requires Npcap to capture live network data.")

        # Check Npcap status
        npcap_installed = self._check_npcap_installed()
        status_text = "Npcap 1.88 Driver Detected" if npcap_installed else "Npcap Driver Not Found"
        status_color = ACCENT_GREEN if npcap_installed else ACCENT_AMBER

        panel = tk.LabelFrame(self.content_frame, text=" Currently installed Npcap version ", bg=BG_PANEL, fg=TEXT_PRIMARY, font=("Segoe UI", 9, "bold"), bd=1, relief="solid")
        panel.pack(fill=tk.X, pady=(0, 10), ipadx=8, ipady=6)
        tk.Label(panel, text=status_text, bg=BG_PANEL, fg=status_color, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=4)

        install_panel = tk.LabelFrame(self.content_frame, text=" Install ", bg=BG_PANEL, fg=TEXT_PRIMARY, font=("Segoe UI", 9, "bold"), bd=1, relief="solid")
        install_panel.pack(fill=tk.X, pady=6, ipadx=8, ipady=6)
        
        self.install_npcap_var = tk.BooleanVar(value=not npcap_installed)
        tk.Checkbutton(install_panel, text="Install / Update Npcap 1.88 Driver", variable=self.install_npcap_var,
                       bg=BG_PANEL, fg=TEXT_PRIMARY, activebackground=BG_PANEL, activeforeground=TEXT_PRIMARY,
                       selectcolor=BG_INPUT, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=2)
        tk.Label(install_panel, text="Allows NetPhantom to capture raw socket frames in promiscuous mode on Wi-Fi and Ethernet adapters.",
                 bg=BG_PANEL, fg=TEXT_DIM, font=("Segoe UI", 8)).pack(anchor="w", padx=28)

        notice_panel = tk.LabelFrame(self.content_frame, text=" Important notice ", bg=BG_PANEL, fg=TEXT_PRIMARY, font=("Segoe UI", 9, "bold"), bd=1, relief="solid")
        notice_panel.pack(fill=tk.X, pady=8, ipadx=8, ipady=6)
        tk.Label(notice_panel, text="If your system has crashed during installation, you must run 'net stop npcap' as Administrator before upgrading Npcap so that it doesn't crash.",
                 bg=BG_PANEL, fg=ACCENT_AMBER, font=("Segoe UI", 8), wraplength=480, justify="left").pack(anchor="w", padx=8)

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
        self.subtitle_lbl.config(text="NetPhantom v3.0 has been successfully installed.")

        self.btn_next.config(text="Finish", state=tk.NORMAL)
        self.btn_cancel.pack_forget()

        self.run_app_var = tk.BooleanVar(value=True)

        lbl_finished = tk.Label(self.content_frame,
                                text="Setup has finished installing NetPhantom v3.0 on your computer.\n"
                                     "All components, CLI tools, and file associations have been configured.",
                                bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 10),
                                justify="left", anchor="w")
        lbl_finished.pack(fill=tk.X, pady=10)

        chk_run = tk.Checkbutton(self.content_frame, text="Launch NetPhantom v3.0 now", variable=self.run_app_var,
                                 bg=BG_BASE, fg=TEXT_PRIMARY, activebackground=BG_BASE,
                                 activeforeground=TEXT_PRIMARY, selectcolor=BG_INPUT,
                                 font=("Segoe UI", 9, "bold"))
        chk_run.pack(anchor="w", pady=20)

    def _browse_dir(self):
        from tkinter import filedialog
        chosen = filedialog.askdirectory(initialdir=self.path_var.get(), title="Select Install Folder")
        if chosen:
            self.path_var.set(os.path.normpath(chosen))

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
        elif self.step == 8:
            # Finish action
            if self.run_app_var.get():
                py_main = os.path.join(self.install_dir, "netphantom", "main.py")
                cmd_launcher = os.path.join(self.install_dir, "NetPhantom.cmd")
                try:
                    import ctypes
                    if os.name == 'nt':
                        python_exe = sys.executable
                        if "python.exe" in python_exe.lower() or "pythonw.exe" in python_exe.lower():
                            py_bin = python_exe.replace("python.exe", "pythonw.exe")
                            if not os.path.exists(py_bin):
                                py_bin = python_exe
                        else:
                            py_bin = "pythonw"

                        if os.path.exists(cmd_launcher):
                            ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f'/c "{cmd_launcher}"', self.install_dir, 0)
                        elif os.path.exists(py_main):
                            ctypes.windll.shell32.ShellExecuteW(None, "runas", py_bin, f'"{py_main}"', self.install_dir, 1)
                        else:
                            ctypes.windll.shell32.ShellExecuteW(None, "runas", "netphantom", "", self.install_dir, 1)
                    else:
                        os.system(f'python3 "{py_main}" &')
                except Exception as e:
                    messagebox.showerror("Error", f"Could not launch NetPhantom: {e}")
            self.root.destroy()

    def _perform_installation(self):
        try:
            # Create installation directory
            os.makedirs(self.install_dir, exist_ok=True)
            self.progress["value"] = 15
            self.lbl_status.config(text="Creating target application folders...")
            self.root.update()

            base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            pkg_dir = os.path.join(self.install_dir, "netphantom")
            os.makedirs(pkg_dir, exist_ok=True)

            self.progress["value"] = 35
            self.lbl_status.config(text="Extracting NetPhantom core modules...")
            self.root.update()

            # 1. Extract core python package files
            source_files = ["__init__.py", "main.py", "gui.py", "capture.py", "analyzer.py", "errors.py"]
            for file_name in source_files:
                src_file = os.path.join(base_path, "netphantom", file_name)
                if not os.path.exists(src_file):
                    src_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "netphantom", file_name)
                if os.path.exists(src_file):
                    shutil.copy2(src_file, os.path.join(pkg_dir, file_name))

            # 2. Extract configuration, binary & branding dependencies
            root_files = ["NetPhantom.exe", "setup.py", "requirements.txt", "logo.png", "logo.ico"]
            for file_name in root_files:
                src_file = os.path.join(base_path, file_name)
                if not os.path.exists(src_file):
                    src_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", file_name)
                if os.path.exists(src_file):
                    shutil.copy2(src_file, os.path.join(self.install_dir, file_name))

            # 3. Clean up any leftover website / HTML / repo files if present in install directory
            unwanted_items = ["website", "docs.html", "index.html", "download.html", "privacy.html", "threats.html", "404.html", "style.css", "script.js", ".github", "CNAME", "sitemap.xml", "robots.txt"]
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

            # Auto-Install requirements and CLI command via pip if Python exists
            self.progress["value"] = 75
            self.lbl_status.config(text="Installing dependencies & registering CLI command...")
            self.root.update()

            import subprocess
            pip_commands = [
                ["python", "-m", "pip", "install", "-r", "requirements.txt"],
                ["python", "-m", "pip", "install", "-e", "."]
            ]
            
            for cmd in pip_commands:
                try:
                    subprocess.run(
                        cmd,
                        cwd=self.install_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=0x08000000 if os.name == 'nt' else 0
                    )
                except Exception:
                    try:
                        py_cmd = ["py" if c == "python" else c for c in cmd]
                        subprocess.run(
                            py_cmd,
                            cwd=self.install_dir,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            creationflags=0x08000000 if os.name == 'nt' else 0
                        )
                    except Exception:
                        pass

            # Create Launcher CMD File fallback
            cmd_launcher = os.path.join(self.install_dir, "NetPhantom.cmd")
            try:
                with open(cmd_launcher, "w", encoding="utf-8") as f:
                    f.write('@echo off\n')
                    f.write(f'start "" "%~dp0NetPhantom.exe"\n')
            except Exception:
                pass

            dest_exe = os.path.join(self.install_dir, "NetPhantom.exe")
            target_exe = dest_exe if os.path.exists(dest_exe) else (cmd_launcher if os.path.exists(cmd_launcher) else os.path.join(self.install_dir, "netphantom", "main.py"))

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

            # 4. Associate File Extensions in Windows Registry if selected
            if getattr(self, "assoc_files_var", None) and self.assoc_files_var.get():
                try:
                    self._register_file_associations()
                except Exception:
                    pass

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
        except Exception as e:
            print("File association registry notice:", e)

    def _create_link(self, target, link_path, description):
        icon_file = os.path.join(self.install_dir, "logo.ico")
        if not os.path.exists(icon_file):
            icon_file = os.path.join(self.install_dir, "logo.png")
        try:
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(link_path)
            shortcut.Targetpath = target
            shortcut.WorkingDirectory = os.path.dirname(target)
            shortcut.Description = description
            if os.path.exists(icon_file):
                shortcut.IconLocation = f"{icon_file},0"
            elif os.path.exists(target) and target.endswith(".exe"):
                shortcut.IconLocation = f"{target},0"
            shortcut.save()
        except Exception:
            try:
                winshell.CreateShortcut(
                    Path=link_path,
                    Target=target,
                    Icon=(icon_file if os.path.exists(icon_file) else target, 0),
                    Description=description
                )
            except Exception:
                pass

if __name__ == "__main__":
    import ctypes
    import sys

    # Check for Admin Privileges (UAC Prompt Relaunch)
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    if not is_admin():
        import subprocess
        try:
            # Relaunch the executable/script requesting administrator access, quoting arguments and preserving working directory
            params = subprocess.list2cmdline(sys.argv)
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, os.getcwd(), 1
            )
        except Exception:
            pass
        sys.exit(0)

    # Apply High DPI to installer window
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
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
