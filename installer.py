"""
installer.py - Graphical Setup Wizard for NetPhantom v3.0
Author: Luckyverse | Cybersecurity Project

This script is compiled with the bundled NetPhantom.exe to form NetPhantom_Setup.exe.
It guides the user through EULA agreement, location selection, shortcut selection,
extracts the executable, and configures the desktop shortcuts.
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
        
        # To set a custom window icon for the installer later, uncomment the following block:
        # try:
        #     self.root.iconbitmap("logo.ico")
        # except Exception:
        #     pass

        self.root.configure(bg=BG_BASE)
        self.root.geometry("560x420")
        self.root.resizable(False, False)

        # Center window
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"560x420+{(sw-560)//2}+{(sh-420)//2}")

        # Default Install Path
        local_app_data = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
        self.install_dir = os.path.join(local_app_data, "Programs", "NetPhantom")

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
        # Clear content frame
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Choose Install Location")
        self.subtitle_lbl.config(text="Where should NetPhantom be installed?")

        lbl_desc = tk.Label(self.content_frame,
                            text="Setup will install NetPhantom in the following folder.\n"
                                 "To install to this folder, click Next. To install to a different folder, enter it below.",
                            bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 9),
                            justify="left", anchor="w")
        lbl_desc.pack(fill=tk.X, pady=(0, 10))

        # Path input box
        path_frame = tk.Frame(self.content_frame, bg=BG_BASE)
        path_frame.pack(fill=tk.X, pady=8)

        self.path_var = tk.StringVar(value=self.install_dir)
        self.entry_path = tk.Entry(path_frame, textvariable=self.path_var, bg=BG_INPUT,
                                   fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                                   font=("Segoe UI", 9), relief="flat", bd=6)
        # Fix pack arguments: replaced incorrect marginRight with padx=(0, 6)
        self.entry_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        btn_browse = tk.Button(path_frame, text="Browse...", command=self._browse_dir,
                               bg=BG_INPUT, fg=TEXT_PRIMARY, activebackground=BG_HOVER,
                               activeforeground=TEXT_PRIMARY, font=("Segoe UI", 9),
                               relief="flat", bd=0, padx=12, pady=4, cursor="hand2")
        btn_browse.pack(side=tk.RIGHT, padx=(8, 0))

        # Shortcut Options
        self.shortcut_desktop = tk.BooleanVar(value=True)
        self.shortcut_start = tk.BooleanVar(value=True)

        chk_frame = tk.Frame(self.content_frame, bg=BG_BASE)
        chk_frame.pack(fill=tk.X, pady=12)

        tk.Checkbutton(chk_frame, text="Create a desktop shortcut", variable=self.shortcut_desktop,
                       bg=BG_BASE, fg=TEXT_PRIMARY, activebackground=BG_BASE,
                       activeforeground=TEXT_PRIMARY, selectcolor=BG_INPUT,
                       font=("Segoe UI", 9)).pack(anchor="w", pady=2)

        tk.Checkbutton(chk_frame, text="Create a Start Menu program group shortcut", variable=self.shortcut_start,
                       bg=BG_BASE, fg=TEXT_PRIMARY, activebackground=BG_BASE,
                       activeforeground=TEXT_PRIMARY, selectcolor=BG_INPUT,
                       font=("Segoe UI", 9)).pack(anchor="w", pady=2)

    def _show_step_4(self):
        # Clear content frame
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Installing NetPhantom")
        self.subtitle_lbl.config(text="Please wait while Setup installs NetPhantom on your system.")

        self.btn_next.config(state=tk.DISABLED)
        self.btn_cancel.config(state=tk.DISABLED)

        self.lbl_status = tk.Label(self.content_frame, text="Extracting files...",
                                   bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 9))
        self.lbl_status.pack(anchor="w", pady=(20, 4))

        self.progress = ttk.Progressbar(self.content_frame, mode="determinate", length=480)
        self.progress.pack(fill=tk.X, pady=8)

        # Trigger installation after UI updates
        self.root.after(500, self._perform_installation)

    def _show_step_5(self):
        # Clear content frame
        for child in self.content_frame.winfo_children():
            child.destroy()

        self.title_lbl.config(text="Installation Complete")
        self.subtitle_lbl.config(text="NetPhantom has been successfully installed.")

        self.btn_next.config(text="Finish", state=tk.NORMAL)
        self.btn_cancel.pack_forget()

        # Run Checkbox
        self.run_app_var = tk.BooleanVar(value=True)
        
        lbl_finished = tk.Label(self.content_frame,
                                text="Setup has finished installing NetPhantom on your computer.\n"
                                     "The application may be launched by selecting the created shortcuts.",
                                bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 10),
                                justify="left", anchor="w")
        lbl_finished.pack(fill=tk.X, pady=10)

        chk_run = tk.Checkbutton(self.content_frame, text="Launch NetPhantom now", variable=self.run_app_var,
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
            chosen = self.path_var.get().strip()
            if os.path.basename(chosen.rstrip("\\/")) != "NetPhantom":
                chosen = os.path.join(chosen, "NetPhantom")
            self.install_dir = os.path.normpath(chosen)
            self.step = 4
            self._show_step_4()
        elif self.step == 5:
            # Finish action
            if self.run_app_var.get():
                # Launch the app
                exe_path = os.path.join(self.install_dir, "NetPhantom.exe")
                try:
                    os.startfile(exe_path)
                except Exception as e:
                    messagebox.showerror("Error", f"Could not launch NetPhantom: {e}")
            self.root.destroy()

    def _perform_installation(self):
        try:
            # Create installation directory
            os.makedirs(self.install_dir, exist_ok=True)
            self.progress["value"] = 15
            self.lbl_status.config(text="Creating target folders...")
            self.root.update()

            # Locate the bundled NetPhantom.exe
            base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            
            # Source file path
            src_exe = os.path.join(base_path, "NetPhantom.exe")
            
            # If running locally for testing, check dist/NetPhantom.exe
            if not os.path.exists(src_exe):
                src_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "NetPhantom.exe")

            if not os.path.exists(src_exe):
                raise FileNotFoundError(f"Embedded executable not found. Make sure NetPhantom.exe is built first.")

            # Destination file path
            dest_exe = os.path.join(self.install_dir, "NetPhantom.exe")

            self.progress["value"] = 35
            self.lbl_status.config(text="Extracting NetPhantom.exe...")
            self.root.update()

            # Copy the executable
            shutil.copy2(src_exe, dest_exe)

            # Copy source modules (so CLI 'netphantom' works locally)
            self.progress["value"] = 50
            self.lbl_status.config(text="Extracting python source files...")
            self.root.update()

            source_files = ["main.py", "gui.py", "capture.py", "analyzer.py", "setup.py", "requirements.txt"]
            for file_name in source_files:
                src_file = os.path.join(base_path, file_name)
                if not os.path.exists(src_file):
                    src_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_name)
                
                if os.path.exists(src_file):
                    shutil.copy2(src_file, os.path.join(self.install_dir, file_name))

            # Auto-Install requirements and CLI command via pip if Python exists
            self.progress["value"] = 70
            self.lbl_status.config(text="Installing requirements and registering CLI command...")
            self.root.update()

            import subprocess
            pip_commands = [
                ["python", "-m", "pip", "install", "-r", "requirements.txt"],
                ["python", "-m", "pip", "install", "-e", "."]
            ]
            
            # Execute pip installation silently (no popups)
            for cmd in pip_commands:
                try:
                    subprocess.run(
                        cmd,
                        cwd=self.install_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=0x08000000 if os.name == 'nt' else 0 # CREATE_NO_WINDOW
                    )
                except Exception:
                    # Try fallback to 'py' command
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

            # Create Shortcuts
            self.progress["value"] = 85
            self.lbl_status.config(text="Creating system shortcuts...")
            self.root.update()

            if self.shortcut_desktop.get():
                desktop_path = winshell.desktop()
                shortcut_path = os.path.join(desktop_path, "NetPhantom.lnk")
                self._create_link(dest_exe, shortcut_path, "NetPhantom Network Analyzer")

            if self.shortcut_start.get():
                start_menu_path = winshell.programs()
                group_dir = os.path.join(start_menu_path, "NetPhantom")
                os.makedirs(group_dir, exist_ok=True)
                shortcut_path = os.path.join(group_dir, "NetPhantom.lnk")
                self._create_link(dest_exe, shortcut_path, "NetPhantom Network Analyzer")

            # Complete!
            self.progress["value"] = 100
            self.lbl_status.config(text="Setup complete!")
            self.root.update()
            
            self.step = 5
            self._show_step_5()

        except Exception as e:
            messagebox.showerror("Installation Failed", f"An error occurred: {e}")
            self.root.destroy()

    def _create_link(self, target, link_path, description):
        try:
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(link_path)
            shortcut.Targetpath = target
            shortcut.WorkingDirectory = os.path.dirname(target)
            shortcut.Description = description
            shortcut.save()
        except Exception as e:
            # Fallback using winshell
            try:
                winshell.CreateShortcut(
                    Path=link_path,
                    Target=target,
                    Icon=(target, 0),
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
        try:
            # Relaunch the executable/script requesting administrator access
            # ShellExecuteW with verb 'runas' prompts Windows UAC approval dialog
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
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
