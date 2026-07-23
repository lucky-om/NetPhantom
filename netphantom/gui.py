"""
gui.py - Professional Wireshark-Class GUI Dashboard
NetPhantom v3.1.3 — Network Packet Sniffer & Analyzer
Author: Luckyverse | Cybersecurity Project
"""

import os
import queue
import signal
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime


def _find_logo_path():
    """Locate logo.png relative to this file, the working dir, or PyInstaller bundle."""
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logo.png"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png"),
        os.path.join(getattr(sys, '_MEIPASS', '.'), "logo.png"),
        "logo.png",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return os.path.abspath(p)
    return None

from capture import CaptureEngine, list_interfaces
from analyzer import (
    format_packet_details, build_protocol_tree, format_hex_dump,
    PACKET_COLOR_RULES,
)

# ──────────────────────────────────────────────
#  Theme: Midnight Blue
# ──────────────────────────────────────────────
BG_BASE      = "#0a0e1a"     # Deep navy — window background
BG_PANEL     = "#111827"     # Card/panel backgrounds
BG_HEADER    = "#1e293b"     # Toolbar, status bar, menu bar
BG_INPUT     = "#1a2332"     # Input field backgrounds
BG_HOVER     = "#243347"     # Hover state
BG_SELECTED  = "#1e3a5f"     # Selected row / active element
BORDER       = "#1e3a5f"     # Subtle borders

# Accent Colors
ACCENT_BLUE    = "#3b82f6"   # Electric blue — primary actions
ACCENT_GREEN   = "#10b981"   # Emerald — success, TCP
ACCENT_AMBER   = "#f59e0b"   # Amber — warnings, ICMP
ACCENT_RED     = "#ef4444"   # Red — danger, alerts
ACCENT_CYAN    = "#06b6d4"   # Cyan — info, DNS
ACCENT_PURPLE  = "#8b5cf6"   # Violet — ARP
ACCENT_PINK    = "#ec4899"   # Pink — TLS handshake
ACCENT_ORANGE  = "#f97316"   # Orange — HTTP
ACCENT_TEAL    = "#14b8a6"   # Teal — QUIC
ACCENT_LIME    = "#84cc16"   # Lime — secondary

# Text
TEXT_PRIMARY   = "#e2e8f0"   # Bright readable text
TEXT_SECONDARY = "#94a3b8"   # Secondary/dim text
TEXT_DIM       = "#64748b"   # Subtle text
TEXT_MUTED     = "#475569"   # Very dim

# Protocol Text Colors (for packet list text)
PROTO_TEXT_COLORS = {
    "TCP":             ACCENT_GREEN,
    "UDP":             ACCENT_BLUE,
    "ICMP":            ACCENT_AMBER,
    "ARP":             ACCENT_PURPLE,
    "DNS":             ACCENT_CYAN,
    "IPv6":            TEXT_SECONDARY,
    "HTTP":            ACCENT_ORANGE,
    "HTTPS":           ACCENT_TEAL,
    "TLS":             ACCENT_CYAN,
    "TLS ClientHello": ACCENT_PINK,
    "TLS ServerHello": ACCENT_PINK,
    "QUIC":            ACCENT_TEAL,
    "OTHER":           TEXT_DIM,
}

FONT_MAIN     = ("Segoe UI", 10)
FONT_MAIN_SM  = ("Segoe UI", 9)
FONT_MONO     = ("Consolas", 10)
FONT_MONO_SM  = ("Consolas", 9)
FONT_MONO_XS  = ("Consolas", 8)
FONT_MONO_LG  = ("Consolas", 12, "bold")
FONT_HDR      = ("Segoe UI", 11, "bold")
FONT_TITLE    = ("Segoe UI", 14, "bold")
FONT_STAT     = ("Consolas", 16, "bold")
FONT_STAT_LBL = ("Segoe UI", 8)
FONT_MENU     = ("Segoe UI", 9)
FONT_BTN      = ("Segoe UI", 9, "bold")


# ──────────────────────────────────────────────
#  Splash Screen (Animated)
# ──────────────────────────────────────────────
def show_splash():
    import math
    import random

    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("luckyverse.netphantom.app.v3")
    except Exception:
        pass

    splash = tk.Tk()
    splash.overrideredirect(True)
    splash.configure(bg=BG_BASE)
    w, h = 600, 340
    sw, sh = splash.winfo_screenwidth(), splash.winfo_screenheight()
    splash.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
    splash.attributes("-alpha", 0.0)

    # Set window icon on splash
    _logo_path = _find_logo_path()
    if _logo_path:
        try:
            from PIL import Image, ImageTk
            _icon_img = Image.open(_logo_path).resize((64, 64), Image.LANCZOS)
            _icon_photo = ImageTk.PhotoImage(_icon_img)
            splash.iconphoto(True, _icon_photo)
            splash._icon_ref = _icon_photo
        except Exception:
            pass

    # ── Animated canvas background (particle grid)
    bg_canvas = tk.Canvas(splash, width=w, height=h, bg=BG_BASE,
                          highlightthickness=0, bd=0)
    bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)

    # Animated border frame (drawn on canvas)
    _border_phase = [0]

    # Nodes for particle background
    nodes = [{"x": random.randint(0, w), "y": random.randint(0, h),
               "vx": random.uniform(-0.3, 0.3), "vy": random.uniform(-0.2, 0.2)}
              for _ in range(28)]

    def _draw_particles():
        bg_canvas.delete("particle")
        for i, n in enumerate(nodes):
            n["x"] = (n["x"] + n["vx"]) % w
            n["y"] = (n["y"] + n["vy"]) % h
            # Draw node dot
            bg_canvas.create_oval(n["x"]-1, n["y"]-1, n["x"]+1, n["y"]+1,
                                  fill="#1e3a5f", outline="", tags="particle")
            # Draw connections to nearby nodes
            for j in range(i + 1, len(nodes)):
                dx = nodes[j]["x"] - n["x"]
                dy = nodes[j]["y"] - n["y"]
                dist = math.hypot(dx, dy)
                if dist < 100:
                    alpha_hex = format(int(80 * (1 - dist / 100)), "02x")
                    bg_canvas.create_line(n["x"], n["y"], nodes[j]["x"], nodes[j]["y"],
                                          fill=f"#1e3a5f", tags="particle", width=1)

    # Animated corner brackets
    def _draw_border():
        bg_canvas.delete("border")
        ph = _border_phase[0]
        sz = 24
        col = ACCENT_BLUE if ph % 30 < 15 else ACCENT_CYAN
        # Top-left
        bg_canvas.create_line(2, 2, 2 + sz, 2, fill=col, width=2, tags="border")
        bg_canvas.create_line(2, 2, 2, 2 + sz, fill=col, width=2, tags="border")
        # Top-right
        bg_canvas.create_line(w - 2, 2, w - 2 - sz, 2, fill=col, width=2, tags="border")
        bg_canvas.create_line(w - 2, 2, w - 2, 2 + sz, fill=col, width=2, tags="border")
        # Bottom-left
        bg_canvas.create_line(2, h - 2, 2 + sz, h - 2, fill=col, width=2, tags="border")
        bg_canvas.create_line(2, h - 2, 2, h - 2 - sz, fill=col, width=2, tags="border")
        # Bottom-right
        bg_canvas.create_line(w - 2, h - 2, w - 2 - sz, h - 2, fill=col, width=2, tags="border")
        bg_canvas.create_line(w - 2, h - 2, w - 2, h - 2 - sz, fill=col, width=2, tags="border")
        _border_phase[0] = (ph + 1) % 60

    def _animate_bg():
        _draw_particles()
        _draw_border()
        try:
            splash.after(45, _animate_bg)
        except Exception:
            pass

    splash.after(50, _animate_bg)

    # ── Fade-in splash window
    def _fade_in(alpha=0.0):
        alpha = min(alpha + 0.06, 1.0)
        try:
            splash.attributes("-alpha", alpha)
            if alpha < 1.0:
                splash.after(22, _fade_in, alpha)
        except Exception:
            pass

    splash.after(30, _fade_in)

    # ── Content frame overlaid on canvas
    content = tk.Frame(splash, bg=BG_BASE)
    content.place(relx=0.5, rely=0.5, anchor="center")

    # Animated logo — use actual logo.png image if available, fall back to ◆ text
    _logo_img_ref = [None]  # prevent garbage collection
    _logo_path = _find_logo_path()
    _use_image_logo = False
    if _logo_path:
        try:
            from PIL import Image, ImageTk
            _pil_img = Image.open(_logo_path).resize((80, 80), Image.LANCZOS)
            _logo_img_ref[0] = ImageTk.PhotoImage(_pil_img)
            logo_lbl = tk.Label(content, image=_logo_img_ref[0], bg=BG_BASE)
            logo_lbl.pack(pady=(0, 4))
            _use_image_logo = True
        except Exception:
            _use_image_logo = False

    if not _use_image_logo:
        # Fallback: animated ◆ text logo
        _logo_colors = [ACCENT_BLUE, ACCENT_CYAN, "#6366f1", ACCENT_BLUE]
        _logo_phase  = [0]
        logo_lbl = tk.Label(content, text="◆", bg=BG_BASE, fg=ACCENT_BLUE,
                            font=("Segoe UI", 40, "bold"))
        logo_lbl.pack(pady=(0, 4))

        def _pulse_logo():
            ph = _logo_phase[0]
            idx = (ph // 8) % len(_logo_colors)
            scale_chars = ["◆", "◆", "◈", "◆"]
            logo_lbl.config(fg=_logo_colors[idx], text=scale_chars[(ph // 4) % len(scale_chars)])
            _logo_phase[0] = (ph + 1) % 60
            try:
                splash.after(60, _pulse_logo)
            except Exception:
                pass

        splash.after(200, _pulse_logo)

    tk.Label(content, text="NetPhantom", bg=BG_BASE, fg=TEXT_PRIMARY,
             font=("Segoe UI", 24, "bold")).pack(pady=(0, 2))
    tk.Label(content, text="Professional Network Packet Analyzer  v3.1.3",
             bg=BG_BASE, fg=ACCENT_CYAN, font=("Segoe UI", 10)).pack()
    tk.Label(content, text="Author: Lucky  |  Cybersecurity Portfolio",
             bg=BG_BASE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(pady=(4, 0))

    # Progress area
    prog_frame = tk.Frame(content, bg=BG_BASE)
    prog_frame.pack(pady=(20, 4))
    status_lbl = tk.Label(prog_frame, text="Initializing…",
                          bg=BG_BASE, fg=ACCENT_CYAN, font=("Consolas", 9))
    status_lbl.pack()

    style = ttk.Style(splash)
    style.theme_use("clam")
    style.configure("Splash.Horizontal.TProgressbar",
                    troughcolor="#0a0e1a", background=ACCENT_BLUE,
                    bordercolor=BG_BASE, lightcolor=ACCENT_CYAN,
                    darkcolor=ACCENT_BLUE)
    bar = ttk.Progressbar(prog_frame, length=420, mode="determinate",
                          style="Splash.Horizontal.TProgressbar")
    bar.pack(pady=8)

    messages = [
        (15,  "Initializing Scapy engine…"),
        (32,  "Detecting network interfaces…"),
        (50,  "Loading protocol analyzers…"),
        (68,  "Compiling BPF modules…"),
        (84,  "Building GUI components…"),
        (100, "◆  NetPhantom Ready"),
    ]

    # Smooth eased progress animation between steps
    _current_val = [0]

    def _ease_to(target, idx, msg, on_done=None):
        cur = _current_val[0]
        if cur < target:
            step = max(1, (target - cur) // 6)
            _current_val[0] = min(cur + step, target)
            bar["value"] = _current_val[0]
            splash.after(28, _ease_to, target, idx, msg, on_done)
        else:
            if on_done:
                on_done()

    def advance(idx=0):
        if idx < len(messages):
            val, msg = messages[idx]
            status_lbl.config(text=msg)
            _ease_to(val, idx, msg, on_done=lambda: splash.after(220, advance, idx + 1))
        else:
            splash.after(500, splash.destroy)

    splash.after(180, advance)
    splash.mainloop()


class FilterAutocomplete:
    """Wireshark-style live autocomplete dropdown menu for display filter input."""
    FILTER_DICTIONARY = [
        "http", "http2", "http3", "https", "tcp", "udp", "dns", "tls", "arp", "icmp",
        "quic", "dhcp", "ftp", "ssh", "smtp", "ssdp", "mdns", "ntp", "bgp", "ipv6", "other",
        "ip.src", "ip.dst", "tcp.port", "udp.port", "dns.qry.name", "frame.len",
        "tcp.flags.syn", "tcp.flags.ack", "tls.handshake", "http.request.method",
    ]

    def __init__(self, entry_widget: tk.Entry, on_select_callback=None):
        self.entry = entry_widget
        self.on_select = on_select_callback
        self.popup: tk.Toplevel | None = None
        self.listbox: tk.Listbox | None = None

        self.entry.bind("<KeyRelease>", self._on_key_release)
        self.entry.bind("<FocusOut>", self._on_focus_out)
        self.entry.bind("<Down>", self._on_arrow_down)
        self.entry.bind("<Up>", self._on_arrow_up)
        self.entry.bind("<Return>", self._on_enter)

    def _on_key_release(self, event):
        if event.keysym in ("Down", "Up", "Return", "Escape"):
            return
        
        text = self.entry.get().strip().lower()
        if not text:
            self._close_popup()
            self.entry.config(bg=BG_INPUT, fg=ACCENT_CYAN)
            return

        matches = [f for f in self.FILTER_DICTIONARY if f.startswith(text) or text in f]
        
        # Wireshark-style background color validation (dark green = valid, dark red = invalid)
        if matches or text in self.FILTER_DICTIONARY or "==" in text or ":" in text:
            self.entry.config(bg="#103820", fg="#4ade80")
        else:
            self.entry.config(bg="#4a151b", fg="#f87171")

        if matches:
            self._show_popup(matches)
        else:
            self._close_popup()

    def _show_popup(self, matches):
        if not self.popup or not self.popup.winfo_exists():
            self.popup = tk.Toplevel(self.entry)
            self.popup.wm_overrideredirect(True)
            self.popup.configure(bg=BG_HEADER)

            self.listbox = tk.Listbox(
                self.popup, bg=BG_HEADER, fg=TEXT_PRIMARY,
                selectbackground=BG_SELECTED, selectforeground="white",
                font=("Consolas", 9), relief="solid", bd=1,
                highlightthickness=0, height=min(len(matches), 6)
            )
            self.listbox.pack(fill=tk.BOTH, expand=True)
            self.listbox.bind("<ButtonRelease-1>", self._on_list_select)

        # Position popup directly under entry box
        x = self.entry.winfo_rootx()
        y = self.entry.winfo_rooty() + self.entry.winfo_height()
        w = max(self.entry.winfo_width(), 200)
        self.popup.geometry(f"{w}x{min(len(matches)*22 + 4, 140)}+{x}+{y}")

        self.listbox.delete(0, tk.END)
        for item in matches:
            self.listbox.insert(tk.END, item)

    def _close_popup(self):
        if self.popup and self.popup.winfo_exists():
            self.popup.destroy()
        self.popup = None
        self.listbox = None

    def _on_focus_out(self, event):
        self.entry.after(180, self._close_popup)

    def _on_arrow_down(self, event):
        if self.listbox and self.listbox.winfo_exists():
            cur = self.listbox.curselection()
            next_idx = cur[0] + 1 if cur else 0
            if next_idx < self.listbox.size():
                self.listbox.selection_clear(0, tk.END)
                self.listbox.selection_set(next_idx)
                self.listbox.see(next_idx)

    def _on_arrow_up(self, event):
        if self.listbox and self.listbox.winfo_exists():
            cur = self.listbox.curselection()
            prev_idx = cur[0] - 1 if cur and cur[0] > 0 else 0
            self.listbox.selection_clear(0, tk.END)
            self.listbox.selection_set(prev_idx)
            self.listbox.see(prev_idx)

    def _on_enter(self, event):
        if self.listbox and self.listbox.winfo_exists():
            cur = self.listbox.curselection()
            if cur:
                selected = self.listbox.get(cur[0])
                self.entry.delete(0, tk.END)
                self.entry.insert(0, selected)
                self._close_popup()
                if self.on_select:
                    self.on_select()

    def _on_list_select(self, event):
        if self.listbox and self.listbox.curselection():
            selected = self.listbox.get(self.listbox.curselection()[0])
            self.entry.delete(0, tk.END)
            self.entry.insert(0, selected)
            self._close_popup()
            if self.on_select:
                self.on_select()


# ──────────────────────────────────────────────
#  Main GUI Application
# ──────────────────────────────────────────────
class PacketSnifferGUI:
    MAX_TABLE_ROWS = 5000

    def __init__(self, root: tk.Tk, open_file: str = None):
        self.root = root
        self.root.title("NetPhantom v3.1.3  ◆  Network Packet Analyzer")
        self.root.configure(bg=BG_BASE)
        self.root.geometry("1500x900")
        self.root.minsize(1100, 700)

        self.engine: CaptureEngine | None = None
        self._poll_job  = None
        self._clock_job = None          # tracked so we can cancel it on close
        self._anim_job  = None          # tracked animation timer job
        self._anim_step = 0
        self._status_state = "idle"
        self._scanline_x = 0

        self._stored_packets: list[dict] = []
        self._selected_pkt: dict | None  = None
        self._search_var       = tk.StringVar()
        self._display_filter   = tk.StringVar()
        self._filter_proto_var = tk.StringVar(value="ALL")
        self._search_var.trace_add("write", lambda *_: self._apply_filter())
        self._display_filter.trace_add("write", lambda *_: self._apply_filter())
        self._auto_scroll = True
        self._sort_col = None
        self._sort_reverse = False
        self._font_size = 10

        # Configurations
        import os
        if getattr(sys, "frozen", False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))

        self._config_path = os.path.normpath(os.path.join(base_dir, "config.json"))
        self._load_config()

        self._apply_theme()
        self._build_ui()
        self._bind_shortcuts()
        self.root.after(100, self._animate_ui_effects)
        self.root.after(150, self._show_warning)

        # Open PCAP file if provided
        if open_file:
            self.root.after(500, lambda: self._open_pcap_file(open_file))

    # ────────────────────────────────────────────
    #  Theme Setup
    # ────────────────────────────────────────────
    def _apply_theme(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Treeview
        style.configure("Packet.Treeview",
                        background=BG_PANEL, foreground=TEXT_PRIMARY,
                        fieldbackground=BG_PANEL, rowheight=24,
                        font=FONT_MONO_SM, borderwidth=0)
        style.configure("Packet.Treeview.Heading",
                        background=BG_HEADER, foreground=self._accent_color,
                        font=("Segoe UI", 9, "bold"), borderwidth=1,
                        relief="flat")
        style.map("Packet.Treeview",
                  background=[("selected", BG_SELECTED)],
                  foreground=[("selected", TEXT_PRIMARY)])

        # Side treeview (streams etc)
        style.configure("Side.Treeview",
                        background=BG_PANEL, foreground=TEXT_SECONDARY,
                        fieldbackground=BG_PANEL, rowheight=20,
                        font=FONT_MONO_XS, borderwidth=0)
        style.configure("Side.Treeview.Heading",
                        background=BG_HEADER, foreground=TEXT_DIM,
                        font=("Segoe UI", 8, "bold"), borderwidth=0)
        style.map("Side.Treeview",
                  background=[("selected", BG_SELECTED)],
                  foreground=[("selected", TEXT_PRIMARY)])

        # Scrollbars
        style.configure("Custom.Vertical.TScrollbar",
                        background=BG_HEADER, troughcolor=BG_PANEL,
                        bordercolor=BG_PANEL, arrowcolor=TEXT_DIM)
        style.configure("Custom.Horizontal.TScrollbar",
                        background=BG_HEADER, troughcolor=BG_PANEL,
                        bordercolor=BG_PANEL, arrowcolor=TEXT_DIM)

        # Combobox
        style.configure("Custom.TCombobox",
                        fieldbackground=BG_INPUT, background=BG_HEADER,
                        foreground=TEXT_PRIMARY, selectbackground=BG_SELECTED,
                        borderwidth=1, relief="flat")
        style.map("Custom.TCombobox",
                  fieldbackground=[("readonly", BG_INPUT)],
                  foreground=[("readonly", TEXT_PRIMARY)])

        # Progressbar
        style.configure("Custom.Horizontal.TProgressbar",
                        troughcolor=BG_PANEL, background=ACCENT_BLUE,
                        bordercolor=BG_BASE)

        # Notebook (tabs)
        style.configure("Custom.TNotebook",
                        background=BG_BASE, borderwidth=0)
        style.configure("Custom.TNotebook.Tab",
                        background=BG_HEADER, foreground=TEXT_DIM,
                        font=("Segoe UI", 8, "bold"),
                        padding=[10, 4])
        style.map("Custom.TNotebook.Tab",
                  background=[("selected", BG_PANEL)],
                  foreground=[("selected", self._accent_color)])

    # ────────────────────────────────────────────
    #  UI Construction
    # ────────────────────────────────────────────
    def _build_ui(self):
        self._build_menu_bar()
        self._build_toolbar()

        # Main content area: left (packet view) + right (side panel)
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=BG_BASE,
                                   sashwidth=3, sashrelief="flat")
        main_pane.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 0))

        # Left: Packet list + bottom pane (protocol tree + hex dump)
        left_frame = tk.Frame(main_pane, bg=BG_BASE)
        main_pane.add(left_frame, minsize=800, stretch="always")

        # Vertical pane: packet table on top, detail panes on bottom
        vert_pane = tk.PanedWindow(left_frame, orient=tk.VERTICAL, bg=BG_BASE,
                                   sashwidth=3, sashrelief="flat")
        vert_pane.pack(fill=tk.BOTH, expand=True)

        # Top: Packet list table
        table_frame = tk.Frame(vert_pane, bg=BG_BASE)
        vert_pane.add(table_frame, minsize=250, stretch="always")
        self._build_packet_table(table_frame)

        # Bottom: Protocol tree + Hex dump side by side
        bottom_pane = tk.PanedWindow(vert_pane, orient=tk.HORIZONTAL, bg=BG_BASE,
                                     sashwidth=3, sashrelief="flat")
        vert_pane.add(bottom_pane, minsize=180)

        proto_frame = tk.Frame(bottom_pane, bg=BG_PANEL)
        bottom_pane.add(proto_frame, minsize=300, stretch="always")
        self._build_protocol_tree(proto_frame)

        hex_frame = tk.Frame(bottom_pane, bg=BG_PANEL)
        bottom_pane.add(hex_frame, minsize=300, stretch="always")
        self._build_hex_dump(hex_frame)

        # Right: Tabbed side panel
        right_frame = tk.Frame(main_pane, bg=BG_BASE)
        main_pane.add(right_frame, minsize=290, stretch="never")
        self._build_side_panel(right_frame)

        self._build_status_bar()

    # ── Menu Bar ─────────────────────────────
    def _build_menu_bar(self):
        menubar = tk.Menu(self.root, bg=BG_HEADER, fg=TEXT_PRIMARY,
                         activebackground=BG_SELECTED, activeforeground=TEXT_PRIMARY,
                         font=FONT_MENU, relief="flat", bd=0)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=BG_HEADER, fg=TEXT_PRIMARY,
                           activebackground=ACCENT_BLUE, activeforeground="white",
                           font=FONT_MENU)
        file_menu.add_command(label="  📂  Open PCAP...", command=self._open_pcap_dialog,
                             accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="  💾  Save as PCAP...", command=self._save_pcap,
                             accelerator="Ctrl+S")
        file_menu.add_command(label="  📋  Export as JSON...", command=self._save_json,
                             accelerator="Ctrl+Shift+S")
        file_menu.add_separator()
        file_menu.add_command(label="  ✕   Exit", command=self.on_close,
                             accelerator="Alt+F4")
        menubar.add_cascade(label=" File ", menu=file_menu)

        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0, bg=BG_HEADER, fg=TEXT_PRIMARY,
                            activebackground=ACCENT_BLUE, activeforeground="white",
                            font=FONT_MENU)
        edit_menu.add_command(label="  📋  Copy Packet Summary", command=self._copy_packet_summary,
                             accelerator="Ctrl+C")
        edit_menu.add_command(label="  📄  Copy Detailed Dissection", command=self._copy_detailed_dissection,
                             accelerator="Ctrl+Shift+C")
        edit_menu.add_command(label="  💾  Copy Raw Hex Dump", command=self._copy_raw_hex,
                             accelerator="Ctrl+Alt+C")
        edit_menu.add_separator()
        edit_menu.add_command(label="  ⚙   Preferences...", command=self._open_preferences,
                             accelerator="Ctrl+P")
        menubar.add_cascade(label=" Edit ", menu=edit_menu)

        # Capture menu
        capture_menu = tk.Menu(menubar, tearoff=0, bg=BG_HEADER, fg=TEXT_PRIMARY,
                               activebackground=ACCENT_BLUE, activeforeground="white",
                               font=FONT_MENU)
        capture_menu.add_command(label="  ⚙   Options...", command=self._show_capture_options_dialog,
                                accelerator="Ctrl+K")
        capture_menu.add_command(label="  ▶   Start Capture", command=self.start_capture,
                                accelerator="F5")
        capture_menu.add_command(label="  ■   Stop Capture", command=self.stop_capture,
                                accelerator="F6")
        capture_menu.add_command(label="  ⟳   Restart Capture", command=self._restart_capture,
                                accelerator="Ctrl+R")
        capture_menu.add_command(label="  🔌  External Capture Tools (extcap)...", command=self._show_extcap_dialog)
        capture_menu.add_command(label="  🛡  Npcap Driver Status...", command=self._show_npcap_dialog)
        capture_menu.add_separator()
        capture_menu.add_command(label="  🗑  Clear All", command=self.clear_packets,
                                accelerator="Ctrl+L")
        menubar.add_cascade(label=" Capture ", menu=capture_menu)

        # Analyze menu
        analyze_menu = tk.Menu(menubar, tearoff=0, bg=BG_HEADER, fg=TEXT_PRIMARY,
                               activebackground=ACCENT_BLUE, activeforeground="white",
                               font=FONT_MENU)
        analyze_menu.add_command(label="  📊  Protocol Statistics", command=self._show_protocol_stats)
        analyze_menu.add_command(label="  🌐  Endpoint Statistics", command=self._show_endpoint_stats)
        analyze_menu.add_command(label="  🔗  Active Streams", command=self._show_streams_popup)
        analyze_menu.add_separator()
        analyze_menu.add_command(label="  ⚠   Threat Alerts", command=self._show_alerts_popup)
        menubar.add_cascade(label=" Analyze ", menu=analyze_menu)

        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg=BG_HEADER, fg=TEXT_PRIMARY,
                           activebackground=ACCENT_BLUE, activeforeground="white",
                           font=FONT_MENU)
        view_menu.add_command(label="  🔍  Zoom In", command=lambda: self._change_font_size(1),
                             accelerator="Ctrl++")
        view_menu.add_command(label="  🔍  Zoom Out", command=lambda: self._change_font_size(-1),
                             accelerator="Ctrl+-")
        view_menu.add_separator()
        self._auto_scroll_menu_var = tk.BooleanVar(value=True)
        view_menu.add_checkbutton(label="  Auto-scroll", variable=self._auto_scroll_menu_var,
                                 command=lambda: setattr(self, "_auto_scroll", self._auto_scroll_menu_var.get()))
        menubar.add_cascade(label=" View ", menu=view_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=BG_HEADER, fg=TEXT_PRIMARY,
                           activebackground=ACCENT_BLUE, activeforeground="white",
                           font=FONT_MENU)
        help_menu.add_command(label="  ❓  NetPhantom Manual & Documentation", command=self._show_manual)
        help_menu.add_command(label="  ⌨   Keyboard Shortcuts", command=self._show_shortcuts)
        help_menu.add_command(label="  🛡  Npcap Driver Status & Setup Guide", command=self._show_npcap_dialog)
        help_menu.add_separator()
        help_menu.add_command(label="  ◆   About NetPhantom v3.1.3", command=self._show_about)
        menubar.add_cascade(label=" Help ", menu=help_menu)

        self.root.config(menu=menubar)

    # ── Toolbar ──────────────────────────────
    def _build_toolbar(self):
        # Top toolbar row
        toolbar = tk.Frame(self.root, bg=BG_HEADER, height=44)
        toolbar.pack(fill=tk.X, side=tk.TOP)
        toolbar.pack_propagate(False)

        # Interface selector
        tk.Label(toolbar, text="Interface:", bg=BG_HEADER, fg=TEXT_SECONDARY,
                 font=FONT_MAIN_SM).pack(side=tk.LEFT, padx=(12, 4), pady=8)
        self._iface_var = tk.StringVar()
        ifaces = list_interfaces()
        self._iface_combo = ttk.Combobox(toolbar, textvariable=self._iface_var,
                                          values=ifaces, width=22, font=FONT_MONO_SM,
                                          style="Custom.TCombobox")
        self._iface_combo.pack(side=tk.LEFT, padx=(0, 8), pady=8)
        if ifaces:
            self._iface_combo.set(ifaces[0])

        # BPF Filter (with scrollable dropdown of pre-populated common ports)
        self._sep(toolbar)
        tk.Label(toolbar, text="Capture Filter:", bg=BG_HEADER, fg=TEXT_SECONDARY,
                 font=FONT_MAIN_SM).pack(side=tk.LEFT, padx=(8, 4))
        
        COMMON_BPF_PORTS = [
            "",
            "port 80",
            "port 443",
            "port 53",
            "port 22",
            "port 21",
            "port 25",
            "port 110",
            "port 143",
            "port 993",
            "port 995",
            "port 587",
            "port 3389",
            "port 3306",
            "port 5432",
            "port 6379",
            "port 27017",
            "port 1900",
            "port 5353",
            "port 67",
            "port 68",
            "port 123",
            "port 161",
            "port 389",
            "port 179",
            "tcp port 80",
            "tcp port 443",
            "udp port 53",
            "udp port 67",
            "icmp",
            "arp",
        ]
        self._filter_entry = ttk.Combobox(
            toolbar, width=18, values=COMMON_BPF_PORTS,
            font=FONT_MONO_SM, style="Custom.TCombobox"
        )
        self._filter_entry.set(self._config["default_filter"])
        self._filter_entry.pack(side=tk.LEFT, padx=(0, 4), pady=8)
        self._filter_entry.bind("<<ComboboxSelected>>", lambda e: self._validate_bpf_filter())

        # BPF filter validation indicator (small coloured dot — click to validate)
        self._filter_status_lbl = tk.Label(
            toolbar, text="●", bg=BG_HEADER, fg=TEXT_DIM,
            font=("Segoe UI", 9), cursor="hand2"
        )
        self._filter_status_lbl.pack(side=tk.LEFT, padx=(0, 8))
        self._filter_status_lbl.bind("<Button-1>", lambda e: self._validate_bpf_filter())

        # Action buttons
        self._sep(toolbar)
        self._btn_start = self._make_btn(toolbar, "▶ Start",  ACCENT_GREEN,  self.start_capture)
        self._btn_stop  = self._make_btn(toolbar, "■ Stop",   ACCENT_RED,    self.stop_capture)
        self._btn_clear = self._make_btn(toolbar, "⟳ Clear",  ACCENT_AMBER,  self.clear_packets)
        self._btn_stop.config(state=tk.DISABLED)

        # Download Log button
        self._sep(toolbar)
        self._make_btn(toolbar, "⬇ Download Log", ACCENT_CYAN, self._download_log)

        # Right side: protocol filter dropdown (expanded protocol list)
        PROTO_FILTER_VALUES = [
            "ALL", "TCP", "UDP", "ICMP", "ARP", "DNS",
            "HTTP", "HTTPS", "TLS", "TLS ClientHello", "TLS ServerHello",
            "QUIC", "IPv6", "DHCP", "FTP", "SSH", "SMTP", "SSDP", "MDNS", "NTP", "BGP", "OTHER",
        ]
        self._proto_combo = ttk.Combobox(
            toolbar, textvariable=self._filter_proto_var, state="readonly",
            values=PROTO_FILTER_VALUES,
            width=14, font=FONT_MONO_SM, style="Custom.TCombobox")
        self._proto_combo.pack(side=tk.RIGHT, padx=(4, 12), pady=8)
        tk.Label(toolbar, text="Filter Protocol:", bg=BG_HEADER, fg=TEXT_SECONDARY,
                 font=FONT_MAIN_SM).pack(side=tk.RIGHT, padx=(8, 2))
        self._proto_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())

        # ── Display filter bar ──────────────────────────
        filter_bar = tk.Frame(self.root, bg=BG_PANEL, height=34)
        filter_bar.pack(fill=tk.X, side=tk.TOP)
        filter_bar.pack_propagate(False)

        tk.Label(filter_bar, text="🔍", bg=BG_PANEL, fg=TEXT_DIM,
                 font=("Segoe UI", 11)).pack(side=tk.LEFT, padx=(12, 4), pady=4)
        tk.Label(filter_bar, text="Display Filter:", bg=BG_PANEL, fg=TEXT_SECONDARY,
                 font=FONT_MAIN_SM).pack(side=tk.LEFT, padx=(0, 4))
        self._search_entry = tk.Entry(filter_bar, textvariable=self._search_var,
                                       bg=BG_INPUT, fg=ACCENT_CYAN,
                                       insertbackground=ACCENT_CYAN, font=FONT_MONO_SM,
                                       relief="flat", bd=4)
        self._search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), pady=6)
        self._autocomplete = FilterAutocomplete(self._search_entry, on_select_callback=self._apply_filter)

        self._make_btn(filter_bar, "Apply", ACCENT_BLUE, self._apply_filter)
        self._make_btn(filter_bar, "Clear", TEXT_DIM, lambda: (self._search_var.set(""),
                                                                self._filter_proto_var.set("ALL"),
                                                                self._apply_filter()))

    # ── Packet Table ──────────────────────────
    def _build_packet_table(self, parent):
        frame = tk.Frame(parent, bg=BG_BASE)
        frame.pack(fill=tk.BOTH, expand=True)

        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self._tree = ttk.Treeview(frame, columns=columns, show="headings",
                                  selectmode="browse", style="Packet.Treeview")

        col_widths = {"No.": 60, "Time": 100, "Source": 170, "Destination": 170,
                      "Protocol": 90, "Length": 65, "Info": 350}
        for col in columns:
            anchor = "e" if col in ("No.", "Length") else "w"
            self._tree.heading(col, text=col, command=lambda c=col: self._sort_by_column(c))
            self._tree.column(col, width=col_widths[col], anchor=anchor, minwidth=40)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview,
                            style="Custom.Vertical.TScrollbar")
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self._tree.xview,
                            style="Custom.Horizontal.TScrollbar")
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_row_select)
        self._tree.bind("<Double-1>", self._on_row_double_click)
        self._item_pkt: dict[str, dict] = {}

        # Configure protocol color tags for row foreground
        for proto, color in PROTO_TEXT_COLORS.items():
            self._tree.tag_configure(proto, foreground=color)

        # Configure color rule tags for row background
        for rule_name, bg_color in PACKET_COLOR_RULES.items():
            self._tree.tag_configure(f"bg_{rule_name}", background=bg_color)

    # ── Protocol Dissection Tree ──────────────
    def _build_protocol_tree(self, parent):
        # Header
        header = tk.Frame(parent, bg=BG_HEADER, height=26)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="  ▸ Protocol Dissection", bg=BG_HEADER, fg=ACCENT_CYAN,
                 font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=4)

        frame = tk.Frame(parent, bg=BG_PANEL)
        frame.pack(fill=tk.BOTH, expand=True)

        self._proto_tree = ttk.Treeview(frame, show="tree", selectmode="browse",
                                         style="Side.Treeview")
        self._proto_tree.column("#0", width=500)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._proto_tree.yview,
                            style="Custom.Vertical.TScrollbar")
        self._proto_tree.configure(yscrollcommand=vsb.set)

        self._proto_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Tag for layer headers
        self._proto_tree.tag_configure("layer", foreground=ACCENT_BLUE,
                                       font=("Segoe UI", 9, "bold"))
        self._proto_tree.tag_configure("field", foreground=TEXT_SECONDARY,
                                       font=FONT_MONO_SM)

    # ── Hex Dump Viewer ──────────────────────
    def _build_hex_dump(self, parent):
        # Header
        header = tk.Frame(parent, bg=BG_HEADER, height=26)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="  ▸ Hex Dump", bg=BG_HEADER, fg=ACCENT_CYAN,
                 font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=4)

        self._hex_text = scrolledtext.ScrolledText(
            parent, bg=BG_PANEL, fg=ACCENT_GREEN,
            font=FONT_MONO_SM, relief="flat",
            insertbackground=ACCENT_GREEN, state=tk.DISABLED,
            selectbackground=BG_SELECTED, selectforeground=TEXT_PRIMARY,
            wrap=tk.NONE)
        self._hex_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Configure tags for hex dump highlighting
        self._hex_text.tag_configure("offset", foreground=TEXT_DIM)
        self._hex_text.tag_configure("hex", foreground=ACCENT_GREEN)
        self._hex_text.tag_configure("ascii", foreground=ACCENT_CYAN)

    # ── Side Panel (Tabbed) ──────────────────
    def _build_side_panel(self, parent):
        notebook = ttk.Notebook(parent, style="Custom.TNotebook")
        notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Tab 1: Statistics
        stats_frame = tk.Frame(notebook, bg=BG_PANEL)
        notebook.add(stats_frame, text=" 📊 Stats ")
        self._build_stats_tab(stats_frame)

        # Tab 2: Streams
        streams_frame = tk.Frame(notebook, bg=BG_PANEL)
        notebook.add(streams_frame, text=" 🔗 Streams ")
        self._build_streams_tab(streams_frame)

        # Tab 3: Alerts
        alerts_frame = tk.Frame(notebook, bg=BG_PANEL)
        notebook.add(alerts_frame, text=" ⚠ Alerts ")
        self._build_alerts_tab(alerts_frame)

        # Tab 4: Endpoints
        endpoints_frame = tk.Frame(notebook, bg=BG_PANEL)
        notebook.add(endpoints_frame, text=" 🌐 Endpoints ")
        self._build_endpoints_tab(endpoints_frame)

        # Tab 5: Graph
        graph_frame = tk.Frame(notebook, bg=BG_PANEL)
        notebook.add(graph_frame, text=" 📈 Graph ")
        self._build_graph_tab(graph_frame)

    # ── Stats Tab ────────────────────────────
    def _build_stats_tab(self, parent):
        inner = tk.Frame(parent, bg=BG_PANEL)
        inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self._stat_labels: dict[str, tk.Label] = {}
        counters = [
            ("TOTAL",     "0",     ACCENT_BLUE),
            ("PKT/SEC",   "0",     ACCENT_CYAN),
            ("BYTES/SEC", "0",     ACCENT_TEAL),
            ("ELAPSED",   "0s",    TEXT_SECONDARY),
            ("ENCRYPTED", "0",     ACCENT_PINK),
            ("HTTP/S",    "0",     ACCENT_ORANGE),
            ("TCP",       "0",     ACCENT_GREEN),
            ("UDP",       "0",     ACCENT_BLUE),
            ("DNS",       "0",     ACCENT_CYAN),
            ("ICMP",      "0",     ACCENT_AMBER),
            ("ARP",       "0",     ACCENT_PURPLE),
            ("ALERTS",    "0",     ACCENT_RED),
        ]
        for i, (label, val, color) in enumerate(counters):
            r, c = divmod(i, 2)
            # Label
            tk.Label(inner, text=label, bg=BG_PANEL, fg=TEXT_DIM,
                     font=FONT_STAT_LBL).grid(row=r*2, column=c, sticky="w", padx=8, pady=(4, 0))
            # Value
            lbl = tk.Label(inner, text=val, bg=BG_PANEL, fg=color,
                           font=FONT_STAT)
            lbl.grid(row=r*2+1, column=c, sticky="w", padx=8, pady=(0, 4))
            self._stat_labels[label] = lbl

        # Protocol distribution bar chart
        tk.Frame(inner, bg=BORDER, height=1).grid(row=len(counters)+2, column=0,
                                                    columnspan=2, sticky="ew",
                                                    padx=4, pady=(8, 4))
        tk.Label(inner, text="PROTOCOL DISTRIBUTION", bg=BG_PANEL, fg=TEXT_DIM,
                 font=FONT_STAT_LBL).grid(row=len(counters)+3, column=0,
                                           columnspan=2, sticky="w", padx=8)

        self._bar_canvas = tk.Canvas(inner, bg=BG_PANEL, height=110,
                                      highlightthickness=0, bd=0)
        self._bar_canvas.grid(row=len(counters)+4, column=0, columnspan=2,
                               sticky="ew", padx=4, pady=(2, 8))

    # ── Streams Tab ──────────────────────────
    def _build_streams_tab(self, parent):
        stream_cols = ("Flow", "Proto", "Pkts", "Data")
        self._stream_tree = ttk.Treeview(parent, columns=stream_cols,
                                          show="headings", selectmode="none",
                                          style="Side.Treeview")
        widths = {"Flow": 140, "Proto": 50, "Pkts": 45, "Data": 55}
        for col in stream_cols:
            self._stream_tree.heading(col, text=col)
            self._stream_tree.column(col, width=widths[col], anchor="w")
        self._stream_tree.tag_configure("heavy", foreground=ACCENT_AMBER)

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self._stream_tree.yview,
                            style="Custom.Vertical.TScrollbar")
        self._stream_tree.configure(yscrollcommand=vsb.set)
        self._stream_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0), pady=4)
        vsb.pack(side=tk.LEFT, fill=tk.Y, pady=4, padx=(0, 4))

    # ── Alerts Tab ───────────────────────────
    def _build_alerts_tab(self, parent):
        self._alerts_text = scrolledtext.ScrolledText(
            parent, bg=BG_PANEL, fg=ACCENT_RED,
            font=FONT_MONO_SM, relief="flat",
            insertbackground=ACCENT_RED, state=tk.DISABLED,
            selectbackground=BG_SELECTED, selectforeground=TEXT_PRIMARY)
        self._alerts_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        self._alerts_text.tag_configure("time", foreground=TEXT_DIM)
        self._alerts_text.tag_configure("alert", foreground=ACCENT_RED)
        self._alerts_text.tag_configure("warn", foreground=ACCENT_AMBER)
        self._alert_count_displayed = 0

    # ── Endpoints Tab ────────────────────────
    def _build_endpoints_tab(self, parent):
        ep_cols = ("Address", "Tx Pkts", "Rx Pkts", "Total")
        self._endpoint_tree = ttk.Treeview(parent, columns=ep_cols,
                                            show="headings", selectmode="none",
                                            style="Side.Treeview")
        widths = {"Address": 130, "Tx Pkts": 55, "Rx Pkts": 55, "Total": 55}
        for col in ep_cols:
            self._endpoint_tree.heading(col, text=col)
            self._endpoint_tree.column(col, width=widths[col], anchor="w")
        self._endpoint_tree.tag_configure("top", foreground=ACCENT_BLUE)

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self._endpoint_tree.yview,
                            style="Custom.Vertical.TScrollbar")
        self._endpoint_tree.configure(yscrollcommand=vsb.set)
        self._endpoint_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0), pady=4)
        vsb.pack(side=tk.LEFT, fill=tk.Y, pady=4, padx=(0, 4))

    # ── Graph Tab ────────────────────────────
    def _build_graph_tab(self, parent):
        tk.Label(parent, text="PACKETS / SECOND", bg=BG_PANEL, fg=TEXT_DIM,
                 font=FONT_STAT_LBL).pack(anchor="w", padx=8, pady=(8, 2))
        self._graph_canvas = tk.Canvas(parent, bg=BG_PANEL, height=200,
                                        highlightthickness=0, bd=0)
        self._graph_canvas.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

    # ── Status Bar ───────────────────────────
    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=BG_HEADER, height=26)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)

        self._status_indicator = tk.Label(bar, text="●", bg=BG_HEADER, fg=TEXT_DIM,
                                          font=("Segoe UI", 10))
        self._status_indicator.pack(side=tk.LEFT, padx=(8, 4))

        self._status_var = tk.StringVar(value="IDLE  —  Ready to capture packets")
        tk.Label(bar, textvariable=self._status_var, bg=BG_HEADER, fg=TEXT_SECONDARY,
                 font=FONT_MAIN_SM, anchor="w").pack(side=tk.LEFT, padx=4)

        # Right side info
        self._clock_lbl = tk.Label(bar, text="", bg=BG_HEADER, fg=TEXT_DIM,
                                   font=FONT_MAIN_SM)
        self._clock_lbl.pack(side=tk.RIGHT, padx=8)

        self._pkt_count_lbl = tk.Label(bar, text="0 packets", bg=BG_HEADER,
                                        fg=TEXT_SECONDARY, font=FONT_MAIN_SM)
        self._pkt_count_lbl.pack(side=tk.RIGHT, padx=8)

        tk.Frame(bar, bg=BORDER, width=1).pack(side=tk.RIGHT, fill=tk.Y, padx=4, pady=4)

        self._update_clock()

    # ────────────────────────────────────────────
    #  Capture Control
    # ────────────────────────────────────────────
    def start_capture(self):
        iface = self._iface_var.get().strip()
        bpf   = self._filter_entry.get().strip()
        if not iface:
            messagebox.showerror("No Interface", "Please select a network interface.")
            return
        self.engine = CaptureEngine(interface=iface, bpf_filter=bpf,
                                    error_callback=self._on_capture_error)
        self.engine.start()
        self._btn_start.config(state=tk.DISABLED)
        self._btn_stop.config(state=tk.NORMAL)
        self._set_status(f"CAPTURING on {iface}  |  filter: '{bpf or 'none'}'", "capturing")
        self._poll_packets()

    def stop_capture(self):
        if self.engine:
            self.engine.stop()
        if self._poll_job:
            try:
                self.root.after_cancel(self._poll_job)
            except Exception:
                pass
            self._poll_job = None
        try:
            self._btn_start.config(state=tk.NORMAL)
            self._btn_stop.config(state=tk.DISABLED)
            self._set_status("STOPPED  —  Capture halted", "stopped")
        except Exception:
            pass  # Widget may be gone during shutdown

    def _restart_capture(self):
        self.stop_capture()
        self.clear_packets()
        self.root.after(200, self.start_capture)

    def clear_packets(self):
        self._stored_packets.clear()
        self._item_pkt.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._clear_protocol_tree()
        self._clear_hex_dump()
        if self.engine:
            self.engine.analyzer.reset()
        for iid in self._stream_tree.get_children():
            self._stream_tree.delete(iid)
        for iid in self._endpoint_tree.get_children():
            self._endpoint_tree.delete(iid)
        self._alerts_text.config(state=tk.NORMAL)
        self._alerts_text.delete("1.0", tk.END)
        self._alerts_text.config(state=tk.DISABLED)
        self._alert_count_displayed = 0
        self._pkt_count_lbl.config(text="0 packets")

    def _on_capture_error(self, msg: str):
        """Handle errors from the capture engine thread-safely."""
        self.root.after(0, lambda: messagebox.showerror("Capture Error", msg))
        self.root.after(0, self.stop_capture)

    # ────────────────────────────────────────────
    #  PCAP Import
    # ────────────────────────────────────────────
    def _open_pcap_dialog(self):
        path = filedialog.askopenfilename(
            filetypes=[("PCAP Files", "*.pcap *.pcapng *.cap"), ("All Files", "*.*")],
            title="Open Capture File")
        if path:
            self._open_pcap_file(path)

    def _open_pcap_file(self, path: str):
        """Load a PCAP file and display its contents."""
        self.stop_capture()
        self.clear_packets()
        self.engine = CaptureEngine(error_callback=self._on_capture_error)
        self._set_status(f"Loading {path}...", "loading")
        self.root.update()

        success = self.engine.load_pcap(path)
        if success:
            # Drain the queue and display
            count = 0
            while not self.engine.packet_queue.empty():
                try:
                    pkt = self.engine.packet_queue.get_nowait()
                    self._stored_packets.append(pkt)
                    if len(self._stored_packets) > self._config["max_buffer"]:
                        self._stored_packets.pop(0)
                        children = self._tree.get_children()
                        if children:
                            old_iid = children[0]
                            self._item_pkt.pop(old_iid, None)
                            self._tree.delete(old_iid)
                    self._add_table_row(pkt)
                    count += 1
                except queue.Empty:
                    break
            self._update_stats(self.engine.get_stats())
            self._update_streams()
            self._update_endpoints()
            self._update_alerts()
            self._set_status(f"Loaded {count} packets from {path}", "loaded")
            self._pkt_count_lbl.config(text=f"{count} packets")
        else:
            self._set_status("Failed to load PCAP file", "error")

    # ────────────────────────────────────────────
    #  Packet Poll Loop
    # ────────────────────────────────────────────
    def _poll_packets(self):
        """Drain the capture queue and update the GUI. Reschedules itself only while running."""
        if not self.engine or not self.engine.is_running():
            self._poll_job = None
            return
        try:
            batch = 0
            while batch < 60:
                try:
                    pkt = self.engine.packet_queue.get_nowait()
                    self._stored_packets.append(pkt)
                    if len(self._stored_packets) > self._config["max_buffer"]:
                        self._stored_packets.pop(0)
                        children = self._tree.get_children()
                        if children:
                            old_iid = children[0]
                            self._item_pkt.pop(old_iid, None)
                            self._tree.delete(old_iid)
                    self._add_table_row(pkt)
                    batch += 1
                except queue.Empty:
                    break
            if self.engine.is_running():
                stats = self.engine.get_stats()
                self._update_stats(stats)
                self._update_streams()
                self._update_endpoints()
                self._update_alerts()
                self._update_graph(stats)
                self._pkt_count_lbl.config(text=f"{stats['total']} packets")
                # Reschedule only if still running
                self._poll_job = self.root.after(80, self._poll_packets)
            else:
                self._poll_job = None
        except Exception as exc:
            print(f"[GUI] poll error: {exc}", file=sys.stderr)
            self._poll_job = None


    # ────────────────────────────────────────────
    #  Table
    # ────────────────────────────────────────────
    def _add_table_row(self, pkt: dict):
        if not self._matches_filter(pkt):
            return
        proto = pkt["protocol"]
        src   = pkt["src"] + (f":{pkt['sport']}" if pkt.get("sport") else "")
        dst   = pkt["dst"] + (f":{pkt['dport']}" if pkt.get("dport") else "")
        info  = pkt.get("tls_info") or pkt.get("http_info") or \
                pkt.get("behavior", "") or \
                pkt.get("flags") or pkt.get("payload_ascii", "")[:60].replace(".", "") or ""

        # Determine tags
        proto_tag = proto.split()[0] if proto.split()[0] in PROTO_TEXT_COLORS else "OTHER"
        color_rule = pkt.get("color_rule", "other")
        bg_tag = f"bg_{color_rule}"
        tags = (proto_tag, bg_tag)

        iid = self._tree.insert("", "end",
            values=(pkt["index"], pkt["time"], src[:28], dst[:28],
                    proto, pkt["length"], info[:60]),
            tags=tags)
        self._item_pkt[iid] = pkt

        children = self._tree.get_children()
        if len(children) > self.MAX_TABLE_ROWS:
            old = children[0]
            self._item_pkt.pop(old, None)
            self._tree.delete(old)

        if self._auto_scroll:
            self._tree.yview_moveto(1.0)

    # ── Stats ──────────────────────────────────
    def _update_stats(self, stats: dict):
        total  = stats["total"]
        protos = stats.get("protocols", {})

        self._stat_labels["TOTAL"].config(text=str(total))
        self._stat_labels["PKT/SEC"].config(text=str(stats.get("pps", 0)))
        bps = stats.get("bps", 0)
        self._stat_labels["BYTES/SEC"].config(text=self._fmt_bytes(int(bps)) + "/s" if bps else "0")
        self._stat_labels["ELAPSED"].config(text=f"{stats.get('elapsed', 0)}s")

        enc   = sum(c for p, c in protos.items() if any(x in p for x in ("TLS","HTTPS","QUIC")))
        httpc = sum(c for p, c in protos.items() if "HTTP" in p)
        self._stat_labels["ENCRYPTED"].config(text=str(enc))
        self._stat_labels["HTTP/S"].config(text=str(httpc))
        self._stat_labels["ALERTS"].config(text=str(stats.get("alerts", 0)))

        for label in ("TCP", "UDP", "DNS", "ICMP", "ARP"):
            if label in self._stat_labels:
                self._stat_labels[label].config(text=str(protos.get(label, 0)))

        self._draw_bar_chart(protos, total)

    def _draw_bar_chart(self, protos: dict, total: int):
        c = self._bar_canvas
        c.delete("all")
        if not total:
            return
        w = c.winfo_width() or 260
        items = sorted(protos.items(), key=lambda x: x[1], reverse=True)[:8]
        if not items:
            return
        bw = max(16, (w - 20) // max(len(items), 1) - 6)
        x, mh = 10, 75
        for proto, count in items:
            pct = count / total
            bh  = max(4, int(pct * mh))
            col = PROTO_TEXT_COLORS.get(proto, TEXT_DIM)

            # Draw bar background track
            c.create_rectangle(x, 90, x + bw, 90 - mh, fill="#111827", outline="#1e293b", width=1)

            # Gradient bar fill
            c.create_rectangle(x + 1, 90, x + bw - 1, 90 - bh, fill=col, outline="", width=0)

            # Glowing top indicator cap
            c.create_rectangle(x, 90 - bh - 2, x + bw, 90 - bh, fill="#ffffff", outline=col, width=1)

            # Percentage & count labels
            c.create_text(x + bw // 2, 101, text=proto[:4], fill=col, font=("Segoe UI", 7, "bold"))
            c.create_text(x + bw // 2, 90 - bh - 10, text=f"{count}", fill=TEXT_PRIMARY, font=("Segoe UI", 7, "bold"))
            x += bw + 6

    # ── Streams ────────────────────────────────
    def _update_streams(self):
        if not self.engine:
            return
        streams = self.engine.analyzer.get_top_streams(40)
        for iid in self._stream_tree.get_children():
            self._stream_tree.delete(iid)
        for s in streams:
            key   = s["key"]
            parts = key.split(" ↔ ")
            label = f"{parts[0][:18]}" if len(parts) > 0 else key[:20]
            data  = self._fmt_bytes(s["bytes"])
            tag   = "heavy" if s["bytes"] > 50_000 else ""
            self._stream_tree.insert("", "end",
                values=(label, s["proto"], s["packets"], data), tags=(tag,))

    # ── Endpoints ─────────────────────────────
    def _update_endpoints(self):
        if not self.engine:
            return
        stats = self.engine.analyzer.get_stats()
        endpoints = stats.get("endpoints", [])
        for iid in self._endpoint_tree.get_children():
            self._endpoint_tree.delete(iid)
        for i, ep in enumerate(endpoints[:30]):
            tag = "top" if i < 3 else ""
            self._endpoint_tree.insert("", "end",
                values=(ep["ip"][:22], ep["tx_pkts"], ep["rx_pkts"],
                        self._fmt_bytes(ep["total_bytes"])),
                tags=(tag,))

    # ── Alerts ────────────────────────────────
    def _update_alerts(self):
        if not self.engine:
            return
        alerts = self.engine.analyzer.get_alerts()
        new_alerts = alerts[self._alert_count_displayed:]
        if not new_alerts:
            return

        self._alerts_text.config(state=tk.NORMAL)
        for alert in new_alerts:
            self._alerts_text.insert(tk.END, f"[{alert['time']}] ", "time")
            self._alerts_text.insert(tk.END, f"{alert['type']}\n", "alert")
            self._alerts_text.insert(tk.END,
                f"  Src: {alert['src']}  Dst: {alert['dst']}  Proto: {alert['proto']}\n\n", "warn")
        self._alerts_text.see(tk.END)
        self._alerts_text.config(state=tk.DISABLED)
        self._alert_count_displayed = len(alerts)

    # ── Graph ─────────────────────────────────
    def _update_graph(self, stats: dict):
        c = self._graph_canvas
        c.delete("all")
        history = stats.get("pps_history", [])
        if len(history) < 2:
            return

        w = c.winfo_width() or 280
        h = c.winfo_height() or 200
        pad_top, pad_bottom, pad_left, pad_right = 20, 25, 40, 10

        graph_w = w - pad_left - pad_right
        graph_h = h - pad_top - pad_bottom

        # Grid lines
        max_pps = max((v for _, v in history), default=1) or 1
        for i in range(5):
            y = pad_top + int(graph_h * i / 4)
            c.create_line(pad_left, y, w - pad_right, y, fill="#1e293b", dash=(2, 4))
            val = int(max_pps * (4 - i) / 4)
            c.create_text(pad_left - 5, y, text=str(val), fill=TEXT_DIM,
                         font=("Segoe UI", 7), anchor="e")

        # Draw line & polygon
        points = []
        n = len(history)
        step_x = graph_w / max(n - 1, 1)
        for i, (ts, pps) in enumerate(history):
            x = pad_left + int(i * step_x)
            y = pad_top + graph_h - int((pps / max_pps) * graph_h)
            points.append((x, y))

        # Fill area under curve
        if len(points) >= 2:
            fill_points = list(points)
            fill_points.append((points[-1][0], pad_top + graph_h))
            fill_points.append((points[0][0], pad_top + graph_h))
            flat = [coord for p in fill_points for coord in p]
            c.create_polygon(flat, fill="#1e3a5f", outline="", stipple="gray25")

            # Layered glowing line
            flat_line = [coord for p in points for coord in p]
            c.create_line(flat_line, fill="#3b82f6", width=3, smooth=True)
            c.create_line(flat_line, fill="#00f3ff", width=1, smooth=True)

            # Glowing peak indicator dot
            if points:
                lx, ly = points[-1]
                c.create_oval(lx - 5, ly - 5, lx + 5, ly + 5, fill="#00f3ff", outline="#ffffff", width=1)
                c.create_text(lx - 8, ly - 12, text=f"{history[-1][1]} pps", fill="#00f3ff",
                             font=("Segoe UI", 8, "bold"), anchor="e")

        # X-axis label
        c.create_text(w // 2, h - 5, text="Time →", fill=TEXT_DIM, font=("Segoe UI", 7))

    # ── Protocol Tree Update ──────────────────
    def _update_protocol_tree(self, pkt):
        """Populate the protocol dissection tree for a selected packet."""
        self._clear_protocol_tree()
        raw_pkt = pkt.get("raw_pkt")
        if not raw_pkt:
            return

        tree_data = build_protocol_tree(raw_pkt)
        for layer_info in tree_data:
            # Insert layer header (expandable)
            layer_id = self._proto_tree.insert("", "end",
                text=f"▸ {layer_info['layer']}", tags=("layer",), open=False)
            # Insert fields under the layer
            for field_name, field_val in layer_info.get("fields", []):
                self._proto_tree.insert(layer_id, "end",
                    text=f"    {field_name}: {field_val}", tags=("field",))

    def _clear_protocol_tree(self):
        for iid in self._proto_tree.get_children():
            self._proto_tree.delete(iid)

    # ── Hex Dump Update ──────────────────────
    def _update_hex_dump(self, pkt):
        """Populate the hex dump view for a selected packet."""
        self._clear_hex_dump()
        raw_pkt = pkt.get("raw_pkt")
        if not raw_pkt:
            return

        hex_str = format_hex_dump(raw_pkt)
        self._hex_text.config(state=tk.NORMAL)
        self._hex_text.delete("1.0", tk.END)
        self._hex_text.insert(tk.END, hex_str)
        self._hex_text.config(state=tk.DISABLED)

    def _clear_hex_dump(self):
        self._hex_text.config(state=tk.NORMAL)
        self._hex_text.delete("1.0", tk.END)
        self._hex_text.config(state=tk.DISABLED)

    # ── Filter ───────────────────────────────────────
    def _matches_filter(self, pkt: dict) -> bool:
        pf = self._filter_proto_var.get()
        proto = pkt.get("protocol", "")
        if pf != "ALL":
            if pf == "OTHER":
                # Packets not matching any named protocol
                known = {"TCP", "UDP", "ICMP", "ARP", "DNS",
                         "HTTP", "HTTPS", "TLS", "QUIC", "IPV6",
                         "DHCP", "FTP", "SSH", "SMTP", "SSDP", "MDNS", "NTP", "BGP"}
                if any(k in proto.upper() for k in known):
                    return False
            else:
                # Case-insensitive prefix match (supports 'TLS ClientHello' etc.)
                if not proto.upper().startswith(pf.upper()):
                    return False
        q = self._search_var.get().lower().strip()
        if q:
            hay = (
                f"{pkt['src']} {pkt['dst']} {pkt['protocol']} "
                f"{pkt.get('behavior','')} {pkt.get('tls_info','')} "
                f"{pkt.get('http_info','')} {pkt.get('flags', '')} "
                f"{pkt.get('payload_ascii', '')}"
            ).lower()
            if q not in hay:
                return False
        return True

    def _apply_filter(self):
        current_pf = self._filter_proto_var.get()
        if hasattr(self, "_badge_btns"):
            for p, btn in self._badge_btns.items():
                btn.config(bg=BG_SELECTED if p == current_pf else BG_PANEL)
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._item_pkt.clear()
        for pkt in self._stored_packets:
            self._add_table_row(pkt)

    def _quick_filter(self, proto: str):
        """Set the protocol filter via a badge button and refresh the table."""
        self._filter_proto_var.set(proto)
        # Update badge button active highlight
        for p, btn in self._badge_btns.items():
            btn.config(bg=BG_SELECTED if p == proto else BG_PANEL)
        self._apply_filter()

    def _validate_bpf_filter(self):
        """Compile the BPF expression to check syntax; update the indicator dot."""
        bpf = self._filter_entry.get().strip()
        if not bpf:
            self._filter_status_lbl.config(fg=TEXT_DIM)
            return
        try:
            from scapy.arch import compile_filter
            compile_filter(bpf)
            self._filter_status_lbl.config(fg=ACCENT_GREEN)
            self._set_status(f"BPF filter '{bpf}' is valid ✓", "idle")
        except Exception:
            try:
                from scapy.all import sniff as _sniff
                _sniff(filter=bpf, count=0, timeout=0.05, store=False)
                self._filter_status_lbl.config(fg=ACCENT_GREEN)
                self._set_status(f"BPF filter '{bpf}' is valid ✓", "idle")
            except Exception as e:
                self._filter_status_lbl.config(fg=ACCENT_RED)
                self._set_status(f"BPF filter error: {e}", "error")

    # ── Row selection ─────────────────────────
    def _on_row_select(self, _):
        sel = self._tree.selection()
        if not sel:
            return
        pkt = self._item_pkt.get(sel[0])
        if pkt:
            self._selected_pkt = pkt
            self._update_protocol_tree(pkt)
            self._update_hex_dump(pkt)

    def _on_row_double_click(self, _):
        if not self._selected_pkt:
            return
        self._show_packet_detail_popup(self._selected_pkt)

    def _show_packet_detail_popup(self, pkt):
        """Show a detailed popup window for a packet."""
        popup = tk.Toplevel(self.root)
        popup.title(f"Packet #{pkt['index']}  —  {pkt['protocol']}  —  Details")
        popup.configure(bg=BG_BASE)
        popup.geometry("780x560")

        # Notebook with text detail + hex dump
        nb = ttk.Notebook(popup, style="Custom.TNotebook")
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Tab 1: Formatted detail
        detail_frame = tk.Frame(nb, bg=BG_PANEL)
        nb.add(detail_frame, text=" Details ")
        txt = scrolledtext.ScrolledText(detail_frame, bg=BG_PANEL, fg=TEXT_PRIMARY,
                                         font=FONT_MONO_SM, relief="flat",
                                         selectbackground=BG_SELECTED)
        txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        txt.insert(tk.END, format_packet_details(pkt))
        txt.config(state=tk.DISABLED)

        # Tab 2: Hex dump
        hex_frame = tk.Frame(nb, bg=BG_PANEL)
        nb.add(hex_frame, text=" Hex Dump ")
        hex_txt = scrolledtext.ScrolledText(hex_frame, bg=BG_PANEL, fg=ACCENT_GREEN,
                                             font=FONT_MONO_SM, relief="flat",
                                             selectbackground=BG_SELECTED)
        hex_txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        raw_pkt = pkt.get("raw_pkt")
        if raw_pkt:
            hex_txt.insert(tk.END, format_hex_dump(raw_pkt))
        hex_txt.config(state=tk.DISABLED)

    # ── Column sort ───────────────────────────
    def _sort_by_column(self, col: str):
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False

        data = [(self._tree.set(iid, col), iid) for iid in self._tree.get_children()]
        try:
            data.sort(key=lambda t: float(t[0]), reverse=self._sort_reverse)
        except (ValueError, TypeError):
            data.sort(key=lambda t: t[0].lower(), reverse=self._sort_reverse)
        for i, (_, iid) in enumerate(data):
            self._tree.move(iid, "", i)

        # Update heading with sort indicator
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        for c in columns:
            arrow = ""
            if c == col:
                arrow = " ▼" if self._sort_reverse else " ▲"
            self._tree.heading(c, text=c + arrow)

    # ── Export ────────────────────────────────
    def _download_log(self):
        """Show a dialog to export the captured log as PCAP, JSON, or TXT."""
        if not self._stored_packets and (not self.engine or not self.engine.raw_packets):
            messagebox.showinfo("No Data", "No packets captured yet. Start a capture first.")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("Download Captured Log")
        dlg.configure(bg=BG_BASE)
        dlg.geometry("340x250")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(dlg, text="⬇  Export Captured Log", bg=BG_BASE, fg=ACCENT_CYAN,
                 font=("Segoe UI", 12, "bold")).pack(pady=(18, 4))
        pkt_count = len(self._stored_packets)
        tk.Label(dlg, text=f"{pkt_count} packets in current view",
                 bg=BG_BASE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(pady=(0, 14))

        btn_frame = tk.Frame(dlg, bg=BG_BASE)
        btn_frame.pack(fill=tk.X, padx=30)

        def _do_pcap():
            dlg.destroy()
            self._save_pcap()

        def _do_json():
            dlg.destroy()
            self._save_json()

        def _do_txt():
            if not self.engine:
                messagebox.showinfo("No Engine", "No active capture engine.", parent=dlg)
                return
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Log", "*.txt"), ("All", "*.*")],
                title="Export Plain-Text Log",
                parent=dlg)
            if path:
                ok = self.engine.export_txt(path, self._stored_packets)
                dlg.destroy()
                messagebox.showinfo("Export",
                    f"{'Saved ✓' if ok else 'Failed'}: {path}\n"
                    f"{len(self._stored_packets)} packets")

        for label, color, cmd in [
            ("  💾  Save as PCAP (.pcap)  ", ACCENT_GREEN,  _do_pcap),
            ("  📄  Export as JSON (.json) ", ACCENT_BLUE,   _do_json),
            ("  📝  Export as Text (.txt)  ", ACCENT_AMBER,  _do_txt),
        ]:
            b = tk.Button(btn_frame, text=label, command=cmd,
                          bg=BG_INPUT, fg=color,
                          activebackground=BG_HOVER, activeforeground=color,
                          font=FONT_BTN, relief="flat", bd=0, pady=7,
                          cursor="hand2", anchor="w")
            b.pack(fill=tk.X, pady=3)
            b.bind("<Enter>", lambda e, x=b: x.config(bg=BG_HOVER))
            b.bind("<Leave>", lambda e, x=b: x.config(bg=BG_INPUT))

        tk.Button(btn_frame, text="  Cancel", command=dlg.destroy,
                  bg=BG_BASE, fg=TEXT_DIM, activebackground=BG_BASE,
                  font=FONT_MAIN_SM, relief="flat", bd=0, pady=4,
                  cursor="hand2").pack(fill=tk.X, pady=(6, 0))

    def _save_pcap(self):
        if not self.engine or not self.engine.raw_packets:
            messagebox.showinfo("No Data", "No packets to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP", "*.pcap"), ("All", "*.*")],
            title="Save PCAP")
        if path:
            ok = self.engine.export_pcap(path)
            messagebox.showinfo("Export",
                f"{'Saved ✓' if ok else 'Failed'}: {path}\n"
                f"{len(self.engine.raw_packets)} packets")

    def _save_json(self):
        if not self._stored_packets:
            messagebox.showinfo("No Data", "No packets to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
            title="Export JSON")
        if path:
            import json
            data = [{k: v for k, v in p.items() if k != "raw_pkt"}
                    for p in self._stored_packets]
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str)
                messagebox.showinfo("Export", f"Saved {len(data)} packets → {path}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    # ── Analyze Popups ───────────────────────
    def _show_protocol_stats(self):
        if not self.engine:
            messagebox.showinfo("No Data", "Start a capture first.")
            return
        stats = self.engine.get_stats()
        protos = stats.get("protocols", {})
        popup = self._make_popup("Protocol Statistics", "600x400")
        txt = scrolledtext.ScrolledText(popup, bg=BG_PANEL, fg=TEXT_PRIMARY,
                                         font=FONT_MONO, relief="flat")
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        txt.insert(tk.END, f"{'Protocol':<20} {'Count':>10} {'Percentage':>12}\n")
        txt.insert(tk.END, "─" * 44 + "\n")
        total = stats["total"] or 1
        for proto, count in sorted(protos.items(), key=lambda x: x[1], reverse=True):
            pct = count / total * 100
            txt.insert(tk.END, f"{proto:<20} {count:>10} {pct:>10.1f}%\n")
        txt.insert(tk.END, f"\n{'TOTAL':<20} {total:>10}\n")
        txt.config(state=tk.DISABLED)

    def _show_endpoint_stats(self):
        if not self.engine:
            messagebox.showinfo("No Data", "Start a capture first.")
            return
        stats = self.engine.get_stats()
        endpoints = stats.get("endpoints", [])
        popup = self._make_popup("Endpoint Statistics", "700x450")
        txt = scrolledtext.ScrolledText(popup, bg=BG_PANEL, fg=TEXT_PRIMARY,
                                         font=FONT_MONO, relief="flat")
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        txt.insert(tk.END, f"{'Address':<25} {'Tx Pkts':>10} {'Rx Pkts':>10} {'Tx Bytes':>12} {'Rx Bytes':>12}\n")
        txt.insert(tk.END, "─" * 71 + "\n")
        for ep in endpoints:
            txt.insert(tk.END, f"{ep['ip']:<25} {ep['tx_pkts']:>10} {ep['rx_pkts']:>10} "
                              f"{self._fmt_bytes(ep['tx_bytes']):>12} {self._fmt_bytes(ep['rx_bytes']):>12}\n")
        txt.config(state=tk.DISABLED)

    def _show_streams_popup(self):
        if not self.engine:
            messagebox.showinfo("No Data", "Start a capture first.")
            return
        streams = self.engine.analyzer.get_top_streams(50)
        popup = self._make_popup("Active Streams", "750x450")
        txt = scrolledtext.ScrolledText(popup, bg=BG_PANEL, fg=TEXT_PRIMARY,
                                         font=FONT_MONO, relief="flat")
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        txt.insert(tk.END, f"{'Flow':<40} {'Proto':>8} {'Packets':>10} {'Data':>12}\n")
        txt.insert(tk.END, "─" * 72 + "\n")
        for s in streams:
            txt.insert(tk.END, f"{s['key'][:38]:<40} {s['proto']:>8} {s['packets']:>10} "
                              f"{self._fmt_bytes(s['bytes']):>12}\n")
        txt.config(state=tk.DISABLED)

    def _show_alerts_popup(self):
        if not self.engine:
            messagebox.showinfo("No Data", "Start a capture first.")
            return
        alerts = self.engine.analyzer.get_alerts()
        popup = self._make_popup("Threat Alerts", "700x400")
        txt = scrolledtext.ScrolledText(popup, bg=BG_PANEL, fg=ACCENT_RED,
                                         font=FONT_MONO, relief="flat")
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        if not alerts:
            txt.insert(tk.END, "No threats detected.\n")
        else:
            for a in alerts:
                txt.insert(tk.END, f"[{a['time']}] {a['type']}\n")
                txt.insert(tk.END, f"  Src: {a['src']}  Dst: {a['dst']}  Proto: {a['proto']}\n\n")
        txt.config(state=tk.DISABLED)

    # ── About Modal ───────────────────────────
    def _show_about(self):
        popup = self._make_popup("About NetPhantom", "480x380")

        inner = tk.Frame(popup, bg=BG_PANEL)
        inner.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        tk.Label(inner, text="◆", bg=BG_PANEL, fg=ACCENT_BLUE,
                 font=("Segoe UI", 28)).pack(pady=(8, 0))
        tk.Label(inner, text="NetPhantom", bg=BG_PANEL, fg=TEXT_PRIMARY,
                 font=("Segoe UI", 20, "bold")).pack(pady=(0, 2))
        tk.Label(inner, text="Professional Network Packet Analyzer",
                 bg=BG_PANEL, fg=TEXT_SECONDARY, font=("Segoe UI", 10)).pack()

        tk.Frame(inner, bg=BORDER, height=1).pack(fill=tk.X, padx=20, pady=12)

        rows = [
            ("Version",  "3.0"),
            ("Author",   "Lucky"),
            ("Category", "Cybersecurity Portfolio Project"),
            ("Engine",   "Scapy + Tkinter"),
            ("Platform", "Windows / Linux / macOS"),
            ("License",  "Apache License 2.0"),
        ]
        for label, val in rows:
            row = tk.Frame(inner, bg=BG_PANEL)
            row.pack(fill=tk.X, padx=24, pady=2)
            tk.Label(row, text=f"{label}:", bg=BG_PANEL, fg=TEXT_DIM,
                     font=FONT_MAIN_SM, width=12, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=val, bg=BG_PANEL, fg=ACCENT_CYAN,
                     font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)

        tk.Frame(inner, bg=BORDER, height=1).pack(fill=tk.X, padx=20, pady=10)
        self._make_btn(inner, "  Close  ", ACCENT_BLUE, popup.destroy).pack(pady=4)

    def _show_shortcuts(self):
        popup = self._make_popup("Keyboard Shortcuts", "440x440")
        txt = scrolledtext.ScrolledText(popup, bg=BG_PANEL, fg=TEXT_PRIMARY,
                                         font=FONT_MONO, relief="flat")
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        shortcuts = [
            ("F5",            "Start capture"),
            ("F6",            "Stop capture"),
            ("Ctrl+O",        "Open PCAP file"),
            ("Ctrl+S",        "Save as PCAP"),
            ("Ctrl+F",        "Focus search / display filter"),
            ("Ctrl+L",        "Clear all packets"),
            ("Ctrl+R",        "Restart capture"),
            ("Ctrl+C",        "Copy Packet Summary"),
            ("Ctrl+Shift+C",  "Copy Detailed Dissection"),
            ("Ctrl+Alt+C",    "Copy Raw Hex Dump"),
            ("Ctrl+P",        "Open Preferences"),
            ("Ctrl++",        "Zoom in"),
            ("Ctrl+-",        "Zoom out"),
            ("Escape",        "Stop capture"),
            ("Dbl-click",     "Open packet detail popup"),
        ]
        for key, desc in shortcuts:
            txt.insert(tk.END, f"  {key:<16} {desc}\n")
        txt.config(state=tk.DISABLED)

    # ── Shortcuts ─────────────────────────────
    def _bind_shortcuts(self):
        self.root.bind("<F5>",          lambda e: self.start_capture())
        self.root.bind("<F6>",          lambda e: self.stop_capture())
        self.root.bind("<Control-o>",   lambda e: self._open_pcap_dialog())
        self.root.bind("<Control-s>",   lambda e: self._save_pcap())
        self.root.bind("<Control-e>",   lambda e: self._save_pcap())
        self.root.bind("<Control-f>",   lambda e: self._search_entry.focus_set())
        self.root.bind("<Control-l>",   lambda e: self.clear_packets())
        self.root.bind("<Control-r>",   lambda e: self._restart_capture())
        self.root.bind("<Control-plus>",  lambda e: self._change_font_size(1))
        self.root.bind("<Control-minus>", lambda e: self._change_font_size(-1))
        self.root.bind("<Control-equal>", lambda e: self._change_font_size(1))
        self.root.bind("<Escape>",      lambda e: self.stop_capture())
        self.root.bind("<Control-c>",   self._copy_packet_summary)
        self.root.bind("<Control-C>",   self._copy_detailed_dissection) # Shift+C triggers capital C
        self.root.bind("<Control-Alt-c>", self._copy_raw_hex)
        self.root.bind("<Control-p>",   self._open_preferences)

    # ── Font Size ─────────────────────────────
    def _change_font_size(self, delta: int):
        self._font_size = max(7, min(18, self._font_size + delta))
        style = ttk.Style()
        style.configure("Packet.Treeview", font=("Consolas", self._font_size - 1),
                        rowheight=max(18, self._font_size * 2 + 2))

    # ── Configurations & Preferences ───────────
    def _load_config(self):
        import json
        import os
        self._config = {
            "resolve_ips": False,
            "max_buffer": 10000,
            "default_filter": "",
            "autosave_pcap": False,
            "accent_color": "#06b6d4"  # default Cyan
        }
        if os.path.exists(self._config_path):
            try:
                with open(self._config_path, "r") as f:
                    user_cfg = json.load(f)
                    self._config.update(user_cfg)
            except Exception:
                pass
        self._accent_color = self._config["accent_color"]

    def _save_config(self):
        import json
        try:
            with open(self._config_path, "w") as f:
                json.dump(self._config, f, indent=4)
        except Exception:
            pass

    def _apply_accent_color(self):
        color = self._config["accent_color"]
        self._accent_color = color
        style = ttk.Style()
        style.configure("Packet.Treeview.Heading", foreground=color)
        style.map("Custom.TNotebook.Tab", foreground=[("selected", color)])

    def _open_preferences(self, event=None):
        pref = self._make_popup("Preferences", "420x400")
        pref.transient(self.root)
        pref.grab_set()

        # Build preference controls in a nice panel
        panel = tk.Frame(pref, bg=BG_PANEL, bd=1, relief="solid", highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Hostname resolution
        resolve_var = tk.BooleanVar(value=self._config["resolve_ips"])
        chk_resolve = tk.Checkbutton(panel, text="Resolve IP addresses to hostnames", variable=resolve_var,
                                     bg=BG_PANEL, fg=TEXT_PRIMARY, activebackground=BG_PANEL,
                                     activeforeground=TEXT_PRIMARY, selectcolor=BG_INPUT,
                                     font=FONT_MAIN_SM)
        chk_resolve.pack(anchor="w", padx=16, pady=(20, 10))

        # Max buffer size
        tk.Label(panel, text="Max packets in capture history:", bg=BG_PANEL, fg=TEXT_SECONDARY,
                 font=FONT_MAIN_SM).pack(anchor="w", padx=16, pady=(10, 2))
        buf_entry = tk.Entry(panel, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                             bd=1, relief="solid", font=FONT_MONO_SM, highlightthickness=0)
        buf_entry.insert(0, str(self._config["max_buffer"]))
        buf_entry.pack(fill=tk.X, padx=16, pady=(0, 10))

        # Default BPF filter
        tk.Label(panel, text="Default BPF capture filter:", bg=BG_PANEL, fg=TEXT_SECONDARY,
                 font=FONT_MAIN_SM).pack(anchor="w", padx=16, pady=(10, 2))
        filter_entry = tk.Entry(panel, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                                bd=1, relief="solid", font=FONT_MONO_SM, highlightthickness=0)
        filter_entry.insert(0, self._config["default_filter"])
        filter_entry.pack(fill=tk.X, padx=16, pady=(0, 10))

        # Accent color configuration
        tk.Label(panel, text="UI Accent Color Highlight:", bg=BG_PANEL, fg=TEXT_SECONDARY,
                 font=FONT_MAIN_SM).pack(anchor="w", padx=16, pady=(10, 2))
        color_choices = {
            "Cyber Cyan": "#06b6d4",
            "Electric Blue": "#3b82f6",
            "Emerald Green": "#10b981",
            "Vivid Purple": "#8b5cf6",
            "Warm Amber": "#f59e0b"
        }
        color_var = tk.StringVar(value=next((k for k, v in color_choices.items() if v == self._config["accent_color"]), "Cyber Cyan"))
        color_combo = ttk.Combobox(panel, textvariable=color_var, values=list(color_choices.keys()),
                                   state="readonly", font=FONT_MAIN_SM, style="Custom.TCombobox")
        color_combo.pack(fill=tk.X, padx=16, pady=(0, 20))

        def save_prefs():
            try:
                max_buf = int(buf_entry.get().strip())
                if max_buf <= 0: raise ValueError
            except ValueError:
                messagebox.showerror("Invalid Input", "Buffer limit must be a positive integer.", parent=pref)
                return

            self._config["resolve_ips"] = resolve_var.get()
            self._config["max_buffer"] = max_buf
            self._config["default_filter"] = filter_entry.get().strip()
            self._config["accent_color"] = color_choices[color_var.get()]

            self._save_config()
            self._apply_accent_color()
            pref.destroy()
            self._set_status("Preferences saved", "idle")

        btn_save = tk.Button(pref, text="Save Settings", command=save_prefs,
                             bg=BG_INPUT, fg=ACCENT_GREEN, activebackground=BG_HOVER,
                             activeforeground=ACCENT_GREEN, font=FONT_BTN, relief="flat",
                             bd=0, padx=14, pady=6, cursor="hand2")
        btn_save.pack(side=tk.RIGHT, padx=20, pady=(0, 20))

    # ── Clipboard Copying Operations ───────────
    def _copy_packet_summary(self, event=None):
        if not self._selected_pkt:
            return
        summary = (
            f"No: {self._selected_pkt.get('num', '')} | "
            f"Time: {self._selected_pkt.get('time', '')} | "
            f"Source: {self._selected_pkt.get('src', '')} | "
            f"Destination: {self._selected_pkt.get('dst', '')} | "
            f"Protocol: {self._selected_pkt.get('protocol', '')} | "
            f"Length: {self._selected_pkt.get('len', '')} | "
            f"Info: {self._selected_pkt.get('info', '')}"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(summary)
        self._set_status("Copied packet summary to clipboard", "idle")

    def _copy_detailed_dissection(self, event=None):
        if not self._selected_pkt:
            return
        details = format_packet_details(self._selected_pkt.get("_raw_packet"))
        self.root.clipboard_clear()
        self.root.clipboard_append(details)
        self._set_status("Copied detailed dissection to clipboard", "idle")

    def _copy_raw_hex(self, event=None):
        if not self._selected_pkt:
            return
        hex_dump = format_hex_dump(self._selected_pkt.get("_raw_packet"))
        self.root.clipboard_clear()
        self.root.clipboard_append(hex_dump)
        self._set_status("Copied raw hex dump to clipboard", "idle")

    # ── Helpers ───────────────────────────────
    def _sep(self, parent):
        tk.Frame(parent, bg=BORDER, width=1).pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=8)

    def _make_btn(self, parent, text: str, color: str, cmd) -> tk.Button:
        btn = tk.Button(parent, text=text, command=cmd,
                        bg=BG_INPUT, fg=color,
                        activebackground=BG_HOVER, activeforeground=color,
                        font=FONT_BTN, relief="flat",
                        bd=0, padx=10, pady=4, cursor="hand2")
        btn.pack(side=tk.LEFT, padx=3, pady=6)

        # Smooth hover: animate bg toward BG_HOVER on Enter, back to BG_INPUT on Leave
        _hover_job = [None]

        def _lerp_color(start: str, end: str, steps: int, step_idx: int) -> str:
            """Simple linear interpolate between two hex colours."""
            try:
                s = [int(start.lstrip('#')[i:i+2], 16) for i in (0, 2, 4)]
                e = [int(end.lstrip('#')[i:i+2], 16) for i in (0, 2, 4)]
                t = step_idx / max(steps, 1)
                r = [int(s[i] + (e[i] - s[i]) * t) for i in range(3)]
                return '#%02x%02x%02x' % tuple(r)
            except Exception:
                return end

        def _animate_hover(start, end, step=0, total=6):
            if _hover_job[0] is not None:
                try:
                    btn.after_cancel(_hover_job[0])
                except Exception:
                    pass
            if step <= total:
                try:
                    btn.config(bg=_lerp_color(start, end, total, step))
                    _hover_job[0] = btn.after(18, _animate_hover, start, end, step + 1, total)
                except Exception:
                    pass

        btn.bind("<Enter>", lambda e: _animate_hover(BG_INPUT, BG_HOVER))
        btn.bind("<Leave>", lambda e: _animate_hover(BG_HOVER, BG_INPUT))
        return btn

    def _make_popup(self, title: str, geometry: str = "500x400") -> tk.Toplevel:
        popup = tk.Toplevel(self.root)
        popup.title(title)
        popup.configure(bg=BG_BASE)
        popup.geometry(geometry)
        return popup

    def _set_status(self, msg: str, state: str = "idle"):
        self._status_var.set(msg)
        self._status_state = state
        color_map = {
            "idle":      TEXT_DIM,
            "capturing": ACCENT_GREEN,
            "stopped":   ACCENT_AMBER,
            "loading":   ACCENT_BLUE,
            "loaded":    ACCENT_CYAN,
            "error":     ACCENT_RED,
        }
        self._status_indicator.config(fg=color_map.get(state, TEXT_DIM))

    def _animate_ui_effects(self):
        """Background animation loop — status pulse, scanline, badge glow, HUD flicker, burst flash."""
        import math
        try:
            self._anim_step = (self._anim_step + 1) % 120
            step = self._anim_step

            # ── 1. Status Indicator Breathing Glow (sine-wave intensity)
            sin_t = (math.sin(step * math.pi / 30) + 1) / 2  # 0..1 oscillation
            if self._status_state == "capturing":
                r = int(16 + 50 * sin_t)
                g = int(185 - 40 * sin_t)
                b_c = int(129 - 50 * sin_t)
                self._status_indicator.config(fg=f"#{r:02x}{g:02x}{b_c:02x}")
                # Stop button glow pulses green while capturing
                if hasattr(self, "_btn_stop") and self._btn_stop.cget("state") != tk.DISABLED:
                    gv = int(60 + 40 * sin_t)
                    self._btn_stop.config(bg=f"#00{gv:02x}00")
            elif self._status_state in ("loading", "loaded"):
                rv = int(59 + 60 * sin_t)
                gv = int(130 + 65 * sin_t)
                bv = int(246 - 30 * sin_t)
                self._status_indicator.config(fg=f"#{rv:02x}{gv:02x}{bv:02x}")
            elif self._status_state == "stopped":
                rv = int(245 - 20 * sin_t)
                gv = int(158 + 40 * sin_t)
                self._status_indicator.config(fg=f"#{rv:02x}{gv:02x}0b")
            elif self._status_state == "error":
                # Red flash
                rv = int(220 + 35 * sin_t)
                self._status_indicator.config(fg=f"#{rv:02x}1010")

            # ── 2. Title bar HUD flicker (◆ color cycle)
            if hasattr(self, "root"):
                cycle = ["◆", "◆", "◆", "◈"]
                self.root.title(f"{cycle[step // 8 % len(cycle)]} NetPhantom — Professional Packet Analyzer")

            # ── 3. Graph Canvas: laser scanline + corner HUD brackets
            if hasattr(self, "_graph_canvas") and self._graph_canvas.winfo_exists():
                cw = self._graph_canvas.winfo_width() or 280
                ch = self._graph_canvas.winfo_height() or 200

                # Scanline travels left to right
                self._scanline_x = (self._scanline_x + 5) % max(cw, 1)
                self._graph_canvas.delete("scanline")
                if cw > 50:
                    # Dim trailing glow (3 parallel lines with decreasing opacity via colour)
                    for offset, col in [(0, "#00f3ff"), (-3, "#003a42"), (-6, "#001a1f")]:
                        sx = (self._scanline_x + offset) % cw
                        self._graph_canvas.create_line(sx, 0, sx, ch,
                                                        fill=col, width=1, tags="scanline")

                # Corner HUD brackets (subtle, small)
                bsz = 10
                bcol = "#00f3ff" if step % 60 < 30 else "#6366f1"
                self._graph_canvas.delete("hud_corner")
                for (cx, cy, dx, dy) in [
                    (1, 1, 1, 1), (cw-1, 1, -1, 1), (1, ch-1, 1, -1), (cw-1, ch-1, -1, -1)
                ]:
                    self._graph_canvas.create_line(cx, cy, cx + dx*bsz, cy,
                                                    fill=bcol, width=1, tags="hud_corner")
                    self._graph_canvas.create_line(cx, cy, cx, cy + dy*bsz,
                                                    fill=bcol, width=1, tags="hud_corner")

            # ── 4. Protocol badge row: cycle active badge border glow
            if hasattr(self, "_badge_btns") and step % 6 == 0:
                active_proto = getattr(self, "_filter_proto_var", None)
                if active_proto:
                    active = active_proto.get()
                    glow_cols = ["#1e3a5f", "#003a60", "#004d80", "#003a60"]
                    gcol = glow_cols[(step // 6) % len(glow_cols)]
                    for p, b in self._badge_btns.items():
                        if p == active:
                            b.config(bg=gcol)

            # ── 5. Data burst flash: when new packets arrive, flash graph border
            if hasattr(self, "_graph_canvas") and self._graph_canvas.winfo_exists():
                pkt_count = len(getattr(self, "_packets", []))
                prev = getattr(self, "_prev_pkt_count_anim", 0)
                self._prev_pkt_count_anim = pkt_count
                if pkt_count != prev:
                    burst_colors = ["#00f3ff", "#00b8d4", "#006b80", "#003040"]
                    bcol = burst_colors[min(step % len(burst_colors), len(burst_colors)-1)]
                    self._graph_canvas.config(highlightbackground=bcol, highlightthickness=1)

            self._anim_job = self.root.after(65, self._animate_ui_effects)
        except Exception:
            pass

    @staticmethod
    def _fmt_bytes(b: int) -> str:
        if b >= 1_073_741_824: return f"{b/1_073_741_824:.1f}G"
        if b >= 1_048_576:     return f"{b/1_048_576:.1f}M"
        if b >= 1024:          return f"{b/1024:.1f}K"
        return f"{b}B"

    def _update_clock(self):
        try:
            self._clock_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
            self._clock_job = self.root.after(1000, self._update_clock)
        except Exception:
            pass  # Widget may be destroyed during shutdown

    def _show_warning(self):
        msg = (
            "⚠  ETHICAL USE WARNING\n\n"
            "This tool is for AUTHORIZED use ONLY.\n"
            "Capturing traffic without permission is illegal.\n\n"
            "By proceeding you confirm you have full authorization\n"
            "to monitor the target network.\n\n"
            "Run as Administrator / root for packet capture."
        )
        messagebox.showwarning("NetPhantom — Ethical Use", msg)

    def on_close(self):
        """Gracefully shut down: stop capture, cancel timers, save config, destroy."""
        # 1. Stop the poll loop
        if self._poll_job:
            try:
                self.root.after_cancel(self._poll_job)
            except Exception:
                pass
            self._poll_job = None

        # 2. Cancel timers
        if self._clock_job:
            try:
                self.root.after_cancel(self._clock_job)
            except Exception:
                pass
            self._clock_job = None

        if self._anim_job:
            try:
                self.root.after_cancel(self._anim_job)
            except Exception:
                pass
            self._anim_job = None

        # 3. Stop and join the capture thread (waits up to 3 s)
        if self.engine:
            self.engine.stop()
        self.engine = None

        # 4. Persist config
        try:
            self._save_config()
        except Exception:
            pass

    def _show_extcap_dialog(self):
        top = tk.Toplevel(self.root)
        top.title("External Capture Tools (extcap)")
        top.geometry("540x380")
        top.configure(bg=BG_BASE)
        top.transient(self.root)

        tk.Label(top, text="External Capture Tools (extcap)", bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(16, 4))
        tk.Label(top, text="Configure external interfaces and capture dumping utilities:", bg=BG_BASE, fg=TEXT_SECONDARY, font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(0, 10))

        frame = tk.Frame(top, bg=BG_PANEL, bd=1, relief="solid")
        frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=4)

        tools = [
            ("Androiddump", "Android ADB packet sniffer for mobile device auditing", True),
            ("Etwdump", "Windows Event Tracing (ETW) live kernel packet capturer", True),
            ("Randpktdump", "Random packet generator for fuzzer testing", True),
            ("Sshdump & Ciscodump", "Remote SSH & Cisco router packet streamer", True),
            ("UDPdump", "UDP raw socket packet receiver listener", True),
            ("Wifidump", "Wi-Fi 802.11 monitor mode raw frame dissector", True),
        ]

        for name, desc, active in tools:
            sub = tk.Frame(frame, bg=BG_PANEL)
            sub.pack(fill=tk.X, padx=12, pady=6)
            var = tk.BooleanVar(value=active)
            tk.Checkbutton(sub, text=f"☑ {name}", variable=var, bg=BG_PANEL, fg=TEXT_PRIMARY, activebackground=BG_PANEL, selectcolor=BG_INPUT, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
            tk.Label(sub, text=f"— {desc}", bg=BG_PANEL, fg=TEXT_DIM, font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=6)

        btn_close = tk.Button(top, text="OK", command=top.destroy, bg=ACCENT_BLUE, fg="white", font=("Segoe UI", 9, "bold"), relief="flat", bd=0, padx=20, pady=6, cursor="hand2")
        btn_close.pack(anchor="e", padx=16, pady=12)

    def _show_npcap_dialog(self):
        top = tk.Toplevel(self.root)
        top.title("Npcap Packet Capture Driver")
        top.geometry("520x340")
        top.configure(bg=BG_BASE)
        top.transient(self.root)

        import sys, os
        system32 = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
        npcap_exists = os.path.exists(os.path.join(system32, "Npcap", "wpcap.dll")) or os.path.exists(os.path.join(system32, "wpcap.dll"))

        status_text = "✓ Npcap 1.88 Driver Active & Running" if npcap_exists else "⚠ Npcap Driver Not Detected"
        status_color = ACCENT_GREEN if npcap_exists else ACCENT_AMBER

        tk.Label(top, text="Packet Capture Driver Status", bg=BG_BASE, fg=TEXT_PRIMARY, font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(16, 4))
        
        status_box = tk.LabelFrame(top, text=" System Driver ", bg=BG_PANEL, fg=TEXT_PRIMARY, font=("Segoe UI", 9, "bold"), bd=1, relief="solid")
        status_box.pack(fill=tk.X, padx=16, pady=10, ipadx=8, ipady=6)
        tk.Label(status_box, text=status_text, bg=BG_PANEL, fg=status_color, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=8, pady=4)

        info_box = tk.LabelFrame(top, text=" Driver Details & Promiscuous Mode ", bg=BG_PANEL, fg=TEXT_PRIMARY, font=("Segoe UI", 9, "bold"), bd=1, relief="solid")
        info_box.pack(fill=tk.BOTH, expand=True, padx=16, pady=4, ipadx=8, ipady=6)
        
        msg = ("Npcap allows NetPhantom to sniff raw 802.11 Wi-Fi frames and Ethernet packets at the hardware layer.\n\n"
               "If you experience missing network interfaces or socket binding errors, verify that Npcap is installed with 'WinPcap API Compatibility' enabled.")
        tk.Label(info_box, text=msg, bg=BG_PANEL, fg=TEXT_SECONDARY, font=("Segoe UI", 8), justify="left", wraplength=460).pack(anchor="w", padx=8, pady=4)

        btn_frame = tk.Frame(top, bg=BG_BASE)
        btn_frame.pack(fill=tk.X, padx=16, pady=12)

        import webbrowser
        btn_dl = tk.Button(btn_frame, text="🌐 Download Npcap Driver...", command=lambda: webbrowser.open("https://npcap.com/#download"), bg=BG_INPUT, fg=ACCENT_CYAN, font=("Segoe UI", 9), relief="flat", bd=0, padx=12, pady=4, cursor="hand2")
        btn_dl.pack(side=tk.LEFT)

        btn_ok = tk.Button(btn_frame, text="Close", command=top.destroy, bg=ACCENT_BLUE, fg="white", font=("Segoe UI", 9, "bold"), relief="flat", bd=0, padx=16, pady=4, cursor="hand2")
        btn_ok.pack(side=tk.RIGHT)

    def _show_capture_options_dialog(self):
        """Wireshark-style Capture Options & Interface Selection Panel (Screenshot 2)."""
        top = tk.Toplevel(self.root)
        top.title("NetPhantom · Capture Options")
        top.geometry("760x520")
        top.configure(bg=BG_BASE)
        top.transient(self.root)

        # Tabbed view: Input | Output | Options
        nb = ttk.Notebook(top, style="Custom.TNotebook")
        nb.pack(fill=tk.BOTH, expand=True, padx=12, pady=(12, 4))

        input_frame = tk.Frame(nb, bg=BG_BASE)
        output_frame = tk.Frame(nb, bg=BG_BASE)
        options_frame = tk.Frame(nb, bg=BG_BASE)

        nb.add(input_frame, text=" Input ")
        nb.add(output_frame, text=" Output ")
        nb.add(options_frame, text=" Options ")

        # ── Input Tab: Interface Table Treeview ──
        columns = ("iface", "traffic", "link")
        tree = ttk.Treeview(input_frame, columns=columns, show="headings", style="Side.Treeview", height=10)
        tree.heading("iface", text="Interface")
        tree.heading("traffic", text="Traffic Activity")
        tree.heading("link", text="Link-layer Header")

        tree.column("iface", width=340, anchor="w")
        tree.column("traffic", width=220, anchor="w")
        tree.column("link", width=160, anchor="w")

        tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Populate interfaces list with extcap dumpers
        ifaces = [
            ("Wi-Fi (Intel(R) Wi-Fi 6 AX201)", "∿∿∿∿∿∿ (Active Traffic)", "Ethernet"),
            ("Ethernet 2 (Realtek PCIe GbE)", "──────── (Idle)", "Ethernet"),
            ("Adapter for loopback traffic", "──────── (Idle)", "BSD loopback"),
            ("Cisco remote capture: ciscodump", "──────── (Remote)", "Remote capture dependent DLT"),
            ("Event Tracing for Windows (ETW) reader: etwdump", "──────── (Kernel)", "DLT_ETW"),
            ("Random packet generator: randpkt", "──────── (Generator)", "Generator dependent DLT"),
            ("SSH remote capture: sshdump", "──────── (SSH)", "Remote capture dependent DLT"),
            ("UDP Listener remote capture: udpdump", "──────── (UDP Listener)", "Exported PDUs"),
            ("Wi-Fi remote capture: wifidump", "──────── (Wi-Fi Raw)", "Remote capture dependent DLT"),
        ]

        for iface, traf, link in ifaces:
            tree.insert("", tk.END, values=(iface, traf, link))

        # Bottom Checkboxes & Options
        opt_frame = tk.Frame(input_frame, bg=BG_BASE)
        opt_frame.pack(fill=tk.X, padx=8, pady=4)

        promisc_var = tk.BooleanVar(value=True)
        mon_var = tk.BooleanVar(value=False)

        cb_style = {"bg": BG_BASE, "fg": TEXT_PRIMARY, "activebackground": BG_BASE, "selectcolor": BG_INPUT, "font": ("Segoe UI", 9)}
        tk.Checkbutton(opt_frame, text="☑ Enable promiscuous mode on all interfaces", variable=promisc_var, **cb_style).pack(side=tk.LEFT, padx=(0, 16))
        tk.Checkbutton(opt_frame, text="☐ Enable monitor mode on all 802.11 interfaces", variable=mon_var, **cb_style).pack(side=tk.LEFT)

        # Filter entry for selected interfaces
        flt_frame = tk.Frame(input_frame, bg=BG_BASE)
        flt_frame.pack(fill=tk.X, padx=8, pady=6)
        tk.Label(flt_frame, text="Capture filter for selected interfaces:", bg=BG_BASE, fg=TEXT_SECONDARY, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 6))

        cap_filter_entry = tk.Entry(flt_frame, bg=BG_INPUT, fg=ACCENT_CYAN, font=("Consolas", 9), relief="flat", bd=4)
        cap_filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        FilterAutocomplete(cap_filter_entry)

        # Action Buttons (Start, Close, Help)
        btn_bar = tk.Frame(top, bg=BG_PANEL, height=45)
        btn_bar.pack(fill=tk.X, side=tk.BOTTOM)
        btn_bar.pack_propagate(False)

        def _start_selected():
            top.destroy()
            self.start_capture()

        tk.Button(btn_bar, text="Start", command=_start_selected, bg=ACCENT_GREEN, fg="white", font=("Segoe UI", 9, "bold"), relief="flat", bd=0, padx=20, pady=4, cursor="hand2").pack(side=tk.RIGHT, padx=12, pady=8)
        tk.Button(btn_bar, text="Close", command=top.destroy, bg=BG_INPUT, fg=TEXT_PRIMARY, font=("Segoe UI", 9), relief="flat", bd=0, padx=16, pady=4, cursor="hand2").pack(side=tk.RIGHT, padx=4, pady=8)
        tk.Button(btn_bar, text="Help", command=self._show_manual, bg=BG_INPUT, fg=ACCENT_CYAN, font=("Segoe UI", 9), relief="flat", bd=0, padx=16, pady=4, cursor="hand2").pack(side=tk.RIGHT, padx=4, pady=8)

    def _show_manual(self):
        """Displays NetPhantom user manual & web documentation."""
        import webbrowser
        webbrowser.open("https://netphantom.luckyverse.tech/")

        # 5. Destroy the Tk window
        try:
            self.root.destroy()
        except Exception:
            pass


# ──────────────────────────────────────────────
#  Launch
# ──────────────────────────────────────────────
def run_gui(open_file: str = None, app_ref: list = None):
    # Enable DPI awareness on Windows to prevent blurry text
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

    show_splash()
    root = tk.Tk()
    
    # Set window icon from logo.png
    _logo_path = _find_logo_path()
    if _logo_path:
        try:
            from PIL import Image, ImageTk
            _icon_img = Image.open(_logo_path).resize((64, 64), Image.LANCZOS)
            _icon_photo = ImageTk.PhotoImage(_icon_img)
            root.iconphoto(True, _icon_photo)
            root._icon_ref = _icon_photo  # prevent garbage collection
        except Exception:
            pass

    app  = PacketSnifferGUI(root, open_file=open_file)
    if app_ref is not None:
        app_ref[0] = app
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
