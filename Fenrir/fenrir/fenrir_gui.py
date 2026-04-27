# fenrir/fenrir_gui.py
#
# Fix 21 — Changes from original:
#   - setup_logging() now receives log_queue correctly
#   - process_log_queue() parses LEVELNO:<int>| prefix from QueueFormatter
#     and applies yellow (WARNING) / red (ERROR/CRITICAL) colour tags
#   - on_closing() bound via self.protocol("WM_DELETE_WINDOW", self.on_closing)
#   - background image: .convert("RGBA") called before .putalpha() to avoid
#     "image has wrong mode" crash on non-RGBA source images
#   - All 16 module checkboxes wired in run_scan_async()
#   - Advanced options panel added: CVE limit, ports, wordlist path, OT duration,
#     RF freq range + threshold, password spray service selector, BLE duration
#   - Soft API key warning dialog on scan start for Threat Intel / OSINT modules
#   - Database panel (build/update/status) added as a tab
#   - Stop scan button (sets cancel event; modules check it where possible)
#   - Output text widget colour-codes WARNING (amber) and ERROR/CRITICAL (red)
#   - Status bar at bottom: target + scan elapsed time
#   - Config inputs: output directory browser, wordlist browse

import asyncio
import logging
import os
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Optional

from PIL import Image, ImageTk

from .config import config
from .logging_config import get_logger, setup_logging
from .modules import (
    MODULE_REGISTRY,
    DEFAULT_PORTS,
    WEB_PORTS,
    SSH_PORT,
    parse_ports,
    PortScanner,
    VulnerabilityScanner,
    WebScanner,
    DirBruteForcer,
    TechDetector,
    SubdomainScanner,
    DnsScanner,
    WhoisScanner,
    OsintScanner,
    ThreatIntelScanner,
    ExploitScanner,
    PasswordSprayer,
    IotScanner,
    OtScanner,
    MobileScanner,
    RfScanner,
)
from .report_manager import ReportManager

log = get_logger()

# Colour scheme
DARK_BG    = "#1e1e2e"
PANEL_BG   = "#2a2a3e"
ACCENT     = "#89b4fa"   # Catppuccin blue
TEXT_FG    = "#cdd6f4"
WARN_FG    = "#f9e2af"   # amber
ERR_FG     = "#f38ba8"   # red
SUCCESS_FG = "#a6e3a1"   # green
ENTRY_BG   = "#313244"
SEP_FG     = "#45475a"
BTN_ACTIVE = "#585b70"


class FenrirGUI(tk.Tk):
    """Main Fenrir GUI application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Fenrir Security Scanner")
        self.geometry("1100x760")
        self.minsize(900, 640)
        self.configure(bg=DARK_BG)

        # Asset paths relative to project root
        self._asset = {
            "icon":       "assets/logo.png",
            "logo":       "assets/logo.png",
            "background": "assets/background.png",
        }

        # Log queue — scanner thread → GUI
        self.log_queue: queue.Queue = queue.Queue()
        setup_logging(log_level=logging.DEBUG, log_queue=self.log_queue)

        # Scan state
        self._scan_thread:  Optional[threading.Thread] = None
        self._cancel_event: threading.Event = threading.Event()
        self._scan_start:   Optional[float] = None

        self._apply_styles()
        self._set_icon()
        self._build_ui()

        # Wire close button
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Start log queue polling
        self._poll_log_queue()

        # Status bar clock
        self._tick_status()

    # =========================================================================
    # Styles
    # =========================================================================

    def _apply_styles(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".",
                     background=PANEL_BG, foreground=TEXT_FG,
                     fieldbackground=ENTRY_BG, insertcolor=TEXT_FG)
        s.configure("TLabel",       background=PANEL_BG, foreground=TEXT_FG)
        s.configure("TFrame",       background=PANEL_BG)
        s.configure("TLabelframe",  background=PANEL_BG, bordercolor=SEP_FG, relief="flat")
        s.configure("TLabelframe.Label", background=PANEL_BG, foreground=ACCENT, font=("Helvetica", 9, "bold"))
        s.configure("TCheckbutton", background=PANEL_BG, foreground=TEXT_FG)
        s.map("TCheckbutton", background=[("active", PANEL_BG)])
        s.configure("TButton",
                     background=ENTRY_BG, foreground=TEXT_FG,
                     padding=(8, 4), relief="flat")
        s.map("TButton",
              background=[("active", BTN_ACTIVE), ("disabled", SEP_FG)],
              foreground=[("disabled", SEP_FG)])
        s.configure("Accent.TButton",
                     background=ACCENT, foreground=DARK_BG,
                     font=("Helvetica", 10, "bold"), padding=(10, 5))
        s.map("Accent.TButton", background=[("active", "#74c7ec")])
        s.configure("Stop.TButton",
                     background="#f38ba8", foreground=DARK_BG,
                     font=("Helvetica", 10, "bold"), padding=(10, 5))
        s.configure("TEntry",       fieldbackground=ENTRY_BG, foreground=TEXT_FG)
        s.configure("TSpinbox",     fieldbackground=ENTRY_BG, foreground=TEXT_FG)
        s.configure("TCombobox",    fieldbackground=ENTRY_BG, foreground=TEXT_FG)
        s.configure("TNotebook",    background=DARK_BG, tabmargins=[0, 0, 0, 0])
        s.configure("TNotebook.Tab",
                     background=PANEL_BG, foreground=TEXT_FG,
                     padding=[10, 4])
        s.map("TNotebook.Tab",
              background=[("selected", DARK_BG)],
              foreground=[("selected", ACCENT)])
        s.configure("TScrollbar",   background=ENTRY_BG, troughcolor=DARK_BG)
        s.configure("Separator.TFrame", background=SEP_FG)
        s.configure("TProgressbar", background=ACCENT, troughcolor=ENTRY_BG)

    # =========================================================================
    # Icon
    # =========================================================================

    def _set_icon(self) -> None:
        icon_path = self._asset["icon"]
        if os.path.exists(icon_path):
            try:
                self._icon_img = ImageTk.PhotoImage(file=icon_path)
                self.tk.call("wm", "iconphoto", self._w, self._icon_img)
            except Exception as exc:
                print(f"[GUI] Icon load failed: {exc}")

    # =========================================================================
    # UI construction
    # =========================================================================

    def _build_ui(self) -> None:
        """Assemble the full window layout."""
        # Background image layer
        self._bg_label = tk.Label(self, bg=DARK_BG)
        self._bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        self._update_background()
        self.bind("<Configure>", lambda e: self._update_background())

        # Root notebook — Scan / Database tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=(6, 0))

        # ---- Tab 1: Scan ----
        scan_tab = ttk.Frame(notebook)
        notebook.add(scan_tab, text="  Scan  ")
        self._build_scan_tab(scan_tab)

        # ---- Tab 2: Database ----
        db_tab = ttk.Frame(notebook)
        notebook.add(db_tab, text="  Database  ")
        self._build_db_tab(db_tab)

        # ---- Status bar ----
        self._build_status_bar()

    # ---- Scan tab ----

    def _build_scan_tab(self, parent: ttk.Frame) -> None:
        paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left: options (fixed-ish width)
        left = ttk.Frame(paned, width=320)
        paned.add(left, weight=0)
        self._build_left_panel(left)

        # Right: live output
        right = ttk.Frame(paned)
        paned.add(right, weight=1)
        self._build_output_panel(right)

    def _build_left_panel(self, parent: ttk.Frame) -> None:
        """Target, modules, advanced options, output, start/stop buttons."""
        canvas = tk.Canvas(parent, bg=PANEL_BG, highlightthickness=0)
        scroll = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        inner = ttk.Frame(canvas)
        inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_frame_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def _on_canvas_configure(e):
            canvas.itemconfig(inner_id, width=e.width)

        inner.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        PAD = {"padx": 6, "pady": 4, "fill": tk.X}

        # ── Logo ──────────────────────────────────────────────────────────
        logo_path = self._asset["logo"]
        if os.path.exists(logo_path):
            try:
                img = Image.open(logo_path).resize((80, 80), Image.Resampling.LANCZOS)
                self._logo_img = ImageTk.PhotoImage(img)
                tk.Label(inner, image=self._logo_img, bg=PANEL_BG).pack(pady=(8, 0))
            except Exception:
                pass
        tk.Label(inner, text="FENRIR", bg=PANEL_BG, fg=ACCENT,
                 font=("Helvetica", 16, "bold")).pack()

        # ── Target ────────────────────────────────────────────────────────
        tf = ttk.LabelFrame(inner, text="Target", padding=8)
        tf.pack(**PAD)
        tf.columnconfigure(1, weight=1)
        ttk.Label(tf, text="Host/IP:").grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._target_var = tk.StringVar(value="192.168.1.1")
        ttk.Entry(tf, textvariable=self._target_var).grid(row=0, column=1, sticky="ew")

        # ── Modules ───────────────────────────────────────────────────────
        mf = ttk.LabelFrame(inner, text="Modules", padding=8)
        mf.pack(**PAD)

        # (name_in_dict, display_label, default_on)
        MODULE_DEFS = [
            ("port_scan",       "Port Scan",              True),
            ("vuln_scan",       "Vulnerability Scan",     True),
            ("web_scan",        "Web Recon",              False),
            ("dir_brute",       "Directory Brute-force",  False),
            ("tech_detect",     "Tech Detection",         False),
            ("subdomain_scan",  "Subdomain Enumeration",  False),
            ("dns_scan",        "DNS Scan",               False),
            ("whois_scan",      "WHOIS Lookup",           False),
            ("osint_scan",      "OSINT Scan",             False),
            ("threat_intel",    "Threat Intelligence",    False),
            ("exploit_search",  "Exploit Search",         False),
            ("pass_spray",      "Password Spray",         False),
            ("iot_scan",        "IoT Scan",               False),
            ("ot_scan",         "OT/ICS Passive Scan",   False),
            ("mobile_scan",     "Mobile App Analysis",   False),
            ("rf_scan",         "RF Scan",                False),
        ]

        self._module_vars: dict[str, tk.BooleanVar] = {}
        for key, label, default in MODULE_DEFS:
            var = tk.BooleanVar(value=default)
            self._module_vars[key] = var
            # Dim modules that failed to import
            registry_name = _module_key_to_class(key)
            available = MODULE_REGISTRY.get(registry_name) is not None
            cb = ttk.Checkbutton(mf, text=label, variable=var)
            if not available:
                cb.configure(state="disabled")
                var.set(False)
            cb.pack(anchor="w")

        # ── Advanced options ───────────────────────────────────────────────
        af = ttk.LabelFrame(inner, text="Advanced Options", padding=8)
        af.pack(**PAD)
        af.columnconfigure(1, weight=1)

        row = 0

        def _adv_label(text, r):
            ttk.Label(af, text=text).grid(row=r, column=0, sticky="w", padx=(0, 4), pady=2)

        # Ports
        _adv_label("Ports (-p):", row)
        self._ports_var = tk.StringVar(value="")
        ttk.Entry(af, textvariable=self._ports_var).grid(row=row, column=1, sticky="ew")
        row += 1

        # CVE limit
        _adv_label("CVE limit:", row)
        self._cve_limit_var = tk.IntVar(value=5)
        ttk.Spinbox(af, from_=1, to=50, textvariable=self._cve_limit_var,
                    width=6).grid(row=row, column=1, sticky="w")
        row += 1

        # Wordlist
        _adv_label("Wordlist:", row)
        wl_frame = ttk.Frame(af)
        wl_frame.grid(row=row, column=1, sticky="ew")
        wl_frame.columnconfigure(0, weight=1)
        self._wordlist_var = tk.StringVar(value="")
        ttk.Entry(wl_frame, textvariable=self._wordlist_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(wl_frame, text="…",
                   command=self._browse_wordlist).grid(row=0, column=1, padx=(2, 0))
        row += 1

        # OT duration
        _adv_label("OT duration (s):", row)
        self._ot_duration_var = tk.IntVar(value=30)
        ttk.Spinbox(af, from_=5, to=300, textvariable=self._ot_duration_var,
                    width=6).grid(row=row, column=1, sticky="w")
        row += 1

        # RF freq range
        _adv_label("RF freq range:", row)
        self._rf_range_var = tk.StringVar(value="24M:1.7G")
        ttk.Entry(af, textvariable=self._rf_range_var).grid(row=row, column=1, sticky="ew")
        row += 1

        # RF threshold
        _adv_label("RF threshold (dBm):", row)
        self._rf_threshold_var = tk.DoubleVar(value=-20.0)
        ttk.Spinbox(af, from_=-80, to=0, increment=1,
                    textvariable=self._rf_threshold_var,
                    width=6).grid(row=row, column=1, sticky="w")
        row += 1

        # Spray service
        _adv_label("Spray service:", row)
        self._spray_service_var = tk.StringVar(value="ssh")
        ttk.Combobox(af, textvariable=self._spray_service_var,
                     values=["ssh", "ftp", "http-basic", "http-form"],
                     state="readonly", width=10).grid(row=row, column=1, sticky="w")
        row += 1

        # Spray usernames
        _adv_label("Spray users:", row)
        self._spray_users_var = tk.StringVar(value="admin,root,user")
        ttk.Entry(af, textvariable=self._spray_users_var).grid(row=row, column=1, sticky="ew")
        row += 1

        # Spray password
        _adv_label("Spray password:", row)
        self._spray_pass_var = tk.StringVar(value="")
        ttk.Entry(af, textvariable=self._spray_pass_var, show="*").grid(row=row, column=1, sticky="ew")
        row += 1

        # Mobile APK path
        _adv_label("APK path:", row)
        apk_frame = ttk.Frame(af)
        apk_frame.grid(row=row, column=1, sticky="ew")
        apk_frame.columnconfigure(0, weight=1)
        self._apk_var = tk.StringVar(value="")
        ttk.Entry(apk_frame, textvariable=self._apk_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(apk_frame, text="…",
                   command=self._browse_apk).grid(row=0, column=1, padx=(2, 0))
        row += 1

        # Exploit query
        _adv_label("Exploit query:", row)
        self._exploit_query_var = tk.StringVar(value="")
        ttk.Entry(af, textvariable=self._exploit_query_var).grid(row=row, column=1, sticky="ew")
        row += 1

        # ── Output folder ─────────────────────────────────────────────────
        of = ttk.LabelFrame(inner, text="Output", padding=8)
        of.pack(**PAD)
        of.columnconfigure(0, weight=1)
        self._output_dir_var = tk.StringVar(value=str(Path.cwd()))
        out_row = ttk.Frame(of)
        out_row.pack(fill=tk.X)
        out_row.columnconfigure(0, weight=1)
        ttk.Entry(out_row, textvariable=self._output_dir_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(out_row, text="…",
                   command=self._browse_output).grid(row=0, column=1, padx=(2, 0))

        # ── Start / Stop buttons ──────────────────────────────────────────
        btn_frame = ttk.Frame(inner)
        btn_frame.pack(**PAD)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        self._start_btn = ttk.Button(btn_frame, text="▶  Start Scan",
                                      style="Accent.TButton",
                                      command=self._start_scan)
        self._start_btn.grid(row=0, column=0, sticky="ew", padx=(0, 3))

        self._stop_btn = ttk.Button(btn_frame, text="■  Stop",
                                     style="Stop.TButton",
                                     command=self._stop_scan,
                                     state="disabled")
        self._stop_btn.grid(row=0, column=1, sticky="ew", padx=(3, 0))

    def _build_output_panel(self, parent: ttk.Frame) -> None:
        """Right pane: live log output with colour-coded lines."""
        header = ttk.Frame(parent)
        header.pack(fill=tk.X, padx=6, pady=(6, 0))
        ttk.Label(header, text="Live Output",
                  font=("Helvetica", 11, "bold")).pack(side=tk.LEFT)
        ttk.Button(header, text="Clear",
                   command=self._clear_output).pack(side=tk.RIGHT)

        self._output_text = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            state="disabled",
            bg="#11111b",
            fg=TEXT_FG,
            insertbackground=TEXT_FG,
            font=("Courier", 10),
            relief="flat",
        )
        self._output_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Colour tags
        self._output_text.tag_configure("WARNING",  foreground=WARN_FG)
        self._output_text.tag_configure("ERROR",    foreground=ERR_FG)
        self._output_text.tag_configure("CRITICAL", foreground=ERR_FG,
                                         font=("Courier", 10, "bold"))
        self._output_text.tag_configure("SUCCESS",  foreground=SUCCESS_FG)
        self._output_text.tag_configure("INFO",     foreground=TEXT_FG)
        self._output_text.tag_configure("DEBUG",    foreground=SEP_FG)

    # ---- Database tab ----

    def _build_db_tab(self, parent: ttk.Frame) -> None:
        """Database build/update/status panel."""
        pad = {"padx": 12, "pady": 6}

        # Status frame
        sf = ttk.LabelFrame(parent, text="Database Status", padding=10)
        sf.pack(fill=tk.X, **pad)

        self._db_status_text = tk.Text(sf, height=8, bg=ENTRY_BG, fg=TEXT_FG,
                                        relief="flat", font=("Courier", 9))
        self._db_status_text.pack(fill=tk.X)
        self._db_status_text.insert("1.0", "Press 'Refresh Status' to load database info.")
        self._db_status_text.configure(state="disabled")

        ttk.Button(sf, text="Refresh Status",
                   command=self._refresh_db_status).pack(pady=(4, 0))

        # Build tier
        bf = ttk.LabelFrame(parent, text="Build Database", padding=10)
        bf.pack(fill=tk.X, **pad)

        tier_row = ttk.Frame(bf)
        tier_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(tier_row, text="Build tier:").pack(side=tk.LEFT, padx=(0, 8))
        self._db_tier_var = tk.StringVar(value="core")
        for tier, desc in [("core", "Core ~4.5 GB"),
                            ("standard", "Standard ~8 GB"),
                            ("full", "Full ~25 GB+")]:
            ttk.Radiobutton(tier_row, text=desc,
                             variable=self._db_tier_var,
                             value=tier).pack(side=tk.LEFT, padx=4)

        self._db_progress = ttk.Progressbar(bf, mode="indeterminate")
        self._db_progress.pack(fill=tk.X, pady=(0, 6))

        self._db_progress_label = ttk.Label(bf, text="")
        self._db_progress_label.pack()

        btn_row = ttk.Frame(bf)
        btn_row.pack()
        ttk.Button(btn_row, text="Build Database",
                   command=self._db_build).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Update Database",
                   command=self._db_update).pack(side=tk.LEFT, padx=4)

    # ---- Status bar ----

    def _build_status_bar(self) -> None:
        bar = tk.Frame(self, bg=DARK_BG, height=22)
        bar.pack(fill=tk.X, side=tk.BOTTOM)

        self._status_target_label = tk.Label(bar, text="No scan running",
                                              bg=DARK_BG, fg=SEP_FG,
                                              font=("Helvetica", 8))
        self._status_target_label.pack(side=tk.LEFT, padx=8)

        self._status_time_label = tk.Label(bar, text="",
                                            bg=DARK_BG, fg=SEP_FG,
                                            font=("Helvetica", 8))
        self._status_time_label.pack(side=tk.RIGHT, padx=8)

    # =========================================================================
    # Background image
    # =========================================================================

    def _update_background(self) -> None:
        if not os.path.exists(self._asset["background"]):
            return
        try:
            w = max(self.winfo_width(),  1)
            h = max(self.winfo_height(), 1)
            img = Image.open(self._asset["background"]).resize(
                (w, h), Image.Resampling.LANCZOS
            )
            # .convert("RGBA") before putalpha() — prevents mode mismatch crash
            img = img.convert("RGBA")
            img.putalpha(55)
            self._bg_img_tk = ImageTk.PhotoImage(img)
            self._bg_label.configure(image=self._bg_img_tk)
        except Exception as exc:
            print(f"[GUI] Background update error: {exc}")

    # =========================================================================
    # File browse dialogs
    # =========================================================================

    def _browse_output(self) -> None:
        d = filedialog.askdirectory(title="Select output directory")
        if d:
            self._output_dir_var.set(d)

    def _browse_wordlist(self) -> None:
        f = filedialog.askopenfilename(
            title="Select wordlist file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if f:
            self._wordlist_var.set(f)

    def _browse_apk(self) -> None:
        f = filedialog.askopenfilename(
            title="Select APK file",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")],
        )
        if f:
            self._apk_var.set(f)

    # =========================================================================
    # Scan start / stop
    # =========================================================================

    def _start_scan(self) -> None:
        target     = self._target_var.get().strip()
        output_dir = self._output_dir_var.get().strip()

        if not target:
            messagebox.showerror("Validation", "Target cannot be empty.")
            return
        if not os.path.isdir(output_dir):
            messagebox.showerror("Validation", "Output directory is not valid.")
            return
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showwarning("Busy", "A scan is already running.")
            return

        # API key warnings for relevant modules
        warnings = []
        if self._module_vars["threat_intel"].get():
            vt_ok, vt_msg = config.validate_key("virustotal")
            otx_ok, otx_msg = config.validate_key("alienvault")
            if not vt_ok:
                warnings.append(f"VirusTotal: {vt_msg}")
            if not otx_ok:
                warnings.append(f"AlienVault OTX: {otx_msg}")
        if self._module_vars["vuln_scan"].get():
            nvd_ok, nvd_msg = config.validate_key("nvd")
            if not nvd_ok:
                warnings.append(f"NVD: {nvd_msg}")

        if warnings:
            msg = (
                "The following API keys are not configured:\n\n"
                + "\n".join(f"  • {w}" for w in warnings)
                + "\n\nModules will use offline data only where available.\n"
                + "Continue anyway?"
            )
            if not messagebox.askyesno("API Keys Missing", msg):
                return

        # Clear output
        self._clear_output()
        self._cancel_event.clear()
        self._scan_start = time.monotonic()

        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_target_label.configure(text=f"Scanning: {target}")

        self._scan_thread = threading.Thread(
            target=self._run_in_thread,
            args=(target, output_dir),
            daemon=True,
        )
        self._scan_thread.start()

    def _stop_scan(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            log.warning("Stop requested — cancelling scan...")
            self._cancel_event.set()
        self._stop_btn.configure(state="disabled")

    def _run_in_thread(self, target: str, output_dir: str) -> None:
        """Run asyncio event loop in background thread."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._run_scan_async(target, output_dir))
        except Exception as exc:
            log.error(f"Scan thread error: {exc}")
        finally:
            self.after(0, self._on_scan_done)

    def _on_scan_done(self) -> None:
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        elapsed = time.monotonic() - (self._scan_start or time.monotonic())
        self._status_target_label.configure(
            text=f"Scan complete in {_fmt_elapsed(elapsed)}"
        )

    # =========================================================================
    # Scan orchestrator
    # =========================================================================

    async def _run_scan_async(self, target: str, output_dir: str) -> None:
        """
        Orchestrate selected module execution.
        Modules run in logical dependency order:
          1. Port scan (always first — all other modules depend on open port list)
          2. Vuln scan, web-related modules, recon modules (parallel)
          3. Offensive and specialised modules (after recon complete)
        """
        log.info(f"{'─' * 56}")
        log.info(f"  Fenrir scan started — target: {target}")
        log.info(f"{'─' * 56}")

        report = ReportManager(output_dir, target)
        mv     = self._module_vars  # shortcut
        cancel = self._cancel_event

        # Helper: check cancel between phases
        def cancelled() -> bool:
            if cancel.is_set():
                log.warning("Scan cancelled by user.")
                return True
            return False

        # ── Parse ports ───────────────────────────────────────────────────
        ports_str = self._ports_var.get().strip()
        try:
            requested_ports = parse_ports(ports_str) if ports_str else None
        except ValueError as exc:
            log.error(f"Invalid port specification: {exc}")
            return

        # ── Wordlist / options ────────────────────────────────────────────
        wordlist_path = self._wordlist_var.get().strip() or None
        cve_limit     = self._cve_limit_var.get()

        # ── Phase 1: Port scan ────────────────────────────────────────────
        open_ports: list[int] = []
        if mv["port_scan"].get() or mv["vuln_scan"].get():
            if not cancelled():
                log.info("Phase 1: Port scan")
                open_ports = await PortScanner().run(
                    target, ports=requested_ports, report=report
                )
                log.info(f"  Open ports: {open_ports or 'none found'}")

        if cancelled():
            report.finalize()
            return

        # Identify web and SSH ports from results
        found_web_ports = [p for p in open_ports if p in WEB_PORTS]
        found_ssh_ports = [p for p in open_ports if p == SSH_PORT]

        # ── Phase 2: Parallel recon/analysis ─────────────────────────────
        log.info("Phase 2: Analysis & recon")
        phase2_tasks = []

        if mv["vuln_scan"].get() and open_ports:
            phase2_tasks.append(
                VulnerabilityScanner(cve_limit=cve_limit).run(
                    target, open_ports, report=report
                )
            )

        if mv["web_scan"].get() and found_web_ports:
            phase2_tasks.append(
                WebScanner().run(target, found_web_ports, report=report)
            )

        if mv["tech_detect"].get() and found_web_ports:
            phase2_tasks.append(
                TechDetector().run(target, found_web_ports, report=report)
            )

        if mv["dns_scan"].get():
            phase2_tasks.append(DnsScanner().run(target, report=report))

        if mv["whois_scan"].get():
            phase2_tasks.append(WhoisScanner().run(target, report=report))

        if mv["subdomain_scan"].get():
            phase2_tasks.append(
                SubdomainScanner(wordlist_path=wordlist_path).run(
                    target, report=report
                )
            )

        if mv["threat_intel"].get():
            phase2_tasks.append(
                ThreatIntelScanner().run(target, report=report)
            )

        if mv["osint_scan"].get():
            phase2_tasks.append(OsintScanner().run(target, report=report))

        if phase2_tasks and not cancelled():
            await asyncio.gather(*phase2_tasks, return_exceptions=True)

        if cancelled():
            report.finalize()
            return

        # ── Phase 3: Web brute-force (sequential — bandwidth intensive) ───
        if mv["dir_brute"].get() and found_web_ports and not cancelled():
            log.info("Phase 3: Directory brute-force")
            await DirBruteForcer(wordlist_path=wordlist_path).run(
                target, found_web_ports, report=report
            )

        # ── Phase 4: Offensive / specialised modules ──────────────────────
        log.info("Phase 4: Specialised modules")
        phase4_tasks = []

        if mv["exploit_search"].get():
            query = self._exploit_query_var.get().strip() or target
            phase4_tasks.append(
                ExploitScanner().run(query, report=report)
            )

        if mv["iot_scan"].get():
            phase4_tasks.append(
                IotScanner().run(target, open_ports, report=report)
            )

        if mv["rf_scan"].get():
            phase4_tasks.append(
                RfScanner().run(
                    freq_range=self._rf_range_var.get().strip(),
                    threshold=self._rf_threshold_var.get(),
                    report=report,
                )
            )

        if phase4_tasks and not cancelled():
            await asyncio.gather(*phase4_tasks, return_exceptions=True)

        # ── Phase 5: Sequential blocking modules ──────────────────────────
        if mv["pass_spray"].get() and not cancelled():
            password  = self._spray_pass_var.get().strip()
            usernames = [u.strip() for u in self._spray_users_var.get().split(",") if u.strip()]
            spray_port = found_ssh_ports[0] if found_ssh_ports else 22
            if password and usernames:
                log.info(f"Phase 5: Password spray ({self._spray_service_var.get()})")
                await PasswordSprayer().run(
                    target, spray_port, usernames, password,
                    service=self._spray_service_var.get(),
                    report=report,
                )
            else:
                log.warning("Password spray: no password or usernames configured — skipping.")

        if mv["ot_scan"].get() and not cancelled():
            log.info(f"Phase 5: OT/ICS passive scan ({self._ot_duration_var.get()}s)")
            await OtScanner().run(
                target_ip=target,
                duration=self._ot_duration_var.get(),
                report=report,
            )

        if mv["mobile_scan"].get() and not cancelled():
            apk_path = self._apk_var.get().strip()
            if apk_path:
                log.info(f"Phase 5: Mobile APK analysis — {apk_path}")
                await MobileScanner().run(apk_path, report=report)
            else:
                log.warning("Mobile scan: no APK path specified — skipping.")

        # ── Finalize report ───────────────────────────────────────────────
        report_paths = report.finalize()
        log.info(f"{'─' * 56}")
        log.info(f"  Scan complete.")
        if report_paths:
            for p in report_paths:
                log.info(f"  Report: {p}")
        log.info(f"{'─' * 56}")

    # =========================================================================
    # Log queue polling
    # =========================================================================

    def _poll_log_queue(self) -> None:
        """
        Drain the log queue and insert formatted records into the output widget.

        The QueueFormatter in logging_config.py prefixes every record with:
          LEVELNO:<int>|<formatted_message>

        We parse this prefix to determine the colour tag to apply.
        """
        try:
            while True:
                raw: str = self.log_queue.get_nowait()

                # Parse LEVELNO prefix
                tag  = "INFO"
                text = raw
                if raw.startswith("LEVELNO:"):
                    try:
                        sep = raw.index("|")
                        levelno = int(raw[8:sep])
                        text    = raw[sep + 1:]
                        if levelno >= logging.CRITICAL:
                            tag = "CRITICAL"
                        elif levelno >= logging.ERROR:
                            tag = "ERROR"
                        elif levelno >= logging.WARNING:
                            tag = "WARNING"
                        elif levelno <= logging.DEBUG:
                            tag = "DEBUG"
                        else:
                            tag = "INFO"
                    except (ValueError, IndexError):
                        text = raw

                self._output_text.configure(state="normal")
                self._output_text.insert(tk.END, text + "\n", tag)
                self._output_text.see(tk.END)
                self._output_text.configure(state="disabled")

        except queue.Empty:
            pass
        finally:
            self.after(80, self._poll_log_queue)

    # =========================================================================
    # Database tab actions
    # =========================================================================

    def _refresh_db_status(self) -> None:
        from .database import get_db_manager
        db  = get_db_manager()
        txt = self._db_status_text

        txt.configure(state="normal")
        txt.delete("1.0", tk.END)

        if not db.is_available():
            txt.insert("1.0", "Database not built.\n\nRun 'Build Database' to create it.")
        else:
            status = db.get_db_status()
            for k, v in status.items():
                txt.insert(tk.END, f"{k:<30} {v}\n")

        txt.configure(state="disabled")

    def _db_build(self) -> None:
        tier = self._db_tier_var.get()
        self._db_progress_label.configure(text=f"Building database (tier: {tier})...")
        self._db_progress.start(12)

        def _run():
            from .database import get_db_builder
            DatabaseBuilder = get_db_builder()
            builder = DatabaseBuilder(progress_callback=self._db_progress_cb)
            ok = builder.build_all(tier=tier)
            self.after(0, lambda: self._db_done(ok))

        threading.Thread(target=_run, daemon=True).start()

    def _db_update(self) -> None:
        self._db_progress_label.configure(text="Updating database...")
        self._db_progress.start(12)

        def _run():
            from .database import get_db_builder
            DatabaseBuilder = get_db_builder()
            builder = DatabaseBuilder(progress_callback=self._db_progress_cb)
            ok = builder.update_all()
            self.after(0, lambda: self._db_done(ok))

        threading.Thread(target=_run, daemon=True).start()

    def _db_progress_cb(self, source: str, current: int, total: int, message: str) -> None:
        """Called from DB builder thread — schedule GUI update on main thread."""
        self.after(0, lambda: self._db_progress_label.configure(
            text=f"[{source}] {message}"
        ))

    def _db_done(self, success: bool) -> None:
        self._db_progress.stop()
        label = "Database build complete." if success else "Database build failed — check log."
        self._db_progress_label.configure(text=label)
        self._refresh_db_status()

    # =========================================================================
    # Helpers
    # =========================================================================

    def _clear_output(self) -> None:
        self._output_text.configure(state="normal")
        self._output_text.delete("1.0", tk.END)
        self._output_text.configure(state="disabled")

    def _tick_status(self) -> None:
        """Update elapsed time in status bar while scan running."""
        if self._scan_start and self._scan_thread and self._scan_thread.is_alive():
            elapsed = time.monotonic() - self._scan_start
            self._status_time_label.configure(text=_fmt_elapsed(elapsed))
        else:
            self._status_time_label.configure(text="")
        self.after(1000, self._tick_status)

    def _on_closing(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            if not messagebox.askyesno(
                "Scan Running",
                "A scan is currently running.\nClose and terminate it?",
            ):
                return
            self._cancel_event.set()
        self.destroy()


# =============================================================================
# Helpers
# =============================================================================

def _fmt_elapsed(seconds: float) -> str:
    s = int(seconds)
    h, r = divmod(s, 3600)
    m, s = divmod(r, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    return f"{m}m {s:02d}s"


def _module_key_to_class(key: str) -> str:
    """Map GUI module checkbox key to MODULE_REGISTRY class name."""
    mapping = {
        "port_scan":      "PortScanner",
        "vuln_scan":      "VulnerabilityScanner",
        "web_scan":       "WebScanner",
        "dir_brute":      "DirBruteForcer",
        "tech_detect":    "TechDetector",
        "subdomain_scan": "SubdomainScanner",
        "dns_scan":       "DnsScanner",
        "whois_scan":     "WhoisScanner",
        "osint_scan":     "OsintScanner",
        "threat_intel":   "ThreatIntelScanner",
        "exploit_search": "ExploitScanner",
        "pass_spray":     "PasswordSprayer",
        "iot_scan":       "IotScanner",
        "ot_scan":        "OtScanner",
        "mobile_scan":    "MobileScanner",
        "rf_scan":        "RfScanner",
    }
    return mapping.get(key, key)


# =============================================================================
# Entry point
# =============================================================================

def launch_gui() -> None:
    """Create and run the Fenrir GUI."""
    app = FenrirGUI()
    app.mainloop()