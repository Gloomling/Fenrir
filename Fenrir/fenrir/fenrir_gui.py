# fenrir/fenrir_gui.py
#
# Fenrir GUI — complete rewrite adding:
#   - Debug tab: per-module timing, memory usage, live status table
#   - Results tabs: Ports, Vulnerabilities, Exploits, Recon, Threats
#   - Search bar across all results tabs
#   - Memory guard: asyncio.Semaphore limiting concurrent heavy modules
#   - Per-module timeout wrapper (configurable, default 300s)
#   - Offline CVE results shown in Vulnerabilities tab
#   - Exploit↔CVE cross-linking in Exploits tab
#   - Scan populated directly into results tabs on completion

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
    AndroidScanner,
    RfScanner,
)
from .report_manager import ReportManager

log = get_logger()

# ── Colour palette ─────────────────────────────────────────────────────────────
DARK_BG    = "#1e1e2e"
PANEL_BG   = "#2a2a3e"
ACCENT     = "#89b4fa"
TEXT_FG    = "#cdd6f4"
WARN_FG    = "#f9e2af"
ERR_FG     = "#f38ba8"
SUCCESS_FG = "#a6e3a1"
ENTRY_BG   = "#313244"
SEP_FG     = "#45475a"
BTN_ACTIVE = "#585b70"
CRIT_FG    = "#ff5555"
DEBUG_FG   = "#6272a4"
TIMING_OK  = "#a6e3a1"
TIMING_SLOW= "#f9e2af"
TIMING_BAD = "#f38ba8"

# Per-module soft timeout (seconds).  Heavy modules get more time.
MODULE_TIMEOUTS = {
    "port_scan":      120,
    "vuln_scan":      300,
    "web_scan":        90,
    "dir_brute":      180,
    "tech_detect":     60,
    "subdomain_scan": 120,
    "dns_scan":        60,
    "whois_scan":      30,
    "osint_scan":     120,
    "threat_intel":    90,
    "exploit_search":  60,
    "pass_spray":     180,
    "iot_scan":       120,
    "ot_scan":        120,
    "mobile_scan":     60,
    "rf_scan":        120,
}

# Maximum concurrent "heavy" modules (those that can spike RAM).
HEAVY_MODULES    = {"vuln_scan", "dir_brute", "subdomain_scan", "osint_scan",
                    "pass_spray", "ot_scan"}
MAX_CONCURRENT_HEAVY = 2


class FenrirGUI(tk.Tk):
    """Main Fenrir GUI application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Fenrir Security Scanner")
        self.geometry("1280x820")
        self.minsize(1024, 700)
        self.configure(bg=DARK_BG)

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

        # Debug/timing data
        self._module_timings: dict[str, dict] = {}   # key -> {start, end, status}
        self._timing_queue:   queue.Queue = queue.Queue()

        # Report reference (populated after scan)
        self._last_report: Optional[ReportManager] = None

        self._apply_styles()
        self._set_icon()
        self._build_ui()
        self._build_status_bar()
        self._poll_log_queue()
        self._poll_timing_queue()
        self._tick_status()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    # =========================================================================
    # Styles
    # =========================================================================

    def _apply_styles(self) -> None:
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass

        s.configure(".",              background=DARK_BG,   foreground=TEXT_FG,
                     fieldbackground=ENTRY_BG, borderwidth=1, relief="flat",
                     font=("Helvetica", 9))
        s.configure("TFrame",         background=PANEL_BG)
        s.configure("TLabelframe",    background=PANEL_BG, bordercolor=SEP_FG,
                     relief="flat")
        s.configure("TLabelframe.Label", background=PANEL_BG, foreground=ACCENT,
                     font=("Helvetica", 9, "bold"))
        s.configure("TCheckbutton",   background=PANEL_BG, foreground=TEXT_FG)
        s.map("TCheckbutton",         background=[("active", PANEL_BG)])
        s.configure("TEntry",         fieldbackground=ENTRY_BG, foreground=TEXT_FG,
                     insertcolor=TEXT_FG)
        s.configure("TCombobox",      fieldbackground=ENTRY_BG, foreground=TEXT_FG,
                     selectbackground=ENTRY_BG)
        s.configure("TSpinbox",       fieldbackground=ENTRY_BG, foreground=TEXT_FG)
        s.configure("TButton",        background=ENTRY_BG, foreground=TEXT_FG,
                     padding=(6, 3))
        s.map("TButton",              background=[("active", BTN_ACTIVE)])
        s.configure("Accent.TButton", background=ACCENT,   foreground=DARK_BG,
                     font=("Helvetica", 9, "bold"), padding=(6, 4))
        s.map("Accent.TButton",       background=[("active", "#7aa2f7")])
        s.configure("Stop.TButton",   background="#45475a", foreground=ERR_FG)
        s.map("Stop.TButton",         background=[("active", "#585b70")])
        s.configure("TLabel",         background=PANEL_BG, foreground=TEXT_FG)
        s.configure("TScrollbar",     background=ENTRY_BG, troughcolor=DARK_BG,
                     arrowcolor=TEXT_FG)
        s.configure("TProgressbar",   background=ACCENT, troughcolor=ENTRY_BG)
        s.configure("Separator.TFrame", background=SEP_FG)
        s.configure("TNotebook",      background=DARK_BG, tabmargins=[0, 0, 0, 0])
        s.configure("TNotebook.Tab",
                     background=ENTRY_BG, foreground=TEXT_FG, padding=(10, 4),
                     font=("Helvetica", 9))
        s.map("TNotebook.Tab",
              background=[("selected", PANEL_BG)],
              foreground=[("selected", ACCENT)])
        s.configure("Treeview",       background=ENTRY_BG, foreground=TEXT_FG,
                     fieldbackground=ENTRY_BG, rowheight=22, borderwidth=0)
        s.configure("Treeview.Heading", background=PANEL_BG, foreground=ACCENT,
                     relief="flat", font=("Helvetica", 9, "bold"))
        s.map("Treeview",             background=[("selected", ACCENT)],
              foreground=[("selected", DARK_BG)])

    # =========================================================================
    # Icon
    # =========================================================================

    def _set_icon(self) -> None:
        icon_path = self._asset["icon"]
        if os.path.exists(icon_path):
            try:
                icon = Image.open(icon_path).resize((32, 32), Image.Resampling.LANCZOS)
                self._icon_img = ImageTk.PhotoImage(icon)
                self.iconphoto(True, self._icon_img)
            except Exception:
                pass

    # =========================================================================
    # UI construction
    # =========================================================================

    def _build_ui(self) -> None:
        self._bg_label = tk.Label(self, bg=DARK_BG)
        self._bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        self._update_background()
        self.bind("<Configure>", lambda e: self._update_background())

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=(6, 0))

        # Tab 1: Scan (control + live log)
        scan_tab = ttk.Frame(notebook)
        notebook.add(scan_tab, text="  Scan  ")
        self._build_scan_tab(scan_tab)

        # Tab 2: Results (sub-notebook with sections)
        self._results_tab = ttk.Frame(notebook)
        notebook.add(self._results_tab, text="  Results  ")
        self._build_results_tab(self._results_tab)

        # Tab 3: Debug
        debug_tab = ttk.Frame(notebook)
        notebook.add(debug_tab, text="  Debug  ")
        self._build_debug_tab(debug_tab)

        # Tab 4: Database
        db_tab = ttk.Frame(notebook)
        notebook.add(db_tab, text="  Database  ")
        self._build_db_tab(db_tab)

        self._root_notebook = notebook

    # ─── Scan tab ────────────────────────────────────────────────────────────

    def _build_scan_tab(self, parent: ttk.Frame) -> None:
        paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(paned, width=300)
        paned.add(left, weight=0)
        self._build_left_panel(left)

        right = ttk.Frame(paned)
        paned.add(right, weight=1)
        self._build_output_panel(right)

    def _build_left_panel(self, parent: ttk.Frame) -> None:
        canvas = tk.Canvas(parent, bg=PANEL_BG, highlightthickness=0)
        scroll = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        inner    = ttk.Frame(canvas)
        inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_frame_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def _on_canvas_configure(e):
            canvas.itemconfig(inner_id, width=e.width)

        inner.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        # Mouse-wheel scroll
        def _on_wheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_wheel)

        PAD = {"padx": 6, "pady": 4, "fill": tk.X}

        # Logo
        logo_path = self._asset["logo"]
        if os.path.exists(logo_path):
            try:
                img = Image.open(logo_path).resize((72, 72), Image.Resampling.LANCZOS)
                self._logo_img = ImageTk.PhotoImage(img)
                tk.Label(inner, image=self._logo_img, bg=PANEL_BG).pack(pady=(8, 0))
            except Exception:
                pass
        tk.Label(inner, text="FENRIR", bg=PANEL_BG, fg=ACCENT,
                 font=("Helvetica", 15, "bold")).pack()

        # ── Scan Profile ─────────────────────────────────────────────────────
        pf = ttk.LabelFrame(inner, text="Scan Profile", padding=8)
        pf.pack(**PAD)
        pf.columnconfigure(1, weight=1)

        ttk.Label(pf, text="Profile:").grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._profile_var = tk.StringVar(value="General Network")
        profile_cb = ttk.Combobox(pf, textvariable=self._profile_var,
                                   values=["General Network", "Android Device",
                                           "Web Application", "Internal Network",
                                           "IoT / Embedded", "Custom"],
                                   state="readonly", width=18)
        profile_cb.grid(row=0, column=1, sticky="ew")
        profile_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_profile())

        ttk.Button(pf, text="Apply", command=self._apply_profile).grid(
            row=0, column=2, padx=(4, 0))

        self._profile_note = tk.Label(pf, text="", bg=PANEL_BG, fg=DEBUG_FG,
                                       font=("Helvetica", 8), wraplength=240,
                                       justify="left")
        self._profile_note.grid(row=1, column=0, columnspan=3, sticky="w", pady=(2, 0))

        # ── Target ────────────────────────────────────────────────────────────
        tf = ttk.LabelFrame(inner, text="Target", padding=8)
        tf.pack(**PAD)
        tf.columnconfigure(1, weight=1)
        ttk.Label(tf, text="Host/IP:").grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._target_var = tk.StringVar(value="192.168.1.1")
        self._target_var.trace_add("write", lambda *_: self._on_target_change())
        ttk.Entry(tf, textvariable=self._target_var).grid(row=0, column=1, sticky="ew")

        self._target_advisory = tk.Label(tf, text="", bg=PANEL_BG, fg=WARN_FG,
                                          font=("Helvetica", 8), wraplength=240,
                                          justify="left")
        self._target_advisory.grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

        # Module timeout (global)
        ttk.Label(tf, text="Module timeout (s):").grid(row=2, column=0, sticky="w",
                                                        padx=(0, 4), pady=(4, 0))
        self._module_timeout_var = tk.IntVar(value=300)
        ttk.Spinbox(tf, from_=30, to=1800, textvariable=self._module_timeout_var,
                    width=6).grid(row=2, column=1, sticky="w", pady=(4, 0))

        # Modules
        mf = ttk.LabelFrame(inner, text="Modules", padding=8)
        mf.pack(**PAD)

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
            ("exploit_search",  "Exploit Search (manual query)",  False),
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
            registry_name = _module_key_to_class(key)
            available     = MODULE_REGISTRY.get(registry_name) is not None
            heavy_mark    = "  ⚡" if key in HEAVY_MODULES else ""
            cb = ttk.Checkbutton(mf, text=label + heavy_mark, variable=var)
            if not available:
                cb.configure(state="disabled")
                var.set(False)
            cb.pack(anchor="w")

        tk.Label(mf, text="⚡ = memory-intensive (max 2 concurrent)",
                 bg=PANEL_BG, fg=DEBUG_FG, font=("Helvetica", 8)).pack(anchor="w", pady=(4, 0))
        tk.Label(mf, text="★ CVE→Exploit matching is automatic (no tick needed)",
                 bg=PANEL_BG, fg=SUCCESS_FG, font=("Helvetica", 8)).pack(anchor="w")

        # Advanced options
        af = ttk.LabelFrame(inner, text="Advanced Options", padding=8)
        af.pack(**PAD)
        af.columnconfigure(1, weight=1)

        row = 0
        def _adv_label(text, r):
            ttk.Label(af, text=text).grid(row=r, column=0, sticky="w", padx=(0, 4), pady=2)

        _adv_label("Ports (-p):", row)
        self._ports_var = tk.StringVar(value="")
        ttk.Entry(af, textvariable=self._ports_var).grid(row=row, column=1, sticky="ew"); row += 1

        _adv_label("Port timeout (s):", row)
        self._port_timeout_var = tk.DoubleVar(value=1.5)
        ttk.Spinbox(af, from_=0.5, to=10.0, increment=0.5,
                    textvariable=self._port_timeout_var,
                    width=6).grid(row=row, column=1, sticky="w"); row += 1

        _adv_label("Skip host-up check:", row)
        self._skip_hostup_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(af, variable=self._skip_hostup_var,
                        text="(scan even if no ping response)").grid(
            row=row, column=1, sticky="w"); row += 1

        _adv_label("CVE limit:", row)
        self._cve_limit_var = tk.IntVar(value=5)
        ttk.Spinbox(af, from_=1, to=50, textvariable=self._cve_limit_var,
                    width=6).grid(row=row, column=1, sticky="w"); row += 1

        _adv_label("Wordlist:", row)
        wl_frame = ttk.Frame(af)
        wl_frame.grid(row=row, column=1, sticky="ew"); wl_frame.columnconfigure(0, weight=1)
        self._wordlist_var = tk.StringVar(value="")
        ttk.Entry(wl_frame, textvariable=self._wordlist_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(wl_frame, text="…", command=self._browse_wordlist).grid(row=0, column=1, padx=(2, 0))
        row += 1

        _adv_label("OT duration (s):", row)
        self._ot_duration_var = tk.IntVar(value=30)
        ttk.Spinbox(af, from_=5, to=300, textvariable=self._ot_duration_var,
                    width=6).grid(row=row, column=1, sticky="w"); row += 1

        _adv_label("RF freq range:", row)
        self._rf_range_var = tk.StringVar(value="24M:1.7G")
        ttk.Entry(af, textvariable=self._rf_range_var).grid(row=row, column=1, sticky="ew"); row += 1

        _adv_label("RF threshold (dBm):", row)
        self._rf_threshold_var = tk.DoubleVar(value=-20.0)
        ttk.Spinbox(af, from_=-80, to=0, increment=1,
                    textvariable=self._rf_threshold_var,
                    width=6).grid(row=row, column=1, sticky="w"); row += 1

        _adv_label("Spray service:", row)
        self._spray_service_var = tk.StringVar(value="ssh")
        ttk.Combobox(af, textvariable=self._spray_service_var,
                     values=["ssh", "ftp", "http-basic", "http-form"],
                     state="readonly", width=10).grid(row=row, column=1, sticky="w"); row += 1

        _adv_label("Spray users:", row)
        self._spray_users_var = tk.StringVar(value="admin,root,user")
        ttk.Entry(af, textvariable=self._spray_users_var).grid(row=row, column=1, sticky="ew"); row += 1

        _adv_label("Spray password:", row)
        self._spray_pass_var = tk.StringVar(value="")
        ttk.Entry(af, textvariable=self._spray_pass_var,
                  show="*").grid(row=row, column=1, sticky="ew"); row += 1

        _adv_label("APK path:", row)
        apk_frame = ttk.Frame(af)
        apk_frame.grid(row=row, column=1, sticky="ew"); apk_frame.columnconfigure(0, weight=1)
        self._apk_var = tk.StringVar(value="")
        ttk.Entry(apk_frame, textvariable=self._apk_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(apk_frame, text="…", command=self._browse_apk).grid(row=0, column=1, padx=(2, 0))
        row += 1

        _adv_label("Exploit query:", row)
        self._exploit_query_var = tk.StringVar(value="")
        ttk.Entry(af, textvariable=self._exploit_query_var).grid(row=row, column=1, sticky="ew"); row += 1

        # Output folder
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

        # Start / Stop
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

    # ─── Scan profiles ───────────────────────────────────────────────────────

    # Profile definitions: (ports_str, modules_on, note)
    _PROFILES: dict[str, tuple[str, list[str], str]] = {
        "General Network": (
            "",
            ["port_scan", "vuln_scan"],
            "Scans top-1000 ports, CVE lookup, auto exploit match.",
        ),
        "Android Device": (
            "5555,5554,5556,5558,8080,443,80",
            ["port_scan", "vuln_scan"],
            "Targets ADB-over-TCP ports. AndroidScanner auto-triggers on port 5555.\n"
            "Ensure ADB is enabled on device: Settings → Developer Options → ADB over network.",
        ),
        "Web Application": (
            "80,443,8080,8443,8000,8888,3000,4443,9443",
            ["port_scan", "vuln_scan", "web_scan", "tech_detect", "dir_brute"],
            "Web ports only. Includes header analysis, tech fingerprint, dir brute-force.",
        ),
        "Internal Network": (
            "",
            ["port_scan", "vuln_scan", "dns_scan", "whois_scan"],
            "Full port scan + DNS/WHOIS. Note: WHOIS/VirusTotal/OSINT auto-skipped for private IPs.",
        ),
        "IoT / Embedded": (
            "21,22,23,80,443,502,1883,4786,5683,8080,8883,47808",
            ["port_scan", "vuln_scan", "iot_scan"],
            "Common IoT/ICS ports. IoT default-cred testing and MQTT checks included.",
        ),
        "Custom": (
            "",
            [],
            "Configure ports and modules manually.",
        ),
    }

    def _apply_profile(self) -> None:
        """Configure ports and module checkboxes for the selected scan profile."""
        profile = self._profile_var.get()
        if profile not in self._PROFILES:
            return

        ports_str, modules_on, note = self._PROFILES[profile]

        # Set ports
        self._ports_var.set(ports_str)

        if profile != "Custom":
            # Reset all module checkboxes, then enable the profile set
            for key, var in self._module_vars.items():
                var.set(key in modules_on)

        self._profile_note.configure(text=note)
        log.info(f"Scan profile applied: {profile}")

    def _on_target_change(self) -> None:
        """Show advisory when target looks like a private/RFC1918 address."""
        target = self._target_var.get().strip()
        if _is_private_ip(target):
            self._target_advisory.configure(
                text="⚠ Private IP: WHOIS, VirusTotal, OSINT and Subdomain "
                     "modules will be skipped automatically."
            )
        elif target:
            self._target_advisory.configure(text="")

    def _build_output_panel(self, parent: ttk.Frame) -> None:
        header = ttk.Frame(parent)
        header.pack(fill=tk.X, padx=6, pady=(6, 0))
        ttk.Label(header, text="Live Output",
                  font=("Helvetica", 11, "bold")).pack(side=tk.LEFT)

        # Search within live output
        self._log_search_var = tk.StringVar()
        self._log_search_var.trace_add("write", lambda *_: self._highlight_log_search())
        ttk.Entry(header, textvariable=self._log_search_var,
                  width=20).pack(side=tk.RIGHT, padx=(2, 0))
        ttk.Label(header, text="Search:").pack(side=tk.RIGHT)
        ttk.Button(header, text="Clear",
                   command=self._clear_output).pack(side=tk.RIGHT, padx=(0, 6))

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

        self._output_text.tag_configure("WARNING",  foreground=WARN_FG)
        self._output_text.tag_configure("ERROR",    foreground=ERR_FG)
        self._output_text.tag_configure("CRITICAL", foreground=CRIT_FG,
                                         font=("Courier", 10, "bold"))
        self._output_text.tag_configure("SUCCESS",  foreground=SUCCESS_FG)
        self._output_text.tag_configure("INFO",     foreground=TEXT_FG)
        self._output_text.tag_configure("DEBUG",    foreground=DEBUG_FG)
        self._output_text.tag_configure("SEARCH_HL",
                                         background=WARN_FG, foreground=DARK_BG)

    # ─── Results tab ─────────────────────────────────────────────────────────

    def _build_results_tab(self, parent: ttk.Frame) -> None:
        """Results notebook with Ports / Vulnerabilities / Exploits / Recon / Threats tabs."""

        # Global search bar at the top
        search_row = ttk.Frame(parent)
        search_row.pack(fill=tk.X, padx=8, pady=(6, 2))
        ttk.Label(search_row, text="Search results:",
                  font=("Helvetica", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        self._results_search_var = tk.StringVar()
        self._results_search_var.trace_add("write", lambda *_: self._filter_results())
        ttk.Entry(search_row, textvariable=self._results_search_var,
                  width=40).pack(side=tk.LEFT)
        ttk.Button(search_row, text="Clear search",
                   command=lambda: self._results_search_var.set("")).pack(side=tk.LEFT, padx=4)
        self._results_count_label = ttk.Label(search_row, text="")
        self._results_count_label.pack(side=tk.RIGHT)

        # Sub-notebook
        rn = ttk.Notebook(parent)
        rn.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        self._results_notebook = rn

        self._ports_tree      = self._make_results_tree(rn, "  Ports  ",
            columns=["Port", "Protocol", "Service", "Version", "State"],
            col_widths=[70, 70, 120, 180, 60])

        self._vulns_tree      = self._make_results_tree(rn, "  Vulnerabilities  ",
            columns=["CVE ID", "Score", "Severity", "Port", "Service", "Description"],
            col_widths=[120, 55, 75, 60, 100, 350],
            sortable_col="Score")

        self._exploits_tree   = self._make_results_tree(rn, "  Exploits  ",
            columns=["ID", "Title", "Type", "Platform", "CVEs", "Verified", "Source"],
            col_widths=[80, 280, 80, 80, 100, 60, 80])

        self._recon_tree      = self._make_results_tree(rn, "  Recon  ",
            columns=["Category", "Key", "Value"],
            col_widths=[120, 160, 400])

        self._threats_tree    = self._make_results_tree(rn, "  Threats  ",
            columns=["Indicator", "Type", "Source", "Severity", "Details"],
            col_widths=[160, 80, 100, 80, 300])

        # Status label under each tree
        self._results_status = ttk.Label(parent, text="Run a scan to populate results.",
                                          font=("Helvetica", 9))
        self._results_status.pack(pady=(0, 4))

        # Right-click context menu for trees
        self._tree_menu = tk.Menu(self, tearoff=0, bg=PANEL_BG, fg=TEXT_FG)
        self._tree_menu.add_command(label="Copy selected",    command=self._copy_tree_selection)
        self._tree_menu.add_command(label="Show full detail", command=self._show_tree_detail)

        for tree in [self._ports_tree, self._vulns_tree, self._exploits_tree,
                     self._recon_tree, self._threats_tree]:
            tree.bind("<Button-3>", self._show_tree_context_menu)
            tree.bind("<Double-1>", lambda e: self._show_tree_detail())

    def _make_results_tree(
        self,
        parent: ttk.Notebook,
        tab_label: str,
        columns: list[str],
        col_widths: list[int],
        sortable_col: Optional[str] = None,
    ) -> ttk.Treeview:
        """Create a scrollable Treeview and add it as a notebook tab."""
        frame = ttk.Frame(parent)
        parent.add(frame, text=tab_label)

        vsb = ttk.Scrollbar(frame, orient="vertical")
        hsb = ttk.Scrollbar(frame, orient="horizontal")
        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            selectmode="extended",
        )
        vsb.configure(command=tree.yview)
        hsb.configure(command=tree.xview)

        vsb.pack(side=tk.RIGHT,  fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(fill=tk.BOTH, expand=True)

        for col, width in zip(columns, col_widths):
            tree.heading(col, text=col, anchor="w")
            tree.column(col, width=width, anchor="w", minwidth=40)

        if sortable_col:
            tree.heading(sortable_col, text=sortable_col + " ▼",
                         command=lambda: self._sort_tree_by_score(tree, sortable_col))

        # Alternating row colours
        tree.tag_configure("odd",  background="#1a1a2e")
        tree.tag_configure("even", background=ENTRY_BG)
        tree.tag_configure("critical", foreground=CRIT_FG)
        tree.tag_configure("high",     foreground=ERR_FG)
        tree.tag_configure("medium",   foreground=WARN_FG)
        tree.tag_configure("low",      foreground=SUCCESS_FG)
        tree.tag_configure("match",    background="#2d4a1e", foreground=SUCCESS_FG)

        return tree

    # ─── Debug tab ───────────────────────────────────────────────────────────

    def _build_debug_tab(self, parent: ttk.Frame) -> None:
        """Per-module timing, memory usage, live status."""
        # Top: memory + system info bar
        info_frame = ttk.LabelFrame(parent, text="System", padding=6)
        info_frame.pack(fill=tk.X, padx=8, pady=(8, 2))

        self._mem_label    = ttk.Label(info_frame, text="Memory: –")
        self._mem_label.pack(side=tk.LEFT, padx=8)
        self._cpu_label    = ttk.Label(info_frame, text="CPU: –")
        self._cpu_label.pack(side=tk.LEFT, padx=8)
        self._thread_label = ttk.Label(info_frame, text="Threads: –")
        self._thread_label.pack(side=tk.LEFT, padx=8)

        ttk.Button(info_frame, text="Refresh",
                   command=self._refresh_system_info).pack(side=tk.RIGHT, padx=4)

        # Middle: module timing table
        timing_frame = ttk.LabelFrame(parent, text="Module Timings (last scan)", padding=6)
        timing_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        timing_cols = ["Module", "Status", "Start", "Duration", "Note"]
        timing_widths = [160, 90, 120, 80, 300]

        vsb = ttk.Scrollbar(timing_frame, orient="vertical")
        self._timing_tree = ttk.Treeview(
            timing_frame,
            columns=timing_cols,
            show="headings",
            yscrollcommand=vsb.set,
            height=12,
        )
        vsb.configure(command=self._timing_tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._timing_tree.pack(fill=tk.BOTH, expand=True)

        for col, width in zip(timing_cols, timing_widths):
            self._timing_tree.heading(col, text=col, anchor="w")
            self._timing_tree.column(col, width=width, anchor="w", minwidth=40)

        self._timing_tree.tag_configure("running",  foreground=ACCENT)
        self._timing_tree.tag_configure("done_ok",  foreground=SUCCESS_FG)
        self._timing_tree.tag_configure("done_slow",foreground=WARN_FG)
        self._timing_tree.tag_configure("done_err", foreground=ERR_FG)
        self._timing_tree.tag_configure("timeout",  foreground=CRIT_FG)
        self._timing_tree.tag_configure("skipped",  foreground=SEP_FG)
        self._timing_tree.tag_configure("cancelled",foreground=DEBUG_FG)

        # Bottom: event/error log specific to debug
        log_frame = ttk.LabelFrame(parent, text="Scan Events & Errors", padding=6)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(2, 8))

        self._debug_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            state="disabled",
            bg="#11111b",
            fg=TEXT_FG,
            font=("Courier", 9),
            relief="flat",
            height=8,
        )
        self._debug_text.pack(fill=tk.BOTH, expand=True)
        self._debug_text.tag_configure("ERROR",   foreground=ERR_FG)
        self._debug_text.tag_configure("WARNING", foreground=WARN_FG)
        self._debug_text.tag_configure("TIMEOUT", foreground=CRIT_FG,
                                        font=("Courier", 9, "bold"))
        self._debug_text.tag_configure("INFO",    foreground=TEXT_FG)

        ttk.Button(log_frame, text="Clear",
                   command=self._clear_debug_log).pack(side=tk.RIGHT, padx=4, pady=(2, 0))

        self._refresh_system_info()
        self.after(5000, self._auto_refresh_system_info)

    # ─── Database tab ────────────────────────────────────────────────────────

    def _build_db_tab(self, parent: ttk.Frame) -> None:
        sf = ttk.LabelFrame(parent, text="Database Status", padding=10)
        sf.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self._db_status_text = scrolledtext.ScrolledText(
            sf, wrap=tk.WORD, state="disabled",
            bg="#11111b", fg=TEXT_FG, font=("Courier", 9), height=10)
        self._db_status_text.pack(fill=tk.BOTH, expand=True)

        bf = ttk.LabelFrame(parent, text="Build Database", padding=10)
        bf.pack(fill=tk.X, padx=8, pady=(0, 8))

        tier_row = ttk.Frame(bf)
        tier_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(tier_row, text="Build tier:").pack(side=tk.LEFT)
        self._db_tier_var = tk.StringVar(value="core")
        for tier in ["core", "standard", "full"]:
            ttk.Radiobutton(tier_row, text=tier.capitalize(),
                            variable=self._db_tier_var, value=tier).pack(side=tk.LEFT, padx=4)

        self._db_progress_label = ttk.Label(bf, text="")
        self._db_progress_label.pack(fill=tk.X)
        self._db_progress = ttk.Progressbar(bf, mode="indeterminate")
        self._db_progress.pack(fill=tk.X, pady=4)

        btn_row = ttk.Frame(bf)
        btn_row.pack()
        ttk.Button(btn_row, text="Build Database",
                   command=self._db_build).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Update Database",
                   command=self._db_update).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Refresh Status",
                   command=self._refresh_db_status).pack(side=tk.LEFT, padx=4)

    # ─── Status bar ──────────────────────────────────────────────────────────

    def _build_status_bar(self) -> None:
        bar = tk.Frame(self, bg=DARK_BG, height=22)
        bar.pack(side=tk.BOTTOM, fill=tk.X, padx=6, pady=(0, 4))

        self._status_target_label = tk.Label(
            bar, text="Ready", bg=DARK_BG, fg=ACCENT,
            font=("Helvetica", 9), anchor="w")
        self._status_target_label.pack(side=tk.LEFT, padx=4)

        self._status_time_label = tk.Label(
            bar, text="", bg=DARK_BG, fg=TEXT_FG,
            font=("Helvetica", 9), anchor="e")
        self._status_time_label.pack(side=tk.RIGHT, padx=4)

        self._status_mem_label = tk.Label(
            bar, text="", bg=DARK_BG, fg=DEBUG_FG,
            font=("Helvetica", 9), anchor="e")
        self._status_mem_label.pack(side=tk.RIGHT, padx=4)

    def _update_background(self) -> None:
        bg_path = self._asset["background"]
        if not os.path.exists(bg_path):
            return
        try:
            w, h = self.winfo_width(), self.winfo_height()
            if w < 10 or h < 10:
                return
            img = Image.open(bg_path).resize((w, h), Image.Resampling.LANCZOS)
            img = img.convert("RGBA")
            overlay = Image.new("RGBA", img.size, (30, 30, 46, 200))
            img.paste(overlay, mask=overlay)
            self._bg_photo = ImageTk.PhotoImage(img)
            self._bg_label.configure(image=self._bg_photo)
        except Exception:
            pass

    # =========================================================================
    # Scan control
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

        warnings = []
        if self._module_vars["threat_intel"].get():
            for key in ("virustotal", "alienvault"):
                ok, msg = config.validate_key(key)
                if not ok:
                    warnings.append(msg)
        if self._module_vars["vuln_scan"].get():
            ok, msg = config.validate_key("nvd")
            if not ok:
                warnings.append(f"NVD: {msg} — offline DB will be used if available")

        if warnings:
            msg = ("Some API keys not configured:\n\n"
                   + "\n".join(f"  • {w}" for w in warnings)
                   + "\n\nOffline data will be used where available. Continue?")
            if not messagebox.askyesno("API Keys", msg):
                return

        # Reset debug timings
        self._module_timings.clear()
        self._clear_timing_tree()
        self._clear_debug_log()

        # Clear previous results
        for tree in [self._ports_tree, self._vulns_tree, self._exploits_tree,
                     self._recon_tree, self._threats_tree]:
            tree.delete(*tree.get_children())

        self._clear_output()
        self._cancel_event.clear()
        self._scan_start = time.monotonic()

        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_target_label.configure(text=f"Scanning: {target}")
        self._results_status.configure(text="Scan in progress...")

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
            self._debug_log("Scan cancelled by user.", "WARNING")
        self._stop_btn.configure(state="disabled")

    def _run_in_thread(self, target: str, output_dir: str) -> None:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._run_scan_async(target, output_dir))
        except Exception as exc:
            log.error(f"Scan thread error: {exc}")
            self._debug_log(f"Scan thread error: {exc}", "ERROR")
        finally:
            self.after(0, self._on_scan_done)

    def _on_scan_done(self) -> None:
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        elapsed = time.monotonic() - (self._scan_start or time.monotonic())
        self._status_target_label.configure(
            text=f"Scan complete — {_fmt_elapsed(elapsed)}"
        )
        # Populate results tabs
        if self._last_report:
            self.after(0, self._populate_results)

    # =========================================================================
    # Scan orchestrator
    # =========================================================================

    async def _run_scan_async(self, target: str, output_dir: str) -> None:
        log.info(f"{'─' * 56}")
        log.info(f"  Fenrir scan started — target: {target}")
        log.info(f"{'─' * 56}")

        report = ReportManager(output_dir, target)
        self._last_report = report
        mv     = self._module_vars
        cancel = self._cancel_event
        global_timeout = self._module_timeout_var.get()

        # Semaphore for heavy modules — prevents OOM when all ticked
        heavy_sem = asyncio.Semaphore(MAX_CONCURRENT_HEAVY)

        def cancelled() -> bool:
            if cancel.is_set():
                log.warning("Scan cancelled by user.")
                return True
            return False

        async def _run_module(key: str, coro) -> None:
            """Wrap a module coroutine with timing, timeout, and heavy-module gating."""
            module_timeout = min(global_timeout, MODULE_TIMEOUTS.get(key, 300))
            is_heavy = key in HEAVY_MODULES

            self._timing_queue.put(("start", key, time.monotonic()))
            try:
                if is_heavy:
                    async with heavy_sem:
                        await asyncio.wait_for(coro, timeout=module_timeout)
                else:
                    await asyncio.wait_for(coro, timeout=module_timeout)
                self._timing_queue.put(("done", key, time.monotonic(), "ok", ""))
            except asyncio.TimeoutError:
                msg = f"Module '{key}' timed out after {module_timeout}s"
                log.error(msg)
                self._debug_log(msg, "TIMEOUT")
                self._timing_queue.put(("done", key, time.monotonic(), "timeout",
                                        f"Timed out after {module_timeout}s"))
            except asyncio.CancelledError:
                self._timing_queue.put(("done", key, time.monotonic(), "cancelled", ""))
                raise
            except Exception as exc:
                msg = f"Module '{key}' raised: {exc}"
                log.error(msg)
                self._debug_log(msg, "ERROR")
                self._timing_queue.put(("done", key, time.monotonic(), "error", str(exc)))

        # Parse options
        ports_str = self._ports_var.get().strip()
        try:
            requested_ports = parse_ports(ports_str) if ports_str else None
        except ValueError as exc:
            log.error(f"Invalid port specification: {exc}")
            return

        wordlist_path  = self._wordlist_var.get().strip() or None
        cve_limit      = self._cve_limit_var.get()
        port_timeout   = self._port_timeout_var.get()
        skip_hostup    = self._skip_hostup_var.get()
        is_private     = _is_private_ip(target)

        if is_private:
            log.info(
                f"Target {target} is a private/RFC1918 address — "
                f"WHOIS raw, VirusTotal, OSINT, and Subdomain modules "
                f"will be skipped (no useful results for private IPs)."
            )

        # ── Host-up pre-check ─────────────────────────────────────────────────
        if not skip_hostup:
            log.info(f"Pre-check: testing reachability of {target}...")
            host_up = await _host_is_up(target, timeout=2.0)
            if not host_up:
                log.warning(
                    f"  {target} did not respond to any probe port. "
                    f"Host may be offline, heavily firewalled, or sleeping. "
                    f"Continuing with port scan anyway (tick 'Skip host-up check' "
                    f"to suppress this warning)."
                )
            else:
                log.info(f"  {target} is reachable.")

        # ── Phase 1: Port scan ────────────────────────────────────────────────
        open_ports: list[int] = []
        if mv["port_scan"].get() or mv["vuln_scan"].get():
            if not cancelled():
                log.info("Phase 1: Port scan")
                self._timing_queue.put(("start", "port_scan", time.monotonic()))
                try:
                    open_ports = await asyncio.wait_for(
                        PortScanner(timeout=port_timeout).run(
                            target, ports=requested_ports, report=report),
                        timeout=MODULE_TIMEOUTS["port_scan"],
                    )
                    self._timing_queue.put(("done", "port_scan", time.monotonic(), "ok",
                                            f"{len(open_ports)} open ports"))
                except asyncio.TimeoutError:
                    self._timing_queue.put(("done", "port_scan", time.monotonic(), "timeout",
                                            "Timed out"))
                    log.error("Port scan timed out.")
                except Exception as exc:
                    self._timing_queue.put(("done", "port_scan", time.monotonic(), "error",
                                            str(exc)))
                    log.error(f"Port scan error: {exc}")
                log.info(f"  Open ports: {open_ports or 'none found'}")

        if cancelled():
            report.finalize(); return

        found_web_ports = [p for p in open_ports if p in WEB_PORTS]
        found_ssh_ports = [p for p in open_ports if p == SSH_PORT]

        # ── Auto: Android device detection ────────────────────────────────────
        # Port 5555 = ADB-over-TCP.  Trigger automatically without a checkbox.
        ADB_PORTS = [p for p in open_ports if p in (5555, 5554, 5556, 5558)]
        if ADB_PORTS and AndroidScanner is not None:
            log.info(
                f"ADB port(s) detected: {ADB_PORTS} — "
                f"triggering Android Device Scanner automatically."
            )
            for adb_port in ADB_PORTS:
                await _run_module(
                    "android_scan",
                    AndroidScanner().run(target, port=adb_port, report=report),
                )
        elif not ADB_PORTS and self._profile_var.get() == "Android Device":
            log.warning(
                "Android Device profile selected but port 5555 (ADB) was not found open. "
                "To enable ADB over network on the device:\n"
                "  1. Connect via USB and run: adb tcpip 5555\n"
                "  2. Or: Settings → Developer Options → Wireless debugging\n"
                "  3. Check the device is not sleeping (screen lock disables ADB TCP on some ROMs)\n"
                "  Try increasing Port timeout in Advanced Options if the device is slow to respond."
            )

        # ── Phase 2: Parallel recon/analysis ──────────────────────────────────
        log.info("Phase 2: Analysis & recon")
        phase2 = []

        if mv["vuln_scan"].get() and open_ports:
            phase2.append(_run_module("vuln_scan",
                VulnerabilityScanner(cve_limit=cve_limit).run(target, open_ports, report=report)))
        elif mv["vuln_scan"].get() and not open_ports:
            self._timing_queue.put(("skip", "vuln_scan", time.monotonic(), "skipped",
                                    "No open ports"))
            log.info("Vulnerability scan skipped — no open ports found.")

        if mv["web_scan"].get() and found_web_ports:
            phase2.append(_run_module("web_scan",
                WebScanner().run(target, found_web_ports, report=report)))
        elif mv["web_scan"].get() and not found_web_ports:
            self._timing_queue.put(("skip", "web_scan", time.monotonic(), "skipped",
                                    "No web ports open"))

        if mv["tech_detect"].get() and found_web_ports:
            phase2.append(_run_module("tech_detect",
                TechDetector().run(target, found_web_ports, report=report)))

        if mv["dns_scan"].get():
            phase2.append(_run_module("dns_scan",
                DnsScanner().run(target, report=report)))

        # WHOIS: skip raw text for private IPs — it's just RFC1918 boilerplate
        if mv["whois_scan"].get() and not is_private:
            phase2.append(_run_module("whois_scan",
                WhoisScanner().run(target, report=report)))
        elif mv["whois_scan"].get() and is_private:
            self._timing_queue.put(("skip", "whois_scan", time.monotonic(), "skipped",
                                    "Private IP — no useful WHOIS data"))
            log.info("WHOIS skipped — private/RFC1918 address.")

        # Subdomain: pointless on raw IPs
        if mv["subdomain_scan"].get() and not is_private and not _looks_like_ip(target):
            phase2.append(_run_module("subdomain_scan",
                SubdomainScanner(wordlist_path=wordlist_path).run(target, report=report)))
        elif mv["subdomain_scan"].get():
            self._timing_queue.put(("skip", "subdomain_scan", time.monotonic(), "skipped",
                                    "IP address target — subdomain scan N/A"))

        # Threat intel: skip for private IPs (VirusTotal returns 0 detections always)
        if mv["threat_intel"].get() and not is_private:
            phase2.append(_run_module("threat_intel",
                ThreatIntelScanner().run(target, report=report)))
        elif mv["threat_intel"].get() and is_private:
            self._timing_queue.put(("skip", "threat_intel", time.monotonic(), "skipped",
                                    "Private IP — VirusTotal/OTX not useful"))
            log.info("Threat intelligence skipped — private/RFC1918 address.")

        # OSINT: skip for private IPs (no public records)
        if mv["osint_scan"].get() and not is_private:
            phase2.append(_run_module("osint_scan",
                OsintScanner().run(target, report=report)))
        elif mv["osint_scan"].get() and is_private:
            self._timing_queue.put(("skip", "osint_scan", time.monotonic(), "skipped",
                                    "Private IP — no public OSINT data"))
            log.info("OSINT scan skipped — private/RFC1918 address.")

        if phase2 and not cancelled():
            await asyncio.gather(*phase2, return_exceptions=True)

        if cancelled():
            report.finalize(); return

        # ── Phase 3: Dir brute-force ───────────────────────────────────────────
        if mv["dir_brute"].get() and found_web_ports and not cancelled():
            log.info("Phase 3: Directory brute-force")
            await _run_module("dir_brute",
                DirBruteForcer(wordlist_path=wordlist_path).run(
                    target, found_web_ports, report=report))

        # ── Phase 4: Specialised (parallel) ────────────────────────────────────
        log.info("Phase 4: Specialised modules")
        phase4 = []

        if mv["exploit_search"].get():
            query = self._exploit_query_var.get().strip() or target
            phase4.append(_run_module("exploit_search",
                ExploitScanner().run(query, report=report)))

        if mv["iot_scan"].get():
            if open_ports:
                phase4.append(_run_module("iot_scan",
                    IotScanner().run(target, open_ports, report=report)))
            else:
                self._timing_queue.put(("skip", "iot_scan", time.monotonic(), "skipped",
                                        "No open ports — IoT scan skipped"))
                log.info("IoT scan skipped — no open ports found.")

        if mv["rf_scan"].get():
            phase4.append(_run_module("rf_scan",
                RfScanner().run(
                    freq_range=self._rf_range_var.get().strip(),
                    threshold=self._rf_threshold_var.get(),
                    report=report)))

        if phase4 and not cancelled():
            await asyncio.gather(*phase4, return_exceptions=True)

        # ── Phase 5: Sequential blocking modules ───────────────────────────────
        if mv["pass_spray"].get() and not cancelled():
            password  = self._spray_pass_var.get().strip()
            usernames = [u.strip() for u in self._spray_users_var.get().split(",") if u.strip()]
            spray_port = found_ssh_ports[0] if found_ssh_ports else 22
            if password and usernames:
                log.info(f"Phase 5: Password spray ({self._spray_service_var.get()})")
                await _run_module("pass_spray",
                    PasswordSprayer().run(
                        target, spray_port, usernames, password,
                        service=self._spray_service_var.get(), report=report))
            else:
                log.warning("Password spray: no password or usernames configured — skipping.")
                self._timing_queue.put(("skip", "pass_spray", time.monotonic(), "skipped",
                                        "No credentials provided"))

        if mv["ot_scan"].get() and not cancelled():
            # OT scan is meaningful even without open ports (passive sniffing)
            # but log clearly if no OT-relevant ports were found
            ot_ports = {p for p in open_ports if p in (
                502, 102, 44818, 20000, 47808, 4840, 1089, 1090, 1091,
                2222, 4000, 9600, 19999, 20547, 34962, 34963, 34964,
            )}
            if ot_ports:
                log.info(
                    f"Phase 5: OT/ICS scan — OT-relevant port(s) found: {ot_ports}"
                )
            else:
                log.info(
                    "Phase 5: OT/ICS scan — no OT-specific ports found in port scan. "
                    "Running passive detection anyway."
                )
            await _run_module("ot_scan",
                OtScanner().run(target_ip=target, duration=self._ot_duration_var.get(),
                                report=report))

        if mv["mobile_scan"].get() and not cancelled():
            apk_path = self._apk_var.get().strip()
            if apk_path:
                log.info(f"Phase 5: Mobile APK analysis — {apk_path}")
                await _run_module("mobile_scan",
                    MobileScanner().run(apk_path, report=report))
            else:
                log.warning("Mobile scan: no APK path specified — skipping.")
                self._timing_queue.put(("skip", "mobile_scan", time.monotonic(), "skipped",
                                        "No APK path"))

        # ── Finalize ──────────────────────────────────────────────────────────
        report.finalize()
        log.info(f"{'─' * 56}")
        log.info(f"  Scan complete.")
        for p in (report.txt_path, report.json_path):
            log.info(f"  Report: {p}")
        log.info(f"{'─' * 56}")

    # =========================================================================
    # Results population
    # =========================================================================

    def _populate_results(self) -> None:
        """Parse report sections and populate all results trees after scan."""
        if not self._last_report:
            return

        sections = self._last_report.get_sections()

        # Clear trees
        for tree in [self._ports_tree, self._vulns_tree, self._exploits_tree,
                     self._recon_tree, self._threats_tree]:
            tree.delete(*tree.get_children())

        total_items = 0

        for section in sections:
            title    = section.get("title", "").lower()
            findings = section.get("findings", [])

            for finding in findings:
                total_items += 1

                # ── Ports ──────────────────────────────────────────────
                if "port" in title and ("open" in title or "scan" in title):
                    self._insert_port_finding(finding)

                # ── Vulnerabilities / CVEs ─────────────────────────────
                elif any(k in title for k in ("cve", "vulnerabilit", "vuln")):
                    self._insert_vuln_finding(finding)

                # ── Exploits ───────────────────────────────────────────
                elif any(k in title for k in ("exploit", "shellcode", "ghdb")):
                    self._insert_exploit_finding(finding)
                # ── Threats / IOC ──────────────────────────────────────
                elif any(k in title for k in ("threat", "ioc", "malware", "reputation",
                                               "virustotal", "otx", "intel")):
                    self._insert_threat_finding(finding)

                # ── Android security findings → Vulnerabilities tab ────
                elif any(k in title for k in ("android security", "android root",
                                               "android attack", "android suspicious")):
                    self._insert_vuln_finding(finding)

                # ── Recon (everything else, incl. Android identity/policy)
                else:
                    self._insert_recon_finding(section["title"], finding)

        # Re-number rows with alternating colours
        for tree in [self._ports_tree, self._vulns_tree, self._exploits_tree,
                     self._recon_tree, self._threats_tree]:
            self._restripe_tree(tree)

        # Cross-link: for each CVE in vulns, find matching exploits
        self._crosslink_cve_exploits()

        # Update status
        vuln_count    = len(self._vulns_tree.get_children())
        exploit_count = len(self._exploits_tree.get_children())
        port_count    = len(self._ports_tree.get_children())
        self._results_status.configure(
            text=f"Results: {port_count} ports · {vuln_count} vulnerabilities · "
                 f"{exploit_count} exploits · {total_items} total findings"
        )
        self._results_count_label.configure(
            text=f"{total_items} findings"
        )

        # Switch to Results tab automatically
        self._root_notebook.select(1)

    def _insert_port_finding(self, finding) -> None:
        if isinstance(finding, dict):
            port     = str(finding.get("port", finding.get("Port", "")))
            proto    = str(finding.get("protocol", finding.get("Protocol", "tcp")))
            service  = str(finding.get("service", finding.get("Service", "")))
            version  = str(finding.get("version", finding.get("Version", "")))
            state    = str(finding.get("state", finding.get("State", "open")))
        else:
            # Plain string like "80/tcp - http"
            parts = str(finding).split()
            port    = parts[0] if parts else str(finding)
            proto   = "tcp"
            service = parts[-1] if len(parts) > 1 else ""
            version = ""
            state   = "open"
        self._ports_tree.insert("", tk.END, values=(port, proto, service, version, state))

    def _insert_vuln_finding(self, finding) -> None:
        if not isinstance(finding, dict):
            self._vulns_tree.insert("", tk.END,
                values=(str(finding), "", "", "", "", ""))
            return

        # Android security finding format: {severity, check, detail}
        if "check" in finding and "detail" in finding and "id" not in finding:
            severity = str(finding.get("severity", "")).upper()
            check    = str(finding.get("check", ""))
            detail   = str(finding.get("detail", ""))[:250]
            sev_lower = severity.lower()
            tag = ("critical" if "critical" in sev_lower else
                   "high"     if "high"     in sev_lower else
                   "medium"   if "medium"   in sev_lower else "low")
            self._vulns_tree.insert("", tk.END,
                values=(check, "—", severity, "—", "Android", detail),
                tags=(tag,))
            return

        # Standard CVE format
        cve_id   = str(finding.get("id", finding.get("cve_id", "")))
        score    = finding.get("score", finding.get("cvss_v3_score", ""))
        severity = str(finding.get("severity", finding.get("cvss_v3_severity", ""))).upper()
        port     = str(finding.get("port", ""))
        service  = str(finding.get("service", ""))
        desc     = str(finding.get("description", ""))[:200]

        sev_lower = severity.lower()
        tag = ("critical" if "critical" in sev_lower else
               "high"     if "high"     in sev_lower else
               "medium"   if "medium"   in sev_lower else
               "low"      if "low"      in sev_lower else "")

        self._vulns_tree.insert("", tk.END,
            values=(cve_id, score, severity, port, service, desc),
            tags=(tag,))

    def _insert_exploit_finding(self, finding) -> None:
        if not isinstance(finding, dict):
            self._exploits_tree.insert("", tk.END,
                values=(str(finding), "", "", "", "", "", ""))
            return
        eid      = str(finding.get("id", finding.get("edb_id", "")))
        title    = str(finding.get("title", ""))[:120]
        etype    = str(finding.get("type", ""))
        platform = str(finding.get("platform", ""))
        cves     = ", ".join(finding.get("cve_ids", []) or [])
        verified = "✓" if finding.get("verified") else ""
        source   = str(finding.get("source", ""))
        self._exploits_tree.insert("", tk.END,
            values=(eid, title, etype, platform, cves, verified, source))

    def _insert_threat_finding(self, finding) -> None:
        if not isinstance(finding, dict):
            self._threats_tree.insert("", tk.END,
                values=(str(finding), "", "", "", ""))
            return
        indicator = str(finding.get("indicator", finding.get("ip", finding.get("ioc", ""))))
        ioc_type  = str(finding.get("ioc_type", finding.get("type", "")))
        source    = str(finding.get("source", finding.get("feed", "")))
        severity  = str(finding.get("severity", "")).upper()
        details   = str(finding.get("details", finding.get("malware_family",
                        finding.get("tags", ""))))[:200]

        sev_lower = severity.lower()
        tag = ("critical" if "critical" in sev_lower else
               "high"     if "high"     in sev_lower else
               "medium"   if "medium"   in sev_lower else "")

        self._threats_tree.insert("", tk.END,
            values=(indicator, ioc_type, source, severity, details),
            tags=(tag,))

    def _insert_recon_finding(self, category: str, finding) -> None:
        if isinstance(finding, dict):
            for key, value in finding.items():
                self._recon_tree.insert("", tk.END,
                    values=(category, str(key), str(value)[:300]))
        else:
            self._recon_tree.insert("", tk.END,
                values=(category, "", str(finding)[:300]))

    def _crosslink_cve_exploits(self) -> None:
        """
        For each CVE in the Vulnerabilities tree, check if any exploits in the
        Exploits tree list that CVE.  If so, add the CVE as a tag/highlight on
        the exploit row and add a note to the CVE row.
        """
        # Build CVE → exploit_iid mapping
        cve_to_exploits: dict[str, list[str]] = {}
        for iid in self._exploits_tree.get_children():
            vals = self._exploits_tree.item(iid, "values")
            cves_str = vals[4] if len(vals) > 4 else ""
            for cve_id in cves_str.split(","):
                cve_id = cve_id.strip()
                if cve_id:
                    cve_to_exploits.setdefault(cve_id, []).append(iid)

        # Annotate vuln rows that have matching exploits
        for iid in self._vulns_tree.get_children():
            vals   = self._vulns_tree.item(iid, "values")
            cve_id = vals[0] if vals else ""
            if cve_id in cve_to_exploits:
                n = len(cve_to_exploits[cve_id])
                # Append exploit count to description
                existing = list(vals)
                existing[5] = f"[{n} exploit(s) available] " + existing[5]
                self._vulns_tree.item(iid, values=existing,
                                       tags=(self._vulns_tree.item(iid, "tags") + ("match",)))

        self._restripe_tree(self._exploits_tree)

    def _restripe_tree(self, tree: ttk.Treeview) -> None:
        for i, iid in enumerate(tree.get_children()):
            existing_tags = list(tree.item(iid, "tags"))
            # Remove old stripe tags
            existing_tags = [t for t in existing_tags if t not in ("odd", "even")]
            existing_tags.append("odd" if i % 2 == 0 else "even")
            tree.item(iid, tags=existing_tags)

    # ─── Search / filter ─────────────────────────────────────────────────────

    def _filter_results(self) -> None:
        """Filter all results trees to show only rows matching the search query."""
        query = self._results_search_var.get().strip().lower()

        # We re-populate from the report — hide non-matching rows by storing full data
        # in tags and re-populating filtered.  Since tkinter Treeview can't hide rows,
        # we rebuild with a subset.
        if not self._last_report:
            return

        # Re-populate everything, then filter
        self._populate_results()  # rebuilds from report

        if not query:
            return

        match_count = 0
        for tree in [self._ports_tree, self._vulns_tree, self._exploits_tree,
                     self._recon_tree, self._threats_tree]:
            to_delete = []
            for iid in tree.get_children():
                vals = tree.item(iid, "values")
                row_text = " ".join(str(v) for v in vals).lower()
                if query in row_text:
                    match_count += 1
                else:
                    to_delete.append(iid)
            for iid in to_delete:
                tree.delete(iid)

        self._results_count_label.configure(text=f"{match_count} matching")

    def _sort_tree_by_score(self, tree: ttk.Treeview, col: str) -> None:
        """Sort vulnerabilities by CVSS score descending."""
        data = [(tree.item(iid, "values"), iid) for iid in tree.get_children()]
        col_idx = tree["columns"].index(col)
        data.sort(key=lambda x: float(x[0][col_idx]) if x[0][col_idx] else 0,
                  reverse=True)
        for vals, iid in data:
            tree.move(iid, "", tk.END)
        self._restripe_tree(tree)

    # ─── Context menu ────────────────────────────────────────────────────────

    def _show_tree_context_menu(self, event: tk.Event) -> None:
        self._tree_event_widget = event.widget
        self._tree_menu.tk_popup(event.x_root, event.y_root)

    def _copy_tree_selection(self) -> None:
        tree = getattr(self, "_tree_event_widget", None)
        if not tree:
            return
        selected = tree.selection()
        lines = []
        for iid in selected:
            vals = tree.item(iid, "values")
            lines.append("\t".join(str(v) for v in vals))
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))

    def _show_tree_detail(self) -> None:
        tree = getattr(self, "_tree_event_widget", None)
        if not tree:
            return
        selected = tree.selection()
        if not selected:
            return
        vals = tree.item(selected[0], "values")
        cols = tree["columns"]
        detail = "\n".join(f"{c}: {v}" for c, v in zip(cols, vals))
        detail_win = tk.Toplevel(self)
        detail_win.title("Finding Detail")
        detail_win.configure(bg=DARK_BG)
        detail_win.geometry("600x300")
        txt = scrolledtext.ScrolledText(detail_win, wrap=tk.WORD,
                                         bg=ENTRY_BG, fg=TEXT_FG,
                                         font=("Courier", 10))
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        txt.insert("1.0", detail)
        txt.configure(state="disabled")

    # =========================================================================
    # Log queue polling
    # =========================================================================

    def _poll_log_queue(self) -> None:
        try:
            while True:
                raw: str = self.log_queue.get_nowait()
                tag  = "INFO"
                text = raw
                if raw.startswith("LEVELNO:"):
                    try:
                        sep     = raw.index("|")
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
                    except (ValueError, IndexError):
                        text = raw

                self._output_text.configure(state="normal")
                self._output_text.insert(tk.END, text + "\n", tag)
                self._output_text.see(tk.END)
                self._output_text.configure(state="disabled")

                # Mirror errors/warnings to debug tab
                if tag in ("ERROR", "CRITICAL", "WARNING"):
                    self._debug_log(text, tag)

        except queue.Empty:
            pass
        finally:
            self.after(80, self._poll_log_queue)

    # ─── Timing queue ────────────────────────────────────────────────────────

    def _poll_timing_queue(self) -> None:
        try:
            while True:
                event = self._timing_queue.get_nowait()
                action = event[0]
                key    = event[1]
                ts     = event[2]

                if action == "start":
                    self._module_timings[key] = {
                        "start": ts, "end": None, "status": "running", "note": ""
                    }
                elif action in ("done", "skip"):
                    status = event[3] if len(event) > 3 else "done"
                    note   = event[4] if len(event) > 4 else ""
                    if key in self._module_timings:
                        self._module_timings[key].update(
                            {"end": ts, "status": status, "note": note}
                        )
                    else:
                        self._module_timings[key] = {
                            "start": ts, "end": ts,
                            "status": status, "note": note
                        }

                self._update_timing_tree()

        except queue.Empty:
            pass
        finally:
            self.after(200, self._poll_timing_queue)

    def _update_timing_tree(self) -> None:
        tree = self._timing_tree
        # Rebuild (small table, fast)
        tree.delete(*tree.get_children())
        now = time.monotonic()

        for key, data in self._module_timings.items():
            start    = data.get("start")
            end      = data.get("end")
            status   = data.get("status", "")
            note     = data.get("note", "")

            start_str = time.strftime("%H:%M:%S", time.localtime(
                time.time() - (now - start))) if start else "—"

            if end and start:
                dur_s  = end - start
                dur_str = f"{dur_s:.1f}s"
            elif start:
                dur_s  = now - start
                dur_str = f"{dur_s:.1f}s ⟳"
            else:
                dur_s  = 0
                dur_str = "—"

            status_display = {
                "running":   "▶ Running",
                "ok":        "✓ OK",
                "error":     "✗ Error",
                "timeout":   "⏱ Timeout",
                "cancelled": "◼ Cancelled",
                "skipped":   "— Skipped",
            }.get(status, status)

            tag = {
                "running":   "running",
                "ok":        "done_slow" if dur_s > 60 else "done_ok",
                "error":     "done_err",
                "timeout":   "timeout",
                "cancelled": "cancelled",
                "skipped":   "skipped",
            }.get(status, "running")

            tree.insert("", tk.END,
                values=(key, status_display, start_str, dur_str, note),
                tags=(tag,))

    def _clear_timing_tree(self) -> None:
        self._timing_tree.delete(*self._timing_tree.get_children())

    # =========================================================================
    # Debug log
    # =========================================================================

    def _debug_log(self, message: str, level: str = "INFO") -> None:
        ts  = time.strftime("%H:%M:%S")
        self._debug_text.configure(state="normal")
        self._debug_text.insert(tk.END, f"[{ts}] {message}\n", level)
        self._debug_text.see(tk.END)
        self._debug_text.configure(state="disabled")

    def _clear_debug_log(self) -> None:
        self._debug_text.configure(state="normal")
        self._debug_text.delete("1.0", tk.END)
        self._debug_text.configure(state="disabled")

    # =========================================================================
    # System info (Debug tab)
    # =========================================================================

    def _refresh_system_info(self) -> None:
        try:
            import psutil, os as _os
            proc = psutil.Process(_os.getpid())
            mem_mb  = proc.memory_info().rss / 1024 / 1024
            mem_pct = psutil.virtual_memory().percent
            cpu_pct = psutil.cpu_percent(interval=None)
            n_threads = proc.num_threads()

            mem_colour = ERR_FG if mem_pct > 85 else WARN_FG if mem_pct > 70 else SUCCESS_FG
            self._mem_label.configure(
                text=f"Memory: {mem_mb:.0f} MB  ({mem_pct:.0f}% system)",
                foreground=mem_colour,
            )
            self._cpu_label.configure(text=f"CPU: {cpu_pct:.0f}%")
            self._thread_label.configure(text=f"Threads: {n_threads}")
            self._status_mem_label.configure(
                text=f"RAM {mem_mb:.0f}MB/{mem_pct:.0f}%",
                foreground=mem_colour,
            )
        except ImportError:
            self._mem_label.configure(text="Memory: install psutil for stats")
        except Exception as exc:
            self._mem_label.configure(text=f"Memory: {exc}")

    def _auto_refresh_system_info(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            self._refresh_system_info()
        self.after(5000, self._auto_refresh_system_info)

    # =========================================================================
    # Log search highlight
    # =========================================================================

    def _highlight_log_search(self) -> None:
        text = self._output_text
        query = self._log_search_var.get().strip()
        text.tag_remove("SEARCH_HL", "1.0", tk.END)
        if not query:
            return
        start = "1.0"
        while True:
            pos = text.search(query, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            text.tag_add("SEARCH_HL", pos, end)
            start = end

    # =========================================================================
    # Database tab
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
            builder = get_db_builder()(progress_callback=self._db_progress_cb)
            ok = builder.build_all(tier=tier)
            self.after(0, lambda: self._db_done(ok))

        threading.Thread(target=_run, daemon=True).start()

    def _db_update(self) -> None:
        self._db_progress_label.configure(text="Updating database...")
        self._db_progress.start(12)

        def _run():
            from .database import get_db_builder
            builder = get_db_builder()(progress_callback=self._db_progress_cb)
            ok = builder.update_all()
            self.after(0, lambda: self._db_done(ok))

        threading.Thread(target=_run, daemon=True).start()

    def _db_progress_cb(self, source: str, current: int, total: int, message: str) -> None:
        self.after(0, lambda: self._db_progress_label.configure(
            text=f"[{source}] {message}"))

    def _db_done(self, success: bool) -> None:
        self._db_progress.stop()
        label = "Database build complete." if success else "Database build failed — check log."
        self._db_progress_label.configure(text=label)
        self._refresh_db_status()

    # =========================================================================
    # Misc helpers
    # =========================================================================

    def _browse_output(self) -> None:
        d = filedialog.askdirectory(title="Select output directory")
        if d:
            self._output_dir_var.set(d)

    def _browse_wordlist(self) -> None:
        f = filedialog.askopenfilename(
            title="Select wordlist",
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

    def _clear_output(self) -> None:
        self._output_text.configure(state="normal")
        self._output_text.delete("1.0", tk.END)
        self._output_text.configure(state="disabled")

    def _tick_status(self) -> None:
        if self._scan_start and self._scan_thread and self._scan_thread.is_alive():
            elapsed = time.monotonic() - self._scan_start
            self._status_time_label.configure(text=_fmt_elapsed(elapsed))
        else:
            self._status_time_label.configure(text="")
        self.after(1000, self._tick_status)

    def _on_closing(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            if not messagebox.askyesno("Scan Running",
                                        "A scan is running.\nClose and terminate it?"):
                return
            self._cancel_event.set()
        self.destroy()


# =============================================================================
# Helpers
# =============================================================================

def _is_private_ip(target: str) -> bool:
    """Return True if target looks like an RFC1918/loopback/link-local address."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(target)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False  # hostname — assume public


def _looks_like_ip(target: str) -> bool:
    """Return True if target is a bare IP address (v4 or v6), not a hostname."""
    import ipaddress
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


async def _host_is_up(target: str, timeout: float = 2.0) -> bool:
    """
    Quick reachability check before committing to a full port scan.
    Tries a TCP connect on ports 80, 443, 22, 5555 in parallel.
    Falls back to True (scan anyway) if all attempts time out,
    so we don't block scanning on firewalled hosts.
    """
    probe_ports = [80, 443, 22, 5555, 23, 8080]

    async def _probe(port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    results = await asyncio.gather(*[_probe(p) for p in probe_ports],
                                    return_exceptions=True)
    return any(r is True for r in results)


def _fmt_elapsed(seconds: float) -> str:
    s = int(seconds)
    h, r = divmod(s, 3600)
    m, s = divmod(r, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    return f"{m}m {s:02d}s"


def _module_key_to_class(key: str) -> str:
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
    app = FenrirGUI()
    app.mainloop()