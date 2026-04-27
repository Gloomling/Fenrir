#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║         FENRIR BRANDING TOOL  —  Operator / Administrator Only       ║
╠══════════════════════════════════════════════════════════════════════╣
║  This tool writes branding.json which Fenrir reads on every launch.  ║
║  Keep this file separate from the Fenrir installation.               ║
║  Do NOT distribute this tool to end users.                           ║
╚══════════════════════════════════════════════════════════════════════╝

Usage:
    python3 fenrir_brand.py                     # GUI mode (default)
    python3 fenrir_brand.py --target /opt/fenrir # point at a different install
    python3 fenrir_brand.py --export theme.json  # export current theme
    python3 fenrir_brand.py --import theme.json  # apply a theme file

The tool writes:
    <fenrir_root>/branding.json    — main config read by Fenrir GUI
    <fenrir_root>/assets/          — copies logo/background here for portability

Fenrir itself has zero branding controls — it only reads branding.json.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tkinter as tk
from pathlib import Path
from tkinter import colorchooser, filedialog, messagebox, ttk
from typing import Optional

try:
    from PIL import Image, ImageDraw, ImageTk
    PIL_OK = True
except ImportError:
    PIL_OK = False

# ── Version ────────────────────────────────────────────────────────────────────
TOOL_VERSION = "1.0.0"
TOOL_TITLE   = "Fenrir Branding Tool"

# ── Default branding values (mirrors branding_config.py defaults) ──────────────
DEFAULTS: dict = {
    "window_title":       "Fenrir Security Scanner",
    "logo_path":          "",
    "background_path":    "",
    "bg_opacity":         0.25,
    "accent_colour":      "#89b4fa",
    "dark_bg":            "#1e1e2e",
    "panel_bg":           "#2a2a3e",
    "text_fg":            "#cdd6f4",
    "entry_bg":           "#313244",
    "success_fg":         "#a6e3a1",
    "warn_fg":            "#f9e2af",
    "err_fg":             "#f38ba8",
    "sep_fg":             "#45475a",
    "btn_active":         "#585b70",
    "crit_fg":            "#ff5555",
    "debug_fg":           "#6272a4",
    "font_family":        "Helvetica",
    "font_size":          9,
    "show_logo_in_header": True,
}

# ── Tool colour palette (the TOOL's own UI, not Fenrir's) ──────────────────────
T_BG     = "#13131f"
T_PANEL  = "#1e1e30"
T_ACCENT = "#cba6f7"   # lavender — distinct from Fenrir's blue so you know which app you're in
T_TEXT   = "#cdd6f4"
T_ENTRY  = "#262637"
T_SEP    = "#3b3b52"
T_OK     = "#a6e3a1"
T_WARN   = "#f9e2af"
T_ERR    = "#f38ba8"


# =============================================================================
# Core logic  — no GUI dependency
# =============================================================================

def find_fenrir_root(hint: Optional[str] = None) -> Optional[Path]:
    """
    Locate the Fenrir installation root.

    Search order:
    1.  --target CLI argument
    2.  FENRIR_ROOT environment variable
    3.  Same directory as this script
    4.  Parent directory of this script
    5.  Common install locations
    """
    candidates: list[Path] = []

    if hint:
        candidates.append(Path(hint))

    env = os.environ.get("FENRIR_ROOT")
    if env:
        candidates.append(Path(env))

    script_dir = Path(__file__).resolve().parent
    candidates += [
        script_dir,
        script_dir.parent,
        Path.home() / ".fenrir" / "fenrir",
        Path("/opt/fenrir"),
        Path("/opt/fenrir-scanner"),
        Path.home() / "fenrir",
        Path.home() / "fenrir-scanner",
    ]

    for c in candidates:
        # Fenrir root contains pyproject.toml or a fenrir/ sub-package
        if (c / "pyproject.toml").exists() or (c / "fenrir" / "__init__.py").exists():
            return c.resolve()
        # Or directly contains branding.json already
        if (c / "branding.json").exists():
            return c.resolve()

    return None


def load_branding(root: Path) -> dict:
    """Load branding.json from root, merging with defaults."""
    path = root / "branding.json"
    data = dict(DEFAULTS)
    if path.exists():
        try:
            stored = json.loads(path.read_text("utf-8"))
            data.update(stored)
        except Exception as e:
            print(f"[warn] Could not read {path}: {e}")
    return data


def save_branding(root: Path, data: dict) -> Path:
    """Write branding.json to root. Returns the path written."""
    path = root / "branding.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def copy_asset(src: str, root: Path, kind: str) -> str:
    """
    Copy a logo/background file into <root>/assets/ for portability.
    Returns the new absolute path (stored in branding.json).
    """
    if not src or not Path(src).exists():
        return src
    assets_dir = root / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(src).suffix
    dest   = assets_dir / f"{kind}{suffix}"
    shutil.copy2(src, dest)
    return str(dest)


def export_theme(root: Path, export_path: str) -> None:
    """Export current branding.json as a portable theme file."""
    data = load_branding(root)
    Path(export_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Theme exported → {export_path}")


def import_theme(root: Path, import_path: str) -> None:
    """Apply a theme file to this Fenrir installation."""
    data = json.loads(Path(import_path).read_text("utf-8"))
    save_branding(root, data)
    print(f"Theme applied from {import_path} → {root / 'branding.json'}")


# =============================================================================
# GUI
# =============================================================================

class BrandingTool(tk.Tk):
    """Standalone Fenrir Branding Tool — operator use only."""

    def __init__(self, root: Optional[Path], hint: Optional[str] = None) -> None:
        super().__init__()
        self.title(TOOL_TITLE)
        self.geometry("860x760")
        self.minsize(780, 640)
        self.configure(bg=T_BG)
        self.resizable(True, True)

        self._fenrir_root: Optional[Path] = root
        self._hint = hint
        self._data: dict = {}
        self._swatch_labels: dict[str, tk.Label] = {}
        self._preview_bg_img = None

        self._apply_styles()
        if self._fenrir_root:
            self._data = load_branding(self._fenrir_root)
        self._build_ui()
        self._set_tool_icon()

    # ── Styles ────────────────────────────────────────────────────────────────

    def _apply_styles(self) -> None:
        s = ttk.Style(self)
        try: s.theme_use("clam")
        except tk.TclError: pass
        s.configure(".",           background=T_BG,    foreground=T_TEXT,
                    fieldbackground=T_ENTRY, font=("Helvetica", 9))
        s.configure("TFrame",      background=T_PANEL)
        s.configure("TLabelframe", background=T_PANEL, bordercolor=T_SEP, relief="flat")
        s.configure("TLabelframe.Label", background=T_PANEL, foreground=T_ACCENT,
                    font=("Helvetica", 9, "bold"))
        s.configure("TLabel",      background=T_PANEL, foreground=T_TEXT)
        s.configure("TEntry",      fieldbackground=T_ENTRY, foreground=T_TEXT, insertcolor=T_TEXT)
        s.configure("TButton",     background=T_ENTRY, foreground=T_TEXT, padding=(6, 3))
        s.map("TButton",           background=[("active", T_SEP)])
        s.configure("Accent.TButton", background=T_ACCENT, foreground=T_BG,
                    font=("Helvetica", 9, "bold"), padding=(8, 4))
        s.map("Accent.TButton",    background=[("active", "#b38ee0")])
        s.configure("TCheckbutton",background=T_PANEL, foreground=T_TEXT)
        s.map("TCheckbutton",      background=[("active", T_PANEL)])
        s.configure("TCombobox",   fieldbackground=T_ENTRY, foreground=T_TEXT,
                    selectbackground=T_ENTRY)
        s.configure("TSpinbox",    fieldbackground=T_ENTRY, foreground=T_TEXT)
        s.configure("TScrollbar",  background=T_ENTRY, troughcolor=T_BG, arrowcolor=T_TEXT)
        s.configure("TScale",      background=T_PANEL, troughcolor=T_ENTRY)
        s.configure("Horizontal.TScale", background=T_PANEL)

    def _set_tool_icon(self) -> None:
        if not PIL_OK: return
        try:
            img  = Image.new("RGBA", (32, 32), (19, 19, 31, 255))
            draw = ImageDraw.Draw(img)
            # Simple "B" for Branding Tool
            draw.rectangle([4, 4, 28, 28], outline=(203, 166, 247, 255), width=2)
            draw.text((9, 7), "B", fill=(203, 166, 247, 255))
            ph = ImageTk.PhotoImage(img)
            self.iconphoto(True, ph)
            self._tool_icon = ph
        except Exception:
            pass

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Header bar ─────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg="#0d0d1a", height=54)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(hdr, text="⚙  FENRIR BRANDING TOOL", bg="#0d0d1a", fg=T_ACCENT,
                 font=("Helvetica", 13, "bold")).pack(side=tk.LEFT, padx=16, pady=12)
        tk.Label(hdr, text=f"v{TOOL_VERSION}  |  Operator use only",
                 bg="#0d0d1a", fg="#6272a4", font=("Helvetica", 9)).pack(side=tk.LEFT)

        # ── Target path bar ────────────────────────────────────────────────────
        tbar = tk.Frame(self, bg=T_SEP, height=1)
        tbar.pack(fill=tk.X)
        trow = ttk.Frame(self, padding=(10, 6))
        trow.pack(fill=tk.X)
        trow.columnconfigure(1, weight=1)
        ttk.Label(trow, text="Fenrir root:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self._root_var = tk.StringVar(value=str(self._fenrir_root or "Not found"))
        ttk.Entry(trow, textvariable=self._root_var, state="readonly").grid(
            row=0, column=1, sticky="ew")
        ttk.Button(trow, text="Browse…", command=self._browse_root).grid(
            row=0, column=2, padx=(6, 0))

        if not self._fenrir_root:
            self._show_not_found()
            return

        # ── Main scrollable canvas ─────────────────────────────────────────────
        canvas = tk.Canvas(self, bg=T_BG, highlightthickness=0)
        vsb    = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(fill=tk.BOTH, expand=True)
        inner = ttk.Frame(canvas)
        _wid  = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: (
            canvas.configure(scrollregion=canvas.bbox("all")),
            canvas.itemconfigure(_wid, width=canvas.winfo_width())))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(_wid, width=e.width))
        canvas.bind_all("<MouseWheel>",
            lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        PAD = dict(fill=tk.X, padx=14, pady=6)

        # ── 1. Live preview ────────────────────────────────────────────────────
        pf = ttk.LabelFrame(inner, text="Live Preview", padding=10)
        pf.pack(**PAD)
        self._preview_frame = tk.Frame(pf, height=70)
        self._preview_frame.pack(fill=tk.X)
        self._preview_frame.pack_propagate(False)
        self._preview_canvas = tk.Canvas(self._preview_frame, highlightthickness=0, height=70)
        self._preview_canvas.pack(fill=tk.BOTH, expand=True)
        self._update_preview()

        # ── 2. Window Title ────────────────────────────────────────────────────
        tf = ttk.LabelFrame(inner, text="Window Title", padding=10)
        tf.pack(**PAD); tf.columnconfigure(0, weight=1)
        self._title_var = tk.StringVar(value=self._data.get("window_title", DEFAULTS["window_title"]))
        ttk.Entry(tf, textvariable=self._title_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(tf, text="Preview", command=self._update_preview).grid(
            row=0, column=1, padx=(6, 0))
        self._title_var.trace_add("write", lambda *_: self._update_preview())

        # ── 3. Logo ────────────────────────────────────────────────────────────
        lf = ttk.LabelFrame(inner, text="Logo / Window Icon", padding=10)
        lf.pack(**PAD)
        self._logo_var = tk.StringVar(value=self._data.get("logo_path", ""))
        lr = ttk.Frame(lf); lr.pack(fill=tk.X); lr.columnconfigure(0, weight=1)
        ttk.Entry(lr, textvariable=self._logo_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(lr, text="Browse…", command=self._browse_logo).grid(row=0, column=1, padx=(4,0))
        ttk.Button(lr, text="Copy to assets", command=self._copy_logo_to_assets).grid(
            row=0, column=2, padx=(4, 0))
        ttk.Label(lf, text="PNG/JPG/ICO — 256×256 px recommended. 'Copy to assets' makes it portable.",
                  foreground="#6272a4", font=("Helvetica", 8)).pack(anchor="w", pady=(4, 0))
        self._logo_var.trace_add("write", lambda *_: self._update_preview())

        # Logo preview thumbnail
        self._logo_thumb_lbl = tk.Label(lf, bg=T_BG, text="No logo", fg="#6272a4",
                                         font=("Helvetica", 8))
        self._logo_thumb_lbl.pack(anchor="w", pady=(6, 0))
        self._refresh_logo_thumb()

        # ── 4. Background ──────────────────────────────────────────────────────
        bf = ttk.LabelFrame(inner, text="Background Image", padding=10)
        bf.pack(**PAD)
        self._bg_var = tk.StringVar(value=self._data.get("background_path", ""))
        br = ttk.Frame(bf); br.pack(fill=tk.X); br.columnconfigure(0, weight=1)
        ttk.Entry(br, textvariable=self._bg_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(br, text="Browse…", command=self._browse_background).grid(
            row=0, column=1, padx=(4, 0))
        ttk.Button(br, text="Copy to assets", command=self._copy_bg_to_assets).grid(
            row=0, column=2, padx=(4, 0))
        ttk.Button(br, text="✕ Clear", command=self._clear_background).grid(
            row=0, column=3, padx=(4, 0))
        ttk.Label(bf, text="PNG/JPG — scaled to fill the window.",
                  foreground="#6272a4", font=("Helvetica", 8)).pack(anchor="w", pady=(4, 0))

        orow = ttk.Frame(bf); orow.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(orow, text="Opacity:").pack(side=tk.LEFT)
        self._opacity_var = tk.DoubleVar(value=self._data.get("bg_opacity", 0.25))
        opacity_slider = ttk.Scale(orow, from_=0.0, to=1.0, orient="horizontal",
                                    variable=self._opacity_var, length=280,
                                    command=lambda _: (self._update_opacity_label(),
                                                       self._update_preview()))
        opacity_slider.pack(side=tk.LEFT, padx=(8, 8))
        self._opacity_lbl = tk.Label(orow, text=f"{int(self._opacity_var.get()*100)}%",
                                      bg=T_PANEL, fg=T_TEXT, width=5)
        self._opacity_lbl.pack(side=tk.LEFT)
        self._bg_var.trace_add("write", lambda *_: self._update_preview())

        # ── 5. Colour palette ──────────────────────────────────────────────────
        cf = ttk.LabelFrame(inner, text="Colour Palette", padding=10)
        cf.pack(**PAD)
        ttk.Label(cf, text="Click a swatch to change it. Changes apply to Fenrir on next launch.",
                  foreground="#6272a4", font=("Helvetica", 8)).pack(anchor="w", pady=(0, 8))

        colour_defs = [
            ("Accent / highlights", "accent_colour"),
            ("Dark background",     "dark_bg"),
            ("Panel background",    "panel_bg"),
            ("Primary text",        "text_fg"),
            ("Input field BG",      "entry_bg"),
            ("Success / open port", "success_fg"),
            ("Warning",             "warn_fg"),
            ("Error / critical",    "err_fg"),
            ("Separator",           "sep_fg"),
            ("Button hover",        "btn_active"),
            ("Critical alert",      "crit_fg"),
            ("Debug / muted text",  "debug_fg"),
        ]
        grid = ttk.Frame(cf); grid.pack(fill=tk.X)
        for i, (label, key) in enumerate(colour_defs):
            row, col = divmod(i, 3)
            cell = ttk.Frame(grid); cell.grid(row=row, column=col, padx=10, pady=4, sticky="w")
            current = self._data.get(key, DEFAULTS.get(key, "#ffffff"))
            swatch = tk.Label(cell, bg=current, width=4, height=1, relief="raised", cursor="hand2")
            swatch.pack(side=tk.LEFT)
            swatch.bind("<Button-1>", lambda e, k=key, sw=swatch: self._pick_colour(k, sw))
            tk.Label(cell, text=label, bg=T_BG, fg=T_TEXT,
                     font=("Helvetica", 8)).pack(side=tk.LEFT, padx=(6, 0))
            self._swatch_labels[key] = swatch

        ttk.Button(cf, text="↺ Reset colours to defaults",
                   command=self._reset_colours).pack(anchor="w", pady=(8, 0))

        # ── 6. Font ────────────────────────────────────────────────────────────
        ff = ttk.LabelFrame(inner, text="Font", padding=10)
        ff.pack(**PAD)
        frow = ttk.Frame(ff); frow.pack(fill=tk.X)
        ttk.Label(frow, text="Family:").pack(side=tk.LEFT)
        self._font_var = tk.StringVar(value=self._data.get("font_family", "Helvetica"))
        ttk.Combobox(frow, textvariable=self._font_var, width=18,
                     values=["Helvetica", "Arial", "Segoe UI", "Ubuntu",
                              "Roboto", "Courier", "Consolas", "DejaVu Sans"],
                     state="readonly").pack(side=tk.LEFT, padx=(6, 20))
        ttk.Label(frow, text="Size (pt):").pack(side=tk.LEFT)
        self._fontsize_var = tk.IntVar(value=self._data.get("font_size", 9))
        ttk.Spinbox(frow, from_=7, to=14, textvariable=self._fontsize_var, width=4).pack(
            side=tk.LEFT, padx=(4, 0))

        # ── 7. Theme import/export ─────────────────────────────────────────────
        xf = ttk.LabelFrame(inner, text="Theme Import / Export", padding=10)
        xf.pack(**PAD)
        xrow = ttk.Frame(xf); xrow.pack(fill=tk.X)
        ttk.Button(xrow, text="📤  Export theme…", command=self._export_theme).pack(
            side=tk.LEFT, padx=(0, 8))
        ttk.Button(xrow, text="📥  Import theme…", command=self._import_theme).pack(
            side=tk.LEFT, padx=(0, 8))
        ttk.Button(xrow, text="↺  Full reset to defaults", command=self._full_reset).pack(
            side=tk.LEFT)
        ttk.Label(xf, text="Export saves a portable .json theme you can apply to other Fenrir installs.",
                  foreground="#6272a4", font=("Helvetica", 8)).pack(anchor="w", pady=(6, 0))

        # ── 8. Save ────────────────────────────────────────────────────────────
        sf = ttk.Frame(inner); sf.pack(**PAD)
        ttk.Button(sf, text="💾  Save branding to Fenrir", style="Accent.TButton",
                   command=self._save).pack(side=tk.LEFT, padx=(0, 10))
        self._status_lbl = tk.Label(sf, text="", bg=T_BG, fg=T_OK,
                                     font=("Helvetica", 9, "bold"))
        self._status_lbl.pack(side=tk.LEFT)

    def _show_not_found(self) -> None:
        """Show a helpful error when Fenrir root can't be located."""
        f = ttk.Frame(self, padding=40); f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text="⚠  Fenrir installation not found",
                  font=("Helvetica", 14, "bold"), foreground=T_WARN).pack()
        ttk.Label(f, text=(
            "This tool needs to know where Fenrir is installed to write branding.json.\n\n"
            "Options:\n"
            "  1. Click 'Browse…' above to select the Fenrir root directory\n"
            "  2. Set the FENRIR_ROOT environment variable\n"
            "  3. Run:  python3 fenrir_brand.py --target /path/to/fenrir\n\n"
            "The Fenrir root is the directory that contains pyproject.toml\n"
            "or the fenrir/ Python package sub-directory."
        ), foreground=T_TEXT, justify=tk.LEFT, font=("Helvetica", 10)).pack(pady=16)

    # ── Browsing ──────────────────────────────────────────────────────────────

    def _browse_root(self) -> None:
        d = filedialog.askdirectory(title="Select Fenrir root directory")
        if not d:
            return
        root = Path(d)
        # Accept if it has pyproject.toml, fenrir/__init__.py, or branding.json
        if not ((root / "pyproject.toml").exists() or
                (root / "fenrir" / "__init__.py").exists() or
                (root / "branding.json").exists()):
            if not messagebox.askyesno("Not recognised",
                    f"{d}\n\ndoes not look like a Fenrir root "
                    "(no pyproject.toml or fenrir/ package found).\n\nUse it anyway?"):
                return
        self._fenrir_root = root
        self._root_var.set(str(root))
        self._data = load_branding(root)
        messagebox.showinfo("Loaded", f"Branding loaded from:\n{root / 'branding.json'}")
        # Rebuild UI with loaded data
        for widget in self.winfo_children():
            widget.destroy()
        self._apply_styles()
        self._build_ui()

    def _browse_logo(self) -> None:
        f = filedialog.askopenfilename(
            title="Select logo image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.ico *.bmp *.webp"),
                       ("All files", "*.*")])
        if f:
            self._logo_var.set(f)
            self._refresh_logo_thumb()

    def _browse_background(self) -> None:
        f = filedialog.askopenfilename(
            title="Select background image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp"),
                       ("All files", "*.*")])
        if f:
            self._bg_var.set(f)
            self._update_preview()

    def _clear_background(self) -> None:
        self._bg_var.set("")
        self._update_preview()

    def _copy_logo_to_assets(self) -> None:
        if not self._fenrir_root:
            return
        path = self._logo_var.get().strip()
        if not path or not Path(path).exists():
            messagebox.showerror("Not found", f"Logo file not found:\n{path}")
            return
        new_path = copy_asset(path, self._fenrir_root, "logo")
        self._logo_var.set(new_path)
        self._status("Logo copied to assets/", ok=True)

    def _copy_bg_to_assets(self) -> None:
        if not self._fenrir_root:
            return
        path = self._bg_var.get().strip()
        if not path or not Path(path).exists():
            messagebox.showerror("Not found", f"Background file not found:\n{path}")
            return
        new_path = copy_asset(path, self._fenrir_root, "background")
        self._bg_var.set(new_path)
        self._status("Background copied to assets/", ok=True)

    # ── Colour ────────────────────────────────────────────────────────────────

    def _pick_colour(self, key: str, swatch: tk.Label) -> None:
        current = self._data.get(key, DEFAULTS.get(key, "#ffffff"))
        result  = colorchooser.askcolor(color=current, title=f"Choose colour — {key}")
        if result and result[1]:
            self._data[key] = result[1]
            swatch.configure(bg=result[1])
            self._update_preview()

    def _reset_colours(self) -> None:
        colour_keys = ["accent_colour","dark_bg","panel_bg","text_fg","entry_bg",
                       "success_fg","warn_fg","err_fg","sep_fg","btn_active","crit_fg","debug_fg"]
        for k in colour_keys:
            self._data[k] = DEFAULTS[k]
            if k in self._swatch_labels:
                self._swatch_labels[k].configure(bg=DEFAULTS[k])
        self._update_preview()
        self._status("Colours reset to defaults", ok=True)

    # ── Theme ─────────────────────────────────────────────────────────────────

    def _export_theme(self) -> None:
        self._collect()
        path = filedialog.asksaveasfilename(
            title="Export theme", defaultextension=".json",
            filetypes=[("JSON theme", "*.json"), ("All files", "*.*")])
        if path:
            Path(path).write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            self._status(f"Exported → {Path(path).name}", ok=True)

    def _import_theme(self) -> None:
        path = filedialog.askopenfilename(
            title="Import theme",
            filetypes=[("JSON theme", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            imported = json.loads(Path(path).read_text("utf-8"))
            self._data.update(imported)
            # Refresh swatches
            for key, swatch in self._swatch_labels.items():
                if key in self._data:
                    swatch.configure(bg=self._data[key])
            self._update_preview()
            self._status(f"Theme imported from {Path(path).name}", ok=True)
        except Exception as exc:
            messagebox.showerror("Import error", str(exc))

    def _full_reset(self) -> None:
        if messagebox.askyesno("Full reset", "Reset ALL branding to factory defaults?"):
            self._data = dict(DEFAULTS)
            for key, swatch in self._swatch_labels.items():
                if key in self._data:
                    swatch.configure(bg=self._data[key])
            self._update_preview()
            self._status("All settings reset to defaults", ok=True)

    # ── Save ─────────────────────────────────────────────────────────────────

    def _collect(self) -> None:
        """Pull all widget values into self._data."""
        self._data["window_title"]    = self._title_var.get().strip() or "Fenrir Security Scanner"
        self._data["logo_path"]       = self._logo_var.get().strip()
        self._data["background_path"] = self._bg_var.get().strip()
        self._data["bg_opacity"]      = round(float(self._opacity_var.get()), 3)
        self._data["font_family"]     = self._font_var.get()
        self._data["font_size"]       = int(self._fontsize_var.get())

    def _save(self) -> None:
        if not self._fenrir_root:
            messagebox.showerror("No target", "Select a Fenrir root directory first.")
            return
        self._collect()
        path = save_branding(self._fenrir_root, self._data)
        self._status(f"Saved → {path}", ok=True)
        messagebox.showinfo("Saved",
            f"Branding written to:\n{path}\n\n"
            f"Fenrir will pick up the new branding on next launch.")

    def _status(self, msg: str, ok: bool = True) -> None:
        if hasattr(self, "_status_lbl"):
            self._status_lbl.configure(text=msg, fg=T_OK if ok else T_ERR)
            self.after(4000, lambda: self._status_lbl.configure(text=""))

    # ── Preview ───────────────────────────────────────────────────────────────

    def _update_opacity_label(self) -> None:
        if hasattr(self, "_opacity_lbl"):
            self._opacity_lbl.configure(text=f"{int(self._opacity_var.get()*100)}%")

    def _refresh_logo_thumb(self) -> None:
        if not PIL_OK or not hasattr(self, "_logo_thumb_lbl"):
            return
        path = self._logo_var.get().strip()
        try:
            if path and Path(path).exists():
                img = Image.open(path).resize((40, 40), Image.Resampling.LANCZOS)
                ph  = ImageTk.PhotoImage(img)
                self._logo_thumb_lbl.configure(image=ph, text="")
                self._logo_thumb_lbl._ph = ph
            else:
                self._logo_thumb_lbl.configure(image="", text="No logo selected")
        except Exception:
            self._logo_thumb_lbl.configure(image="", text="(cannot preview)")

    def _update_preview(self) -> None:
        """Draw a simple preview of the Fenrir window header in the canvas."""
        if not hasattr(self, "_preview_canvas"):
            return
        c = self._preview_canvas
        c.delete("all")
        w = max(c.winfo_width(), 400)
        h = 70
        bg = self._data.get("dark_bg", DEFAULTS["dark_bg"])
        accent = self._data.get("accent_colour", DEFAULTS["accent_colour"])
        panel  = self._data.get("panel_bg",      DEFAULTS["panel_bg"])
        text   = self._data.get("text_fg",        DEFAULTS["text_fg"])

        # Background
        if PIL_OK:
            bg_path = self._bg_var.get().strip() if hasattr(self, "_bg_var") else ""
            opacity = self._opacity_var.get() if hasattr(self, "_opacity_var") else 0.25
            try:
                if bg_path and Path(bg_path).exists() and opacity > 0.01:
                    img = Image.open(bg_path).resize((w, h), Image.Resampling.LANCZOS).convert("RGBA")
                    ov_a = int((1.0 - opacity) * 255)
                    r, g, b = self._hex_to_rgb(bg)
                    ov  = Image.new("RGBA", (w, h), (r, g, b, ov_a))
                    merged = Image.alpha_composite(img, ov)
                    self._preview_bg_img = ImageTk.PhotoImage(merged)
                    c.create_image(0, 0, anchor="nw", image=self._preview_bg_img)
                else:
                    c.create_rectangle(0, 0, w, h, fill=bg, outline="")
            except Exception:
                c.create_rectangle(0, 0, w, h, fill=bg, outline="")
        else:
            c.create_rectangle(0, 0, w, h, fill=bg, outline="")

        # Tab strip simulation
        c.create_rectangle(0, 48, w, h, fill=panel, outline="")
        tab_labels = ["  Scan  ", "  Network Scan  ", "  Results  ", "  History  "]
        x = 8
        for i, tab in enumerate(tab_labels):
            tw = len(tab) * 6 + 8
            if i == 0:
                c.create_rectangle(x, 50, x+tw, h, fill=panel, outline=accent)
                c.create_text(x + tw//2, 59, text=tab.strip(), fill=accent, font=("Helvetica", 8, "bold"))
            else:
                c.create_text(x + tw//2, 59, text=tab.strip(), fill=text, font=("Helvetica", 8))
            x += tw + 4

        # Title text
        title = self._title_var.get() if hasattr(self, "_title_var") else "Fenrir Security Scanner"
        c.create_text(w//2, 24, text=title, fill=accent,
                      font=("Helvetica", 11, "bold"), anchor="center")

        # Logo thumb (if PIL available and logo set)
        if PIL_OK and hasattr(self, "_logo_var"):
            lp = self._logo_var.get().strip()
            try:
                if lp and Path(lp).exists():
                    img = Image.open(lp).resize((36, 36), Image.Resampling.LANCZOS)
                    self._prev_logo = ImageTk.PhotoImage(img)
                    c.create_image(18, 6, anchor="nw", image=self._prev_logo)
            except Exception:
                pass

    @staticmethod
    def _hex_to_rgb(h: str) -> tuple:
        h = h.lstrip("#")
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


# =============================================================================
# CLI entry point
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fenrir_brand",
        description="Fenrir Branding Tool — write branding.json for a Fenrir installation.")
    parser.add_argument("--target", "-t", metavar="DIR",
                        help="Fenrir root directory (default: auto-detect)")
    parser.add_argument("--export", metavar="FILE",
                        help="Export current branding to a theme JSON file and exit")
    parser.add_argument("--import-theme", metavar="FILE", dest="import_theme",
                        help="Apply a theme JSON file to the Fenrir install and exit")
    parser.add_argument("--version", action="version", version=f"fenrir_brand {TOOL_VERSION}")
    args = parser.parse_args()

    root = find_fenrir_root(args.target)

    # CLI-only mode
    if args.export:
        if not root:
            print("ERROR: Fenrir root not found. Use --target.", file=sys.stderr)
            sys.exit(1)
        export_theme(root, args.export)
        return

    if args.import_theme:
        if not root:
            print("ERROR: Fenrir root not found. Use --target.", file=sys.stderr)
            sys.exit(1)
        import_theme(root, args.import_theme)
        return

    # GUI mode
    if not root:
        print("[warn] Fenrir root not auto-detected — you can browse to it in the GUI.")

    app = BrandingTool(root=root, hint=args.target)
    app.mainloop()


if __name__ == "__main__":
    main()