# fenrir/fenrir_paths.py
"""
Central path registry for Fenrir.

All paths derive from FENRIR_ROOT so the tool is portable — copy the
whole fenrir/ folder anywhere and it still works.

Results directory structure:
  FENRIR_ROOT/
    Results/
      2025-06-01_14-30_192.168.1.1/
        report.json
        ports.txt
        ...
    assets/
      logo.png
      background.png
      icon.ico
    branding.json
    scan_history.db
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

# ── Root: parent of the fenrir package ────────────────────────────────────────
# Works whether installed via pip or run directly from source.
FENRIR_ROOT: Path = Path(__file__).resolve().parent.parent

# ── Sub-directories ────────────────────────────────────────────────────────────
RESULTS_DIR:  Path = FENRIR_ROOT / "Results"
ASSETS_DIR:   Path = FENRIR_ROOT / "assets"
DATA_DIR:     Path = FENRIR_ROOT / "data"

# Ensure core dirs exist on first import
for _d in (RESULTS_DIR, ASSETS_DIR, DATA_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ── Named asset paths ──────────────────────────────────────────────────────────
LOGO_PATH:       Path = ASSETS_DIR / "logo.png"
BACKGROUND_PATH: Path = ASSETS_DIR / "background.png"
ICON_ICO_PATH:   Path = ASSETS_DIR / "icon.ico"
BRANDING_JSON:   Path = FENRIR_ROOT / "branding.json"
HISTORY_DB:      Path = FENRIR_ROOT / "scan_history.db"


def make_result_dir(target: str, scan_type: str = "scan") -> Path:
    """
    Create and return a timestamped result directory.

    Format:  Results/YYYY-MM-DD_HH-MM_<sanitised-target>/
    Example: Results/2025-06-01_14-30_192.168.1.1/
             Results/2025-06-01_14-30_192.168.1.0-24_network/
    """
    ts     = datetime.now().strftime("%Y-%m-%d_%H-%M")
    # Sanitise target: keep alphanumerics, dots, hyphens; replace the rest
    safe   = re.sub(r"[^\w.\-]", "_", target)[:40].strip("_")
    suffix = f"_{scan_type}" if scan_type not in ("scan", "single") else ""
    name   = f"{ts}_{safe}{suffix}"
    path   = RESULTS_DIR / name
    path.mkdir(parents=True, exist_ok=True)
    return path