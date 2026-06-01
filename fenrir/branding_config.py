# fenrir/branding_config.py
"""
Persistent branding and theme configuration for Fenrir GUI.

Stores: logo path, background path, background opacity, accent colour,
window title, and other visual preferences in branding.json at FENRIR_ROOT.

Usage:
    from .branding_config import branding
    logo  = branding.logo_path
    alpha = branding.bg_opacity          # 0.0 – 1.0
    branding.bg_opacity = 0.3
    branding.save()
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("fenrir")

_DEFAULTS: dict = {
    "window_title":  "Fenrir Security Scanner",
    "logo_path":     "",           # empty → use built-in SVG wolf
    "background_path": "",         # empty → solid colour
    "bg_opacity":    0.25,         # 0 = fully transparent, 1 = opaque image
    "accent_colour": "#89b4fa",
    "dark_bg":       "#1e1e2e",
    "panel_bg":      "#2a2a3e",
    "text_fg":       "#cdd6f4",
    "entry_bg":      "#313244",
    "success_fg":    "#a6e3a1",
    "warn_fg":       "#f9e2af",
    "err_fg":        "#f38ba8",
    "font_family":   "Helvetica",
    "font_size":     9,
    "show_logo_in_header": True,
}


class BrandingConfig:
    """Load/save branding.json; exposes all keys as attributes."""

    def __init__(self, path: Optional[Path] = None) -> None:
        if path is None:
            from .fenrir_paths import BRANDING_JSON
            path = BRANDING_JSON
        self._path = path
        self._data: dict = dict(_DEFAULTS)
        self.load()

    # ── Persistence ────────────────────────────────────────────────────────────

    def load(self) -> None:
        if self._path.exists():
            try:
                stored = json.loads(self._path.read_text("utf-8"))
                self._data.update(stored)
            except Exception as exc:
                log.warning(f"[branding] Could not load {self._path}: {exc}")

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._data, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            log.error(f"[branding] Could not save {self._path}: {exc}")

    def reset(self) -> None:
        self._data = dict(_DEFAULTS)
        self.save()

    # ── Attribute access ───────────────────────────────────────────────────────

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"BrandingConfig has no attribute {name!r}")

    def __setattr__(self, name: str, value) -> None:
        if name.startswith("_"):
            super().__setattr__(name, value)
        else:
            self._data[name] = value

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def as_dict(self) -> dict:
        return dict(self._data)

    def update(self, d: dict) -> None:
        self._data.update(d)

    # ── Convenience properties ─────────────────────────────────────────────────

    @property
    def logo_path(self) -> Optional[Path]:
        p = self._data.get("logo_path", "")
        if p and Path(p).exists():
            return Path(p)
        from .fenrir_paths import LOGO_PATH
        return LOGO_PATH if LOGO_PATH.exists() else None

    @property
    def background_path(self) -> Optional[Path]:
        p = self._data.get("background_path", "")
        if p and Path(p).exists():
            return Path(p)
        from .fenrir_paths import BACKGROUND_PATH
        return BACKGROUND_PATH if BACKGROUND_PATH.exists() else None

    @property
    def bg_opacity(self) -> float:
        return float(self._data.get("bg_opacity", 0.25))

    @bg_opacity.setter
    def bg_opacity(self, v: float) -> None:
        self._data["bg_opacity"] = max(0.0, min(1.0, float(v)))


# Module-level singleton
branding = BrandingConfig()
