# fenrir/config.py
#
# Centralised configuration for the Fenrir application.
#
# Design:
#   - All API keys and runtime settings are loaded from a .env file via
#     python-dotenv. A .env file is NOT required — missing keys are handled
#     gracefully via soft warnings rather than hard failures.
#   - The Config class exposes a validate_key() method that modules call
#     before making API requests. This returns a (bool, str) tuple so the
#     caller can decide whether to abort, warn, or skip.
#   - A module-level singleton `config` is provided for convenience so
#     modules do: from ..config import config
#   - APP_VERSION is read dynamically from pyproject.toml so there is a
#     single source of truth for the version number.
#
# API Key Requirements by Module:
#   VIRUSTOTAL_API_KEY   — threat_intel_scanner.py  (VirusTotal IP lookup)
#   ALIENVAULT_OTX_API_KEY — threat_intel_scanner.py (AlienVault OTX lookup)
#   NVD_API_KEY          — vulnerability_scanner.py  (NVD CVE search)
#                          NVD works without a key but is heavily rate-limited;
#                          a key raises the rate limit significantly.

import os
import tomllib  # stdlib in Python 3.11+; fallback below for 3.10
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from .logging_config import get_logger

log = get_logger()

# ---------------------------------------------------------------------------
# Load .env file
# ---------------------------------------------------------------------------
# Search for .env in the project root (two levels up from this file).
# If not found, python-dotenv silently does nothing — os.getenv() calls
# will simply return None, which validate_key() handles gracefully.

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)

# ---------------------------------------------------------------------------
# Version helper
# ---------------------------------------------------------------------------

def _read_version() -> str:
    """
    Read the project version from pyproject.toml.

    Returns the version string (e.g. "2.0.0") or "unknown" if the file
    cannot be parsed. Uses stdlib tomllib (Python 3.11+) with a fallback
    to the third-party tomli package for Python 3.10.
    """
    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"

    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        return data["tool"]["poetry"]["version"]
    except ImportError:
        # Python 3.10 — try tomli
        try:
            import tomli  # type: ignore[import]
            with open(pyproject_path, "rb") as f:
                data = tomli.load(f)
            return data["tool"]["poetry"]["version"]
        except Exception:
            return "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Config class
# ---------------------------------------------------------------------------

class Config:
    """
    Loads and provides all configuration settings for Fenrir.

    Attributes:
        APP_NAME (str):               Human-readable application name.
        APP_VERSION (str):            Version string sourced from pyproject.toml.
        VIRUSTOTAL_API_KEY (str|None): VirusTotal v3 API key.
        ALIENVAULT_OTX_API_KEY (str|None): AlienVault OTX API key.
        NVD_API_KEY (str|None):       NVD API key (optional but recommended).

    Key requirement map — which modules need which keys:
        "virustotal"  -> VIRUSTOTAL_API_KEY   (threat_intel_scanner)
        "alienvault"  -> ALIENVAULT_OTX_API_KEY (threat_intel_scanner)
        "nvd"         -> NVD_API_KEY           (vulnerability_scanner)
    """

    # Map of short key names to (env_var_name, module_name, is_required)
    # is_required=False means the module can degrade gracefully without it.
    _KEY_MAP: dict[str, tuple[str, str, bool]] = {
        "virustotal":  ("VIRUSTOTAL_API_KEY",      "Threat Intelligence Scanner", False),
        "alienvault":  ("ALIENVAULT_OTX_API_KEY",  "Threat Intelligence Scanner", False),
        "nvd":         ("NVD_API_KEY",             "Vulnerability Scanner",       False),
    }

    def __init__(self) -> None:
        self.APP_NAME = "Fenrir Security Scanner"
        self.APP_VERSION = _read_version()

        # Load API keys from environment
        self.VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
        self.ALIENVAULT_OTX_API_KEY: Optional[str] = os.getenv("ALIENVAULT_OTX_API_KEY")
        self.NVD_API_KEY: Optional[str] = os.getenv("NVD_API_KEY")

        log.debug(
            f"Config loaded. Version: {self.APP_VERSION} | "
            f"VT key: {'set' if self.VIRUSTOTAL_API_KEY else 'NOT SET'} | "
            f"OTX key: {'set' if self.ALIENVAULT_OTX_API_KEY else 'NOT SET'} | "
            f"NVD key: {'set' if self.NVD_API_KEY else 'NOT SET'}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_key(self, key_name: str) -> tuple[bool, str]:
        """
        Check whether a required API key is present and non-empty.

        Args:
            key_name: Short name of the key to check. Must be one of:
                      "virustotal", "alienvault", "nvd"

        Returns:
            (True, "")  — key is present and non-empty.
            (False, message) — key is missing; message describes the problem
                               and which module is affected.

        Usage in a module:
            ok, msg = config.validate_key("virustotal")
            if not ok:
                log.warning(msg)
                # Decide: return early, or continue with degraded output.

        Example warning message:
            "VIRUSTOTAL_API_KEY is not set. The Threat Intelligence Scanner
             will be skipped. Add it to your .env file to enable this feature."
        """
        if key_name not in self._KEY_MAP:
            return False, (
                f"Unknown key name '{key_name}'. "
                f"Valid options: {', '.join(self._KEY_MAP.keys())}"
            )

        env_var, module_name, _ = self._KEY_MAP[key_name]
        value = os.getenv(env_var)

        if not value or value.strip() == "":
            return False, (
                f"{env_var} is not set. The {module_name} will be skipped. "
                f"Add it to your .env file to enable this feature."
            )

        return True, ""

    def get_missing_keys_for_modules(self, modules: list[str]) -> list[str]:
        """
        Given a list of short key names, return only those that are missing.

        Useful for the GUI and CLI to build a single pre-scan warning message
        listing all missing keys at once rather than discovering them one by one.

        Args:
            modules: List of short key names, e.g. ["virustotal", "nvd"]

        Returns:
            List of warning message strings for each missing key.
            Empty list if all requested keys are present.

        Usage:
            warnings = config.get_missing_keys_for_modules(["virustotal", "nvd"])
            if warnings:
                for w in warnings:
                    log.warning(w)
        """
        missing = []
        for key_name in modules:
            ok, msg = self.validate_key(key_name)
            if not ok:
                missing.append(msg)
        return missing

    def summary(self) -> str:
        """
        Return a human-readable configuration summary string.

        Useful for debug output at scan start or in the GUI about screen.
        """
        lines = [
            f"Application : {self.APP_NAME} v{self.APP_VERSION}",
            f"VT API Key  : {'✓ configured' if self.VIRUSTOTAL_API_KEY else '✗ not set'}",
            f"OTX API Key : {'✓ configured' if self.ALIENVAULT_OTX_API_KEY else '✗ not set'}",
            f"NVD API Key : {'✓ configured (higher rate limit)' if self.NVD_API_KEY else '✗ not set (rate-limited)'}",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
# All modules import this singleton:
#   from ..config import config

config = Config()