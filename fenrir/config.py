# fenrir/config.py
#
# Centralised configuration and API key management for Fenrir.
#
# Two sources of keys (merged at startup, keyfile takes priority over .env):
#   1. .env file       — traditional dotenv, gitignored, stays on one machine
#   2. fenrir_keys.json — portable JSON keyfile, can be moved between systems,
#                         saved via the GUI "API Keys" button, lives at project root
#
# Key file is separate from branding.json so keys are never accidentally
# committed with the UI config. The keyfile can be encrypted in future.
#
# API Key Registry (all services Fenrir can use):
#   NVD_API_KEY              vulnerability_scanner.py  (NVD CVE API)
#   VIRUSTOTAL_API_KEY       threat_intel_scanner.py   (VirusTotal IP/hash lookup)
#   ALIENVAULT_OTX_API_KEY   threat_intel_scanner.py   (AlienVault OTX pulses)
#   SHODAN_API_KEY           osint_scanner.py           (Shodan host search)
#   CENSYS_API_ID            osint_scanner.py           (Censys host search)
#   CENSYS_API_SECRET        osint_scanner.py           (Censys secret)
#   ABUSEIPDB_API_KEY        threat_intel_scanner.py   (AbuseIPDB IP checks)
#   GITHUB_TOKEN             db_builder.py              (GitHub API for rate limits)
#   HUNTER_API_KEY           osint_scanner.py           (Hunter.io email lookup)
#   SECURITYTRAILS_API_KEY   osint_scanner.py           (SecurityTrails DNS history)

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib          # type: ignore[no-redef]
    except ImportError:
        tomllib = None                   # type: ignore[assignment]

try:
    from dotenv import load_dotenv
    _DOTENV_OK = True
except ImportError:
    _DOTENV_OK = False

from fenrir.logging_config import get_logger

log = get_logger()

# ── Paths ──────────────────────────────────────────────────────────────────────
_FENRIR_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH    = _FENRIR_ROOT / ".env"
_KEYFILE     = _FENRIR_ROOT / "fenrir_keys.json"

# ── Full API key registry ──────────────────────────────────────────────────────
# Format: short_name -> (env_var, display_label, module, required, url, description)
API_KEY_REGISTRY: dict[str, tuple] = {
    # ── Vulnerability intelligence ─────────────────────────────────────────────
    "nvd": (
        "NVD_API_KEY", "NVD API Key", "Vulnerability Scanner", False,
        "https://nvd.nist.gov/developers/request-an-api-key",
        "Raises CVE rate limit 5→50 req/30s. Free, personal email ok.",
    ),
    "vulncheck": (
        "VULNCHECK_API_KEY", "VulnCheck Community Key",
        "Vulnerability Scanner / DB Builder", False,
        "https://vulncheck.com/register",
        "NVD++ (faster than NIST NVD), extended KEV, exploit intel. "
        "Free community tier. Full offline ZIP backup supported. No company email.",
    ),
    # ── Threat intelligence ────────────────────────────────────────────────────
    "virustotal": (
        "VIRUSTOTAL_API_KEY", "VirusTotal API Key",
        "Threat Intelligence / Artefact Scanner", False,
        "https://www.virustotal.com/gui/my-apikey",
        "IP, domain, file hash reputation. Free: 500 lookups/day.",
    ),
    "alienvault": (
        "ALIENVAULT_OTX_API_KEY", "AlienVault OTX API Key",
        "Threat Intelligence / OTX Feed", False,
        "https://otx.alienvault.com/api",
        "Full subscribed pulse feed + bulk offline download. "
        "Without key: public activity feed only.",
    ),
    "abuseipdb": (
        "ABUSEIPDB_API_KEY", "AbuseIPDB API Key", "Threat Intelligence", False,
        "https://www.abuseipdb.com/account/api",
        "IP abuse confidence score. Free: 1000 checks/day. Personal email ok.",
    ),
    # ── abuse.ch suite — ONE auth.abuse.ch account covers all three ───────────
    "malwarebazaar": (
        "MALWAREBAZAAR_API_KEY", "MalwareBazaar Auth-Key",
        "Artefact Scanner / DB Builder", False,
        "https://auth.abuse.ch/",
        "Full hash export + malware sample download. One abuse.ch account covers "
        "MalwareBazaar, ThreatFox, URLhaus and SSLBL. Free, personal email ok. "
        "Without key: recent 100 samples only.",
    ),
    "threatfox": (
        "THREATFOX_API_KEY", "ThreatFox Auth-Key",
        "Threat Intelligence / DB Builder", False,
        "https://auth.abuse.ch/",
        "Full IOC export (all types, all history). Same account as MalwareBazaar. "
        "Without key: recent IOCs only.",
    ),
    "urlhaus": (
        "URLHAUS_API_KEY", "URLhaus Auth-Key",
        "Threat Intelligence / DB Builder", False,
        "https://auth.abuse.ch/",
        "Complete malicious URL DB dump. Same account as MalwareBazaar. "
        "Without key: recent URLs only.",
    ),
    # ── OSINT / Recon ──────────────────────────────────────────────────────────
    "shodan": (
        "SHODAN_API_KEY", "Shodan API Key", "OSINT Scanner", False,
        "https://account.shodan.io/",
        "Host search, banners, exposed services. Free account: basic queries.",
    ),
    "censys_id": (
        "CENSYS_API_ID", "Censys API ID", "OSINT Scanner", False,
        "https://app.censys.io/account/api",
        "Internet-wide host scan data. Requires both ID and Secret. Free: 250/month.",
    ),
    "censys_secret": (
        "CENSYS_API_SECRET", "Censys API Secret", "OSINT Scanner", False,
        "https://app.censys.io/account/api",
        "Paired with Censys API ID. Free: 250 queries/month.",
    ),
    "greynoise": (
        "GREYNOISE_API_KEY", "GreyNoise Community Key", "Threat Intelligence", False,
        "https://www.greynoise.io/viz/signup",
        "Identifies internet background noise vs targeted attacks. "
        "Free community tier. API-only, no bulk offline download.",
    ),
    "hunter": (
        "HUNTER_API_KEY", "Hunter.io API Key", "OSINT Scanner", False,
        "https://hunter.io/api-keys",
        "Email discovery for domains. Free: 25 searches/month.",
    ),
    "securitytrails": (
        "SECURITYTRAILS_API_KEY", "SecurityTrails API Key", "OSINT Scanner", False,
        "https://securitytrails.com/app/account/credentials",
        "DNS history, subdomain discovery. Free: 50 queries/month.",
    ),
    # ── Infrastructure ─────────────────────────────────────────────────────────
    "github": (
        "GITHUB_TOKEN", "GitHub Personal Access Token", "Database Builder", False,
        "https://github.com/settings/tokens",
        "Raises GitHub API rate limit 60→5000 req/hr during DB builds. "
        "Free. Needed when cloning Sigma, YARA-Rules, SecLists, etc.",
    ),
}



def _read_version() -> str:
    pyproject = _FENRIR_ROOT / "pyproject.toml"
    if not pyproject.exists() or tomllib is None:
        return "unknown"
    try:
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        return data["tool"]["poetry"]["version"]
    except Exception:
        return "unknown"


class Config:
    """
    Loads and exposes all Fenrir API keys and configuration settings.

    Key priority (highest wins):
      1. fenrir_keys.json  (portable keyfile — GUI-managed)
      2. .env file         (dotenv — traditional)
      3. OS environment    (shell exports)

    Usage:
        from fenrir.config import config
        key = config.get("nvd")          # returns key string or None
        ok, msg = config.validate_key("nvd")
        config.save_keyfile({"nvd": "abc123", ...})
    """

    def __init__(self) -> None:
        self.APP_NAME    = "Fenrir Security Scanner"
        self.APP_VERSION = _read_version()
        self._keys: dict[str, str] = {}
        self.reload()

    def reload(self) -> None:
        """Re-read .env and fenrir_keys.json and merge into _keys."""
        # Layer 1: dotenv
        if _DOTENV_OK and _ENV_PATH.exists():
            load_dotenv(dotenv_path=_ENV_PATH, override=False)

        # Layer 2: OS environment (populated by dotenv above, or by shell)
        for short, (env_var, *_rest) in API_KEY_REGISTRY.items():
            val = os.environ.get(env_var, "").strip()
            if val:
                self._keys[short] = val

        # Layer 3: fenrir_keys.json (highest priority — overrides .env)
        stored = self._load_keyfile()
        for short, val in stored.items():
            if val and val.strip():
                self._keys[short] = val.strip()
                # Also push into os.environ so libraries that read env vars directly work
                env_var = API_KEY_REGISTRY.get(short, (short.upper(),))[0]
                os.environ[env_var] = val.strip()

        log.debug(
            f"Config reloaded. Version: {self.APP_VERSION} | "
            f"Keys set: {[k for k, v in self._keys.items() if v]}"
        )

        # Convenience attributes for backward compatibility
        for short, (env_var, *_rest) in API_KEY_REGISTRY.items():
            setattr(self, env_var, self._keys.get(short))

    # ── Keyfile management ─────────────────────────────────────────────────────

    @staticmethod
    def keyfile_path() -> Path:
        """Return the path to fenrir_keys.json."""
        return _KEYFILE

    def _load_keyfile(self) -> dict[str, str]:
        """Load fenrir_keys.json. Returns empty dict if missing or malformed."""
        if not _KEYFILE.exists():
            return {}
        try:
            data = json.loads(_KEYFILE.read_text(encoding="utf-8"))
            return {k: v for k, v in data.get("keys", {}).items() if isinstance(v, str)}
        except Exception as exc:
            log.warning(f"[config] Could not read keyfile {_KEYFILE}: {exc}")
            return {}

    def save_keyfile(self, keys: dict[str, str],
                     path: Optional[Path] = None) -> Path:
        """
        Write keys to fenrir_keys.json (or a custom path for export).

        Args:
            keys: dict of {short_name: api_key_string}
            path: override destination (default: _KEYFILE)

        Returns:
            Path that was written.
        """
        dest = path or _KEYFILE
        dest.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "_comment": (
                "Fenrir API key file. Keep this private — do not commit to git. "
                "Copy this file between machines to transfer keys."
            ),
            "_version":  self.APP_VERSION,
            "keys": {k: v for k, v in keys.items() if v and v.strip()},
        }
        dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info(f"[config] Keys saved to {dest}")

        # Merge saved keys into runtime state
        if path is None:
            self.reload()

        return dest

    def export_keyfile(self, export_path: Path) -> Path:
        """Export the current keys to an arbitrary path for transfer."""
        current = {short: self._keys.get(short, "")
                   for short in API_KEY_REGISTRY}
        return self.save_keyfile(current, path=export_path)

    def import_keyfile(self, import_path: Path) -> int:
        """
        Import keys from an external keyfile. Returns count of keys imported.
        Merges with existing keys (imported values win on conflict).
        """
        try:
            data = json.loads(import_path.read_text(encoding="utf-8"))
            imported = data.get("keys", {})
            if not isinstance(imported, dict):
                raise ValueError("'keys' field missing or not a dict")
        except Exception as exc:
            raise ValueError(f"Could not read keyfile: {exc}") from exc

        current = self._load_keyfile()
        current.update({k: v for k, v in imported.items() if v and v.strip()})
        self.save_keyfile(current)
        log.info(f"[config] Imported {len(imported)} keys from {import_path}")
        return len(imported)

    # ── Key access ─────────────────────────────────────────────────────────────

    def get(self, short_name: str) -> Optional[str]:
        """Return the API key value for a short name, or None if not set."""
        return self._keys.get(short_name) or None

    def set(self, short_name: str, value: str) -> None:
        """Set a key in memory (call save_keyfile to persist)."""
        self._keys[short_name] = value.strip()
        env_var = API_KEY_REGISTRY.get(short_name, (short_name.upper(),))[0]
        os.environ[env_var] = value.strip()

    def all_keys(self) -> dict[str, str]:
        """Return all short_name → value pairs (empty string if not set)."""
        return {short: self._keys.get(short, "")
                for short in API_KEY_REGISTRY}

    def validate_key(self, key_name: str) -> tuple[bool, str]:
        """
        Check whether a key is present and non-empty.

        Returns:
            (True, "")          — key is set
            (False, message)    — key missing, message explains effect
        """
        if key_name not in API_KEY_REGISTRY:
            return False, (
                f"Unknown key '{key_name}'. "
                f"Valid: {', '.join(API_KEY_REGISTRY.keys())}"
            )
        env_var, label, module, _, _, desc = API_KEY_REGISTRY[key_name]
        val = self._keys.get(key_name)
        if not val:
            return False, (
                f"{label} not set — {module} will run in offline/degraded mode. "
                f"Get a free key at {API_KEY_REGISTRY[key_name][4]}"
            )
        return True, ""

    def get_missing_keys_for_modules(self, modules: list[str]) -> list[str]:
        """Return warning strings for each missing key in the list."""
        return [msg for k in modules for ok, msg in [self.validate_key(k)] if not ok]

    def summary(self) -> str:
        lines = [f"Fenrir {self.APP_VERSION}  |  Key file: {_KEYFILE}"]
        for short, (env_var, label, module, *_) in API_KEY_REGISTRY.items():
            status = "✓" if self._keys.get(short) else "✗"
            lines.append(f"  {status}  {label:<35} ({module})")
        return "\n".join(lines)


# Module-level singleton
config = Config()
