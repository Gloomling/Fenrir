# fenrir/modules/__init__.py
#
# Package initialiser for the Fenrir modules package.
#
# Design:
#   - Provides explicit, named imports for every scanner class so the rest of
#     the application can do clean single-line imports:
#
#       from fenrir.modules import PortScanner, VulnerabilityScanner
#
#   - Avoids wildcard exports (no `from .module import *`) so that:
#       1. IDEs and linters can resolve names correctly.
#       2. Accidental name collisions between modules are caught at import time.
#       3. The public surface of the package is unambiguous.
#
#   - Each import is wrapped in its own try/except so that a single module
#     with a missing optional dependency (e.g. bleak not installed) does not
#     prevent the rest of the application from loading. The failed module is
#     replaced with None and a clear warning is logged. The CLI and GUI check
#     for None before attempting to use a module.
#
# Adding a new module:
#   1. Create fenrir/modules/my_scanner.py with class MyScanner.
#   2. Add the import block below following the same try/except pattern.
#   3. Add "MyScanner" to __all__.

from ..logging_config import get_logger

log = get_logger()

# ---------------------------------------------------------------------------
# Module imports — each wrapped individually for graceful dependency failures
# ---------------------------------------------------------------------------

# --- Reconnaissance ---

try:
    from .subdomain_scanner import SubdomainScanner
except ImportError as e:
    log.warning(f"SubdomainScanner could not be loaded: {e}")
    SubdomainScanner = None  # type: ignore[assignment,misc]

try:
    from .dns_scanner import DnsScanner
except ImportError as e:
    log.warning(f"DnsScanner could not be loaded: {e}")
    DnsScanner = None  # type: ignore[assignment,misc]

try:
    from .whois_scanner import WhoisScanner
except ImportError as e:
    log.warning(f"WhoisScanner could not be loaded: {e}")
    WhoisScanner = None  # type: ignore[assignment,misc]

try:
    from .osint_scanner import OsintScanner
except ImportError as e:
    log.warning(f"OsintScanner could not be loaded: {e}")
    OsintScanner = None  # type: ignore[assignment,misc]

try:
    from .threat_intel_scanner import ThreatIntelScanner
except ImportError as e:
    log.warning(f"ThreatIntelScanner could not be loaded: {e}")
    ThreatIntelScanner = None  # type: ignore[assignment,misc]

# --- Port Scanning & Vulnerability Analysis ---

try:
    from .port_scanner import PortScanner, parse_ports, DEFAULT_PORTS, WEB_PORTS, SSH_PORT
except ImportError as e:
    log.warning(f"PortScanner could not be loaded: {e}")
    PortScanner = None      # type: ignore[assignment,misc]
    parse_ports = None      # type: ignore[assignment]
    DEFAULT_PORTS = []      # type: ignore[assignment]
    WEB_PORTS = []          # type: ignore[assignment]
    SSH_PORT = 22           # type: ignore[assignment]

try:
    from .vulnerability_scanner import VulnerabilityScanner
except ImportError as e:
    log.warning(f"VulnerabilityScanner could not be loaded: {e}")
    VulnerabilityScanner = None  # type: ignore[assignment,misc]

try:
    from .exploit_scanner import ExploitScanner
except ImportError as e:
    log.warning(f"ExploitScanner could not be loaded: {e}")
    ExploitScanner = None  # type: ignore[assignment,misc]

# --- Web Application ---

try:
    from .web_scanner import WebScanner
except ImportError as e:
    log.warning(f"WebScanner could not be loaded: {e}")
    WebScanner = None  # type: ignore[assignment,misc]

try:
    from .dir_brute_forcer import DirBruteForcer
except ImportError as e:
    log.warning(f"DirBruteForcer could not be loaded: {e}")
    DirBruteForcer = None  # type: ignore[assignment,misc]

try:
    from .tech_detector import TechDetector
except ImportError as e:
    log.warning(f"TechDetector could not be loaded: {e}")
    TechDetector = None  # type: ignore[assignment,misc]

# --- Offensive ---

try:
    from .password_sprayer import PasswordSprayer
except ImportError as e:
    log.warning(f"PasswordSprayer could not be loaded: {e}")
    PasswordSprayer = None  # type: ignore[assignment,misc]

# --- Specialised ---

try:
    from .iot_scanner import IotScanner
except ImportError as e:
    log.warning(f"IotScanner could not be loaded: {e}")
    IotScanner = None  # type: ignore[assignment,misc]

try:
    from .ot_scanner import OtScanner
except ImportError as e:
    log.warning(f"OtScanner could not be loaded: {e}")
    OtScanner = None  # type: ignore[assignment,misc]

try:
    from .mobile_scanner import MobileScanner
except ImportError as e:
    log.warning(f"MobileScanner could not be loaded: {e}")
    MobileScanner = None  # type: ignore[assignment,misc]

try:
    from .android_scanner import AndroidScanner
except ImportError as e:
    log.warning(f"AndroidScanner could not be loaded: {e}")
    AndroidScanner = None  # type: ignore[assignment,misc]

try:
    from .rf_scanner import RfScanner
except ImportError as e:
    log.warning(f"RfScanner could not be loaded: {e}")
    RfScanner = None  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Public surface — explicit declaration of what this package exports
# ---------------------------------------------------------------------------

__all__ = [
    # Reconnaissance
    "SubdomainScanner",
    "DnsScanner",
    "WhoisScanner",
    "OsintScanner",
    "ThreatIntelScanner",
    # Port Scanning & Vulnerability Analysis
    "PortScanner",
    "parse_ports",
    "DEFAULT_PORTS",
    "WEB_PORTS",
    "SSH_PORT",
    "VulnerabilityScanner",
    "ExploitScanner",
    # Web Application
    "WebScanner",
    "DirBruteForcer",
    "TechDetector",
    # Offensive
    "PasswordSprayer",
    # Specialised
    "IotScanner",
    "OtScanner",
    "MobileScanner",
    "AndroidScanner",
    "RfScanner",
]

# ---------------------------------------------------------------------------
# Availability map
# ---------------------------------------------------------------------------
# A dict that the CLI and GUI can query to check whether a module loaded
# successfully before trying to instantiate it. Maps display name -> class.
# If a module failed to load, its value is None.

MODULE_REGISTRY: dict[str, object] = {
    "SubdomainScanner":    SubdomainScanner,
    "DnsScanner":          DnsScanner,
    "WhoisScanner":        WhoisScanner,
    "OsintScanner":        OsintScanner,
    "ThreatIntelScanner":  ThreatIntelScanner,
    "PortScanner":         PortScanner,
    "VulnerabilityScanner": VulnerabilityScanner,
    "ExploitScanner":      ExploitScanner,
    "WebScanner":          WebScanner,
    "DirBruteForcer":      DirBruteForcer,
    "TechDetector":        TechDetector,
    "PasswordSprayer":     PasswordSprayer,
    "IotScanner":          IotScanner,
    "OtScanner":           OtScanner,
    "MobileScanner":       MobileScanner,
    "AndroidScanner":      AndroidScanner,
    "RfScanner":           RfScanner,
}


def check_module_availability() -> None:
    """
    Log a summary of which modules loaded successfully and which failed.

    Call this once at application startup (CLI or GUI) to surface any
    dependency problems immediately rather than discovering them mid-scan.

    Example output:
        INFO  - Module availability:
        INFO  -   ✓ PortScanner
        INFO  -   ✓ VulnerabilityScanner
        WARNING -  ✗ IotScanner (bleak not installed)
    """
    log.info("Module availability check:")
    all_ok = True
    for name, cls in MODULE_REGISTRY.items():
        if cls is not None:
            log.debug(f"  ✓ {name}")
        else:
            log.warning(f"  ✗ {name} — failed to load (check dependencies)")
            all_ok = False

    if all_ok:
        log.info("  All modules loaded successfully.")
    else:
        log.warning(
            "  One or more modules failed to load. "
            "Run 'poetry install' to ensure all dependencies are present."
        )