#!/usr/bin/env python3
"""
Fenrir Portable Bundle Builder
================================
Creates a fully self-contained Fenrir folder deployable on any OS.

MODES
-----
bundle   Build a portable bundle (default)
update   Update an existing bundle's source and/or deps
install  Install bundled wheels on the current machine

WHAT IT BUILDS
--------------
fenrir-portable/
  fenrir/              Python source (your editable code)
  fenrir/database/     Offline intelligence DB (optional --include-db)
  assets/              Branding assets
  lib/                 Pre-downloaded Python wheels (offline pip install)
  lib/compiled/        Platform-specific compiled wheels
  bin/
    fenrir             Unix CLI launcher
    fenrir-gui         Unix GUI launcher
    fenrir.bat         Windows CLI launcher
    fenrir-gui.bat     Windows GUI launcher
    update.sh          Unix: pull source + reinstall deps
    update.bat         Windows: pull source + reinstall deps
  python/              Embedded Python (optional --embed-python, Windows only)
  .env.example
  branding.json        (if present)
  README.txt

USAGE
-----
  python3 bundle_fenrir.py bundle --output ~/fenrir-portable
  python3 bundle_fenrir.py bundle --output ~/fenrir-portable --include-db
  python3 bundle_fenrir.py bundle --output ~/fenrir-portable --bundle-deps
  python3 bundle_fenrir.py bundle --output ~/fenrir-portable --embed-python --zip

  # On the target machine to install deps from lib/:
  python3 bundle_fenrir.py install --bundle ~/fenrir-portable

  # Update an existing bundle (from inside the bundle):
  ./bin/update.sh
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import textwrap
import urllib.request
import zipfile
from pathlib import Path

# ── Console colours ────────────────────────────────────────────────────────────
if sys.platform == "win32":
    GREEN=YELLOW=RED=CYAN=BOLD=NC=""
else:
    GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"
    CYAN="\033[96m";  BOLD="\033[1m";    NC="\033[0m"

def ok(m):   print(f"{GREEN}[✓]{NC} {m}")
def warn(m): print(f"{YELLOW}[!]{NC} {m}")
def err(m):  print(f"{RED}[✗]{NC} {m}")
def info(m): print(f"{CYAN}[·]{NC} {m}")
def hdr(m):  print(f"\n{BOLD}{m}{NC}")

# ── Dependency lists ───────────────────────────────────────────────────────────

# Pure-Python: can be downloaded as --platform any and work on all OS
PURE_PYTHON_DEPS = [
    "requests", "urllib3", "certifi", "charset-normalizer", "idna",
    "httpx", "httpcore", "anyio", "sniffio", "h11",
    "python-dotenv", "colorama", "PyYAML", "future",
    "python-whois", "aiodns", "pycares",
    "paho-mqtt", "webtech",
    "beautifulsoup4", "soupsieve",
    "loguru",
]

# Compiled: need a wheel matching platform + Python version
# We download these for the CURRENT platform by default.
# For cross-platform bundles the user must run bundle on each target OS.
COMPILED_DEPS = [
    "Pillow",
    "cryptography",
    "paramiko",
    "bcrypt",
    "PyNaCl",
    "scapy",
    "androguard",
]

# Optional compiled deps — warn if missing, don't fail
OPTIONAL_COMPILED = [
    "bleak",      # BLE (Python < 3.13 only)
    "ssdeep",     # fuzzy hashing
    "yara-python", # YARA
]

# Embedded Python download URLs (Windows embeddable distributions)
EMBEDDED_PYTHON = {
    "3.12": "https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip",
    "3.11": "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip",
    "3.10": "https://www.python.org/ftp/python/3.10.14/python-3.10.14-embed-amd64.zip",
}

# Files/dirs to exclude when copying source
EXCLUDE_FROM_SOURCE = {
    "__pycache__", ".git", ".pytest_cache", ".ruff_cache", ".mypy_cache",
    "*.pyc", "*.pyo", "*.egg-info", ".venv", "venv", "env",
    "Results",          # scan output — not source
    "scan_history.db",  # runtime DB
    "fenrir.log",
}


def _should_exclude(path: Path) -> bool:
    name = path.name
    for pattern in EXCLUDE_FROM_SOURCE:
        if "*" in pattern:
            suffix = pattern.lstrip("*")
            if name.endswith(suffix):
                return True
        elif name == pattern:
            return True
    return False


# =============================================================================
# Step 1 — Copy source
# =============================================================================

def copy_source(src_root: Path, dest_root: Path) -> None:
    hdr("Step 1 — Copying Fenrir source")

    # fenrir/ package
    fenrir_src = src_root / "fenrir"
    fenrir_dst = dest_root / "fenrir"
    if fenrir_dst.exists():
        shutil.rmtree(fenrir_dst)

    def _ignore(directory: str, contents: list[str]) -> list[str]:
        return [c for c in contents
                if _should_exclude(Path(directory) / c)
                or (Path(directory) / c).is_dir()
                and c in ("data",)]  # data/ is runtime, not source

    shutil.copytree(fenrir_src, fenrir_dst, ignore=_ignore)
    ok(f"fenrir/ → {fenrir_dst}")

    # Ensure fenrir/modules/ directory exists (only __init__.py, no scanner files)
    modules_dir = fenrir_dst / "modules"
    modules_dir.mkdir(exist_ok=True)
    modules_init = fenrir_src / "modules" / "__init__.py"
    if modules_init.exists():
        shutil.copy2(modules_init, modules_dir / "__init__.py")
        ok("fenrir/modules/__init__.py included")
    else:
        warn("fenrir/modules/__init__.py missing from source — create it")

    # Root-level files
    for name in (
        "pyproject.toml", ".env.example", "README.md",
        "fenrir_brand.py",
        "pyproject.toml", ".env.example", "README.md",
        "fenrir_brand.py",
    ):
    ):
        src = src_root / name
        if src.exists():
            shutil.copy2(src, dest_root / name)

    # Copy assets
    assets_src = src_root / "assets"
    assets_dst = dest_root / "assets"
    if assets_src.exists():
        shutil.copytree(assets_src, assets_dst, dirs_exist_ok=True)
        ok("assets/ copied")
    else:
        assets_dst.mkdir(parents=True, exist_ok=True)

    # Copy branding.json if present
    brand = src_root / "branding.json"
    if brand.exists():
        shutil.copy2(brand, dest_root / "branding.json")
        ok("branding.json included")

    ok("Source copy complete")


# =============================================================================
# Step 2 — Copy offline database (optional)
# =============================================================================

def copy_database(src_root: Path, dest_root: Path) -> None:
    hdr("Step 2 — Copying offline intelligence database")

    db_src = src_root / "data" / "db" / "fenrir.db"
    db_dst = dest_root / "data" / "db"
    db_dst.mkdir(parents=True, exist_ok=True)

    if db_src.exists():
        size_mb = db_src.stat().st_size // 1024 // 1024
        info(f"Copying fenrir.db ({size_mb} MB)...")
        shutil.copy2(db_src, db_dst / "fenrir.db")
        ok(f"fenrir.db → bundle ({size_mb} MB)")
    else:
        warn("fenrir.db not found — run: ./bin/fenrir --db-build --tier core")
        warn("on the target machine after deployment to build the offline DB")

    # Also copy any wordlist data directories (they are separate from the DB)
    data_src = src_root / "data"
    if data_src.exists():
        info(f"Copying data/ directory tree...")
        shutil.copytree(data_src, dest_root / "data",
                        dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("*.git", "__pycache__"))
        ok("data/ copied")


# =============================================================================
# Step 3 — Bundle Python dependencies
# =============================================================================

def bundle_deps(dest_root: Path, include_compiled: bool = True) -> None:
    hdr("Step 3 — Bundling Python dependencies")

    lib_dir          = dest_root / "lib"
    compiled_lib_dir = dest_root / "lib" / "compiled"
    lib_dir.mkdir(parents=True, exist_ok=True)
    compiled_lib_dir.mkdir(exist_ok=True)

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"

    # ── Pure-Python wheels (platform=any, work everywhere) ────────────────────
    info(f"Downloading pure-Python wheels (Python {py_ver})...")
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--no-deps",
        "--only-binary=:all:",
        f"--python-version={py_ver}",
        "--platform=any",
        "-d", str(lib_dir),
        "--quiet",
    ] + PURE_PYTHON_DEPS

    result = subprocess.run(cmd, capture_output=True, text=True)
    pure_wheels = list(lib_dir.glob("*.whl"))
    ok(f"Pure-Python: {len(pure_wheels)} wheels downloaded")
    if result.returncode != 0 and result.stderr:
        warn(f"Some pure wheels failed:\n{result.stderr[-400:]}")

    # ── Compiled wheels (current platform) ────────────────────────────────────
    if include_compiled:
        plat = _pip_platform_tag()
        info(f"Downloading compiled wheels for {plat}...")
        cmd2 = [
            sys.executable, "-m", "pip", "download",
            "--no-deps",
            "--only-binary=:all:",
            f"--python-version={py_ver}",
            f"--platform={plat}",
            "-d", str(compiled_lib_dir),
            "--quiet",
        ] + COMPILED_DEPS

        result2 = subprocess.run(cmd2, capture_output=True, text=True)
        compiled_wheels = list(compiled_lib_dir.glob("*.whl"))
        ok(f"Compiled ({plat}): {len(compiled_wheels)} wheels downloaded")
        if result2.returncode != 0 and result2.stderr:
            warn(f"Some compiled wheels failed (may not have pre-built wheels):\n"
                 f"{result2.stderr[-400:]}")

        # Optional compiled deps — best-effort
        for pkg in OPTIONAL_COMPILED:
            cmd3 = [
                sys.executable, "-m", "pip", "download",
                "--no-deps", "--only-binary=:all:",
                f"--python-version={py_ver}",
                f"--platform={plat}",
                "-d", str(compiled_lib_dir),
                "--quiet", pkg,
            ]
            r = subprocess.run(cmd3, capture_output=True, text=True)
            if r.returncode == 0:
                ok(f"Optional: {pkg} downloaded")
            else:
                warn(f"Optional {pkg} not available as wheel — will need manual install")

    # Write a manifest of what's in lib/
    manifest = {
        "pure_python": [w.name for w in lib_dir.glob("*.whl")],
        "compiled":    [w.name for w in compiled_lib_dir.glob("*.whl")],
        "platform":    _pip_platform_tag(),
        "python":      py_ver,
    }
    (lib_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    ok("Dependency manifest written to lib/manifest.json")


def _pip_platform_tag() -> str:
    """Return the pip platform tag for the current OS."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        # Use manylinux for maximum compatibility
        arch = "x86_64" if "x86_64" in machine or "amd64" in machine else machine
        return f"manylinux_2_28_{arch}"
    elif system == "darwin":
        arch = "x86_64" if machine == "x86_64" else "arm64"
        return f"macosx_12_0_{arch}"
    elif system == "windows":
        return "win_amd64" if "64" in machine else "win32"
    return "any"


# =============================================================================
# Step 4 — Embed Python (Windows only, optional)
# =============================================================================

def embed_python(dest_root: Path, py_ver: str = "3.12") -> None:
    hdr("Step 4 — Embedding Python (Windows)")
    py_dir = dest_root / "python"
    py_dir.mkdir(exist_ok=True)

    url = EMBEDDED_PYTHON.get(py_ver, EMBEDDED_PYTHON["3.12"])
    zip_path = py_dir / "python-embed.zip"

    info(f"Downloading Windows embeddable Python {py_ver}...")
    info(f"  URL: {url}")
    try:
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(py_dir)
        zip_path.unlink()

        # Patch ._pth to enable site-packages (needed for lib/ to work)
        for pth in py_dir.glob("python*._pth"):
            content = pth.read_text()
            if "#import site" in content:
                pth.write_text(content.replace("#import site", "import site"))
                info(f"Patched {pth.name} to enable site-packages")

        # Add lib paths to ._pth so deps are found without PYTHONPATH
        for pth in py_dir.glob("python*._pth"):
            content = pth.read_text()
            additions = "\n..\\lib\n..\n"
            if additions not in content:
                pth.write_text(content + additions)

        ok(f"Python {py_ver} embedded → {py_dir}")
    except Exception as exc:
        warn(f"Embedded Python download failed: {exc}")
        warn("Target Windows machines will need Python 3.10+ installed.")


# =============================================================================
# Step 5 — Write launchers and update scripts
# =============================================================================

def write_launchers(dest_root: Path) -> None:
    hdr("Step 5 — Writing launchers and update scripts")
    bin_dir = dest_root / "bin"
    bin_dir.mkdir(exist_ok=True)

    # ── Common Unix header ─────────────────────────────────────────────────────
    UNIX_HEADER = textwrap.dedent("""\
        #!/usr/bin/env bash
        set -e
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        ROOT="$(dirname "$SCRIPT_DIR")"

        # Python discovery: embedded → system python3 → python
        PYTHON=""
        for try_py in \\
            "$ROOT/python/bin/python3" \\
            "$ROOT/python/bin/python" \\
            python3.13 python3.12 python3.11 python3.10 python3 python; do
            if [ -f "$try_py" ] || command -v "$try_py" &>/dev/null 2>&1; then
                PYTHON="$try_py"
                break
            fi
        done
        if [ -z "$PYTHON" ]; then
            echo "ERROR: Python 3.10+ not found."
            echo "Install Python or re-bundle with --embed-python."
            exit 1
        fi

        # Add bundled lib/ paths so deps work without pip install
        export PYTHONPATH="$ROOT/lib/compiled:$ROOT/lib:$ROOT:${PYTHONPATH:-}"
        export FENRIR_ROOT="$ROOT"
        cd "$ROOT"
    """)

    # ── CLI launcher ───────────────────────────────────────────────────────────
    (bin_dir / "fenrir").write_text(
        UNIX_HEADER + '\nexec "$PYTHON" -m fenrir.cli "$@"\n',
        encoding="utf-8")

    # ── GUI launcher ───────────────────────────────────────────────────────────
    (bin_dir / "fenrir-gui").write_text(
        UNIX_HEADER + '\nexec "$PYTHON" -m fenrir.fenrir_gui "$@"\n',
        encoding="utf-8")

    # ── Update script (Unix) ───────────────────────────────────────────────────
    (bin_dir / "update.sh").write_text(textwrap.dedent("""\
        #!/usr/bin/env bash
        # Fenrir update script — pulls latest source and reinstalls dependencies.
        # Run this from the bundle's bin/ directory: ./bin/update.sh
        set -e
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        ROOT="$(dirname "$SCRIPT_DIR")"

        PYTHON=""
        for try_py in "$ROOT/python/bin/python3" python3 python; do
            if [ -f "$try_py" ] || command -v "$try_py" &>/dev/null 2>&1; then
                PYTHON="$try_py"; break
            fi
        done

        echo "[fenrir] Updating Fenrir..."

        # Pull latest source if this is a git clone
        if [ -d "$ROOT/.git" ]; then
            echo "[fenrir] Pulling latest source from git..."
            git -C "$ROOT" pull origin main || echo "  (git pull failed — update source manually)"
        else
            echo "[fenrir] No .git directory found."
            echo "  To update source: copy new fenrir/ files into $ROOT/fenrir/"
        fi

        # Reinstall from bundled wheels (no internet needed)
        if [ -d "$ROOT/lib" ] && ls "$ROOT/lib"/*.whl &>/dev/null 2>&1; then
            echo "[fenrir] Installing bundled wheels (offline)..."
            "$PYTHON" -m pip install \\
                --no-index \\
                --find-links="$ROOT/lib/compiled" \\
                --find-links="$ROOT/lib" \\
                --quiet \\
                requests urllib3 certifi charset-normalizer idna \\
                httpx httpcore anyio sniffio h11 \\
                python-dotenv colorama PyYAML python-whois \\
                paho-mqtt webtech beautifulsoup4 \\
                Pillow cryptography paramiko scapy 2>/dev/null || true
            echo "[fenrir] Bundled wheels installed."
        fi

        # Install/update Fenrir itself (editable install from bundle source)
        echo "[fenrir] Installing Fenrir package..."
        "$PYTHON" -m pip install -e "$ROOT" --break-system-packages --quiet 2>/dev/null || \\
        "$PYTHON" -m pip install -e "$ROOT" --quiet || \\
        echo "  (editable install failed — using PYTHONPATH instead)"

        echo ""
        echo "[✓] Update complete. Launch: ./bin/fenrir-gui"
    """), encoding="utf-8")

    # Mark Unix scripts executable
    for f in (bin_dir / "fenrir", bin_dir / "fenrir-gui", bin_dir / "update.sh"):
        f.chmod(0o755)
    ok("Unix launchers and update.sh written")

    # ── Windows launchers ──────────────────────────────────────────────────────
    WIN_HEADER = textwrap.dedent("""\
        @echo off
        set "SCRIPT_DIR=%~dp0"
        set "ROOT=%SCRIPT_DIR%.."

        :: Python discovery: embedded → system python
        set "PYTHON="
        if exist "%ROOT%\\python\\python.exe" set "PYTHON=%ROOT%\\python\\python.exe"
        if "%PYTHON%"=="" (
            where python >nul 2>&1 && set "PYTHON=python"
        )
        if "%PYTHON%"=="" (
            where python3 >nul 2>&1 && set "PYTHON=python3"
        )
        if "%PYTHON%"=="" (
            echo ERROR: Python 3.10+ not found.
            echo Install Python from https://python.org or re-bundle with --embed-python
            pause
            exit /b 1
        )

        set "PYTHONPATH=%ROOT%\\lib\\compiled;%ROOT%\\lib;%ROOT%;%PYTHONPATH%"
        set "FENRIR_ROOT=%ROOT%"
        cd /d "%ROOT%"
    """)

    (bin_dir / "fenrir.bat").write_text(
        WIN_HEADER + '"%PYTHON%" -m fenrir.cli %*\n', encoding="utf-8")

    (bin_dir / "fenrir-gui.bat").write_text(
        WIN_HEADER + 'start "" "%PYTHON%w" -m fenrir.fenrir_gui %*\n',
        encoding="utf-8")

    # ── Windows update script ──────────────────────────────────────────────────
    (bin_dir / "update.bat").write_text(textwrap.dedent("""\
        @echo off
        set "SCRIPT_DIR=%~dp0"
        set "ROOT=%SCRIPT_DIR%.."

        set "PYTHON="
        if exist "%ROOT%\\python\\python.exe" set "PYTHON=%ROOT%\\python\\python.exe"
        if "%PYTHON%"=="" where python >nul 2>&1 && set "PYTHON=python"

        echo [fenrir] Updating Fenrir...

        :: Pull latest source (if git is available and this is a git clone)
        if exist "%ROOT%\\.git" (
            where git >nul 2>&1
            if %errorlevel%==0 (
                echo [fenrir] Pulling latest source from git...
                git -C "%ROOT%" pull origin main || echo   git pull failed - update source manually
            )
        )

        :: Install from bundled wheels
        if exist "%ROOT%\\lib" (
            echo [fenrir] Installing bundled wheels...
            "%PYTHON%" -m pip install ^
                --no-index ^
                --find-links="%ROOT%\\lib\\compiled" ^
                --find-links="%ROOT%\\lib" ^
                --quiet ^
                requests Pillow cryptography paramiko 2>nul
        )

        :: Install Fenrir package
        "%PYTHON%" -m pip install -e "%ROOT%" --quiet
        echo.
        echo [OK] Update complete. Launch: bin\\fenrir-gui.bat
        pause
    """), encoding="utf-8")

    ok("Windows launchers and update.bat written")


# =============================================================================
# Step 6 — Write README
# =============================================================================

def write_readme(dest_root: Path, has_db: bool, has_deps: bool,
                  has_python: bool) -> None:
    hdr("Step 6 — Writing README")

    db_note = (
        "Offline intelligence database INCLUDED — ready to use."
        if has_db else
        "Database NOT included. Build it on first run:\n"
        "    ./bin/fenrir --db-build --tier core       (~5 GB, ~30 min)\n"
        "    ./bin/fenrir --db-build --tier standard   (~9 GB, ~60 min)"
    )

    deps_note = (
        "Python dependencies INCLUDED in lib/ — no internet needed."
        if has_deps else
        "Dependencies NOT bundled. On the target machine run:\n"
        "    pip3 install fenrir-scanner   (requires internet)\n"
        "OR copy the fenrir-portable/lib/ folder from a machine that has it."
    )

    py_note = (
        "Python 3.12 EMBEDDED in python/ — no Python install needed."
        if has_python else
        "Python 3.10+ must be installed on the target machine.\n"
        "    Linux/macOS: sudo apt install python3   (or brew install python)\n"
        "    Windows:     https://python.org/downloads"
    )

    readme = textwrap.dedent(f"""\
    ╔══════════════════════════════════════════════════════════════════╗
    ║          FENRIR SECURITY SCANNER — PORTABLE BUNDLE               ║
    ╚══════════════════════════════════════════════════════════════════╝

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    QUICK START
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Linux / macOS:
      chmod +x bin/fenrir bin/fenrir-gui
      ./bin/fenrir-gui                       Launch GUI
      ./bin/fenrir 192.168.1.1               CLI scan

    Windows:
      bin\\fenrir-gui.bat                    Launch GUI
      bin\\fenrir.bat 192.168.1.1            CLI scan

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    PYTHON
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    {py_note}

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    DEPENDENCIES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    {deps_note}

    Install from bundled lib/ (offline, no internet):
      Linux/macOS:   ./bin/update.sh
      Windows:       bin\\update.bat

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    OFFLINE DATABASE
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    {db_note}

    Database contents:
      MITRE ATT&CK    Techniques, groups, software, mitigations,
                      relationships, campaigns (Enterprise + ICS + Mobile)
      NVD CVEs        250,000+ vulnerabilities with CVSS scores
      EPSS scores     Exploit probability for every CVE
      KEV catalogue   CISA Known Exploited Vulnerabilities
      Exploit-DB      57,000+ exploit scripts and shellcodes
      AlienVault OTX  Threat pulses and IOCs (hashes, IPs, domains)
      MalwareBazaar   Malware hash reputation
      ThreatFox       IOC database
      Sigma rules     SIEM detection rules mapped to ATT&CK
      GHDB            Google Hacking Database dorks
      Default creds   Router/device default credential lists
      SecLists        Wordlists and payloads

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    UPDATING FENRIR (developer workflow)
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    The bundle preserves git history in fenrir/ if bundled from a git
    clone. To pull updates and reinstall:

      Linux/macOS:   ./bin/update.sh
      Windows:       bin\\update.bat

    update.sh / update.bat will:
      1. git pull from the configured remote (if .git exists)
      2. Reinstall Python deps from lib/ (offline, no internet)
      3. Reinstall the Fenrir package in editable mode

    To update the offline database feeds:
      ./bin/fenrir --db-update --source otx
      ./bin/fenrir --db-update --source nvd
      ./bin/fenrir --db-update --source sigma
      ./bin/fenrir --db-build --tier core       (full rebuild)

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    DIRECTORY LAYOUT
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

      fenrir/              Python source code (editable)
      fenrir/modules/      Module registry (__init__.py only)
      fenrir/database/     Intelligence database (fenrir.db)
      data/                Wordlists, rule repos, raw feeds
      assets/              Logo, background image
      lib/                 Pure-Python dependency wheels
      lib/compiled/        Platform-specific compiled wheels
      python/              Embedded Python (Windows, if present)
      bin/                 Launch scripts
      Results/             Scan output folders (auto-created)
      branding.json        GUI appearance config (edit with fenrir_brand.py)
      .env                 API keys (copy from .env.example)
    """)

    (dest_root / "README.txt").write_text(readme, encoding="utf-8")
    ok("README.txt written")


# =============================================================================
# Step 7 — Create .zip archive (optional)
# =============================================================================

def create_zip(dest_root: Path) -> None:
    hdr("Step 7 — Creating ZIP archive")
    zip_path = dest_root.parent / f"{dest_root.name}.zip"
    info(f"Compressing → {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for f in sorted(dest_root.rglob("*")):
            if f.is_file():
                zf.write(f, f.relative_to(dest_root.parent))
    size_mb = zip_path.stat().st_size // 1024 // 1024
    ok(f"ZIP: {zip_path}  ({size_mb} MB)")


# =============================================================================
# Install mode — run on target machine from inside the bundle
# =============================================================================

def install_on_target(bundle_root: Path) -> None:
    """Install bundled wheels on the current machine."""
    hdr("Installing bundled dependencies")
    lib_dir = bundle_root / "lib"
    compiled_dir = lib_dir / "compiled"

    if not lib_dir.exists():
        err("lib/ directory not found — bundle was created without --bundle-deps")
        sys.exit(1)

    python = sys.executable

    find_links = []
    if compiled_dir.exists() and list(compiled_dir.glob("*.whl")):
        find_links += ["--find-links", str(compiled_dir)]
    if list(lib_dir.glob("*.whl")):
        find_links += ["--find-links", str(lib_dir)]

    if not find_links:
        warn("No wheels found in lib/ — nothing to install")
        return

    all_deps = PURE_PYTHON_DEPS + COMPILED_DEPS

    cmd = [python, "-m", "pip", "install",
           "--no-index"] + find_links + ["--quiet"] + all_deps

    info(f"Installing {len(all_deps)} packages from bundled wheels...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        ok("All bundled dependencies installed")
    else:
        warn(f"Some packages failed (may not have compiled wheels for this platform):")
        warn(result.stderr[-600:])

    # Install Fenrir itself (editable)└─$ ./Fenrir/fenrir/bundle_fenrir.py bundle -o ~/Desktop/BundleTest/

Fenrir Portable Bundle Builder
  Source : /home/kali/Desktop/Fenrir/fenrir
  Output : /home/kali/Desktop/BundleTest
  DB     : no
  Deps   : no
  Python : system


Step 1 — Copying Fenrir source
Traceback (most recent call last):
  File "/home/kali/Desktop/./Fenrir/fenrir/bundle_fenrir.py", line 917, in <module>
    main()
    ~~~~^^
  File "/home/kali/Desktop/./Fenrir/fenrir/bundle_fenrir.py", line 863, in main
    copy_source(src_root, dest_root)
    ~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/Desktop/./Fenrir/fenrir/bundle_fenrir.py", line 156, in copy_source
    shutil.copytree(fenrir_src, fenrir_dst, ignore=_ignore)
    ~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/shutil.py", line 591, in copytree
    with os.scandir(src) as itr:
         ~~~~~~~~~~^^^^^
FileNotFoundError: [Errno 2] No such file or directory: '/home/kali/Desktop/Fenrir/fenrir/fenrir'
                    
    pyproject = bundle_root / "pyproject.toml"
    if pyproject.exists():
        info("Installing Fenrir package...")
        r2 = subprocess.run(
            [python, "-m", "pip", "install", "-e", str(bundle_root),
             "--break-system-packages", "--quiet"],
            capture_output=True, text=True
        )
        if r2.returncode != 0:
            # Try without --break-system-packages
            r2 = subprocess.run(
                [python, "-m", "pip", "install", "-e", str(bundle_root), "--quiet"],
                capture_output=True, text=True
            )
        if r2.returncode == 0:
            ok("Fenrir package installed (editable)")
        else:
            warn("pip editable install failed — using PYTHONPATH mode")
            warn(f"Run: PYTHONPATH={bundle_root}:./lib ./bin/fenrir-gui")


# =============================================================================
# Update mode — update source and deps in an existing bundle
# =============================================================================

def update_bundle(bundle_root: Path, update_deps: bool = False) -> None:
    """Pull latest source into an existing bundle."""
    hdr("Updating existing bundle")

    # Git pull if this is a git repo
    git_dir = bundle_root / ".git"
    if git_dir.exists():
        info("Pulling latest source from git...")
        result = subprocess.run(
            ["git", "-C", str(bundle_root), "pull", "origin", "main"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            ok("git pull successful")
            print(result.stdout.strip())
        else:
            warn(f"git pull failed: {result.stderr.strip()}")
    else:
        warn("Bundle is not a git clone — copy new source files manually")

    if update_deps:
        bundle_deps(bundle_root, include_compiled=True)

    # Re-install
    install_on_target(bundle_root)
    ok("Bundle updated")


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bundle_fenrir",
        description="Build, install, or update a portable Fenrir bundle.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 bundle_fenrir.py bundle -o ~/fenrir-portable
              python3 bundle_fenrir.py bundle -o ~/fenrir-portable --include-db --bundle-deps
              python3 bundle_fenrir.py bundle -o ~/fenrir-portable --embed-python --zip
              python3 bundle_fenrir.py install --bundle ~/fenrir-portable
              python3 bundle_fenrir.py update  --bundle ~/fenrir-portable
        """)
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # ── bundle ─────────────────────────────────────────────────────────────────
    bp = sub.add_parser("bundle", help="Create a portable bundle")
    bp.add_argument("--output", "-o", metavar="DIR", required=True,
                    help="Destination directory")
    bp.add_argument("--source", "-s", metavar="DIR",
                    default=str(Path(__file__).parent),
                    help="Fenrir source root (default: directory of this script)")
    bp.add_argument("--include-db", action="store_true",
                    help="Copy offline intelligence database into bundle")
    bp.add_argument("--bundle-deps", action="store_true",
                    help="Download Python dependency wheels into lib/")
    bp.add_argument("--no-compiled", action="store_true",
                    help="Skip compiled wheels (pure-Python only)")
    bp.add_argument("--embed-python", action="store_true",
                    help="Download Windows embeddable Python into bundle")
    bp.add_argument("--python-ver", default="3.12",
                    choices=list(EMBEDDED_PYTHON.keys()),
                    help="Python version for --embed-python (default: 3.12)")
    bp.add_argument("--zip", action="store_true",
                    help="Create a .zip archive of the bundle")

    # ── install ────────────────────────────────────────────────────────────────
    ip = sub.add_parser("install", help="Install bundled deps on this machine")
    ip.add_argument("--bundle", metavar="DIR", required=True,
                    help="Path to the Fenrir bundle directory")

    # ── update ─────────────────────────────────────────────────────────────────
    up = sub.add_parser("update", help="Update an existing bundle")
    up.add_argument("--bundle", metavar="DIR", required=True,
                    help="Path to the Fenrir bundle directory")
    up.add_argument("--update-deps", action="store_true",
                    help="Also re-download dependency wheels")

    args = parser.parse_args()

    if args.mode == "install":
        install_on_target(Path(args.bundle).resolve())
        return

    if args.mode == "update":
        update_bundle(Path(args.bundle).resolve(),
                      update_deps=args.update_deps)
        return

    # ── bundle mode ────────────────────────────────────────────────────────────
    src_root  = Path(args.source).resolve()
    dest_root = Path(args.output).resolve()

    print(f"\n{BOLD}Fenrir Portable Bundle Builder{NC}")
    print(f"  Source : {src_root}")
    print(f"  Output : {dest_root}")
    print(f"  DB     : {'yes' if args.include_db else 'no'}")
    print(f"  Deps   : {'yes' if args.bundle_deps else 'no'}")
    print(f"  Python : {'embed ' + args.python_ver if args.embed_python else 'system'}")
    print()

    dest_root.mkdir(parents=True, exist_ok=True)

    # 1. Source
    copy_source(src_root, dest_root)

    # 2. Database
    if args.include_db:
        copy_database(src_root, dest_root)

    # 3. Dependencies
    if args.bundle_deps:
        bundle_deps(dest_root, include_compiled=not args.no_compiled)

    # 4. Embedded Python
    if args.embed_python:
        embed_python(dest_root, py_ver=args.python_ver)

    # 5. Launchers
    write_launchers(dest_root)

    # 6. README
    write_readme(dest_root,
                 has_db=args.include_db,
                 has_deps=args.bundle_deps,
                 has_python=args.embed_python)

    # 7. Placeholder dirs
    for d in ("Results", "data", "assets"):
        (dest_root / d).mkdir(exist_ok=True)
    (dest_root / "Results" / ".keep").write_text("", encoding="utf-8")

    # 8. Copy .env.example
    env_ex = src_root / ".env.example"
    if env_ex.exists():
        shutil.copy2(env_ex, dest_root / ".env.example")

    # 9. ZIP
    if args.zip:
        create_zip(dest_root)

    print(f"\n{BOLD}{GREEN}Bundle complete!{NC}")
    print(f"  Directory : {dest_root}")
    print(f"  GUI       : {dest_root}/bin/fenrir-gui")
    print(f"  Windows   : {dest_root}\\bin\\fenrir-gui.bat")
    print()

    if not args.bundle_deps:
        warn("Deps not bundled — on the target run:")
        warn("  pip3 install -e .   (internet)")
        warn("  OR: copy lib/ from a machine with deps installed")
    if not args.include_db:
        warn("Database not included — on the target run:")
        warn("  ./bin/fenrir --db-build --tier core")
    print()


if __name__ == "__main__":
    main()
