#!/usr/bin/env python3
"""
Fenrir Portable Bundle Builder
===============================
Creates a fully self-contained Fenrir folder that runs on any Unix or Windows
machine with no internet connection and no pip install required.

What it builds
--------------
fenrir-portable/
  fenrir/                    ← all Python source files
  database/                  ← offline intelligence DB (if --include-db)
  assets/                    ← branding assets
  lib/                       ← all Python dependencies (pure-Python wheels)
  bin/
    fenrir         (Unix)    ← shell launcher
    fenrir-gui     (Unix)    ← GUI launcher
    fenrir.bat     (Windows) ← CLI launcher
    fenrir-gui.bat (Windows) ← GUI launcher
  python/                    ← embedded Python (if --embed-python)
  README.txt
  LAUNCH.txt

Usage
-----
  python3 bundle_fenrir.py --output ~/fenrir-portable
  python3 bundle_fenrir.py --output ~/fenrir-portable --include-db
  python3 bundle_fenrir.py --output /tmp/fenrir --embed-python
  python3 bundle_fenrir.py --output /tmp/fenrir --zip
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

# ── Colour output ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"; YELLOW = "\033[93m"; RED    = "\033[91m"
CYAN   = "\033[96m"; BOLD   = "\033[1m";  NC     = "\033[0m"
def ok(m):   print(f"{GREEN}[✓]{NC} {m}")
def warn(m): print(f"{YELLOW}[!]{NC} {m}")
def err(m):  print(f"{RED}[✗]{NC} {m}")
def info(m): print(f"{CYAN}[·]{NC} {m}")

# ── Pure-Python packages that can be bundled without compilation ───────────────
PURE_PYTHON_DEPS = [
    "requests", "urllib3", "certifi", "charset_normalizer", "idna",
    "httpx", "httpcore", "anyio", "sniffio", "h11",
    "python_dotenv", "colorama", "PyYAML", "python_whois",
    "aiodns", "pycares",
    "paho_mqtt",
    "webtech",
    "beautifulsoup4", "soupsieve",
    "loguru",
]

# Packages that need compiled extensions — note them but don't bundle
COMPILED_DEPS = [
    "cryptography", "paramiko", "scapy",
    "PIL", "Pillow",
    "bleak",         # BLE — platform-specific
    "androguard",    # APK analysis
    "yara",          # YARA
    "ssdeep",        # fuzzy hashing
]


def copy_source(src_root: Path, dest_root: Path) -> None:
    """Copy all Fenrir Python source files."""
    info("Copying Fenrir source files...")
    fenrir_src = src_root / "fenrir"
    fenrir_dst = dest_root / "fenrir"
    if fenrir_dst.exists():
        shutil.rmtree(fenrir_dst)

    def ignore_fn(d, files):
        return [f for f in files
                if f.endswith(".pyc") or f == "__pycache__"
                or (Path(d)/f).is_dir() and f in ("data", "Results")]
    shutil.copytree(fenrir_src, fenrir_dst, ignore=ignore_fn)

    # Copy root-level extras
    for name in ("pyproject.toml", ".env.example", "README.md",
                 "fenrir_brand.py", "update_fenrir.sh"):
        src = src_root / name
        if src.exists():
            shutil.copy2(src, dest_root / name)

    ok(f"Source copied → {fenrir_dst}")


def copy_assets(src_root: Path, dest_root: Path) -> None:
    """Copy branding assets."""
    assets_src = src_root / "assets"
    assets_dst = dest_root / "assets"
    if assets_src.exists():
        shutil.copytree(assets_src, assets_dst, dirs_exist_ok=True)
        ok("Assets copied")
    else:
        assets_dst.mkdir(parents=True, exist_ok=True)
        warn("No assets/ folder found — branding will use defaults")


def copy_database(src_root: Path, dest_root: Path) -> None:
    """Copy the offline intelligence database."""
    db_files = [
        src_root / "fenrir" / "database" / "fenrir.db",
        src_root / "scan_history.db",
        src_root / "branding.json",
    ]
    db_dst = dest_root / "fenrir" / "database"
    db_dst.mkdir(parents=True, exist_ok=True)

    for f in db_files:
        if f.exists():
            dst = dest_root / f.relative_to(src_root)
            dst.parent.mkdir(parents=True, exist_ok=True)
            info(f"Copying database: {f.name} ({f.stat().st_size // 1024 // 1024} MB)...")
            shutil.copy2(f, dst)
            ok(f"  {f.name} → {dst}")
        else:
            warn(f"  {f.name} not found — run --db-build first to generate it")


def bundle_pure_deps(dest_root: Path) -> None:
    """Download pure-Python wheels into lib/ for offline use."""
    lib_dir = dest_root / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)
    info("Downloading pure-Python dependency wheels to lib/...")

    cmd = [
        sys.executable, "-m", "pip", "download",
        "--no-deps",
        "--only-binary=:all:",
        "--python-version=3.10",
        "--platform=any",
        "-d", str(lib_dir),
    ] + PURE_PYTHON_DEPS

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        warn(f"Some wheels could not be downloaded:\n{result.stderr[-600:]}")
    else:
        wheels = list(lib_dir.glob("*.whl"))
        ok(f"Downloaded {len(wheels)} pure-Python wheels to lib/")


def write_launchers(dest_root: Path) -> None:
    """Write Unix shell launchers and Windows .bat files."""
    bin_dir = dest_root / "bin"
    bin_dir.mkdir(exist_ok=True)

    # ── Detect embedded Python path ────────────────────────────────────────────
    # Launchers try: embedded Python → system Python3 → python3
    PYTHON_DETECT = textwrap.dedent("""\
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        ROOT="$(dirname "$SCRIPT_DIR")"

        # Prefer embedded Python
        PYTHON=""
        for try_py in \\
            "$ROOT/python/bin/python3" \\
            "$ROOT/python/bin/python" \\
            python3 python; do
            if command -v "$try_py" &>/dev/null 2>&1 || [ -f "$try_py" ]; then
                PYTHON="$try_py"
                break
            fi
        done

        if [ -z "$PYTHON" ]; then
            echo "ERROR: Python not found. Install Python 3.10+ or use --embed-python."
            exit 1
        fi

        # Add bundled lib/ to PYTHONPATH so pure-Python deps work offline
        export PYTHONPATH="$ROOT/lib:$ROOT:${PYTHONPATH:-}"
        export FENRIR_ROOT="$ROOT"
    """)

    # CLI launcher (Unix)
    (bin_dir / "fenrir").write_text(
        "#!/usr/bin/env bash\n" + PYTHON_DETECT +
        'exec "$PYTHON" -m fenrir.cli "$@"\n')

    # GUI launcher (Unix)
    (bin_dir / "fenrir-gui").write_text(
        "#!/usr/bin/env bash\n" + PYTHON_DETECT +
        'exec "$PYTHON" -m fenrir.fenrir_gui "$@"\n')

    # Make executable
    for f in (bin_dir / "fenrir", bin_dir / "fenrir-gui"):
        f.chmod(0o755)

    # ── Windows launchers ──────────────────────────────────────────────────────
    WIN_DETECT = textwrap.dedent("""\
        @echo off
        set SCRIPT_DIR=%~dp0
        set ROOT=%SCRIPT_DIR%..

        :: Prefer embedded Python
        set PYTHON=
        if exist "%ROOT%\\python\\python.exe" set PYTHON=%ROOT%\\python\\python.exe
        if "%PYTHON%"=="" where python >nul 2>&1 && set PYTHON=python
        if "%PYTHON%"=="" where python3 >nul 2>&1 && set PYTHON=python3
        if "%PYTHON%"=="" (
            echo ERROR: Python not found. Install Python 3.10+ or use --embed-python.
            pause
            exit /b 1
        )

        set PYTHONPATH=%ROOT%\\lib;%ROOT%;%PYTHONPATH%
        set FENRIR_ROOT=%ROOT%
    """)

    (bin_dir / "fenrir.bat").write_text(
        WIN_DETECT + '"%PYTHON%" -m fenrir.cli %*\n')

    (bin_dir / "fenrir-gui.bat").write_text(
        WIN_DETECT + 'start "" "%PYTHON%w" -m fenrir.fenrir_gui %*\n')

    ok("Launchers written (Unix + Windows)")


def write_readme(dest_root: Path) -> None:
    readme = textwrap.dedent(f"""\
        ╔══════════════════════════════════════════════════════════════╗
        ║           FENRIR SECURITY SCANNER — PORTABLE BUNDLE          ║
        ╚══════════════════════════════════════════════════════════════╝

        This is a portable, self-contained Fenrir bundle.
        No installation or internet connection required to run.

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        REQUIREMENTS
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        • Python 3.10+ installed on the target machine
          (OR use --embed-python when bundling to include Python)

        Optional for full functionality:
          pip install Pillow paramiko scapy cryptography
          (these cannot be bundled as pre-built wheels for all platforms)

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        LAUNCHING
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        Linux / macOS:
          chmod +x bin/fenrir bin/fenrir-gui
          ./bin/fenrir-gui                     # launch GUI
          ./bin/fenrir 192.168.1.1             # CLI scan

        Windows:
          bin\\fenrir-gui.bat                   # launch GUI
          bin\\fenrir.bat 192.168.1.1           # CLI scan

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        OFFLINE DATABASE
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        The database contains:
          • MITRE ATT&CK techniques, groups, software, mitigations
          • NVD CVEs + EPSS scores + KEV catalogue
          • Exploit-DB exploits and shellcodes
          • AlienVault OTX pulses and indicators
          • MalwareBazaar + ThreatFox hash feeds
          • Sigma detection rules
          • GHDB dorks

        To rebuild the database (requires internet, run once):
          ./bin/fenrir --db-build --tier core
          ./bin/fenrir --db-build --tier standard    # more data, slower

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        DIRECTORY STRUCTURE
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

          fenrir/          Python source code
          fenrir/database/ Offline intelligence database
          assets/          Logo and background images
          lib/             Bundled pure-Python dependencies
          bin/             Launch scripts
          Results/         Scan output (auto-created)
    """)
    (dest_root / "README.txt").write_text(readme)
    ok("README.txt written")


def embed_python_windows(dest_root: Path) -> None:
    """
    Download the Windows embeddable Python distribution.
    Only runs if --embed-python is specified and we are NOT on Windows
    (i.e. cross-bundling for Windows from Linux/macOS).
    """
    py_dir = dest_root / "python"
    py_dir.mkdir(exist_ok=True)

    url = "https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip"
    info(f"Downloading Windows embeddable Python from:\n  {url}")
    info("(This is ~15 MB — needed only for Windows targets with no Python installed)")

    try:
        import urllib.request
        zip_path = py_dir / "python-embed.zip"
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(py_dir)
        zip_path.unlink()
        ok(f"Embedded Python extracted → {py_dir}")

        # Enable site-packages in the embedded Python
        pth_files = list(py_dir.glob("python*._pth"))
        for f in pth_files:
            content = f.read_text()
            if "#import site" in content:
                f.write_text(content.replace("#import site", "import site"))
                info(f"Patched {f.name} to enable site-packages")
    except Exception as exc:
        warn(f"Could not download embedded Python: {exc}")
        warn("Users will need Python 3.10+ installed on Windows.")


def create_zip(dest_root: Path) -> None:
    """Create a .zip of the entire bundle for easy distribution."""
    zip_path = dest_root.parent / f"{dest_root.name}.zip"
    info(f"Creating {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED,
                          compresslevel=6) as zf:
        for f in dest_root.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(dest_root.parent))
    size_mb = zip_path.stat().st_size // 1024 // 1024
    ok(f"Bundle ZIP: {zip_path}  ({size_mb} MB)")


def install_on_target(bundle_root: Path) -> None:
    """
    Install bundled wheels on the target machine (run this on the target,
    not during bundle creation).
    """
    lib_dir = bundle_root / "lib"
    if not lib_dir.exists() or not list(lib_dir.glob("*.whl")):
        warn("No bundled wheels found in lib/ — skipping dependency install")
        return

    python = sys.executable
    info("Installing bundled dependencies into user site-packages...")
    cmd = [
        python, "-m", "pip", "install",
        "--no-index",
        f"--find-links={lib_dir}",
        "--user", "--quiet",
    ] + PURE_PYTHON_DEPS

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        ok("Bundled dependencies installed.")
    else:
        warn(f"Some deps failed: {result.stderr[-400:]}")
        warn("Run: PYTHONPATH=./lib python3 -m fenrir.fenrir_gui")


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bundle_fenrir",
        description="Build a portable Fenrir bundle for offline deployment.")
    parser.add_argument("--output", "-o", metavar="DIR", required=True,
                        help="Destination directory for the bundle")
    parser.add_argument("--source", "-s", metavar="DIR",
                        default=str(Path(__file__).parent),
                        help="Fenrir source root (default: directory of this script)")
    parser.add_argument("--include-db", action="store_true",
                        help="Include the offline intelligence database (~1-26 GB)")
    parser.add_argument("--bundle-deps", action="store_true",
                        help="Download pure-Python dependency wheels into lib/")
    parser.add_argument("--embed-python", action="store_true",
                        help="Download and embed Windows Python for zero-dependency Windows deploy")
    parser.add_argument("--zip", action="store_true",
                        help="Also create a .zip archive of the bundle")
    parser.add_argument("--install", action="store_true",
                        help="Install bundled wheels on THIS machine (run on target)")
    args = parser.parse_args()

    src_root  = Path(args.source).resolve()
    dest_root = Path(args.output).resolve()

    if args.install:
        install_on_target(dest_root)
        return

    print(f"\n{BOLD}Fenrir Portable Bundle Builder{NC}")
    print(f"  Source: {src_root}")
    print(f"  Output: {dest_root}\n")

    dest_root.mkdir(parents=True, exist_ok=True)

    copy_source(src_root, dest_root)
    copy_assets(src_root, dest_root)

    if args.include_db:
        copy_database(src_root, dest_root)
    else:
        warn("Database not included (--include-db). "
             "Run './bin/fenrir --db-build' on the target machine.")

    if args.bundle_deps:
        bundle_pure_deps(dest_root)
    else:
        info("Skipping dep bundle (--bundle-deps). "
             "Target machine needs: pip install fenrir-scanner")

    if args.embed_python:
        embed_python_windows(dest_root)

    write_launchers(dest_root)
    write_readme(dest_root)

    # Create Results dir placeholder
    (dest_root / "Results" / ".keep").parent.mkdir(parents=True, exist_ok=True)
    (dest_root / "Results" / ".keep").write_text("")

    if args.zip:
        create_zip(dest_root)

    print(f"\n{BOLD}{GREEN}Bundle complete!{NC}")
    print(f"  Directory: {dest_root}")
    print(f"  Launch:    {dest_root}/bin/fenrir-gui  (Unix)")
    print(f"             {dest_root}\\bin\\fenrir-gui.bat  (Windows)\n")


if __name__ == "__main__":
    main()
