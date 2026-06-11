#!/usr/bin/env bash
# =============================================================================
# Fenrir Security Scanner — Installer & Launcher
# =============================================================================
# Usage:
#   chmod +x install_fenrir.sh && ./install_fenrir.sh
#
# Subcommands:
#   install     (default) full install: venv, pip, launchers, .desktop entry
#   launch      launch GUI directly
#   desktop     (re)create desktop entry and app menu shortcut only
#   fix-desktop troubleshoot/repair .desktop visibility issues
#   uninstall   remove launchers and .desktop entries
#
# Why .desktop files don't show up (and how this script fixes each cause):
#   1. Exec= must be an ABSOLUTE path to a real executable (not a bare name)
#   2. Icon= must be an absolute path OR a name present in the GTK icon cache
#   3. File must have Unix line endings — CRLF silently breaks recognition
#   4. update-desktop-database must be run after any changes
#   5. xdg-desktop-menu install is more reliable than copying the file manually
#   6. File must be chmod +x (GNOME/Nautilus requires this to trust it)
#   7. gio set metadata::trusted true  removes the "Untrusted" warning
#   8. StartupWMClass must match the actual WM_CLASS X11 window property
# =============================================================================

set -e

FENRIR_HOME="${HOME}/.fenrir"
VENV="${FENRIR_HOME}/venv"
BIN_DIR="${HOME}/.local/bin"
APP_DIR="${HOME}/.local/share/applications"
ICON_DIR="${HOME}/.local/share/icons/hicolor/256x256/apps"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="fenrir"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[fenrir]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✗]${NC} $*"; }

find_python() {
    for py in python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$py" &>/dev/null; then
            if "$py" -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null; then
                echo "$py"; return 0
            fi
        fi
    done
    return 1
}

install_icon() {
    for candidate in \
        "${SCRIPT_DIR}/assets/logo.png" \
        "${SCRIPT_DIR}/assets/icon.png" \
        "${SCRIPT_DIR}/fenrir/assets/logo.png" \
        "${FENRIR_HOME}/assets/logo.png"; do
        if [[ -f "$candidate" ]]; then
            mkdir -p "${ICON_DIR}"
            cp "$candidate" "${ICON_DIR}/${APP_NAME}.png"
            for size in 16 32 48 64 128; do
                local sdir="${HOME}/.local/share/icons/hicolor/${size}x${size}/apps"
                mkdir -p "${sdir}"
                if command -v convert &>/dev/null; then
                    convert "$candidate" -resize "${size}x${size}" "${sdir}/${APP_NAME}.png" 2>/dev/null \
                        || cp "$candidate" "${sdir}/${APP_NAME}.png"
                else
                    cp "$candidate" "${sdir}/${APP_NAME}.png"
                fi
            done
            gtk-update-icon-cache -f -t "${HOME}/.local/share/icons/hicolor" 2>/dev/null || true
            success "Icon installed → ${ICON_DIR}/${APP_NAME}.png"
            echo "${ICON_DIR}/${APP_NAME}.png"
            return 0
        fi
    done
    warn "No logo.png found in assets/ — using theme icon 'applications-utilities'"
    warn "Drop your icon at: ${SCRIPT_DIR}/assets/logo.png and re-run: ./install_fenrir.sh desktop"
    echo "applications-utilities"
}

write_launcher() {
    mkdir -p "${BIN_DIR}"

    cat > "${BIN_DIR}/fenrir-gui" << LAUNCHER
#!/usr/bin/env bash
if [[ -f "${VENV}/bin/activate" ]]; then source "${VENV}/bin/activate"; fi
cd "${SCRIPT_DIR}"
exec python3 -m fenrir.fenrir_gui "\$@"
LAUNCHER
    chmod +x "${BIN_DIR}/fenrir-gui"
    success "GUI launcher → ${BIN_DIR}/fenrir-gui"

    cat > "${BIN_DIR}/fenrir" << CLILAUNCHER
#!/usr/bin/env bash
if [[ -f "${VENV}/bin/activate" ]]; then source "${VENV}/bin/activate"; fi
cd "${SCRIPT_DIR}"
exec python3 -m fenrir.cli "\$@"
CLILAUNCHER
    chmod +x "${BIN_DIR}/fenrir"
    success "CLI launcher → ${BIN_DIR}/fenrir"

    # Project-local launcher used as the Exec= target (absolute path, always findable)
    cat > "${SCRIPT_DIR}/fenrir-gui.sh" << PROJLAUNCHER
#!/usr/bin/env bash
if [[ -f "${VENV}/bin/activate" ]]; then source "${VENV}/bin/activate"; fi
cd "${SCRIPT_DIR}"
exec python3 -m fenrir.fenrir_gui "\$@"
PROJLAUNCHER
    chmod +x "${SCRIPT_DIR}/fenrir-gui.sh"
    success "Project launcher → ${SCRIPT_DIR}/fenrir-gui.sh"
}

write_desktop() {
    mkdir -p "${APP_DIR}"
    local icon_path
    icon_path=$(install_icon)

    # Prefer absolute launcher path — bare names in Exec= are unreliable
    local exec_path="${SCRIPT_DIR}/fenrir-gui.sh"
    [[ ! -f "$exec_path" ]] && exec_path="${BIN_DIR}/fenrir-gui"

    local desktop_file="${APP_DIR}/${APP_NAME}.desktop"

    # Use printf to guarantee Unix LF line endings — CRLF silently breaks .desktop files
    printf '%s\n' \
        '[Desktop Entry]' \
        'Version=1.1' \
        'Type=Application' \
        'Name=Fenrir Security Scanner' \
        'GenericName=Security Scanner' \
        'Comment=Multi-module penetration testing and network security scanner' \
        "Exec=${exec_path} %u" \
        "TryExec=${exec_path}" \
        "Icon=${icon_path}" \
        'Terminal=false' \
        'NoDisplay=false' \
        'Categories=Network;Security;System;' \
        'Keywords=security;scanner;pentest;nmap;CVE;exploit;network;penetration;' \
        'StartupNotify=true' \
        'StartupWMClass=fenrir_gui' \
        > "${desktop_file}"

    # Must be executable — GNOME/KDE hide or distrust non-executable .desktop files
    chmod +x "${desktop_file}"
    success ".desktop written → ${desktop_file}"

    # xdg-desktop-menu: most portable cross-DE registration method
    if command -v xdg-desktop-menu &>/dev/null; then
        xdg-desktop-menu install --novendor "${desktop_file}" 2>/dev/null \
            && success "Registered via xdg-desktop-menu" \
            || warn "xdg-desktop-menu failed (falling back to file-copy only)"
    fi

    # Rebuild the MIME/application lookup database
    if command -v update-desktop-database &>/dev/null; then
        update-desktop-database "${APP_DIR}" 2>/dev/null \
            && success "Desktop database updated"
    fi

    # Mark as trusted so GNOME Nautilus doesn't show an 'untrusted app' dialog
    if command -v gio &>/dev/null; then
        gio set "${desktop_file}" metadata::trusted true 2>/dev/null \
            && success "Marked trusted (gio)"
    fi

    # KDE: rebuild application catalogue
    if command -v kbuildsycoca5 &>/dev/null; then
        kbuildsycoca5 --noincremental 2>/dev/null & success "KDE catalogue refreshed"
    elif command -v kbuildsycoca6 &>/dev/null; then
        kbuildsycoca6 --noincremental 2>/dev/null &
    fi

    echo ""
    warn "If Fenrir isn't in your menu yet:"
    warn "  GNOME:  Press Alt+F2 → type 'r' → Enter  (restarts the shell)"
    warn "  KDE:    Right-click desktop → Refresh"
    warn "  All DEs: Log out and back in (most reliable)"
    warn "  Also try: xdg-desktop-menu forceupdate"
}

write_desktop_shortcut() {
    local desktop_dir="${HOME}/Desktop"
    command -v xdg-user-dir &>/dev/null && \
        desktop_dir="$(xdg-user-dir DESKTOP 2>/dev/null || echo "${HOME}/Desktop")"
    [[ ! -d "$desktop_dir" ]] && { warn "Desktop dir not found — skipping shortcut"; return; }

    local shortcut="${desktop_dir}/${APP_NAME}.desktop"
    cp "${APP_DIR}/${APP_NAME}.desktop" "${shortcut}"
    chmod +x "${shortcut}"
    command -v gio &>/dev/null && gio set "${shortcut}" metadata::trusted true 2>/dev/null || true
    success "Desktop shortcut → ${shortcut}"
}

fix_desktop() {
    info "=== Diagnosing .desktop visibility ==="
    local desktop_file="${APP_DIR}/${APP_NAME}.desktop"

    [[ ! -f "$desktop_file" ]] && { err "Not found: ${desktop_file}"; info "Run: ./install_fenrir.sh desktop"; return 1; }

    # CRLF check
    if cat -A "${desktop_file}" | grep -q $'\r'; then
        warn "CRLF line endings detected — fixing..."
        sed -i 's/\r//' "${desktop_file}"
        success "Line endings fixed"
    else
        success "Line endings: OK (LF)"
    fi

    # Exec check
    local exec_val; exec_val=$(grep "^Exec=" "${desktop_file}" | head -1 | sed 's/^Exec=//' | awk '{print $1}')
    if [[ -f "$exec_val" ]] || command -v "$exec_val" &>/dev/null 2>&1; then
        success "Exec= target found: ${exec_val}"
    else
        err "Exec= target NOT found: ${exec_val}"
        info "Fix: update Exec= to absolute path of fenrir-gui.sh, then re-run ./install_fenrir.sh fix-desktop"
    fi

    # Icon check
    local icon_val; icon_val=$(grep "^Icon=" "${desktop_file}" | head -1 | sed 's/^Icon=//')
    if [[ -f "$icon_val" ]]; then
        success "Icon= file exists: ${icon_val}"
    elif [[ "$icon_val" == /* ]]; then
        err "Icon= path missing: ${icon_val}"
    else
        info "Icon= theme name: ${icon_val} — refreshing cache..."
        gtk-update-icon-cache -f -t "${HOME}/.local/share/icons/hicolor" 2>/dev/null || true
    fi

    # Permissions
    [[ -x "$desktop_file" ]] && success "chmod: executable" || { chmod +x "$desktop_file"; success "Fixed: chmod +x"; }

    # Re-register
    if command -v xdg-desktop-menu &>/dev/null; then
        xdg-desktop-menu uninstall "${desktop_file}" 2>/dev/null || true
        xdg-desktop-menu install --novendor "${desktop_file}" 2>/dev/null \
            && success "Re-registered" || warn "xdg-desktop-menu failed"
    fi
    command -v update-desktop-database &>/dev/null && update-desktop-database "${APP_DIR}" \
        && success "Database updated"
    command -v gio &>/dev/null && gio set "${desktop_file}" metadata::trusted true 2>/dev/null \
        && success "Trusted"
    echo ""; warn "If still not showing: log out and back in."
}

do_install() {
    info "=== Fenrir Security Scanner Installer ==="
    local PYTHON; PYTHON=$(find_python) || { err "Python 3.10+ required."; exit 1; }
    info "Python: $PYTHON  ($("$PYTHON" --version 2>&1))"
    mkdir -p "${FENRIR_HOME}"
    "$PYTHON" -m venv "${VENV}"
    success "Virtualenv: ${VENV}"
    "${VENV}/bin/pip" install --upgrade pip --quiet
    if [[ -f "${SCRIPT_DIR}/pyproject.toml" ]]; then
        info "Installing from source ..."
        "${VENV}/bin/pip" install -e "${SCRIPT_DIR}" --quiet
    else
        info "Installing from PyPI ..."
        "${VENV}/bin/pip" install fenrir-scanner --quiet
    fi
    "${VENV}/bin/pip" install Pillow reportlab requests --quiet || true
    success "Packages installed"
    write_launcher
    write_desktop
    echo ""; read -rp "Add desktop shortcut on ~/Desktop? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] && write_desktop_shortcut
    [[ ":$PATH:" != *":${BIN_DIR}:"* ]] && \
        warn "Add to ~/.bashrc:  export PATH=\"\$PATH:${BIN_DIR}\""
    echo ""; success "Done! Launch with: fenrir-gui"
}

do_uninstall() {
    info "Uninstalling ..."
    rm -f "${BIN_DIR}/fenrir-gui" "${BIN_DIR}/fenrir" "${SCRIPT_DIR}/fenrir-gui.sh"
    command -v xdg-desktop-menu &>/dev/null && \
        xdg-desktop-menu uninstall "${APP_DIR}/${APP_NAME}.desktop" 2>/dev/null || true
    rm -f "${APP_DIR}/${APP_NAME}.desktop" "${HOME}/Desktop/${APP_NAME}.desktop"
    rm -f "${ICON_DIR}/${APP_NAME}.png"
    command -v update-desktop-database &>/dev/null && \
        update-desktop-database "${APP_DIR}" 2>/dev/null || true
    warn "Venv kept at ${FENRIR_HOME} — to fully remove: rm -rf ${FENRIR_HOME}"
    success "Uninstalled."
}

case "${1:-install}" in
    install)      do_install ;;
    launch)       source "${VENV}/bin/activate" 2>/dev/null; cd "${SCRIPT_DIR}"; exec python3 -m fenrir.fenrir_gui ;;
    desktop)      write_launcher; write_desktop
                  read -rp "Desktop shortcut? [y/N] " a; [[ "$a" =~ ^[Yy]$ ]] && write_desktop_shortcut ;;
    fix-desktop)  fix_desktop ;;
    uninstall)    do_uninstall ;;
    *)            echo "Usage: $0 {install|launch|desktop|fix-desktop|uninstall}"; exit 1 ;;
esac
