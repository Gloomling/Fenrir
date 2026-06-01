#!/usr/bin/env bash
# Fenrir Security Scanner — macOS launcher
# Place this in your Applications folder or Dock.
#
# To make a proper .app bundle:
#   1. Create "Fenrir.app/Contents/MacOS/" directory
#   2. Copy this script there as "Fenrir"
#   3. chmod +x "Fenrir.app/Contents/MacOS/Fenrir"
#   4. Add Info.plist and icon.icns in Contents/

# Activate venv if available
VENV="${HOME}/.fenrir/venv"
if [[ -f "${VENV}/bin/activate" ]]; then
    source "${VENV}/bin/activate"
fi

# macOS: ensure Tk/Tkinter can find the display
export PYTHONPATH="${PYTHONPATH}:$(dirname "$0")/../../.."

# Launch (open in background so Dock shows the window)
python3 -m fenrir.fenrir_gui "$@"
