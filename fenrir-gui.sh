#!/usr/bin/env bash
if [[ -f "/home/kali/.fenrir/venv/bin/activate" ]]; then source "/home/kali/.fenrir/venv/bin/activate"; fi
cd "/home/kali/Desktop/Fenrir"
exec python3 -m fenrir.fenrir_gui "$@"
