#!/usr/bin/env bash
# =============================================================================
# Fenrir Security Scanner — run.sh
# Runs using system Python directly. No virtual environment.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Deactivate any active venv so it cannot interfere
deactivate 2>/dev/null || true
unset VIRTUAL_ENV
unset VIRTUAL_ENV_PROMPT

exec python3 -m fenrir.cli "$@"
